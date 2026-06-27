# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bilbycast-relay is a stateless relay server written in Rust that provides NAT traversal between edge nodes. It is a generic, **opaque per-path forwarder**: it pairs the two ends of each path by tunnel ID and forwards data between them, never inspecting, terminating, or combining the streams it carries (it sees only `[16-byte tunnel_id][AEAD ciphertext]`). It carries three logically distinct path types, all forwarded the same opaque way:

- **QUIC tunnels** — TCP streams + UDP datagrams over QUIC/TLS 1.3 (`:4433`, `server.rs` + `session.rs`).
- **Native SRT/RIST over relay** — plain UDP, no QUIC (`:4434`, `udp_relay.rs`), so SRT/RIST keep their own ARQ + congestion control without QUIC's per-packet overhead or a second congestion controller.
- **Individual bond legs** — a relayed bond leg is just a native plain-UDP tunnel. Bond aggregation, cross-leg ARQ, FEC, and reordering run **end-to-end edge↔edge**; the relay forwards each leg opaquely. **There is no "bond bridge"** — the relay does not terminate or combine bonds (the earlier bond-bridge design was removed).

Every path is established by both edges dialing *out* (so both ends can be behind NAT), can go direct or over any relay in any combination, and may use a primary + backup relay. The relay can run with zero config, but supports optional security hardening: Bearer token authentication for the REST API (`api_token`) and per-tunnel HMAC-SHA256 bind authentication (managed via `authorize_tunnel`/`revoke_tunnel` commands from bilbycast-manager).

## Build & Development Commands

```bash
cargo build                  # Build debug
cargo build --release        # Build release
cargo run                    # Run with defaults (no config needed)
cargo run -- -c relay.json   # Run with optional config file
cargo run -- --quic-addr 0.0.0.0:4433 --api-addr 0.0.0.0:4480  # CLI overrides
cargo test                   # Run all tests (unit + integration)
cargo test --lib             # Unit tests only
cargo test --test integration # Integration tests only
cargo test test_name         # Run a single test by name
```

**Logging**: Controlled via `RUST_LOG` env var (default: `bilbycast_relay=info`).

**Optional security**: Set `api_token` in config to require Bearer token auth on REST API endpoints. Per-tunnel bind authentication is enabled automatically when the manager sends `authorize_tunnel` commands; set `require_bind_auth: true` to additionally reject binds for tunnels without a pre-registered authorization (fail-closed — recommended for production).

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architectural diagram.

The relay runs up to four concurrent tasks:
- **QUIC server** (default `:4433`) — accepts edge node connections, handles tunnel binding, and forwards data
- **Native-UDP relay** (default `:4434`, `udp_relay.rs`) — the plain-UDP data plane for native SRT/RIST over relay and for individual bond legs. Enabled by default (`udp_relay_enabled`). Bind failures are **non-fatal**: the relay logs, drops the `udp-relay` capability, and continues QUIC-only (an upgrade never bricks a relay over a busy port). See "Native-UDP relay data plane" below.
- **REST API** (default `:4480`, Axum) — read-only endpoints: `/health` (always public), `/metrics`, `/api/v1/tunnels`, `/api/v1/udp-sessions`, `/api/v1/edges`, `/api/v1/stats`. Plus two mutating endpoints: `DELETE /api/v1/tunnels/{id}` and `DELETE /api/v1/udp-sessions/{id}` — administrative escape hatches to tear down an orphaned QUIC tunnel / native-UDP session when the manager (the normal cleanup path) is unavailable. The tunnel DELETE revokes the bind authorization **and** force-removes the live tunnel entry (reusing the same `revoke_tunnel` + `force_remove_tunnel` router primitives as the WS commands), notifying any still-bound peer with `TunnelDown`. **Fail-closed**: both DELETEs return `403` unless `api_token` is configured (the read-only GETs stay open-by-default for backwards compatibility, but a destructive route must never be reachable unauthenticated). If `api_token` is configured, all endpoints except `/health` require `Authorization: Bearer <token>`. Invalid UUID → `400`, unknown tunnel/session → `404`.
- **Manager client** (optional) — persistent outbound WebSocket to bilbycast-manager for centralized monitoring, stats streaming (1s interval), health (15s), and command handling

Main uses `tokio::select!` to run all tasks concurrently and handle graceful shutdown via Ctrl+C.

### Connection Lifecycle

1. Edge connects via QUIC and opens a bidirectional control stream
2. Edge sends `Hello { protocol_version, software_version }` as the first message. Relay responds with `HelloAck`. Version mismatches are warned but don't reject the connection. Old edges that skip this step are handled gracefully
3. Edge optionally sends `Identify { edge_id }` with its manager node_id (enables topology correlation in the manager UI)
4. Edge sends `TunnelBind` with a tunnel UUID, direction (ingress/egress), and optional `bind_token` (HMAC-SHA256). If the relay has pre-authorized tokens for this tunnel (via manager `authorize_tunnel` command), the bind_token is verified. When no authorization is registered, behaviour is controlled by `RelayConfig::require_bind_auth`: `false` (default, backwards compatible) allows unauthenticated bind; `true` rejects with `TunnelDown { reason: "bind authentication failed" }`. Recommended value for production: `true`
5. When both sides of a tunnel bind, the relay notifies both edges with `TunnelReady`
6. Data flows: TCP via bidirectional QUIC streams (with `StreamHeader`), UDP via QUIC datagrams (16-byte UUID prefix)

### Native-UDP relay data plane (no QUIC)

`udp_relay.rs` is the additive sibling of the QUIC path, carrying **native SRT/RIST over relay** and **individual bond legs** over plain UDP (default `:4434`). It exists because SRT/RIST (and the bond) run their own ARQ + congestion control; wrapping them in QUIC adds per-packet AEAD/header overhead plus a second congestion controller fighting theirs.

- **Source-address rendezvous**: each edge connects *outbound* and periodically (~every 5 s) sends an authenticated `UdpRelayControl::Register { tunnel_id, direction, bind_token }` control datagram. The relay latches that edge's post-NAT source address into the tunnel's ingress/egress slot (lock-free atomic `SocketAddr`). Because both edges dial out, **both ends can sit behind NAT**.
- **Opaque forwarding**: media datagrams use the identical `[16-byte tunnel_id][AEAD payload]` framing as the QUIC datagram path. The relay forwards each verbatim to the *opposite* latched slot. It holds no media key — for a bond leg this means bond reassembly/ARQ/FEC are invisible to the relay.
- **Control multiplexing**: control datagrams are distinguished from media by a reserved **nil (all-zero) UUID** prefix; real tunnel IDs are random v4 UUIDs (validation rejects nil), so there is no collision. The relay `Ack { ready }`s each register — an edge that stops receiving acks treats the relay as dead and fails over (enabling primary + backup relays per leg).
- **Auth + DoS**: bind tokens are verified against the same `authorize_tunnel` registry as the QUIC path (`TunnelRouter::verify_bind_token`). A per-IP session cap mirrors the QUIC per-IP connection cap; idle sessions (no register/data for 30 s) are reaped.
- **Non-fatal binds**: if no `:4434` socket can bind, the task exits, the relay drops the `udp-relay` capability, and continues QUIC-only. Disable entirely with `udp_relay_enabled: false` / `--no-udp-relay`.

A relayed bond leg is therefore not a special relay concept — it is just one of these native-UDP tunnels. The relay never terminates or combines a bond.

### Key Modules

| Module | Responsibility |
|--------|---------------|
| **`protocol.rs`** | Wire format: 4-byte BE length-prefixed JSON messages, `EdgeMessage`/`RelayMessage`/`PeerMessage` enums, `StreamHeader`, UDP datagram encoding (16-byte UUID prefix + payload). `TUNNEL_PROTOCOL_VERSION` constant (currently **2** — v2 added the plain-UDP relay data plane). `ParsedMessage<T>` enum + `read_message_resilient()` for graceful handling of unknown message types. Also defines `UdpRelayControl` (`Register`/`Ack`) + `encode_udp_control`/`try_decode_udp_control` for the native plane's control datagrams (nil-UUID sentinel prefix; must match `bilbycast-edge/src/tunnel/protocol.rs`) |
| **`session.rs`** | Per-connection handler: control stream loop (uses resilient deserialization), TCP stream forwarding (`forward_tcp_stream`), UDP datagram forwarding. `SessionContext` holds shared state (incl. `udp_sessions: UdpSessionRouter`). Edges get a `connection_id` from remote addr + counter; optionally provide a stable identity via `Identify` message (used for topology correlation) |
| **`tunnel_router.rs`** | `TunnelRouter` pairs ingress/egress QUIC endpoints by tunnel UUID using `DashMap`. Manages bind/unbind lifecycle, peer connection lookup, and per-tunnel bind token authorization (`authorized_tokens` DashMap, constant-time token comparison) — also reused by the native-UDP plane via `verify_bind_token` |
| **`udp_relay.rs`** | Native plain-UDP relay data plane (native SRT/RIST over relay + individual bond legs, no QUIC). `UdpSessionRouter` pairs two edges by tunnel UUID via **source-address rendezvous**: each edge sends authenticated `Register` control datagrams (nil-UUID prefix), the relay latches the post-NAT source address per direction into atomic slots, then forwards media datagrams (`[16B real UUID][AEAD]`) **verbatim** to the opposite latched address — relay stays opaque (no media key). Replies `Ack { ready }` (lets edges detect a dead relay → failover). Per-IP session cap (DoS), 30 s idle reaper, 32 MB socket buffers, dual-stack bind (one socket per `effective_udp_relay_addrs` entry). Bind auth reuses `TunnelRouter::verify_bind_token` |
| **`server.rs`** | QUIC endpoint setup with self-signed TLS fallback. Configures transport parameters (datagram buffers sized for SRT at 10 Mbps, keep-alive at 5s). `create_session_context` builds the shared `SessionContext` (QUIC router + `UdpSessionRouter`) |
| **`api.rs`** | Axum REST routes: `/health` (public), `/metrics`, `/api/v1/tunnels`, `/api/v1/udp-sessions`, `/api/v1/edges`, `/api/v1/stats` (read-only), plus `DELETE /api/v1/tunnels/{id}` and `DELETE /api/v1/udp-sessions/{id}` (administrative teardown, fail-closed — both refuse with `403` unless `api_token` is set). Optional Bearer token auth middleware if `api_token` is configured |
| **`config.rs`** | `RelayConfig` + `ManagerConfig` (JSON, with serde defaults). Fields: `quic_addr`, `quic_addrs` (`Option<Vec<String>>` — dual-stack list, default `["0.0.0.0:4433", "[::]:4433"]` on fresh install), `api_addr`, `api_addrs` (same shape, default `["0.0.0.0:4480", "[::]:4480"]`), `public_quic_addr` (advertised dial address for remote edges — distinct from the bind list; rejected if unspecified `0.0.0.0`/`[::]`; flows through to the manager via health and surfaces in the tunnel-creation dropdown), `udp_relay_enabled` (bool, default `true` — enable the native plain-UDP plane), `udp_relay_addrs` (`Option<Vec<String>>`, default `["0.0.0.0:4434", "[::]:4434"]`), `public_udp_addr` (advertised dial address for the native plane — same rules as `public_quic_addr`; manager falls back to `public_quic_addr`'s host + the UDP port when unset), `tls_cert_path`, `tls_key_path`, `api_token` (optional, 32-128 chars), `require_bind_auth` (bool, default `false`), `max_connections_per_ip` (u32, default `64` — DoS mitigation, per-IP simultaneous QUIC connection cap), `max_tunnels_per_connection` (u32, default `100` — DoS mitigation, per-connection tunnel-bind cap), `manager` (optional), `logging` (optional `LoggingConfig` — structured-JSON log shipper for SIEM/NMS pickup; stdout/file/syslog targets, raw/splunk/dataminer formats; mirrors the edge's shape). v6 entries get `IPV6_V6ONLY=1` on bind via `socket2` so they coexist with v4 listeners on the same port. Resolvers: `RelayConfig::effective_quic_addrs` / `effective_api_addrs` / `effective_udp_relay_addrs`. CLI overrides: `--quic-addr` / `--api-addr` (legacy single-addr) plus `--quic-addrs` / `--api-addrs` (comma-separated dual-stack), `--public-quic-addr`, `--udp-relay-addrs`, `--public-udp-addr`, and `--no-udp-relay` (disable the native plane). |
| **`stats.rs`** | Atomic (`AtomicU64`) per-tunnel and global stats — lock-free counters for bytes, streams, datagrams, plus global `RelayStats` with peak watermarks (tunnels, edges), connection count, and bandwidth estimation |
| **`manager/client.rs`** | WebSocket client to bilbycast-manager: auth (registration token or node_id/secret), stats/health streaming, operational events, command handling (get_config, disconnect_edge, close_tunnel, list_tunnels, list_edges, authorize_tunnel, revoke_tunnel). Health advertises `public_quic_addr`, `public_udp_addr`, `udp_sessions_total` / `udp_sessions_active`, and a `capabilities` array (`"udp-relay"` when the native plane is enabled) |
| **`manager/events.rs`** | `EventSender`/`EventSeverity`/`Event` types and the event channel for forwarding operational events to the manager. See `docs/events-and-alarms.md` for the full event reference |

### Protocol Messages

**EdgeMessage** (edge to relay):
- `Hello` — protocol version handshake (sent first, relay responds with `HelloAck`). Contains `protocol_version` and `software_version`. Old relays ignore this gracefully via resilient deserialization
- `Identify` — optional, sent before TunnelBind to provide a stable edge identity (manager node_id) for topology correlation
- `TunnelBind` — bind to a tunnel with UUID, direction, and optional `bind_token` (HMAC-SHA256 hex for relay authentication)
- `TunnelUnbind` — unbind from a tunnel
- `Ping` — keepalive

**RelayMessage** (relay to edge):
- `HelloAck` — protocol version handshake response. Contains relay's `protocol_version` and `software_version`. Edge logs warning on mismatch. Old edges that don't send `Hello` never receive this
- `TunnelReady` — both sides bound, tunnel is active
- `TunnelWaiting` — only one side bound, waiting for peer
- `TunnelDown` — peer disconnected or unbound
- `Pong` — keepalive response

No `Auth`, `AuthOk`, or `AuthError` messages exist on the control stream. Tunnel bind authentication is handled inline via the `bind_token` field on `TunnelBind`.

**Backward compatibility**: The control stream uses `read_message_resilient()` which returns `ParsedMessage::Unknown` for unrecognized message types instead of a deserialization error. This allows newer nodes to send new message types without tearing down connections with older nodes.

**UdpRelayControl** (native plain-UDP plane, not the QUIC control stream — carried as nil-UUID-prefixed datagrams on `:4434`):
- `Register { tunnel_id, direction, bind_token, protocol_version }` — edge → relay: register/keepalive this endpoint's post-NAT source address (rendezvous) and prove authorization
- `Ack { tunnel_id, ready }` — relay → edge: acknowledge a register and report whether both sides are now latched (media may flow); absence of acks signals a dead relay → failover

### Manager Connection (Optional)

If `manager` is configured in `RelayConfig`, the relay maintains a persistent outbound WebSocket connection to bilbycast-manager using the same protocol as bilbycast-edge:

1. Connects to manager WebSocket URL, sends auth (registration_token or node_id + node_secret, plus `software_version` and `protocol_version` for compatibility detection)
2. On first connect: receives `register_ack` with credentials, persists to config file
3. Sends stats every 1 second: tunnels array, connected edges, total bandwidth/throughput (bps), peak watermarks, active TCP streams, uptime
4. Sends health every 15 seconds: status, version, tunnel/edge counts, total bytes forwarded, peaks, connections total, `api_addr`, `quic_addr` (bind), `public_quic_addr` (advertised dial address; manager UI prefers this when set, falls back to `quic_addr` only when it isn't listen-only), `public_udp_addr` (advertised dial address for the native plane), native-UDP session counts (`udp_sessions_total` / `udp_sessions_active`), and a `capabilities` array (includes `"udp-relay"` when the native plane is enabled — the manager UI gates the native-relay surface on this bit)
5. Handles commands: `get_config`, `disconnect_edge`, `close_tunnel`, `list_tunnels`, `list_edges`, `authorize_tunnel`, `revoke_tunnel`
6. Reconnects with a **fixed 5 s backoff** (not exponential) on disconnection, rotating to the next configured URL on each failure. The backoff constant is `Duration::from_secs(5)` (`let fixed_backoff = Duration::from_secs(5);` in `manager/client.rs`); `cursor` advances by one (`cursor.wrapping_add(1)`) after every connection close/error so successive attempts cycle through `urls[]`. The backoff is *not* reset on success — there is simply no delay while connected; the 5 s sleep only runs between attempts.

**Tunnel bind authentication commands**: `authorize_tunnel` pre-registers expected HMAC-SHA256 bind tokens (ingress + egress) for a tunnel UUID. `revoke_tunnel` removes authorization. When authorized, edges must include a valid `bind_token` in their `TunnelBind` message. Old per-edge commands (`authorize_edge`, `revoke_edge`, `list_authorized_edges`) were removed in favor of this per-tunnel approach.

`ManagerConfig` fields: `enabled`, `urls` (`Vec<String>` — 1-16 ordered `wss://` URLs; plaintext `ws://` is rejected; the client tries `urls[0]` first and rotates to the next on WS close with a fixed 5 s backoff), `accept_self_signed_cert` (default false — requires `BILBYCAST_ALLOW_INSECURE=1` env var as safety guard), `cert_fingerprint` (optional SHA-256 fingerprint for certificate pinning), `registration_token` (one-time), `node_id`, `node_secret` (persistent after registration). Supports `rotate_secret` command for periodic secret rotation.

### Two Connection Modes (ALPN)

- `bilbycast-relay` — edge-to-relay (this server implements this)
- `bilbycast-direct` — edge-to-edge peer-to-peer (defined in protocol but implemented by bilbycast-edge)

### Concurrency Model (Non-Blocking Design)

Each edge connection spawns an independent tokio task. Within each session, three concurrent loops run via `tokio::select!`:

1. **Control stream loop** — processes `Identify`/`TunnelBind`/`TunnelUnbind`/`Ping` on the control bi-stream
2. **Data stream loop** — accepts incoming bi-streams, spawns a task per stream for TCP forwarding (bidirectional copy via `tokio::join!` with 64KB buffers)
3. **Datagram loop** — reads QUIC datagrams and forwards UDP inline (non-blocking `send_datagram`)

This separation prevents head-of-line blocking between control, TCP, and UDP planes. The native plain-UDP plane (`udp_relay.rs`) runs as a separate task family outside the QUIC session model: one `recv_loop` per bound socket sharing a lock-free `UdpSessionRouter`, plus an idle-session reaper — no per-edge connection task, since plain UDP has no connection.

**Concurrency primitives used (zero locks):**

| Primitive | Usage |
|-----------|-------|
| `DashMap<String, Connection>` | Edge registry — lock-free concurrent map |
| `DashMap<Uuid, TunnelState>` | Tunnel state — lock-free concurrent map |
| `AtomicU64` | Stats counters — no contention |
| `tokio::select!` | Multiplexing async tasks within a session |
| `tokio::join!` | Bidirectional TCP copy (both directions concurrent) |
| `tokio::spawn` | Per-connection and per-stream task isolation |

No `Mutex` or `RwLock` is used anywhere in the codebase.

### Security Architecture

| Layer | Mechanism | Detail |
|-------|-----------|--------|
| **Transport encryption** | TLS 1.3 via QUIC | `rustls` + `quinn` — all data encrypted in transit between edge and relay |
| **End-to-end encryption** | ChaCha20-Poly1305 | Edge-to-edge encryption at the edge level. The relay sees only encrypted ciphertext — it cannot read tunnel payloads |
| **REST API auth** | Bearer token (optional) | If `api_token` is configured, all endpoints except `/health` require `Authorization: Bearer <token>`. Prevents topology/tunnel enumeration |
| **Tunnel bind auth** | HMAC-SHA256 (optional) | Manager pre-authorizes tunnels via `authorize_tunnel` command. Edges must include valid `bind_token` in `TunnelBind`. Constant-time comparison prevents timing attacks. Policy for tunnels without a pre-registered entry is controlled by `require_bind_auth`: default `false` = unauthenticated bind allowed (backwards compatible); `true` = fail-closed, recommended for production |
| **ALPN enforcement** | Protocol negotiation | Server enforces `bilbycast-relay` ALPN — prevents protocol downgrade |
| **Tunnel isolation** | Per-tunnel UUID routing | Tunnel IDs must be valid UUIDs (v4 random). Data routed exclusively to the bound peer via `TunnelRouter`. No cross-tunnel leakage |
| **Resource protection** | QUIC transport limits + DoS caps | Max 1024 bidi / 256 uni streams per connection, 5s keep-alive for dead connection detection. Plus per-IP connection cap (`max_connections_per_ip`, default 64) rejecting connection floods at handshake, and per-connection tunnel-bind cap (`max_tunnels_per_connection`, default 100) — both surface a `relay_dos_suspect` event |

**Security model**: The relay forwards encrypted ciphertext between edges without the ability to inspect or modify payloads. Three layers of defense: (1) QUIC/TLS 1.3 transport encryption, (2) ChaCha20-Poly1305 end-to-end encryption between edges, (3) optional per-tunnel HMAC-SHA256 bind authentication preventing unauthorized tunnel hijacking. Tunnel IDs must be valid UUIDs, preventing predictable v5 derivation from human-readable names.

**Scalability**: The relay holds minimal auth state (only pre-authorized tunnel tokens from the manager, stored in a DashMap). Multiple relays can run behind a load balancer — the manager sends `authorize_tunnel` to whichever relay the tunnel uses.

**Config validation** (`config.rs`): Socket addresses validated as parseable. Manager `urls[]` must be 1-16 entries, each `wss://`, ≤2048 chars, unique, when enabled. `api_token` must be 32-128 chars if set. `public_quic_addr` (if set) must be a dialable `host:port` (IP literal or DNS name), rejected if unspecified. `logging` shipper validated (file path / size / backups, syslog addr).

**DoS mitigation** (`session.rs`): two configurable caps bound resource exhaustion from a misbehaving or compromised host. `max_connections_per_ip` (default 64) tracks simultaneous QUIC connections per source IP in a `DashMap<IpAddr, AtomicU32>`; new connections at or above the cap are dropped at handshake. `max_tunnels_per_connection` (default 100) caps tunnel binds on a single connection; excess `TunnelBind` messages are rejected with `TunnelDown { reason: "per-connection tunnel limit exceeded" }`. Both emit a Warning `relay_dos_suspect` event to the manager.

**Protocol message limits:**
- QUIC control messages: max 1MB per message (length-prefixed)
- WebSocket messages to/from manager: bounded by protocol envelope

### QoS & Backpressure

| Aspect | Design | Detail |
|--------|--------|--------|
| **QUIC flow control** | Built-in | Quinn handles stream-level and connection-level flow control automatically |
| **TCP backpressure** | Async I/O | `write_all()` awaits peer readiness — natural backpressure propagation |
| **UDP datagram buffers** | 2 MB send/receive | Sized for SRT at 10 Mbps (~1300+ datagrams of 1500 bytes in-flight) |
| **UDP overflow** | Best-effort drop | `send_datagram()` returns error on full buffer — logged, not fatal. UDP is inherently lossy |
| **Stream concurrency** | 1024 bidi / 256 uni | QUIC transport limits prevent resource exhaustion |
| **Keep-alive** | 5-second interval | Detects dead connections; triggers cleanup via `connection.closed()` |
| **Stream buffers** | 64 KB per direction | Balanced for throughput vs memory per tunnel |

### Error Handling

- All fallible functions return `anyhow::Result<T>` with contextual errors
- Data forwarding errors (stream/datagram) are logged at `debug` level but don't crash the session
- Connection-level errors trigger full cleanup: edge unregistered, all tunnels unbound, peers notified with `TunnelDown`
- UDP datagram send failures are non-fatal (best-effort, continue processing)

### Testing

Integration tests (`tests/integration.rs`) spin up the full QUIC relay, connect two simulated edges, and verify TCP/UDP data forwarding. They duplicate the wire protocol types since this is a binary crate (not a library).

Test coverage: tunnel state transitions (waiting/active), bidirectional TCP forwarding, UDP datagram forwarding, ping/pong keepalive.
