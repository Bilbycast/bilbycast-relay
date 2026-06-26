# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bilbycast-relay is a stateless QUIC relay server written in Rust that enables IP tunneling between NAT'd edge nodes. It acts as a simple traffic forwarder, pairing ingress and egress edge nodes by tunnel ID and forwarding TCP streams and UDP datagrams between them. The relay can run with zero config, but supports optional security hardening: Bearer token authentication for the REST API (`api_token`) and per-tunnel HMAC-SHA256 bind authentication (managed via `authorize_tunnel`/`revoke_tunnel` commands from bilbycast-manager).

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

The relay runs three concurrent tasks:
- **QUIC server** (default `:4433`) — accepts edge node connections, handles tunnel binding, and forwards data
- **REST API** (default `:4480`, Axum) — read-only endpoints: `/health` (always public), `/metrics`, `/api/v1/tunnels`, `/api/v1/edges`, `/api/v1/stats`. Plus one mutating endpoint: `DELETE /api/v1/tunnels/{id}` — an administrative escape hatch to tear down an orphaned tunnel when the manager (the normal cleanup path) is unavailable. It revokes the bind authorization **and** force-removes the live tunnel entry (reusing the same `revoke_tunnel` + `force_remove_tunnel` router primitives as the WS commands), notifying any still-bound peer with `TunnelDown`. **Fail-closed**: the DELETE returns `403` unless `api_token` is configured (the read-only GETs stay open-by-default for backwards compatibility, but a destructive route must never be reachable unauthenticated). If `api_token` is configured, all endpoints except `/health` require `Authorization: Bearer <token>`. Invalid UUID → `400`, unknown tunnel → `404`.
- **Manager client** (optional) — persistent outbound WebSocket to bilbycast-manager for centralized monitoring, stats streaming (1s interval), health (15s), and command handling

Main uses `tokio::select!` to run all tasks concurrently and handle graceful shutdown via Ctrl+C.

### Connection Lifecycle

1. Edge connects via QUIC and opens a bidirectional control stream
2. Edge sends `Hello { protocol_version, software_version }` as the first message. Relay responds with `HelloAck`. Version mismatches are warned but don't reject the connection. Old edges that skip this step are handled gracefully
3. Edge optionally sends `Identify { edge_id }` with its manager node_id (enables topology correlation in the manager UI)
4. Edge sends `TunnelBind` with a tunnel UUID, direction (ingress/egress), and optional `bind_token` (HMAC-SHA256). If the relay has pre-authorized tokens for this tunnel (via manager `authorize_tunnel` command), the bind_token is verified. When no authorization is registered, behaviour is controlled by `RelayConfig::require_bind_auth`: `false` (default, backwards compatible) allows unauthenticated bind; `true` rejects with `TunnelDown { reason: "bind authentication failed" }`. Recommended value for production: `true`
5. When both sides of a tunnel bind, the relay notifies both edges with `TunnelReady`
6. Data flows: TCP via bidirectional QUIC streams (with `StreamHeader`), UDP via QUIC datagrams (16-byte UUID prefix)

### Key Modules

| Module | Responsibility |
|--------|---------------|
| **`protocol.rs`** | Wire format: 4-byte BE length-prefixed JSON messages, `EdgeMessage`/`RelayMessage`/`PeerMessage` enums, `StreamHeader`, UDP datagram encoding (16-byte UUID prefix + payload). `TUNNEL_PROTOCOL_VERSION` constant. `ParsedMessage<T>` enum + `read_message_resilient()` for graceful handling of unknown message types |
| **`session.rs`** | Per-connection handler: control stream loop (uses resilient deserialization), TCP stream forwarding (`forward_tcp_stream`), UDP datagram forwarding. `SessionContext` holds shared state. Edges get a `connection_id` from remote addr + counter; optionally provide a stable identity via `Identify` message (used for topology correlation) |
| **`tunnel_router.rs`** | `TunnelRouter` pairs ingress/egress endpoints by tunnel UUID using `DashMap`. Manages bind/unbind lifecycle, peer connection lookup, and per-tunnel bind token authorization (`authorized_tokens` DashMap, constant-time token comparison) |
| **`server.rs`** | QUIC endpoint setup with self-signed TLS fallback. Configures transport parameters (datagram buffers sized for SRT at 10 Mbps, keep-alive at 5s) |
| **`api.rs`** | Axum REST routes: `/health` (public), `/metrics`, `/api/v1/tunnels`, `/api/v1/edges`, `/api/v1/stats` (read-only), plus `DELETE /api/v1/tunnels/{id}` (administrative tunnel teardown, fail-closed — refuses unless `api_token` is set). Optional Bearer token auth middleware if `api_token` is configured |
| **`config.rs`** | `RelayConfig` + `ManagerConfig` (JSON, with serde defaults). Fields: `quic_addr`, `quic_addrs` (`Option<Vec<String>>` — dual-stack list, default `["0.0.0.0:4433", "[::]:4433"]` on fresh install), `api_addr`, `api_addrs` (same shape, default `["0.0.0.0:4480", "[::]:4480"]`), `public_quic_addr` (advertised dial address for remote edges — distinct from the bind list; rejected if unspecified `0.0.0.0`/`[::]`; flows through to the manager via health and surfaces in the tunnel-creation dropdown), `tls_cert_path`, `tls_key_path`, `api_token` (optional, 32-128 chars), `require_bind_auth` (bool, default `false`), `max_connections_per_ip` (u32, default `64` — DoS mitigation, per-IP simultaneous QUIC connection cap), `max_tunnels_per_connection` (u32, default `100` — DoS mitigation, per-connection tunnel-bind cap), `manager` (optional), `logging` (optional `LoggingConfig` — structured-JSON log shipper for SIEM/NMS pickup; stdout/file/syslog targets, raw/splunk/dataminer formats; mirrors the edge's shape). v6 entries get `IPV6_V6ONLY=1` on bind via `socket2` so they coexist with v4 listeners on the same port. Resolvers: `RelayConfig::effective_quic_addrs` / `effective_api_addrs`. CLI overrides: `--quic-addr` / `--api-addr` (legacy single-addr) plus `--quic-addrs` / `--api-addrs` (comma-separated dual-stack) and `--public-quic-addr`. |
| **`stats.rs`** | Atomic (`AtomicU64`) per-tunnel and global stats — lock-free counters for bytes, streams, datagrams, plus global `RelayStats` with peak watermarks (tunnels, edges), connection count, and bandwidth estimation |
| **`manager/client.rs`** | WebSocket client to bilbycast-manager: auth (registration token or node_id/secret), stats/health streaming, operational events, command handling (get_config, disconnect_edge, close_tunnel, list_tunnels, list_edges, authorize_tunnel, revoke_tunnel) |
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

### Manager Connection (Optional)

If `manager` is configured in `RelayConfig`, the relay maintains a persistent outbound WebSocket connection to bilbycast-manager using the same protocol as bilbycast-edge:

1. Connects to manager WebSocket URL, sends auth (registration_token or node_id + node_secret, plus `software_version` and `protocol_version` for compatibility detection)
2. On first connect: receives `register_ack` with credentials, persists to config file
3. Sends stats every 1 second: tunnels array, connected edges, total bandwidth/throughput (bps), peak watermarks, active TCP streams, uptime
4. Sends health every 15 seconds: status, version, tunnel/edge counts, total bytes forwarded, peaks, connections total, `api_addr`, `quic_addr` (bind), and `public_quic_addr` (advertised dial address; manager UI prefers this when set, falls back to `quic_addr` only when it isn't listen-only)
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

This separation prevents head-of-line blocking between control, TCP, and UDP planes.

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
