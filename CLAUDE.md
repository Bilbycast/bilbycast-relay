# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bilbycast-relay is a QUIC relay server written in Rust that enables IP tunneling between NAT'd edge nodes. It acts as an intermediary, pairing ingress and egress edge nodes by tunnel ID and forwarding TCP streams and UDP datagrams between them.

## Build & Development Commands

```bash
cargo build                  # Build debug
cargo build --release        # Build release
cargo run -- -c relay-config.json   # Run with config file
cargo test                   # Run all tests (unit + integration)
cargo test --lib             # Unit tests only
cargo test --test integration # Integration tests only
cargo test test_name         # Run a single test by name
```

**Logging**: Controlled via `RUST_LOG` env var (default: `bilbycast_relay=info`).

**Shared secret**: Required. Set via config file `shared_secret` field or `RELAY_SHARED_SECRET` env var.

**Token generation**: `cargo run -- --generate-token <edge_id>` generates an auth token and exits.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full architectural diagram.

The relay runs three concurrent tasks:
- **QUIC server** (default `:4433`) — accepts edge node connections, handles auth, tunnel binding, and data forwarding
- **REST API** (default `:4480`, Axum) — health/status endpoints (`/health`, `/api/v1/tunnels`, `/api/v1/edges`)
- **Manager client** (optional) — persistent outbound WebSocket to bilbycast-manager for centralized monitoring, stats streaming (1s interval), health (15s), and command handling

Main uses `tokio::select!` to run all tasks concurrently and handle graceful shutdown via Ctrl+C.

### Connection Lifecycle

1. Edge connects via QUIC and opens a bidirectional control stream
2. Edge sends `Auth` message with HMAC-SHA256 token; relay verifies against shared secret (`session.rs:authenticate`)
3. Edge sends `TunnelBind` with a tunnel UUID and direction (ingress/egress)
4. When both sides of a tunnel bind, the relay notifies both edges with `TunnelReady`
5. Data flows: TCP via bidirectional QUIC streams (with `StreamHeader`), UDP via QUIC datagrams (16-byte UUID prefix)

### Key Modules

| Module | Responsibility |
|--------|---------------|
| **`protocol.rs`** | Wire format: 4-byte BE length-prefixed JSON messages, `EdgeMessage`/`RelayMessage`/`PeerMessage` enums, `StreamHeader`, UDP datagram encoding (16-byte UUID prefix + payload) |
| **`session.rs`** | Per-connection handler: auth, control stream loop, TCP stream forwarding (`forward_tcp_stream`), UDP datagram forwarding. `SessionContext` holds shared state |
| **`tunnel_router.rs`** | `TunnelRouter` pairs ingress/egress endpoints by tunnel UUID using `DashMap`. Manages bind/unbind lifecycle and peer connection lookup |
| **`auth.rs`** | Stateless HMAC-SHA256 token generation/verification. Token format: `base64(identity:hmac_hex)`. Used for both relay auth and direct P2P auth |
| **`server.rs`** | QUIC endpoint setup with self-signed TLS fallback. Configures transport parameters (datagram buffers sized for SRT at 10 Mbps, keep-alive at 15s) |
| **`api.rs`** | Axum REST routes: `/health`, `/api/v1/tunnels`, `/api/v1/edges` |
| **`config.rs`** | `RelayConfig` + `ManagerConfig` (JSON, with serde defaults). Supports config file + CLI overrides + env vars |
| **`stats.rs`** | Atomic (`AtomicU64`) per-tunnel and global stats — lock-free counters for bytes, streams, datagrams |
| **`manager/client.rs`** | WebSocket client to bilbycast-manager: auth (registration token or node_id/secret), stats/health streaming, command handling (get_config, disconnect_edge, close_tunnel, list_tunnels, list_edges) |

### Manager Connection (Optional)

If `manager` is configured in `RelayConfig`, the relay maintains a persistent outbound WebSocket connection to bilbycast-manager using the same protocol as bilbycast-edge:

1. Connects to manager WebSocket URL, sends auth (registration_token or node_id + node_secret)
2. On first connect: receives `register_ack` with credentials, persists to config file
3. Sends stats every 1 second: tunnels array, connected edges, total bandwidth, uptime
4. Sends health every 15 seconds: status, version, tunnel/edge counts, listen addresses
5. Handles commands: `get_config` (returns config with secrets redacted), `disconnect_edge`, `close_tunnel`, `list_tunnels`, `list_edges`
6. Reconnects with exponential backoff (1s → 60s) on disconnection

`ManagerConfig` fields: `enabled`, `url`, `registration_token` (one-time), `node_id`, `node_secret` (persistent after registration).

### Two Connection Modes (ALPN)

- `bilbycast-relay` — edge-to-relay (this server implements this)
- `bilbycast-direct` — edge-to-edge peer-to-peer (defined in protocol but implemented by bilbycast-edge)

### Concurrency Model (Non-Blocking Design)

Each edge connection spawns an independent tokio task. Within each session, three concurrent loops run via `tokio::select!`:

1. **Control stream loop** — processes `TunnelBind`/`TunnelUnbind`/`Ping` on the control bi-stream
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

| Layer | Mechanism | Implementation |
|-------|-----------|----------------|
| **Transport encryption** | TLS 1.3 via QUIC | `rustls` + `quinn` — all data encrypted in transit |
| **Identity verification** | ALPN protocol negotiation | Server enforces `bilbycast-relay` ALPN — prevents protocol downgrade |
| **Authentication** | HMAC-SHA256 stateless tokens | `auth.rs` — token = `base64(edge_id:hmac_sha256_hex(edge_id, secret))` |
| **Auth-before-data** | Mandatory auth gate | `session.rs` — connection rejected immediately on auth failure, no data streams accepted |
| **Tunnel isolation** | Per-tunnel UUID routing | Tunnel data is routed exclusively to the bound peer via `TunnelRouter` |

**Token security notes:**
- Tokens are stateless (no server-side session storage)
- HMAC prevents forgery — edge_id is embedded in token, preventing cross-edge reuse
- Shared secret configurable via config file or `RELAY_SHARED_SECRET` env var

### QoS & Backpressure

| Aspect | Design | Detail |
|--------|--------|--------|
| **QUIC flow control** | Built-in | Quinn handles stream-level and connection-level flow control automatically |
| **TCP backpressure** | Async I/O | `write_all()` awaits peer readiness — natural backpressure propagation |
| **UDP datagram buffers** | 2 MB send/receive | Sized for SRT at 10 Mbps (~1300+ datagrams of 1500 bytes in-flight) |
| **UDP overflow** | Best-effort drop | `send_datagram()` returns error on full buffer — logged, not fatal. UDP is inherently lossy |
| **Stream concurrency** | 1024 bidi / 256 uni | QUIC transport limits prevent resource exhaustion |
| **Keep-alive** | 15-second interval | Detects dead connections; triggers cleanup via `connection.closed()` |
| **Stream buffers** | 64 KB per direction | Balanced for throughput vs memory per tunnel |

### Error Handling

- All fallible functions return `anyhow::Result<T>` with contextual errors
- Data forwarding errors (stream/datagram) are logged at `debug` level but don't crash the session
- Connection-level errors trigger full cleanup: edge unregistered, all tunnels unbound, peers notified with `TunnelDown`
- UDP datagram send failures are non-fatal (best-effort, continue processing)

### Testing

Integration tests (`tests/integration.rs`) spin up the full QUIC relay, connect two simulated edges, and verify TCP/UDP data forwarding. They duplicate the wire protocol types since this is a binary crate (not a library). Unit tests for auth are in `src/auth.rs`.

Test coverage: auth token generation/verification, tunnel state transitions (waiting/active), bidirectional TCP forwarding, UDP datagram forwarding, ping/pong keepalive.
