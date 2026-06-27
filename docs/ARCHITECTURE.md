# bilbycast-relay Architecture

## System Context Diagram

```
    +----------------+     +-------------------+     +----------------+
    |  Ingress Edge  |     |  bilbycast-relay  |     |  Egress Edge   |
    |  (NAT'd node)  +---->|                   |<----+  (NAT'd node)  |
    |                |QUIC |  QUIC  :4433       |QUIC |                |
    |  e.g. camera   | or  |  UDP   :4434       | or  |  e.g. decoder  |
    |                | UDP |  REST  :4480       | UDP |                |
    +----------------+     +--------+----------+     +----------------+
                                    |  |
                              HTTP  |  | WebSocket
                            (REST)  |  | (stats/health/commands)
                                    v  v
                           +--------------------+
                           | bilbycast-manager   |
                           | (centralized mgmt)  |
                           | WS :8443            |
                           +--------------------+
```

The relay is a generic, opaque per-path forwarder that requires no configuration to run — edges connect, pair by tunnel ID, and data flows. It never inspects, terminates, or combines the streams it carries; it only forwards `[16-byte tunnel_id][AEAD ciphertext]` between the two ends of each path. Optionally connects to bilbycast-manager via an outbound WebSocket for centralized monitoring. Supports optional security hardening: Bearer token auth for the REST API (`api_token`) and per-tunnel HMAC-SHA256 bind authentication (`authorize_tunnel`/`revoke_tunnel` commands from manager).

Multiple relays can run behind a load balancer. The only auth state is pre-authorized tunnel bind tokens (managed via WebSocket commands), stored in a lock-free DashMap.

## Path Types & NAT Traversal

The relay carries three logically distinct path types, all forwarded the same opaque way:

| Path type | Data plane | Default port | Notes |
|-----------|-----------|--------------|-------|
| **QUIC tunnel** | TCP streams + UDP datagrams over QUIC/TLS 1.3 | `:4433` | Pairs ingress/egress edges by tunnel UUID. `server.rs` + `session.rs` |
| **Native SRT/RIST over relay** | Plain UDP, no QUIC | `:4434` | SRT/RIST keep their own ARQ + congestion control — no QUIC per-packet overhead or second congestion controller. `udp_relay.rs` |
| **Individual bond leg** | Plain UDP (a native-UDP tunnel) | `:4434` | Each bond leg is its own native-UDP tunnel. The relay forwards it opaquely; bond aggregation, cross-leg ARQ, FEC, and reordering run **end-to-end edge↔edge**. The relay never terminates or combines a bond — there is no "bond bridge" |

**NAT traversal model**: every path is established by both edges dialing *out* — the QUIC client connects outbound, and on the native plain-UDP plane each edge periodically sends an authenticated `Register` control datagram so the relay latches its post-NAT source address (source-address rendezvous). This means **both ends can be behind NAT**. A path can run direct or over any relay, in any combination, and may use a primary + backup relay: the relay `Ack`s each `Register`, so an edge that stops hearing acks treats the relay as dead and fails over.

## Internal Architecture

```
+===========================================================================+
|                          bilbycast-relay process                          |
|                                                                           |
|  tokio::select! { quic_server, udp_relay(:4434), rest_api, manager, ctrl_c }|
|                                                                           |
|  +----------------------------------+   +-----------------------------+  |
|  |        QUIC Server (:4433)       |   |     REST API (:4480)        |  |
|  |        server.rs                 |   |     api.rs (Axum)           |  |
|  |                                  |   |                             |  |
|  |  TLS 1.3 (rustls)               |   |  GET /health                |  |
|  |  ALPN: bilbycast-relay           |   |  GET /metrics (Prometheus)  |  |
|  |  Self-signed or user-provided    |   |  GET .../tunnels (+DELETE)  |  |
|  |                                  |   |  GET .../udp-sessions       |  |
|  |                                  |   |  (+DELETE, fail-closed)     |  |
|  |  For each connection:            |   |  GET /api/v1/edges, /stats  |  |
|  |    tokio::spawn(session)         |   |  GETs open; DELETEs need tok|  |
|  +----------------------------------+   +-----------------------------+  |
|                  |                                                        |
|                  v                                                        |
|  +===================================================================+   |
|  |                  Per-Session (session.rs)                          |   |
|  |                  tokio::select! { 3 concurrent loops }            |   |
|  |                                                                   |   |
|  |  +-------------------+ +-------------------+ +-----------------+  |   |
|  |  | Control Stream    | | Data Streams      | | Datagram Loop   |  |   |
|  |  | Loop              | | Loop              | | (UDP)           |  |   |
|  |  |                   | |                   | |                 |  |   |
|  |  | Hello/HelloAck    | | accept_bi()       | | read_datagram() |  |   |
|  |  | Identify (opt)    | | per-stream task:  | | 16-byte UUID    |  |   |
|  |  | TunnelBind/Unbind | |   StreamHeader    | | lookup peer     |  |   |
|  |  | Ping/Pong         | |   tokio::join!    | | send_datagram() |  |   |
|  |  | Unknown->ignore   | |   (bidir copy)   | | best-effort     |  |   |
|  |  | Edge sends Hello, | |   64KB buffers    | | 2MB buffers     |  |   |
|  |  | Identify, Bind.   | |                   | |                 |  |   |
|  |  +-------------------+ +-------------------+ +-----------------+  |   |
|  |                                                                   |   |
|  +===================================================================+   |
|                  |                          |                             |
|                  v                          v                             |
|  +-------------------------------+  +----------------------------+       |
|  |   TunnelRouter                |  |   SessionContext            |       |
|  |   tunnel_router.rs            |  |   (shared across sessions) |       |
|  |                               |  |                            |       |
|  |   DashMap<Uuid, TunnelState>  |  |   router: Arc<TunnelRouter>|       |
|  |   (lock-free)                 |  |   edge_connections:        |       |
|  |                               |  |     DashMap<String, Conn>  |       |
|  |   bind() -> Active|Waiting    |  |                            |       |
|  |   unbind() -> notify peer     |  |   No shared_secret.        |       |
|  |   get_peer_connection()       |  |   Per-IP conn cap (64),    |       |
|  |   remove_edge() -> cleanup    |  |   per-conn tunnel cap (100)|       |
|  +-------------------------------+  +----------------------------+       |
|                  |                                                        |
|                  v                                                        |
|  +-------------------------------+                                       |
|  |   TunnelStats (stats.rs)      |                                       |
|  |   AtomicU64 counters          |                                       |
|  |                               |                                       |
|  |   bytes_ingress / egress      |                                       |
|  |   tcp_streams_total / active  |                                       |
|  |   udp_datagrams_total         |                                       |
|  +-------------------------------+                                       |
|                                                                          |
|  +-------------------------------+                                       |
|  |   Manager Client (optional)   |                                       |
|  |   manager/client.rs           |                                       |
|  |                               |                                       |
|  |   WebSocket -> manager :8443  |                                       |
|  |   Auth: reg_token / node creds|                                       |
|  |   Stats every 1s (tunnels,    |                                       |
|  |     edges, bandwidth)         |                                       |
|  |   Health every 15s            |                                       |
|  |   Commands: get_config,       |                                       |
|  |     disconnect_edge,          |                                       |
|  |     close_tunnel, list_*      |                                       |
|  +-------------------------------+                                       |
+===========================================================================+
```

## Connection Flow (Optional Bind Authentication)

```
  Edge Node                          Relay
  =========                          =====

  0. (Manager pre-authorizes) -----> authorize_tunnel { tunnel_id, ingress_token, egress_token }
                                     Store in authorized_tokens DashMap

  1. QUIC connect ------------------>
     (TLS 1.3 handshake)             Verify ALPN = "bilbycast-relay"
                                     Accept connection
                                     Assign connection_id (remote addr + counter)
                                     tokio::spawn(session)

  2. Open bi-stream (control) ------>
     Hello { protocol_version,       Respond with HelloAck { protocol_version,
       software_version } ---------->   software_version }
                          <---------   Log warning if versions differ
                                       (Old edges skip Hello — relay proceeds normally)

     [Optional] Identify { edge_id } ->  Store identity for topology correlation
     Send TunnelBind { id, dir,      Verify bind_token (if authorized):
       bind_token } --------------->   - If no auth registered: allow (backwards compat)
                                       - If auth registered: constant-time compare
                                       - If invalid/missing: reject with TunnelDown
                                     router.bind(tunnel_id, direction)
                                       if peer already bound:
                          <---------     TunnelReady to both edges
                                       else:
                          <---------     TunnelWaiting

  3a. TCP: Open bi-stream ---------->
      Send StreamHeader              Read header, lookup peer
                                     Open bi-stream to peer
                                     Write StreamHeader to peer
                                     tokio::join!(
                                       ingress -> egress copy,
                                       egress -> ingress copy
                                     )

  3b. UDP: Send datagram ----------->
      [16B tunnel_id | payload]      Extract UUID, lookup peer
                                     send_datagram() to peer
                                     (best-effort, drop on overflow)

  4. Disconnect -------------------->
                                     remove_edge() from router
                                     Notify peers: TunnelDown
                                     Cleanup all tunnel bindings
```

No Auth/AuthOk/AuthError exchange on the control stream. Tunnel bind authentication is inline via the `bind_token` field on `TunnelBind`. The manager pre-authorizes tunnels via WebSocket `authorize_tunnel` command before edges connect. If no authorization exists for a tunnel, unauthenticated bind is allowed (backwards compatible). The Hello/HelloAck exchange is optional — it provides version awareness but does not gate access. Unknown message types are gracefully ignored via `read_message_resilient()` (returns `ParsedMessage::Unknown` instead of a deserialization error).

## Tunnel State Machine

```
                  bind(ingress)
                  or bind(egress)
    +--------+   =================>   +---------+
    |        |                        |         |
    | (none) |                        | Waiting |
    |        |                        |         |
    +--------+                        +---------+
                                          |
                                          | bind(other side)
                                          v
                                      +--------+
                                      |        |
                                      | Active |-----> TunnelReady
                                      |        |      (sent to both)
                                      +--------+
                                       |      |
                           unbind() /  |      |  \ edge disconnect
                           one side    |      |    removes all tunnels
                                       v      v
                                   +-----------+
                                   |           |
                                   |  Cleanup  |-----> TunnelDown
                                   |           |      (sent to peer)
                                   +-----------+
```

## Data Flow: TCP Tunnel (Non-Blocking)

```
  Ingress Edge              Relay                    Egress Edge
  ============          ============                 ===========

  Local TCP conn                                     Local TCP conn
       |                                                  ^
       v                                                  |
  QUIC bi-stream -----> [Task A: read ingress]       QUIC bi-stream
  (StreamHeader)         write to egress peer ------>  (StreamHeader)
                         64KB async buffer
                                                          |
                        [Task B: read egress]             v
  QUIC bi-stream <-----  write to ingress peer <---- QUIC bi-stream
                         64KB async buffer

  Both Task A and Task B run concurrently via tokio::join!()
  Backpressure: write_all() awaits peer readiness (QUIC flow control)
```

## Data Flow: UDP Tunnel (Non-Blocking, Best-Effort)

```
  Ingress Edge              Relay                    Egress Edge
  ============          ============                 ===========

  Local UDP sock                                     Local UDP sock
       |                                                  ^
       v                                                  |
  QUIC datagram ------> [Datagram Loop]              QUIC datagram
  [16B UUID|payload]     Extract tunnel_id           [16B UUID|payload]
                         Lookup peer conn
                         send_datagram() ----------->
                         (2MB buffer, drop on full)

  No retransmission. No ordering. Fire-and-forget.
  Designed for SRT and real-time media at up to 10 Mbps.
```

## Data Flow: Native SRT/RIST over Relay (Plain UDP, no QUIC)

The native plane (`udp_relay.rs`) binds a plain UDP socket (`:4434`) and pairs the
two edges by tunnel UUID via **source-address rendezvous** — no QUIC, no per-packet
AEAD/header overhead, no congestion controller fighting SRT/RIST's own ARQ. The
same plane carries individual bond legs (a relayed bond leg is just a native-UDP
tunnel).

```
  Source Edge (egress)        Relay :4434              Dest Edge (ingress)
  ====================      ==============             ===================

  Register (nil-UUID) ----> latch post-NAT src addr  <---- Register (nil-UUID)
        <----------------- Ack { ready }  ----------------->
        (re-sent ~every 5s; missed Acks => relay dead => failover)

  [16B tunnel_id|AEAD] ---> forward_target():         [16B tunnel_id|AEAD]
                            verbatim send to the
                            opposite latched addr ----->
        <----------------- (and vice versa) <----------------

  Control plane (Register/Ack) is multiplexed on the SAME socket using the
  reserved nil (all-zero) UUID prefix; real tunnel IDs are random v4 UUIDs.
  Relay holds no media key — it forwards ciphertext verbatim.
  Idle sessions (no register/data for 30s) are reaped.
```

Auth reuses the QUIC path's bind-token registry (the manager's `authorize_tunnel`
tokens), and the same per-IP session cap bounds DoS. Bind failures on `:4434` are
non-fatal — the relay logs, drops the `udp-relay` capability, and continues
QUIC-only, so an upgrade never bricks a relay over a busy port.

## Security Layers

```
  +---------------------------------------------------------------+
  | Layer 1: End-to-End Encryption (Edge Level)                    |
  |   - ChaCha20-Poly1305 between edges                           |
  |   - Relay sees only encrypted ciphertext                      |
  |   - Relay cannot inspect or modify tunnel payloads             |
  +---------------------------------------------------------------+
  | Layer 2: Transport Security (QUIC + TLS 1.3)                  |
  |   - All traffic encrypted in transit (rustls)                  |
  |   - ALPN enforcement prevents protocol downgrade               |
  |   - Optional user-provided certificates for production         |
  +---------------------------------------------------------------+
  | Layer 3: Tunnel Bind Authentication (Optional)                 |
  |   - Manager pre-authorizes tunnels via authorize_tunnel cmd    |
  |   - Edges include HMAC-SHA256 bind_token in TunnelBind         |
  |   - Constant-time comparison prevents timing attacks           |
  |   - Unauthenticated bind allowed if no auth registered         |
  +---------------------------------------------------------------+
  | Layer 4: REST API Authentication (Optional)                    |
  |   - Bearer token auth via api_token config field               |
  |   - /health always public; other endpoints require token       |
  |   - Prevents unauthorized topology/tunnel enumeration          |
  +---------------------------------------------------------------+
  | Layer 5: Tunnel Isolation                                      |
  |   - Tunnel IDs must be valid UUIDs (v4 random)                 |
  |   - Brute-force discovery infeasible (2^122 search space)      |
  |   - Data routed only to the bound peer (ingress <-> egress)    |
  |   - No cross-tunnel data leakage possible via TunnelRouter     |
  +---------------------------------------------------------------+
  | Layer 6: Resource Protection                                   |
  |   - Max 1024 concurrent bi-streams per connection              |
  |   - Max 256 uni-streams per connection                         |
  |   - 5-second keep-alive detects and cleans dead connections    |
  +---------------------------------------------------------------+
```

Security is defense-in-depth: end-to-end encryption protects payload confidentiality, optional bind authentication prevents unauthorized tunnel hijacking, and optional API auth prevents topology enumeration.

**Note on the native plain-UDP plane**: Layer 2 (QUIC + TLS 1.3) applies only to the QUIC tunnel path. The native SRT/RIST path and individual bond legs ride plain UDP with no transport-layer encryption between edge and relay — payload confidentiality there rests entirely on Layer 1 (the edge-to-edge ChaCha20-Poly1305 AEAD), which the relay never holds the key for. Layers 3 (bind auth via `Register`'s `bind_token`) and 5 (UUID tunnel isolation) still apply.

## Non-Blocking Concurrency Model

```
  tokio runtime (multi-threaded)
  |
  +-- QUIC Server task (server.rs)
  |     |
  |     +-- Session task per edge (session.rs) -- tokio::spawn
  |           |
  |           +-- Control loop -------- sequential message processing
  |           +-- Data stream loop ---- tokio::spawn per bi-stream
  |           |     |
  |           |     +-- TCP forward --- tokio::join!(read/write, write/read)
  |           |
  |           +-- Datagram loop ------- inline forwarding (non-blocking send)
  |
  +-- REST API task (api.rs) ---- Axum with shared Arc<SessionContext>
  |
  +-- Ctrl+C handler ------------ graceful shutdown

  Zero locks:
    - DashMap for concurrent maps (lock-free sharded HashMap)
    - AtomicU64 for stats counters
    - Arc for shared ownership
    - No Mutex, no RwLock anywhere
```
