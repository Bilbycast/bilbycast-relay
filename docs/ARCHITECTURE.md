# bilbycast-relay Architecture

## System Context Diagram

```
    +----------------+     +-------------------+     +----------------+
    |  Ingress Edge  |     |  bilbycast-relay  |     |  Egress Edge   |
    |  (NAT'd node)  +---->|                   |<----+  (NAT'd node)  |
    |                |QUIC |  QUIC :4433        |QUIC |                |
    |  e.g. camera   |TLS  |  REST :4480        |TLS  |  e.g. decoder  |
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

The relay is a traffic forwarder that requires no configuration to run — edges connect, bind tunnels, and data flows. Optionally connects to bilbycast-manager via an outbound WebSocket for centralized monitoring. Supports optional security hardening: Bearer token auth for the REST API (`api_token`) and per-tunnel HMAC-SHA256 bind authentication (`authorize_tunnel`/`revoke_tunnel` commands from manager).

Multiple relays can run behind a load balancer. The only auth state is pre-authorized tunnel bind tokens (managed via WebSocket commands), stored in a lock-free DashMap.

## Internal Architecture

```
+===========================================================================+
|                          bilbycast-relay process                          |
|                                                                           |
|  tokio::select! { quic_server, rest_api, ctrl_c }                        |
|                                                                           |
|  +----------------------------------+   +-----------------------------+  |
|  |        QUIC Server (:4433)       |   |     REST API (:4480)        |  |
|  |        server.rs                 |   |     api.rs (Axum)           |  |
|  |                                  |   |                             |  |
|  |  TLS 1.3 (rustls)               |   |  GET /health                |  |
|  |  ALPN: bilbycast-relay           |   |  GET /metrics (Prometheus)  |  |
|  |  Self-signed or user-provided    |   |  GET /api/v1/tunnels        |  |
|  |                                  |   |  GET /api/v1/edges          |  |
|  |                                  |   |  GET /api/v1/stats          |  |
|  |  For each connection:            |   |  All public, read-only.     |  |
|  |    tokio::spawn(session)         |   |  No admin routes.           |  |
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
|  |  | Identify (opt)    | | accept_bi()       | | read_datagram() |  |   |
|  |  | TunnelBind/Unbind | | per-stream task:  | | 16-byte UUID    |  |   |
|  |  | Ping/Pong         | |   StreamHeader    | | lookup peer     |  |   |
|  |  |                   | |   tokio::join!    | | send_datagram() |  |   |
|  |  | No auth step.     | |   (bidir copy)   | | best-effort     |  |   |
|  |  | Edge sends        | |   64KB buffers    | | 2MB buffers     |  |   |
|  |  | Identify+Bind.    | |                   | |                 |  |   |
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
|  |   get_peer_connection()       |  |   No max_edges/tunnels.    |       |
|  |   remove_edge() -> cleanup    |  |                            |       |
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

No Auth/AuthOk/AuthError exchange on the control stream. Tunnel bind authentication is inline via the `bind_token` field on `TunnelBind`. The manager pre-authorizes tunnels via WebSocket `authorize_tunnel` command before edges connect. If no authorization exists for a tunnel, unauthenticated bind is allowed (backwards compatible).

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
  |   - 15-second keep-alive detects and cleans dead connections   |
  +---------------------------------------------------------------+
```

Security is defense-in-depth: end-to-end encryption protects payload confidentiality, optional bind authentication prevents unauthorized tunnel hijacking, and optional API auth prevents topology enumeration.

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
