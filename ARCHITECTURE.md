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

The relay connects to bilbycast-manager via an outbound WebSocket (same protocol as edge nodes). This enables centralized monitoring of tunnels, connected edges, bandwidth, and remote commands (disconnect_edge, close_tunnel).

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
|  |                                  |   |                             |  |
|  |  For each connection:            |   +-----------------------------+  |
|  |    tokio::spawn(session)         |                                    |
|  +----------------------------------+                                    |
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
|  |  | Auth (mandatory)  | | accept_bi()       | | read_datagram() |  |   |
|  |  | TunnelBind/Unbind | | per-stream task:  | | 16-byte UUID    |  |   |
|  |  | Ping/Pong         | |   StreamHeader    | | lookup peer     |  |   |
|  |  |                   | |   tokio::join!    | | send_datagram() |  |   |
|  |  | JSON over bi-     | |   (bidir copy)   | | best-effort     |  |   |
|  |  | stream (4B len    | |   64KB buffers    | | 2MB buffers     |  |   |
|  |  | prefix)           | |                   | |                 |  |   |
|  |  +-------------------+ +-------------------+ +-----------------+  |   |
|  |                                                                   |   |
|  +===================================================================+   |
|                  |                          |                             |
|                  v                          v                             |
|  +-------------------------------+  +----------------------------+       |
|  |   TunnelRouter                |  |   SessionContext            |       |
|  |   tunnel_router.rs            |  |   (shared across sessions) |       |
|  |                               |  |                            |       |
|  |   DashMap<Uuid, TunnelState>  |  |   shared_secret: String    |       |
|  |   (lock-free)                 |  |   router: Arc<TunnelRouter>|       |
|  |                               |  |   edge_connections:        |       |
|  |   bind() -> Active|Waiting    |  |     DashMap<String, Conn>  |       |
|  |   unbind() -> notify peer     |  |                            |       |
|  |   get_peer_connection()       |  +----------------------------+       |
|  |   remove_edge() -> cleanup    |                                       |
|  +-------------------------------+                                       |
|                  |                                                        |
|                  v                                                        |
|  +-------------------------------+                                       |
|  |   TunnelStats (stats.rs)      |                                       |
|  |   AtomicU64 counters          |                                       |
|  |                               |                                       |
|  |   bytes_ingress / egress      |                                       |
|  |   tcp_streams_total           |                                       |
|  |   udp_datagrams_total         |                                       |
|  +-------------------------------+                                       |
|                                                                          |
|  +-------------------------------+                                       |
|  |   Manager Client (optional)   |                                       |
|  |   manager/client.rs           |                                       |
|  |                               |                                       |
|  |   WebSocket → manager :8443   |                                       |
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

## Connection & Authentication Flow

```
  Edge Node                          Relay
  =========                          =====

  1. QUIC connect ------------------>
     (TLS 1.3 handshake)             Verify ALPN = "bilbycast-relay"
                                     Accept connection
                                     tokio::spawn(session)

  2. Open bi-stream (control) ------>
     Send Auth { token }             Verify HMAC-SHA256:
                                       decode base64(edge_id:hmac_hex)
                                       recompute HMAC(edge_id, secret)
                                       compare signatures

                          <--------- AuthOk { edge_id }
                                     Register edge in DashMap

  3. Send TunnelBind { id, dir } --->
                                     router.bind(tunnel_id, direction)
                                       if peer already bound:
                          <---------     TunnelReady to both edges
                                       else:
                          <---------     TunnelWaiting

  4a. TCP: Open bi-stream ---------->
      Send StreamHeader              Read header, lookup peer
                                     Open bi-stream to peer
                                     Write StreamHeader to peer
                                     tokio::join!(
                                       ingress -> egress copy,
                                       egress -> ingress copy
                                     )

  4b. UDP: Send datagram ----------->
      [16B tunnel_id | payload]      Extract UUID, lookup peer
                                     send_datagram() to peer
                                     (best-effort, drop on overflow)

  5. Disconnect -------------------->
                                     remove_edge() from router
                                     Notify peers: TunnelDown
                                     Cleanup all tunnel bindings
```

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
  | Layer 1: Transport Security (QUIC + TLS 1.3)                  |
  |   - All traffic encrypted (rustls)                            |
  |   - ALPN enforcement prevents protocol downgrade              |
  |   - Optional user-provided certificates for production        |
  +---------------------------------------------------------------+
  | Layer 2: Authentication Gate                                   |
  |   - HMAC-SHA256 token required before any data exchange        |
  |   - Token = base64(edge_id : hmac_hex(edge_id, secret))       |
  |   - Connection terminated immediately on auth failure          |
  |   - No data streams accepted until authenticated               |
  +---------------------------------------------------------------+
  | Layer 3: Tunnel Isolation                                      |
  |   - Each tunnel identified by unique UUID                      |
  |   - Data routed only to the bound peer (ingress <-> egress)   |
  |   - No cross-tunnel data leakage possible via TunnelRouter     |
  +---------------------------------------------------------------+
  | Layer 4: Resource Protection                                   |
  |   - Max 1024 concurrent bi-streams per connection              |
  |   - Max 256 uni-streams per connection                         |
  |   - 15-second keep-alive detects and cleans dead connections   |
  |   - Configurable max_edges and max_tunnels limits              |
  +---------------------------------------------------------------+
```

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
