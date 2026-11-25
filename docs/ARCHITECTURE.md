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
|  tokio::select! { quic_server, rest_api, manager, ctrl_c }  — any ends it |
|  watched, never fatal: udp_relay(:4434), distribution(:4485 + :4486)      |
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
|  |   route() -> peer or refused  |  |   Per-IP conn cap (64),    |       |
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
|  |   Every await bounded: dial   |                                       |
|  |     30s, auth 10s+10s, write  |                                       |
|  |     300s, silence 90s+        |                                       |
|  +-------------------------------+                                       |
+===========================================================================+
```

The manager client's reconnect loop is a single task, so an await on the
manager link that never completed used to keep the relay off the manager until
it was restarted (the edge's #180 was the same code). Every await on it is now
bounded: the dial (DNS, TCP to each resolved address Happy-Eyeballs style, TLS
and the HTTP upgrade) in 30 s, the auth frame and its answer in 10 s each,
every session write in 300 s, and once the manager has pinged, 90 s with
nothing from it — or four of its ping intervals, if those are longer — ends
the session. A reader beside the session loop does the listening, so a session
busy writing is never taken for a dead one, and the session only ever ends
between commands, never part-way through `rotate_secret`. Detail and the
reasons: CLAUDE.md, "Manager Connection", Deadlines.

The `distribution` task is `#[cfg(feature = "viewer-distribution")]` and is
only spawned when `distribution.enabled` is true — which it is by default, so
the shipped `-distribution` artefact comes up as a distribution node with no
config edits. A plain forwarder build has no `distribution` module at all
(`lib.rs` gates it, and the select arm degrades to a future that never
resolves) and warns at startup if a config asks for the role. See [Viewer Distribution](#viewer-distribution-optional-role)
below.

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
      Send StreamHeader              Read header; reset if the sender
                                       holds no side of the tunnel
                                     Open bi-stream to peer
                                     Write StreamHeader to peer
                                     tokio::join!(
                                       ingress -> egress copy,
                                       egress -> ingress copy
                                     )

  3b. UDP: Send datagram ----------->
      [16B tunnel_id | payload]      Extract UUID; drop if the sender
                                       holds no side of the tunnel
                                     send_datagram() to peer
                                     (best-effort, drop on overflow)

  4. Disconnect -------------------->
                                     remove_edge() from router
                                     Notify peers: TunnelDown
                                     Cleanup all tunnel bindings
```

No Auth/AuthOk/AuthError exchange on the control stream. Tunnel bind authentication is inline via the `bind_token` field on `TunnelBind`. The manager pre-authorizes tunnels via WebSocket `authorize_tunnel` command before edges connect. If no authorization exists for a tunnel, unauthenticated bind is allowed (backwards compatible). The Hello/HelloAck exchange is optional — it provides version awareness but does not gate access. Unknown message types are gracefully ignored via `read_message_resilient()` (returns `ParsedMessage::Unknown` instead of a deserialization error).

## Who May Send into a QUIC Tunnel

A connection sends into a tunnel only while it holds one of the tunnel's two
sides, and only as that side. The side is the one its `TunnelBind` took, which
is where its bind token was checked. `TunnelRouter::route` asks this of every
datagram, and of every data stream when its header arrives, in the one map
lookup that also gives the peer and the counters.

| The sender | Its datagram | Its data stream |
|---|---|---|
| holds a side, and the other is bound | forwarded, counted as from that side | opened through to the peer, counted |
| holds a side, and nobody holds the other | dropped, not counted | ends empty at its opener, not counted |
| holds both sides | sent back to it, counted as from ingress | the same |
| holds neither, or there is no such tunnel | dropped, not counted | reset and stopped with code 1: no stream is opened to anyone, nothing is counted |

The last row is one answer on purpose, so that a sender cannot tell from it
which tunnel ids are in use. It is logged at debug like a malformed datagram,
and raises no event: a sender that goes on must not fill the log or the event
queue.

A side belongs to the connection that bound it last. Once a newer connection has
taken it over, what the older one still sends is dropped until it binds again, or
is [given the side back](#tokens-that-come-after-the-binds). A data stream
already forwarded runs to its end, whoever holds the side by then. A datagram
the relay handles before its sender's own bind is dropped, and so is one whose
peer has not bound yet; nothing is queued.

**Edges.** Every edge tag from v0.7.0 to v0.117.0 binds a tunnel on a connection
opened for it, sends the tunnel's data on no other, and starts to send only
after it has read `TunnelReady` for that tunnel (`connect_and_bind` in the
edge's `src/tunnel/relay_client.rs`). The failback probe (edges v0.21.0 to
v0.117.0) opens another connection, to the primary relay, which carries a `Hello`
and no data. An edge after v0.117.0 binds a QUIC tunnel that has two relays on
both, each on a connection of its own, while it waits for its peer or is on its
backup. It sends the tunnel's data on the connection it has moved to, after
`TunnelReady` there, and unbinds the other.
The relay sends `TunnelReady` once both sides are in the router, so no edge
sends before its bind. Three things an edge sends can meet the last row:

- what is still in flight on a connection when the edge has bound another in its
  place (after a failure it dials the new one at least a second later);
- what it goes on sending after its tunnel was removed under it (`close_tunnel`,
  the REST delete), until it binds again. An edge after v0.117.0 does about a
  second later; one up to v0.117.0 does not read that it was removed, and binds
  again only with a new connection;
- what it goes on sending on a side that another edge has bound since, until it
  binds again. The relay does not tell it that its side is gone, and an edge binds
  again of its own accord only if it is after v0.117.0 and has two relays: once a
  minute while it waits for its peer, with an unbind first, and when it has let go
  of its connection to the other relay.

**Upgrading from relay v0.20.0 or earlier.** Up to v0.20.0 a connection that was
not the tunnel's bound ingress was taken for its egress, whether or not it had
bound anything. So any QUIC connection that knew a tunnel's id could send
datagrams to its ingress edge, and open streams to it, with no bind token even
under `require_bind_auth`, and all of it was counted as the tunnel's own. No
edge has to change and there is no upgrade order. What an operator may notice: a
client of their own that sent into a tunnel without binding it no longer gets
through; a tunnel's byte and datagram counts no longer include what such a
client sent; an edge up to v0.117.0 whose tunnel was removed under it is no
longer heard by a receiver that bound again on its own; and where two edges bind
the same side of a tunnel (a cloned or restored config, a spare left running),
only the one that bound last is heard. Up to v0.20.0 an older egress edge was
still forwarded to the ingress. Now it goes silent without notice until it binds
again, and the newer one leaving does not bring it back. `GET /api/v1/tunnels`
shows the id and the remote address of the edge that holds each side.

Up to v0.20.0 a connection or native-UDP session that ended just as another
began from the same address could also take that address's count below zero, and
the relay could then refuse it (`relay_dos_suspect`) until a restart. That no
longer happens.

Pinned by `session::bound_sender_tests` (real QUIC on loopback), the counts by
`util::ip_count_tests`, `session::per_ip_cap_tests` and
`udp_relay::removal_race_tests`.

## Tokens That Come After the Binds

The relay holds the bind tokens in memory only, so after a restart it has none
until the manager has sent them again, and by then the edges are usually back.
With `require_bind_auth: false` any bind and any `Register` is taken meanwhile.
The relay remembers what each showed (the SHA-256 of its token, compared in
constant time), on every holder of a side and on each connection that a bind
without its token took a side from. When `authorize_tunnel` comes:

| The side's holder | What happens |
|---|---|
| has shown the token now registered | nothing: it keeps the side, and is told nothing |
| has not, and took the side (directly or through others) from a connection that has and has not unbound or left since | that connection holds the side again, at once. The same if the side is empty because the one that took it has left, or the whole tunnel is: the relay keeps the tunnel, in no list and no count, for as long as it remembers such a connection |
| has not, and no such connection is there | nothing, until an edge binds with the token and takes the side as any bind does |

`TunnelRouter::authorize_tunnel` does this, and `bind` verifies a token under the
same lock, so a bind that races the tokens is either refused or undone. The edge
that has its side back needs to do nothing and need not be new: its connection,
the streams it has open and its next datagram simply go through. It is told how
the tunnel stands now. Each raises a Warning `relay_unproven_holder_replaced`.

A connection is not remembered if it showed no token, which nothing would give
the side back to, nor once another binds the side with the token it showed. That
one is the same edge on a newer connection, or a second edge with the same
configuration, and the older one does not have the side again when it leaves. So
of a side and a token one connection is remembered at most, and none on a tunnel
whose tokens were there before its binds and have not changed since.

On the native-UDP plane an edge sends its token every 5 s, so the rule is in
`UdpSessionRouter::latch`: a `Register` that shows the registered token takes the
slot from a holder that has not shown it, whatever media the holder is sending
(`SLOT_TAKEOVER_GRACE_MS` otherwise refuses it). A holder that has shown it is
protected as before.

**Why a holder is not cut off for want of the token alone.** A live edge can be
without the token the relay has just been given, and the relay cannot tell it
from a stranger:

| The manager's action | What it sends, in order | Who can hold a side without the token |
|---|---|---|
| create a tunnel | `authorize_tunnel` to each relay, `create_tunnel` to each edge | nobody: no edge has bound |
| edit a tunnel | `delete_tunnel` to each edge, `authorize_tunnel` (same tokens), `create_tunnel` | nobody: an edge it could not reach shows the same token |
| rotate a tunnel's bind secret | `delete_tunnel` to each edge, `authorize_tunnel` (new tokens), `create_tunnel` | an edge it cannot reach: still connected to the relay, with the token before. It cannot bind with the new one until it is reached |
| the relay connects to it | `authorize_tunnel` for every tunnel and relayed bond leg | an edge that bound meanwhile with no bind secret, or that missed a rotation |
| the 30 s retry of a push that failed | `authorize_tunnel` | the same |
| apply a Bonded Link | `authorize_tunnel` to each relay, then the edges' inputs and outputs. An edit keeps each leg's secret | nobody |
| release or roll back a Bonded Link | the edges' part, then `revoke_tunnel` | does not matter: nothing is registered |
| delete a tunnel | `delete_tunnel` to each edge, `revoke_tunnel`, `close_tunnel`, and all three again within 30 s from its queue | anyone, until an edge it cannot reach has its `delete_tunnel`: see below |

Every edge since v0.7.0 sends the token of the bind secret it has, with every
bind and every `Register`, and none if it has no secret. So the rule waits for
the edge that has the token, and closes the hole when that edge is there. What
it leaves: while that edge is away a stranger that bound in the window goes on
holding its side, where it gets the ciphertext and what it sends fails the AEAD.
`require_bind_auth: true` closes the window itself.

Up to v0.20.0 tokens were checked on a bind and a `Register` only, never against
what was bound already. A stranger that took a side in the window kept it while
it stayed connected, and on the native plane while it went on sending; the edge
it took it from was not heard, and its `Register`s were refused. Nothing has to
be upgraded with the relay, and there is no order: the rule works with every
edge release. The restart the upgrade takes is itself such a window.

`revoke_tunnel` alone takes the tokens away and leaves what is bound or latched
as it is. Binds and registers after it are refused under `require_bind_auth` and
taken without a token otherwise. The manager sends it alone only where the edges
have already dropped the leg, and with `close_tunnel` where a tunnel is deleted.

An edge that the manager cannot reach when it deletes a tunnel still has it
configured. The relay tells the edge that its side was removed, and one after
v0.117.0 binds it again about a second later. Under `require_bind_auth` that is
refused. Otherwise it is taken, as any bind of the tunnel is then: with both
edges out of the manager's reach the deleted tunnel carries media again, and a
stranger may take a side of it, until `delete_tunnel` reaches them. The manager
drops it from its queue after 24 h. An edge that comes back later keeps the
tunnel, reported in an Info event, unless the manager's
`tunnel_orphan_auto_cleanup` setting is on, which has it deleted.

`DELETE /api/v1/tunnels/{id}` removes a tunnel that the manager still has, and
its edges bind it again in the same way. So it takes the tokens away only under
`require_bind_auth`, where that has the edges refused until the manager
authorizes the tunnel again. Otherwise the tokens stay, and an edge that has not
the right one is refused as a stranger is. Up to v0.20.0 it always took them
away: on such a relay with `require_bind_auth: false`, an edge after v0.117.0 is
back about a second later with nothing to keep a stranger from taking its side,
until the relay next connects to the manager or the tunnel is edited.

Pinned by `session::shown_token_tests` (real QUIC on loopback),
`tunnel_router::displaced_tests`, `udp_relay::shown_token_tests`,
`manager::client::authorize_tests` and `removal_notice_tests`.

## What an Edge Is Told

The answer to a bind is on the control stream: `TunnelReady`, `TunnelWaiting`, or
`TunnelDown` if it is refused. What becomes of the tunnel later is on streams the
relay opens for it, one message each (`notify_edge`):

| What happened | Sent to | Message |
|---|---|---|
| the other side bound | the peer | `TunnelReady` |
| the other side's connection ended, or unbound | the peer | `TunnelDown`, reason `peer disconnected` or `peer unbound` |
| the tunnel was removed | both sides, and the connections the relay remembers a side was taken from | `TunnelDown`, reason `tunnel closed by manager` (`close_tunnel`) or `tunnel deleted via relay REST API`; to all at once |
| a side was given back | the edge that has it, and its peer | `TunnelReady`, or `TunnelDown` with `peer disconnected` to the edge if nobody holds the other side |
| a side was taken over by another bind | nobody | none: two edges of one configuration would take it from each other for ever |

**The reasons are the protocol.** An edge whose peer is gone still holds its
side; one whose own side was removed has to bind again. Edges after v0.117.0
tell the two apart by the reason: `peer disconnected` and `peer unbound`
(`protocol::PEER_DISCONNECTED`, `PEER_UNBOUND`, the words of every release) are
about the peer, and any other is about the edge's own side. Do not reword these
two, and do not use them for anything else.

A `TunnelReady` or a peer's `TunnelDown` is checked against the router once its
stream is open, and not sent if it is no longer true. An edge takes the streams
in the order they were opened, so the last message it reads says how the tunnel
stands, however fast a peer comes and goes.

An edge up to v0.117.0 reads these streams only while it waits for its tunnel to
be up. After that it does not learn that its peer has gone, or that its own side
was removed, and it stays `ready`. Nor does it read the refusal of a bind: it
stays `connecting`. Unread, the messages also use up the 256 streams an edge allows the
relay: after 128 comings and goings of its peer each further one, and each
`close_tunnel`, took `NOTIFY_TIMEOUT` (5 s) to give up. That bound is still
needed for those edges.

Pinned by `session::notice_order_tests`, `session::notify_tests`,
`session::removed_tests` and `manager::client::removal_notice_tests`.

## The Per-Connection Cap

`max_tunnels_per_connection` (default 100) bounds the sides a connection has
bound and not unbound. A side counts once however often it is bound, and both
sides of one tunnel count as two. A side that another connection has taken over
counts for the older one too while the router remembers it as one the side can
[go back to](#tokens-that-come-after-the-binds). An unbind gives back what the
connection had of that tunnel and nothing else, and a tunnel removed by force
gives back its sides. A refused bind does not count. The
session keeps the sides the connection has asked for, and asks the router which
of them it still has once there are as many as the cap. So neither ever holds
more than the cap for one connection.

Up to v0.20.0 the count went up with every bind and down with every unbind. A
connection that unbound tunnels it had never bound could bind any number, and
one that bound the same tunnel 100 times was refused the next.

Pinned by `session::tunnel_cap_tests`.

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
                                   |           |      (sent to peer;
                                   +-----------+       to both sides
                                                       if removed)
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
                         Sender bound? Peer conn
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
  A Register does NOT always latch — see the admission rules below.
```

Auth reuses the QUIC path's bind-token registry (the manager's `authorize_tunnel`
tokens), and the same per-IP session cap bounds DoS. A session counts on the
address that created it, from its first `Register` until it is removed, both
under the session's own lock. The reaper asks again whether a session is idle as
it removes it, so one on which a `Register` was accepted or a datagram forwarded
in between is kept.

A media datagram is taken only from the address latched in one of its session's
two slots, and goes to the other slot; one from any other address is dropped.
That address is all there is to know a sender by on this plane: the bind token
is checked on `Register`, not per datagram, and a source address can be forged.
Whoever knows a tunnel id and the address of one side can therefore send as that
side. The AEAD between the edges is what refuses such a datagram.

Two further rules bound the rendezvous, both inside `UdpSessionRouter::latch` so
they hold for every caller. A `Register` from an address no host can own
(unspecified / multicast / broadcast / port 0), or from an address that already
occupies this tunnel's *opposite* slot — which would build a session forwarding
to its own source, a line-rate loop on a shared recv loop if that address routes
back to the relay — is refused outright (`relay_invalid_source_addr`). And a slot
that has itself carried media does not move to a different source **IP** until
12 s (`SLOT_TAKEOVER_GRACE_MS`, monotonic; two missed 5 s keepalives, comfortably
inside the 30 s idle reap) after the last datagram forwarded from that address
(`relay_slot_takeover_refused`, and no `Ack` — acking would confirm the tunnel id
is real), unless the `Register` shows the token registered for the slot and the
holder has not (`relay_unproven_holder_replaced`, see
[Tokens That Come After the Binds](#tokens-that-come-after-the-binds)). A same-IP
port rebind is always allowed, and a slot that has never
carried media is still first-come-first-served. Note the liveness stamp is
written on the slot a datagram arrived *from*, and keepalives deliberately do not
stamp, so on a one-way path only the transmitting end's slot is protected — the
hold-down raises the cost of a takeover, `require_bind_auth: true` is the control.

Bind failures on `:4434` are non-fatal — the relay logs, raises a Critical
`relay_udp_plane_stopped` event, drops the `udp-relay` capability, and continues
QUIC-only while it retries the bind, so an upgrade never bricks a relay over a
busy port. The same holds for the viewer-distribution subsystem (not retried):
`main` does not wait on either optional task; `src/supervise.rs` watches them
and records a stop (relay#15).

## Relay-Wide Counters

Seven figures are for the whole relay since it started. None falls when a
tunnel or a session goes, and only a restart resets them:

| `GET /metrics` (counters) | JSON key | Counts |
|---|---|---|
| `bilbycast_relay_bytes_ingress_total` | `total_bytes_ingress` | QUIC tunnels: datagram payload bytes forwarded from the edge bound `ingress`, and TCP stream bytes forwarded from the edge that opened the stream |
| `bilbycast_relay_bytes_egress_total` | `total_bytes_egress` | QUIC tunnels: the same the other way |
| `bilbycast_relay_bytes_forwarded_total` | `total_bytes_forwarded` | The sum of the two |
| `bilbycast_relay_tcp_streams_total` | `total_tcp_streams` | TCP streams opened through to the peer |
| `bilbycast_relay_udp_datagrams_total` | `total_udp_datagrams` | QUIC datagrams forwarded |
| `bilbycast_relay_udp_bytes_forwarded_total` | none | Native-UDP plane: bytes of the media datagrams that came from a registered side, tunnel id included |
| `bilbycast_relay_udp_datagrams_forwarded_total` | none | Native-UDP plane: media datagrams forwarded |

The JSON keys are those of `GET /api/v1/stats` and of the manager's stats
payload (1 s); the health payload (15 s) carries `total_bytes_forwarded` only.
Every surface reads the same figures (`TunnelRouter::totals`,
`UdpSessionRouter::totals`).

`bilbycast_relay_tcp_streams_active` (`active_tcp_streams`) is a gauge: the
streams open on the tunnels held now. A stream outlives a tunnel that is removed
under it; it is then out of the gauge, and the bytes it still carries are in the
counters. A tunnel's own figures (the `tunnels` and `udp_sessions` rows, and the
`bilbycast_relay_tunnel_*{tunnel_id=…}` series) go with it and start at 0 when
its id is bound or registered again after it has gone. An edge that takes a side
over from another, or a side that comes back while its peer stayed bound, keeps
the tunnel and its figures.

A datagram is counted in its own tunnel's atomics and nowhere else. A relay-wide
atomic beside them would be one cache line written by every forwarding thread:
measured on 24 cores, the tunnel lookup and count of one datagram (55-60 ns,
with the two map lookups it took then; 45-47 ns with the one it takes now) took
13 % longer with two such atomics on one thread, and about 4 to 18 times as long
on 8 and 16; with a cache-padded total per thread it took about 10 to 20 %
longer. So each router keeps a `DepartedTunnels` (`stats.rs`) instead. Every
removal goes through it: under its lock and the map's, the tunnel goes on its
list and out of the map. A reader adds up the map, the list and what has been
folded under the same lock, so a tunnel is in the sum once whenever the reader
comes. One that a forwarding task still holds is kept whole, because the task
may count into it yet; its counts are folded into one figure at the first
removal after nothing holds it. The forward path takes no lock and does what it
did before.

**Upgrading from relay v0.20.0 or earlier.** Up to v0.20.0 each of the seven was
a sum over the tunnels, or the native-UDP sessions, held when it was read, so it
fell when one went: unbound, lost with its edges, removed by the manager or over
REST, or reaped. `rate()` / `increase()` read that as a counter reset, and
`total_bandwidth_bps` read 0 or low for the sample in which a tunnel ended. All
seven now only grow, names, types and JSON keys unchanged. A panel or an alert
that read a value as the traffic of the tunnels now up shows a total since the
relay started: take its `rate()`, or sum what is held now. For the QUIC tunnels
that is the per-tunnel series. A native-UDP session has no series of its own on
`/metrics`; its figures are in its `udp_sessions` row (the manager's stats
payload) or its `GET /api/v1/udp-sessions` row.

On the manager, "Total Forwarded" and its neighbours on the relay's page become
totals since the start. The Throughput column of the Flows page's relay table
falls back to the byte total while the bandwidth reads 0, with the datagram total
beneath. All three figures are the QUIC tunnels' only, so a relay that has
carried QUIC tunnels and holds none shows those totals where it showed a dash:
an idle one, and one that is busy with native-UDP sessions or bond legs alone.

Pinned by `stats::tunnel_totals_tests` (a tunnel counted once wherever it is, a
late count kept, a finished one let go, a removal that waits for a read to end
and lists the tunnel before the map lets go of it), `tunnel_router::totals_tests`
and `udp_relay::totals_tests` (every way out of each router, and no figure
falling while tunnels are removed and bound again under four forwarding threads;
the first also that a side bound before the empty tunnel is removed keeps it),
`session::tunnel_counter_tests` (real edges, with a TCP stream that outlives its
tunnel) and `manager::client::tunnel_counter_tests` (the four surfaces agree, and
the bandwidth figure takes in a tunnel that ended).

## Viewer Distribution (optional role)

Everything above is the opaque forwarder, and a plain `cargo build` is exactly
that. The `viewer-distribution` feature adds a **second, deliberately stateful**
role on the same process: a WHEP SFU for sub-second WebRTC to browsers, plus an
LL-HLS/CMAF origin on disk with a DVR window. It is isolated behind the feature
so the lean forwarder never links str0m, never binds `:4485` / `:4486`, and
terminates nothing.

```
  +===========================================================================+
  |            Viewer distribution (feature = "viewer-distribution")          |
  |                                                                           |
  |  Ingest (the edge feeds it, two ways)                                     |
  |    QUIC ES ingest  :4486  ALPN bilbycast-distribution  ingest.rs          |
  |      Hello + [kind][flags][pts_90k][len][payload] elementary frames       |
  |    WHIP push       :4485  POST /whip/{stream}       whip_ingest.rs        |
  |    Cascade pull    (client) upstream WHEP -> local hub  cascade.rs        |
  |                              |                                            |
  |                              v                                            |
  |    DistributionHub (hub.rs) - one tokio::broadcast per stream,            |
  |      drop-on-lag, plus an ArcSwapOption keyframe cache for late joiners   |
  |            |                                    |                         |
  |            v                                    v                         |
  |  +----------------------------+   +-----------------------------------+  |
  |  |  WHEP SFU (whep.rs) :4485  |   |  LL-HLS / CMAF origin (origin.rs) |  |
  |  |    POST /whep/{stream}     |   |    PUT/GET /origin/{stream}/{file}|  |
  |  |    DELETE /whep/{s}/{sess} |   |    on-disk segment window,        |  |
  |  |    /watch/{stream} player  |   |      evicted oldest-first         |  |
  |  |    one str0m PC per viewer |   |    /dvr/{stream} scrub-back page  |  |
  |  +----------------------------+   +-----------------------------------+  |
  +===========================================================================+
```

Default binds are `:4485` for the HTTP surface (WHEP signalling, the built-in
`/watch` and `/dvr` player pages, and the origin) and `:4486` for the QUIC ES
ingest — both dual-stack, both overridable via `distribution.http_addrs` /
`distribution.ingest_addrs`. The origin's segment root defaults to
`/var/lib/bilbycast/relay/origin` (`distribution.origin_storage_dir`) and is
re-adopted on restart rather than wiped — and each adopted stream held from
the node default's age test and byte cap until the manager has re-sent each
session's window (see *A relay restart keeps the window* in the reference).
Full reference: [`distribution.md`](distribution.md).

**The viewer portal is a separate binary and a separate process.** `bilbycast-portal`
(`src/portal_bin.rs`) is gated on the `portal` Cargo feature, which is deliberately
**independent of `viewer-distribution`** — a distribution build does not produce a
portal, and a portal can front a relay that is not this one. It ships with its own
systemd unit and its own `bilbycast-portal` system user, precisely so a bug in the
public-facing portal cannot reach the relay's config or manager secret on the same
box. See [`portal.md`](portal.md).

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
  |   - Data taken only from a connection that holds a side        |
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

**Credentials never leave in `get_config`.** The config the relay hands the manager (`RelayConfig::redacted_json`, `config.rs`) shows `api_token`, `manager.registration_token`, `manager.node_secret`, `distribution.token_secret` and every `distribution.cascade_sources[].token` as `"***REDACTED***"` when set, and leaves them absent when not; a userinfo or credential query value (`?token=`) inside a manager or cascade URL is redacted in place. What it serialises is the startup snapshot, so a secret first pushed after start reads as absent until the next restart. It matters because the manager serves a node's config to anyone with View on it, and `distribution.token_secret` is the key every viewer and ingest token in the installation is signed with. The redaction is structural — each config struct is destructured without `..`, so a field added later must be classified before it compiles — and `config.json` keeps the real values.

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

  Zero locks on the forwarding path:
    - DashMap for concurrent maps (lock-free sharded HashMap)
    - AtomicU64 for stats counters
    - Arc for shared ownership
    - No RwLock anywhere; no lock taken per packet
```

The `Mutex`es in the relay are all off the forwarding path — do not read the
bullet above as "`RelayStats` is lock-free in whole":

| Site | Build | Cadence |
|------|-------|---------|
| `RelayStats::prev_sample` — the bandwidth sampler's previous reading (`stats.rs`) | every build, including the lean forwarder | the manager stats tick (1 s) and each `/api/v1/stats` request — never per datagram |
| `DepartedTunnels` — what the tunnels that have left a router counted (`stats.rs`), one in each of the two routers | every build, including the lean forwarder | each tunnel or session removed, and each read of the [relay-wide counters](#relay-wide-counters): the manager's stats (1 s) and health (15 s) ticks, `/metrics` and `/api/v1/stats` — never per datagram |
| `StreamOrigin::order` — the eviction queue of one stream (`distribution/origin.rs`) | `viewer-distribution` only | per stored segment, held for queue surgery only, never across file I/O |
| `OriginStore::clip_admission` and `OriginStore::marks_lock` — clip admission, and writes of a stream's marks (`distribution/origin.rs`) | `viewer-distribution` only | per clip export and per marks edit, and both when a stream is removed |
| `ViewerMetrics::inner` — the players' playback reports (`distribution/origin/metrics.rs`) | `viewer-distribution` only | per report and per telemetry tick |
| `DistributionControl::drop_rx` — one-shot handoff of the drop-queue receiver (`distribution_control.rs`) | compiled into every build — `lib.rs` gates `distribution` but not `distribution_control`, so the non-gated manager client can hold a handle; only ever *constructed* on a distribution build | once, at subscribe |
