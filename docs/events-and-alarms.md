# Events and Alarms

bilbycast-relay generates operational events and forwards them to bilbycast-manager via WebSocket. Events provide real-time visibility into edge connections, tunnel state changes, and manager connectivity.

## Event Protocol

Events are sent as WebSocket messages with type `"event"`:

```json
{
  "type": "event",
  "timestamp": "2026-04-02T12:00:00Z",
  "payload": {
    "severity": "warning",
    "category": "tunnel",
    "message": "Tunnel bind rejected: invalid token",
    "flow_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Severity Levels

| Severity | Meaning | Action |
|----------|---------|--------|
| `critical` | Service-impacting failure | Operator should investigate immediately |
| `warning` | Degradation or potential issue | Operator should investigate when possible |
| `info` | Notable state change | No action required, operational awareness |

### Event Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | yes | `"info"`, `"warning"`, or `"critical"` |
| `category` | string | yes | Event category (see tables below) |
| `message` | string | yes | Human-readable description |
| `flow_id` | string | no | Tunnel UUID (for tunnel-scoped events) |
| `details` | object | no | Structured context |

### Buffering

Events are queued in a **bounded** in-memory channel — capacity 1024
(`EVENT_CHANNEL_CAPACITY` in `src/manager/events.rs`) — and drained by the
manager WebSocket client loop. While the relay is disconnected from the manager,
events queue up to that depth and every further event is **dropped on arrival**:
the queue keeps the events already in it and discards the new ones. So a long
disconnection does not replay a full backlog on reconnect — it replays at most
the first 1024 events of the outage.

The bound exists because the queue was the leak: every rejected native-UDP
`Register` datagram queues an event carrying two strings and a JSON object, and
on an unbounded channel with no manager attached an inbound flood at 50k pps
retains tens of MB/s of heap on a headless relay.

Drops are counted (`EventSender::dropped_total`) and logged at most once per
second — `event queue full — dropping events`. When the `logging` structured-JSON shipper is
configured it sees every event *before* the queue, so a dropped event still
reaches the configured stdout / file / syslog target even though the manager
never gets it. A closed receiver — a standalone relay with no manager
configured — discards events silently and counts nothing.

---

## Event Reference

### Edge Connections (`edge`)

| Severity | Message | Trigger | Details |
|----------|---------|---------|---------|
| info | Edge connected from {addr} | New QUIC connection accepted from an edge node | `{ remote_addr }` |
| info | Edge disconnected from {addr} | Edge QUIC connection closed | `{ remote_addr }` |
| warning | Edge connection failed: control stream error from {addr} | Failed to accept bidirectional control stream | `{ remote_addr }` |
| warning | Connection rejected: per-IP cap exceeded ({n} active from {ip}) | New QUIC connection dropped at handshake — per-IP connection cap (`max_connections_per_ip`, default 64) reached. DoS mitigation | `{ error_code: "relay_dos_suspect", remote_addr, remote_ip, active_connections, cap }` |
| warning | Protocol version mismatch (edge={v}, relay={v}) | Edge Hello message version differs from relay | `{ edge_version, relay_version }` |
| warning | QUIC connection accept failed: {error} | QUIC/TLS handshake failure at the server level | `{ error }` |

**Source**: `src/session.rs`, `src/server.rs`

---

### Tunnels (`tunnel`)

| Severity | Message | Trigger | Details |
|----------|---------|---------|---------|
| info | Tunnel active (both sides bound) | Both ingress and egress edges have bound | `{ direction }` |
| info | Tunnel waiting: {direction} side bound | Only one side has bound, waiting for peer | `{ direction }` |
| info | Tunnel unbound by edge | Edge sent TunnelUnbind | |
| warning | Tunnel bind rejected: invalid token | HMAC-SHA256 bind token verification failed | `{ remote_addr }` |
| warning | Tunnel bind rejected: per-connection cap exceeded | `TunnelBind` rejected — per-connection tunnel-bind cap (`max_tunnels_per_connection`, default 100) reached on this connection: it has `active_binds` sides bound, and this is another. DoS mitigation; relay replies `TunnelDown { reason: "per-connection tunnel limit exceeded" }` | `{ error_code: "relay_dos_suspect", remote_addr, active_binds, cap }` |
| warning | Tunnel down: edge disconnected | Edge QUIC connection lost, affecting bound tunnel | |
| warning | Native-UDP register rejected: invalid token | `Register` on the native plain-UDP plane (`:4434`) failed bind-token verification | `{ remote_addr, transport: "udp" }` |
| warning | Native-UDP register rejected: per-IP session cap exceeded | `Register` on the native plain-UDP plane dropped — per-IP session cap reached. DoS mitigation | `{ error_code: "relay_dos_suspect", remote_addr, remote_ip, transport: "udp" }` |
| warning | Native-UDP register rejected: implausible source address | `Register` on the native plain-UDP plane arrived from an address that can never be a legitimate slot occupant. `reason: "unroutable_source"` — an address no host can own (unspecified / multicast / broadcast / port 0); `reason: "both_slots_same_address"` — the tunnel's *opposite* slot already holds exactly this address, which would make the session forward to its own source (an unbounded loop if that address routes back to the relay). Not latchable — a slot is a send target | `{ error_code: "relay_invalid_source_addr", reason, remote_addr, remote_ip, transport: "udp" }` |
| warning | Native-UDP register refused: slot held by a live peer | `Register` tried to move a slot that is currently carrying media from a *different* source IP. Refused for `SLOT_TAKEOVER_GRACE_MS` (12 s) after the last media datagram, so a flowing contribution feed cannot be redirected by one unauthenticated datagram. A same-IP port rebind is always allowed; a genuine WAN-IP change recovers once the incumbent goes quiet | `{ error_code: "relay_slot_takeover_refused", remote_addr, remote_ip, transport: "udp" }` |
| warning | Tunnel side given back to the edge that showed its token | `authorize_tunnel` came for a QUIC tunnel with a side that had been taken over, while no token was registered, by a connection that has not shown the token, from one that has and is still connected. The side is that one's again, at `remote_addr`. `held_by` is the address of the one that had taken it, `null` if it has left. See `docs/ARCHITECTURE.md`, "Tokens That Come After the Binds" | `{ error_code: "relay_unproven_holder_replaced", transport: "quic", direction, remote_addr, held_by }` |
| warning | Native-UDP slot taken over by the edge that showed its token | A `Register` from `remote_addr` showed the registered token for a slot whose holder, at another IP (`held_by`), is carrying media and has not shown it. The slot is the edge's at once; without the token it would have been refused (`relay_slot_takeover_refused`) | `{ error_code: "relay_unproven_holder_replaced", transport: "udp", direction, remote_addr, held_by }` |
| critical | Native-UDP relay plane stopped: {error} | The native plain-UDP plane (`:4434`) is not running: no listener could be bound at startup, or a receive loop ended. The relay **keeps forwarding QUIC tunnels** — before relay#15 this exited the whole process — withdraws the `udp-relay` capability, and reports `udp_relay_error` on health (`"udp_relay": "stopped"` on the public `/health`). Native SRT/RIST tunnels and relayed bond legs on this relay are down meanwhile. A failed bind is retried (5 s, doubling to 60 s) and raised once per outage; a plane that stops after binding is not retried and needs a restart (`src/supervise.rs`) | `{ error_code: "relay_udp_plane_stopped", transport: "udp", error }` |
| info | Native-UDP relay plane started after a failed bind | A retried bind of the native plain-UDP plane succeeded after `relay_udp_plane_stopped`. The `udp-relay` capability and the `/health` field return to normal | `{ error_code: "relay_udp_plane_recovered", transport: "udp", attempts }` |
| warning | Native-UDP plane accepts unauthenticated registers | Emitted **once at startup** when `require_bind_auth: false` *and* `udp_relay_enabled: true`. For any tunnel the manager has not pre-authorized, a `Register` on the native plane can *move* a slot (media hijack), not merely join a tunnel as on QUIC. See `require_bind_auth` in the README | `{ error_code: "relay_native_plane_unauthenticated", require_bind_auth: false, udp_relay_enabled: true }` |

The `flow_id` field contains the tunnel UUID for all tunnel events.

**Source**: `src/session.rs`, `src/udp_relay.rs`, `src/supervise.rs`

---

### Manager Connection (`manager`)

| Severity | Message | Trigger |
|----------|---------|---------|
| info | Connected to manager | WebSocket auth succeeded (auth_ok or register_ack) |
| warning | Manager connection lost, rotating to next URL | The manager closed the connection: a Close frame, or the stream ended without an error. A write that fails is the `{error}` row below, as `WebSocket write failed: …` |
| warning | Manager connection lost, rotating to next URL: {error} | The attempt or the session failed, and `{error}` says how: a connection or protocol error (`WebSocket error: …`, `WebSocket write failed: …`, `Auth rejected: …`), or the deadline that ended it. Every await on the manager link is bounded. The dial gets 30 s in all and names the stage that failed — `manager DNS lookup for {host} failed: …`, `TCP connect to {host} ({n} addresses) failed: …`, `TCP connect to {host} timed out`, `TLS/WebSocket upgrade with {host} failed: …` or `… timed out after {n}s` (`Manager dial timed out after 30s` if no stage could be named); then `Auth send timed out after 10s`, `Auth response timeout (10s)`; in the session, `A write to the manager made no progress for 300s — the manager stopped reading; ending the session`, and `Nothing heard from the manager for {n}s (limit {m}s from its ping cadence) — treating the session as dead and reconnecting`, which is armed by the manager's first WebSocket ping and allows 90 s or four of its ping intervals, whichever is longer. Raised while the link is down, so the manager sees it once the next session starts |
| critical | Manager authentication failed: {reason} | Auth rejected by manager. After a `rotate_secret` whose acknowledgement was sent but which the manager did not store (the connection dropped before the manager read the acknowledgement, the manager read it after its 10 s wait, or its database write failed), the next reconnect raises this with the new secret before the relay falls back to the previous one: once for each such rotation since the relay last authenticated. A rotation whose acknowledgement could not be sent at all raises nothing, because the relay then presents the previous secret first |

**Source**: `src/manager/client.rs`

---

### Configuration / Security (`manager`)

| Severity | Message | Trigger |
|----------|---------|---------|
| info | Secret rotated successfully | `rotate_secret` saved the new secret to the config file and its acknowledgement was sent. The next authentication presents the new secret |
| warning | Credential persistence failed: {error} | The config file could not be written. A write that fails part-way (a full disk, a quota, an I/O error) can leave `config.json` cut short and unreadable, and the relay then will not start until the file is repaired. On `rotate_secret` the rotation is **refused** (`success: false`), so the manager keeps the old secret and the relay goes on presenting it. When a rotation's acknowledgement could not be sent, the relay puts the previous secret back in the file; if that write fails, the file keeps the new secret, which a restart before the next authentication would present. After an authentication that settled which secret the manager holds after a rotation, the relay is connected but the file may still hold a secret the manager refused, which a restart would present |

**Source**: `src/manager/client.rs`

---

### Viewer Distribution (`distribution`)

Emitted only by a relay built with the optional `viewer-distribution` role (default-off Cargo feature; the shipped distribution artefacts use `viewer-distribution-vendored`). A plain opaque-forwarder relay never emits these; they appear only on a distribution-role build that runs the WHEP SFU + LL-HLS/CMAF origin.

| Severity | Message | Trigger | Details |
|----------|---------|---------|---------|
| critical | Viewer-distribution subsystem stopped: {error} | The distribution subsystem ended: its origin root could not be used (the error names the directory — on 2026-09-22 a root-owned `/var/lib/bilbycast/relay/origin`), an HTTP or ingest listener could not bind or stopped, or the task panicked. The relay **keeps forwarding** QUIC and native-UDP tunnels — before relay#15 this exited the whole process — withdraws the `viewer-distribution` and `origin-policy` capabilities, refuses every later `configure_distribution` push (so the manager keeps what it sent as owed), and reports `distribution_error` on health (`"distribution": "stopped"` on the public `/health`). WHEP viewers, the LL-HLS origin and DVR on this relay are down until the cause is fixed and the relay restarted; the subsystem is not retried in-process (`src/supervise.rs`) | `{ error_code: "relay_distribution_stopped", error }` |
| info | WHIP ingest opened for stream '{stream}' | A WHIP-in ingest began feeding a stream's hub | `{ stream }` |
| info | distribution ingest opened for stream '{stream}' | A QUIC ES ingest began feeding a stream's hub | `{ stream, has_audio }` |
| info | distribution ingest closed for stream '{stream}' | A QUIC ES ingest that held its stream stopped: the stream tears down and its WHEP viewers end (`stream closed`) | `{ stream, superseded: false, held_by: "this" }` |
| info | distribution ingest closed for stream '{stream}'; another ingest holds the stream, which plays on | A QUIC ES ingest stopped after a newer ingest for the same stream id had taken the stream from it, and another ingest holds the stream now: that newer one, or an older one that took the stream back once every ingest newer than it had ended. Its end touches nothing — the stream and its viewers carry on under that ingest | `{ stream, superseded: true, held_by: "another" }` |
| info | distribution ingest closed for stream '{stream}'; a newer ingest had taken the stream from it, and no ingest holds the stream now | A QUIC ES ingest stopped after a newer ingest had taken the stream from it, and every ingest that held the stream since has ended. A superseded ingest takes its stream back only on its next frame after that, and this one sent none before it stopped. Nothing feeds the stream id: a viewer that came back for it waits, connected and sent nothing, until the next ingest for it arrives | `{ stream, superseded: true, held_by: "none" }` |
| info | Clip '{clip}' deleted from stream '{stream}' with a {credential} token ({fingerprint}) | `DELETE /origin/{stream}/clips/{clip}.mp4` removed a clip. Any viewer token for the feed may delete any of its clips — deliberately (bilbycast-relay#14) — so every delete is attributed instead. `credential` is `viewer` or `ingest`; `token_fingerprint` is the first 12 hex digits of the SHA-256 of the token's 32 signature bytes (the hex after its last `.`), and names a token, not a person: the manager records no mint, and the portal mints a fresh token for each delete it makes on a viewer's behalf. Raised from a task the request cannot cancel, so a client that hangs up does not delete unattributed. Bounded by the export allowance, since every delete takes a clip something commissioned | `{ error_code: "clip_deleted", stream, clip, credential, token_fingerprint }` |
| warning | per-IP viewer cap ({cap}) reached from {ip} | A WHEP viewer request was rejected — per-source-IP concurrent-viewer cap (`max_viewers_per_ip`) reached | `{ ip, cap }` |
| warning | WHEP viewer: off-path datagram dropped by the media source pin | A datagram for a live WHEP session arrived from an address other than the one that completed DTLS, and was dropped before str0m saw it, outside the pin's other-path grace. The grace: a datagram from an address with a *claim* to the session — an IP named among the ICE candidates of the viewer's offer, the source of a datagram that arrived before DTLS completed (recorded before str0m checks integrity, so any sender's), or an address the session advertised — is dropped without this event for the first 30 s after DTLS completed and the first 64 such datagrams, because a multi-homed viewer goes on checking its other candidate pairs for a while (measured: up to 24 datagrams, 17.3 s); those count on `bilbycast_relay_distribution_other_path_datagrams_total` instead. A claim is not trust: the viewer writes its offer, and can name its victim. Causes: a source-spoofed ICE reflection attempt (the relay is ICE-Lite and str0m implements no RFC 7675 consent freshness, so the pin is the control) — from any address, or from one with a claim once it outlasts the grace, as a reflection attempt does where a peer's checks stop; or a legitimate viewer whose traffic moved to another address mid-session (Wi-Fi → cellular, CGNAT pool rotation, or its ICE switching to a path the pin refuses) — that viewer goes black until it re-POSTs its WHEP offer. Emitted **once per session**, so a reflection flood cannot amplify its own alarm | `{ error_code: "webrtc_offpath_source", stream, session_id, pinned_ip, source_addr, source_ip }` |
| warning | Clip export on stream '{stream}' has used its allowance of 20 minutes of clips, which refills at 20 minutes an hour; further exports are refused until it refills — or, for one token's share, `A {credential} token ({fingerprint}) exporting clips on stream '{stream}' has used its allowance of 17 minutes of clips, which refills at 10 minutes an hour; …` | A `POST /origin/{stream}/clips` was refused `429` because it would take the feed past its export allowance (`limit: "feed"`) or one token past its share of it (`limit: "credential"`). The allowance bounds what a feed **commissions** of the edge that cuts it, which the count and byte caps cannot: a delete hands those back, so before bilbycast-relay#14 a viewer token could export, delete and export again for ever, each export an all-intra encode on the edge. A delete refunds nothing. **Once per episode** per feed or per token — from the first refusal until that allowance is whole again — so a refused-request loop cannot amplify it; raised from the same blocking step that spends the episode, so a client that hangs up cannot suppress it. Worst case it bounds, once a feed's first allowance is spent: 1,200 clip-seconds and 240 new cuts an hour per feed, each cut attempted up to three times by the edge (`MAX_ATTEMPTS`), so up to 3,600 seconds of footage encoded an hour per feed — and up to twice that in the hour after a whole allowance, since the refill is rolling. `token_fingerprint` is the **refused** request's token: on a `credential` refusal the token that spent its share, but on a `feed` refusal whoever asked next (in an export/delete loop, the viewer it locked out), so a `feed` refusal also carries `top_spender_fingerprint`, the heaviest single token still outstanding on the feed, and `top_spender_outstanding_secs`, how many clip-seconds of its own share it still has spent. Read them together against `allowance_secs`: the heaviest token is not always who spent the feed — a feed spent by many tokens, a fresh one minted per export, names whichever holds the most however light (a viewer with one minute of clips outstanding, beside a hundred ten-second mints) — so only a number that is a real part of the feed's 1,200 points at a culprit. Both `null` on a `credential` refusal, and when no token on the feed has any of its share outstanding. See `docs/distribution.md`, "Clip export" | `{ error_code: "clip_export_rate_limited", stream, limit, asked_secs, retry_after_secs, allowance_secs, refill_secs_per_hour, credential, token_fingerprint, top_spender_fingerprint, top_spender_outstanding_secs }` |
| warning | WebRTC negotiation with {peer} failed: str0m panicked during {step}: {panic} | str0m panicked negotiating a `POST /whep/{stream}` (`peer` = `WHEP viewer`) or `POST /whip/{stream}` (`WHIP publisher`) offer. **Defence in depth: no offer known to panic str0m 0.26 exists**, so expect never to see this — one that does is a new str0m defect worth reporting. The offer that used to (one RTX PT repairing two H.264 PTs, which panicked str0m 0.24.1 "Pt locked multiple times") is now refused while it is parsed ("PT 103 has conflicting apt values 102 and 104 for mid: 0", in the relay's log line `WebRTC: the offer is not valid SDP: …`): a plain `400` that raises nothing, whose body names only the step that failed (`WHEP setup failed: failed to accept SDP offer`, or `WHIP ingest setup failed: failed to accept WHIP offer`). A panic is contained (`webrtc::session::isolate_negotiation`): that one request fails with a `400`, nothing else is affected. `step` is `SDP offer` for an offer; `session setup`, `SDP offer creation` and `SDP answer` are the other isolated steps. **Rate limited** — the endpoints are public — to one event per 10 s relay-wide; `suppressed` counts the panics held back since the previous event. A malformed or refused offer that str0m rejects without panicking raises nothing. Same `error_code` as bilbycast-edge's | `{ error_code: "webrtc_negotiation_panic", peer, stream, step, panic, ip, suppressed }` |

**Source**: `src/distribution/`

---

## Manager-Generated Events

In addition to events sent by the relay, the manager itself generates these events:

| Severity | Category | Message | Trigger |
|----------|----------|---------|---------|
| info | connection | Node connected to manager | Relay successfully authenticates |
| warning | compatibility | Node WS protocol version differs | Protocol version mismatch during auth |
| critical | connection | Node disconnected from manager | Relay WebSocket closes |

These are generated server-side in `bilbycast-manager/crates/manager-server/src/ws/node_hub.rs`.

---

## Event Categories Summary

| Category | Count | Description |
|----------|-------|-------------|
| `edge` | 6 | Edge QUIC connection lifecycle (now with structured details), incl. per-IP DoS cap |
| `tunnel` | 15 | Tunnel state changes, authentication, lifecycle (waiting, unbound), a side taken back by the edge that showed its token (both planes), per-connection DoS cap, native plain-UDP register rejections (invalid token, per-IP session cap, implausible source address, live-slot takeover), the one-shot startup posture warning, and the native-UDP plane stopping and recovering |
| `manager` | 6 | Manager connection and credential management |
| `distribution` | 9 | Viewer-distribution ingest lifecycle, per-IP viewer cap, the WebRTC media source pin, str0m negotiation panics, the subsystem stopping, a spent clip-export allowance, and clip deletes (only on `viewer-distribution` builds) |
| **Total** | **36** | |

The always-compiled `edge`, `tunnel`, and `manager` categories account for 27 events. The `distribution` category (9 events) is present only when the relay is built with the optional `viewer-distribution` role.

### By Severity

The always-compiled surface (excluding the optional `distribution` category) is critical=2, warning=17, info=8.

| Severity | Count | Description |
|----------|-------|-------------|
| critical | 2 | Manager authentication failure, the native-UDP plane stopping |
| warning | 17 | Disconnects, bind rejections, sides taken back by the edge that showed their token, protocol mismatches, QUIC failures, persistence failures, DoS-cap rejections (per-IP + per-connection + native-UDP session cap), native-UDP token rejections, native-UDP source-plausibility and live-slot-takeover refusals, and the unauthenticated-native-plane startup warning |
| info | 8 | Connections, tunnel activation/waiting/unbound, secret rotation, the native-UDP plane recovering |
