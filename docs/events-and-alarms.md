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

Events are queued in an unbounded in-memory channel. When the relay is not connected to the manager, events accumulate and are delivered once the connection is re-established.

---

## Event Reference

### Edge Connections (`edge`)

| Severity | Message | Trigger | Details |
|----------|---------|---------|---------|
| info | Edge connected from {addr} | New QUIC connection accepted from an edge node | `{ remote_addr }` |
| info | Edge disconnected from {addr} | Edge QUIC connection closed | `{ remote_addr }` |
| warning | Edge connection failed: control stream error from {addr} | Failed to accept bidirectional control stream | `{ remote_addr }` |
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
| warning | Tunnel down: edge disconnected | Edge QUIC connection lost, affecting bound tunnel | |

The `flow_id` field contains the tunnel UUID for all tunnel events.

**Source**: `src/session.rs`

---

### Manager Connection (`manager`)

| Severity | Message | Trigger |
|----------|---------|---------|
| info | Connected to manager | WebSocket auth succeeded (auth_ok or register_ack) |
| warning | Manager connection lost, reconnecting | WebSocket closed normally |
| warning | Manager connection lost, reconnecting: {error} | WebSocket errored |
| critical | Manager authentication failed: {reason} | Auth rejected by manager |

**Source**: `src/manager/client.rs`

---

### Configuration / Security (`manager`)

| Severity | Message | Trigger |
|----------|---------|---------|
| info | Secret rotated successfully | rotate_secret command completed |
| warning | Credential persistence failed: {error} | Failed to write credentials to config file after rotation |

**Source**: `src/manager/client.rs`

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
| `edge` | 5 | Edge QUIC connection lifecycle (now with structured details) |
| `tunnel` | 5 | Tunnel state changes, authentication, and lifecycle (waiting, unbound) |
| `manager` | 6 | Manager connection and credential management |
| **Total** | **16** | |

### By Severity

| Severity | Count | Description |
|----------|-------|-------------|
| critical | 1 | Manager authentication failure |
| warning | 7 | Disconnects, bind rejections, protocol mismatches, QUIC failures, persistence failures |
| info | 8 | Connections, tunnel activation/waiting/unbound, secret rotation |
