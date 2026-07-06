# bilbycast-relay

> 🌐 Learn more at **[bilbycast.com](https://bilbycast.com)** — the official website for the Bilbycast broadcast media transport suite.

Stateless relay server that provides NAT traversal for bilbycast-edge nodes. It is a generic, **opaque per-path forwarder**: it pairs the two ends of each path by tunnel ID and forwards encrypted traffic between them, with no ability to read the payload (end-to-end ChaCha20-Poly1305 encryption lives on the edges — the relay sees only `[16-byte tunnel_id][AEAD ciphertext]`). It carries every path type the same way:

- **QUIC tunnels** — TCP streams + UDP datagrams over QUIC/TLS 1.3 (`:4433`).
- **Native SRT/RIST over relay** — plain UDP, no QUIC (`:4434`), so SRT/RIST run their own ARQ + congestion control without QUIC's per-packet overhead or a second congestion controller fighting theirs.
- **Individual bond legs** — a relayed bond leg is just a native plain-UDP tunnel as far as the relay is concerned. The relay forwards each leg's packets opaquely; bond aggregation, cross-leg ARQ, FEC, and reordering all run end-to-end edge↔edge. **The relay never terminates or combines a bond** — there is no "bond bridge".

Each path can go direct or over any relay, in any combination (and a path may use a primary + backup relay), and both ends can be behind NAT — both edges dial out.

## Quick Start

### Install as a service (recommended for production)

`packaging/install-relay.sh` creates the `bilbycast-relay` system user, drops the binary into `/opt/bilbycast/relay/`, writes `/etc/bilbycast/relay.json`, installs the systemd unit, and starts the service. Sigstore-verified Sigstore-keyless trust chain — same trust path the `upgrade-relay.sh` script uses.

```bash
# Standalone (no manager connection):
curl -fsSL https://github.com/Bilbycast/bilbycast-relay/releases/latest/download/install-relay.sh \
  | sudo bash

# With manager connection:
curl -fsSL https://github.com/Bilbycast/bilbycast-relay/releases/latest/download/install-relay.sh \
  | sudo bash -s -- \
      --manager wss://manager.example.com:8443/ws/node \
      --registration-token <token-from-manager-ui> \
      [--api-token <32-128-char-secret>] \
      [--require-bind-auth]
```

Service controls after install:

```bash
sudo systemctl status bilbycast-relay
sudo journalctl -u bilbycast-relay -f
curl http://127.0.0.1:4480/health
```

Uninstall with `sudo packaging/uninstall-relay.sh` (preserves config + persisted node credentials) or `--purge` (wipes everything including the service user).

### From source (development / standalone testing)

```bash
cargo build --release
./target/release/bilbycast-relay
```

Starts with defaults: QUIC on `0.0.0.0:4433`, native SRT/RIST plain-UDP on `0.0.0.0:4434`, REST API on `0.0.0.0:4480`, self-signed TLS certificate. No config file needed.

To build a relay that can also reach browser viewers (see [Viewer Distribution](#viewer-distribution-optional) below), add the feature — releases ship this as the separate `*-linux-distribution` binary:

```bash
cargo build --release --features viewer-distribution   # str0m + OpenSSL
```

### With manager connection (manual config)

1. In the manager UI, create a new node with device type **relay** and copy the registration token.

2. Create `relay.json`:

   ```json
   {
     "quic_addr": "0.0.0.0:4433",
     "api_addr": "0.0.0.0:4480",
     "manager": {
       "enabled": true,
       "urls": ["wss://manager-host:8443/ws/node"],
       "registration_token": "<token-from-manager>"
     }
   }
   ```

3. Start:

   ```bash
   ./target/release/bilbycast-relay -c relay.json
   ```

   The relay registers with the manager on first connect. Credentials are saved automatically — the registration token is consumed and cleared.

## Configuration

All fields are optional. Defaults are used for any omitted field.

```json
{
  "quic_addr": "0.0.0.0:4433",
  "quic_addrs": ["0.0.0.0:4433", "[::]:4433"],
  "api_addr": "0.0.0.0:4480",
  "api_addrs": ["0.0.0.0:4480", "[::]:4480"],
  "public_quic_addr": "relay.example.com:4433",
  "udp_relay_enabled": true,
  "udp_relay_addrs": ["0.0.0.0:4434", "[::]:4434"],
  "public_udp_addr": "relay.example.com:4434",
  "tls_cert_path": "/path/to/cert.pem",
  "tls_key_path": "/path/to/key.pem",
  "api_token": "a-random-token-32-to-128-chars",
  "require_bind_auth": false,
  "max_connections_per_ip": 64,
  "max_tunnels_per_connection": 100,
  "logging": {
    "json_target": { "kind": "stdout", "format": "raw" }
  },
  "manager": {
    "enabled": true,
    "urls": ["wss://manager-host:8443/ws/node"],
    "accept_self_signed_cert": false,
    "cert_fingerprint": "ab:cd:ef:01:23:...",
    "registration_token": "<one-time-token>"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `quic_addr` | `0.0.0.0:4433` | QUIC listen address for edge connections (legacy single-address; ignored when `quic_addrs` is set) |
| `quic_addrs` | `["0.0.0.0:4433", "[::]:4433"]` | Dual-stack QUIC listener addresses. v6 entries get `IPV6_V6ONLY=1` so they coexist with v4 on the same port |
| `api_addr` | `0.0.0.0:4480` | REST API listen address (legacy single-address; ignored when `api_addrs` is set) |
| `api_addrs` | `["0.0.0.0:4480", "[::]:4480"]` | Dual-stack REST API listener addresses (same semantics as `quic_addrs`) |
| `public_quic_addr` | (none — falls back to `quic_addr`) | Publicly-reachable QUIC address remote edges dial (IP literal or DNS `host:port`). Advertised to the manager and surfaced in the tunnel-creation dropdown. Unspecified addresses (`0.0.0.0`/`[::]`) are rejected |
| `udp_relay_enabled` | `true` | Enable the native SRT/RIST plain-UDP data plane (no QUIC). Set `false` for a QUIC-only relay. Bind failures are non-fatal: the relay logs, drops the `udp-relay` capability, and continues |
| `udp_relay_addrs` | `["0.0.0.0:4434", "[::]:4434"]` | Dual-stack listener addresses for the native SRT/RIST path (same semantics as `quic_addrs`) |
| `public_udp_addr` | (none — manager falls back to `public_quic_addr`'s host + the UDP port) | Publicly-reachable address remote edges dial for the native SRT/RIST path. Advertised to the manager. Unspecified addresses are rejected |
| `tls_cert_path` | (auto-generated) | Path to TLS certificate PEM. Self-signed cert generated if absent |
| `tls_key_path` | (auto-generated) | Path to TLS private key PEM |
| `api_token` | (none — API open) | Bearer token for REST API auth (32-128 chars). If set, all endpoints except `/health` require `Authorization: Bearer <token>` |
| `require_bind_auth` | `false` | Reject `TunnelBind` from edges without a manager-registered HMAC token. Recommended `true` for production |
| `max_connections_per_ip` | `64` | DoS mitigation: max simultaneous QUIC connections per source IP. Excess connections are dropped at handshake |
| `max_tunnels_per_connection` | `100` | DoS mitigation: max tunnel binds per connection. Excess `TunnelBind` messages are rejected |
| `logging` | (none) | Optional structured-JSON log shipper for SIEM/NMS pickup. `json_target.kind`: `stdout` / `file` / `syslog`; `format`: `raw` / `splunk` / `dataminer`. Mirrors the edge's shape |
| `manager.enabled` | `false` | Enable outbound WebSocket connection to bilbycast-manager |
| `manager.urls` | — | Ordered list of manager WebSocket URLs (1-16, each `wss://`). Rotates on every WS close |
| `manager.accept_self_signed_cert` | `false` | Accept self-signed TLS from manager (requires `BILBYCAST_ALLOW_INSECURE=1` env var) |
| `manager.cert_fingerprint` | (none) | SHA-256 certificate pin for the manager (hex with colons) |
| `manager.registration_token` | (none) | One-time registration token from manager |

## Viewer Distribution (optional)

Built with `--features viewer-distribution` (the `*-linux-distribution` release
binary), a relay can also reach **browser viewers directly** — a **WHEP SFU**
for sub-second WebRTC plus an **LL-HLS/CMAF origin** for CDN-scale audiences —
with no external streaming server and no ports opened on the edge. It's a
separate, **default-off** capability, hard-isolated from the opaque forwarder;
this binary stays a pure forwarder unless you add a `distribution` block.

Point the edge's existing WebRTC (WHIP) output at `http(s)://<relay>/whip/<stream>`,
then share `http(s)://<relay>/watch/<stream>`. Front the HTTP listener (`:4485`)
with a TLS-terminating proxy for the browser secure context.

```json
{
  "distribution": {
    "enabled": true,
    "http_addrs": ["0.0.0.0:4485", "[::]:4485"],
    "public_ip": "203.0.113.10",
    "public_base_url": "https://relay.example.com",
    "ingest_addrs": ["0.0.0.0:4486", "[::]:4486"],
    "token_secret": "<64 hex chars, shared with the manager>",
    "require_viewer_token": false,
    "require_ingest_token": true,
    "max_viewers_per_ip": 256,
    "origin_window_segments": 8,
    "cascade_sources": []
  }
}
```

Scale past one relay with a **cascade** (regional relays pull from an origin via
`cascade_sources`) or by fronting the LL-HLS origin with a CDN. Full reference:
[`docs/distribution.md`](docs/distribution.md) and the
[website guide](https://docs.bilbycast.com/relay/viewer-distribution/).

## CLI Options

```
bilbycast-relay [OPTIONS]

Options:
  -c, --config <PATH>            Path to config file (JSON)
      --quic-addr <ADDR>         Override QUIC listen address (legacy single-address)
      --api-addr <ADDR>          Override API listen address (legacy single-address)
      --quic-addrs <ADDRS>       Override QUIC dual-stack listeners (comma-separated,
                                 e.g. 0.0.0.0:4433,[::]:4433). Takes precedence over --quic-addr
      --api-addrs <ADDRS>        Override API dual-stack listeners (comma-separated).
                                 Takes precedence over --api-addr
      --public-quic-addr <ADDR>  Override the publicly-reachable QUIC address advertised
                                 to remote edges (e.g. relay.example.com:4433)
      --udp-relay-addrs <ADDRS>  Override native SRT/RIST plain-UDP listeners
                                 (comma-separated, e.g. 0.0.0.0:4434,[::]:4434)
      --public-udp-addr <ADDR>   Override the publicly-reachable native SRT/RIST address
                                 advertised to remote edges (e.g. relay.example.com:4434)
      --no-udp-relay             Disable the native SRT/RIST data plane (QUIC tunnels only)
  -h, --help                     Print help
  -V, --version                  Print version
```

## Upgrading

Run `packaging/upgrade-relay.sh` on the relay host. It downloads the latest signed `manifest.json` + `manifest.sig.bundle`, verifies the Sigstore signature against the publishing workflow's identity (auto-installing cosign with checksum verification if missing), pulls the matching arch-specific tarball (x86_64 / aarch64), verifies SHA-256, atomically swaps the binary with a `.previous` backup, restarts the systemd unit, polls `/health`, and **auto-rolls back** to the previous binary on health-check failure.

```bash
sudo ./packaging/upgrade-relay.sh                       # latest stable, default service name
sudo ./packaging/upgrade-relay.sh --dry-run             # download + verify only; print plan
sudo ./packaging/upgrade-relay.sh --target-version 0.8.0   # pin to a specific release tag
```

The relay is stateless — a restart drops connected edges, which all reconnect automatically. For zero-disruption upgrades, run multiple relay instances behind a load balancer and roll them through one at a time. Pass `--help` for every flag.

## REST API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | Public | Health check (always unauthenticated). Includes `udp_sessions_total` / `udp_sessions_active` for the native SRT/RIST plane |
| `GET /metrics` | Token | Prometheus metrics |
| `GET /api/v1/tunnels` | Token | List active QUIC tunnels |
| `DELETE /api/v1/tunnels/{id}` | Token (required) | Administrative teardown of a QUIC tunnel when the manager is unavailable. **Fail-closed**: returns `403` unless `api_token` is set |
| `GET /api/v1/udp-sessions` | Token | List native SRT/RIST plain-UDP relay sessions |
| `DELETE /api/v1/udp-sessions/{id}` | Token (required) | Administrative teardown of a native-UDP session. **Fail-closed** (same as the tunnel DELETE) |
| `GET /api/v1/edges` | Token | List connected edges |
| `GET /api/v1/stats` | Token | Bandwidth, throughput, peaks, uptime |

"Token" auth means `Authorization: Bearer <api_token>` is required when `api_token` is configured. If no `api_token` is set, the read-only GETs are open, but the destructive `DELETE` routes refuse to run (return `403`) — a destructive route must never be reachable unauthenticated.

## Security

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3 via QUIC (all edge-relay traffic encrypted) |
| End-to-end | ChaCha20-Poly1305 between edges (relay sees only ciphertext) |
| REST API | Optional Bearer token authentication |
| Tunnel binding | Optional per-tunnel HMAC-SHA256 bind tokens (managed via manager) |
| ALPN | `bilbycast-relay` protocol enforced |

## Testing

```bash
cargo test                   # All tests (unit + integration)
cargo test --lib             # Unit tests only
cargo test --test integration # Integration tests only
```

## Licensing

bilbycast-relay is **dual-licensed**:

- **AGPL-3.0-or-later** for open-source users — free for review, private use, and any use where you are comfortable releasing the source of your modifications (and any modified network service built on top of the relay) under AGPL terms. See [LICENSE](LICENSE).
- **Commercial licence** from Softside Tech Pty Ltd for OEMs, hardware integrators, SaaS providers, and commercial customers who need to operate the relay without AGPL § 13's source-release obligation. Contact **contact@bilbycast.com** for terms. See [LICENSE.commercial](LICENSE.commercial).

Contributions are accepted under the Developer Certificate of Origin — see [DCO.md](DCO.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
