# bilbycast-relay

Stateless QUIC relay server that enables IP tunneling between bilbycast-edge nodes behind NAT. The relay pairs ingress and egress edges by tunnel ID and forwards encrypted traffic between them — it cannot read tunnel payloads (end-to-end ChaCha20-Poly1305 encryption between edges).

## Quick Start

### Zero-config (simplest)

```bash
cargo build --release
./target/release/bilbycast-relay
```

Starts with defaults: QUIC on `0.0.0.0:4433`, REST API on `0.0.0.0:4480`, self-signed TLS certificate. No config file needed.

### With manager connection

1. In the manager UI, create a new node with device type **relay** and copy the registration token.

2. Create `relay.json`:

   ```json
   {
     "quic_addr": "0.0.0.0:4433",
     "api_addr": "0.0.0.0:4480",
     "manager": {
       "enabled": true,
       "url": "wss://manager-host:8443/ws/node",
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
  "api_addr": "0.0.0.0:4480",
  "tls_cert_path": "/path/to/cert.pem",
  "tls_key_path": "/path/to/key.pem",
  "api_token": "a-random-token-32-to-128-chars",
  "manager": {
    "enabled": true,
    "url": "wss://manager-host:8443/ws/node",
    "accept_self_signed_cert": false,
    "cert_fingerprint": "ab:cd:ef:01:23:...",
    "registration_token": "<one-time-token>"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `quic_addr` | `0.0.0.0:4433` | QUIC listen address for edge connections |
| `api_addr` | `0.0.0.0:4480` | REST API listen address |
| `tls_cert_path` | (auto-generated) | Path to TLS certificate PEM. Self-signed cert generated if absent |
| `tls_key_path` | (auto-generated) | Path to TLS private key PEM |
| `api_token` | (none — API open) | Bearer token for REST API auth (32-128 chars). If set, all endpoints except `/health` require `Authorization: Bearer <token>` |
| `manager.enabled` | `false` | Enable outbound WebSocket connection to bilbycast-manager |
| `manager.url` | — | Manager WebSocket URL (must use `wss://`) |
| `manager.accept_self_signed_cert` | `false` | Accept self-signed TLS from manager (requires `BILBYCAST_ALLOW_INSECURE=1` env var) |
| `manager.cert_fingerprint` | (none) | SHA-256 certificate pin for the manager (hex with colons) |
| `manager.registration_token` | (none) | One-time registration token from manager |

## CLI Options

```
bilbycast-relay [OPTIONS]

Options:
  -c, --config <PATH>       Path to config file (JSON)
      --quic-addr <ADDR>    Override QUIC listen address
      --api-addr <ADDR>     Override API listen address
  -h, --help                Print help
  -V, --version             Print version
```

## REST API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | Public | Health check (always unauthenticated) |
| `GET /metrics` | Token | Prometheus metrics |
| `GET /api/v1/tunnels` | Token | List active tunnels |
| `GET /api/v1/edges` | Token | List connected edges |
| `GET /api/v1/stats` | Token | Bandwidth, throughput, peaks, uptime |

"Token" auth means `Authorization: Bearer <api_token>` is required when `api_token` is configured. If no `api_token` is set, all endpoints are open.

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

## License

This project is licensed under the [Elastic License 2.0](LICENSE). For use cases not covered by ELv2 (OEM, managed services, resale), a commercial license is available from Softside Tech Pty Ltd — contact admin@softsidetech.com.
