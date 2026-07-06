# Viewer Distribution (WHEP SFU + LL-HLS origin)

The **viewer-distribution** subsystem turns a relay into a public "distribution
node" that reaches **browser viewers directly** — no external WHIP/WHEP server
(mediamtx, LiveKit, Cloudflare Stream, …) and no ports opened on the NAT'd edge.

It is **default-off** and gated behind the `viewer-distribution` Cargo feature,
hard-isolated from the stateless opaque forwarder. A plain `cargo build`
produces the pure forwarder with **zero** media-termination surface and no
OpenSSL/str0m build dependency. Build a distribution-capable relay with:

```bash
cargo build --release --features viewer-distribution
```

## Why the relay

Edges are NAT'd/CGNAT'd and frequently on limited (≈3 Mbps cellular) uplinks —
they physically cannot originate N per-viewer copies. Fan-out therefore **must**
happen at a public, well-connected node, and the relay is exactly that: already
public, already manager-orchestrated, already deployed. See
`../../docs/` and the feasibility analysis for the full rationale (TURN-on-relay
does not solve the bandwidth problem; only server-side fan-out does).

## Two complementary tiers

| Tier | Path | Latency | Scale | Use it for |
|------|------|---------|-------|-----------|
| **WHEP SFU** | WebRTC to the browser | sub-second | ~300–2000 viewers / relay box (uplink- + per-viewer-SRTP-bound), cascade beyond | interactive / betting-grade / bounded audiences |
| **LL-HLS origin** | fMP4 over HTTP + CDN | 1–5 s | millions (ordinary HTTP caching) | one-to-many web audiences at scale |

The **edge produces both** already (its WebRTC + CMAF outputs). Pick per audience;
they are not either/or.

## Data flow

```
 bilbycast-edge  ── WHIP (H.264+Opus, DTLS/SRTP) ──►  relay  ── WHEP ──►  browsers
   (shipped WHIP-client output; demux + AAC→Opus         │      (sub-second)
    transcode already broadcast-quality-gated)           │
                                                          └── LL-HLS origin ──► CDN ──► browsers
 bilbycast-edge  ── CMAF PUT (fMP4 + m3u8/mpd) ──────────┘      (1–5 s, cache-scale)
```

- **WHIP ingest** (zero new edge code): point the edge's existing WHIP-client
  output at `https://{relay}/whip/{stream}`. The relay terminates DTLS/SRTP,
  depacketizes to elementary frames, and fans out to WHEP viewers. This reuses
  the edge's proven, quality-gated encoder — nothing new to verify on the edge.
- **QUIC ES ingest** (optional, lower overhead): a future edge output can ship
  already-encoded H.264+Opus elementary frames over a dedicated QUIC endpoint
  (`ALPN bilbycast-distribution`, default `:4486`). Wire format in
  `src/distribution/ingest.rs`. Not required — WHIP-in works today.
- **Keyframe cache**: the relay caches the last IDR access unit per stream, so a
  late-joining viewer decodes immediately instead of waiting for the source's
  next IDR.

## Endpoints (browser-facing HTTP listener, default `:4485`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/whep/{stream}` | Viewer sends an SDP offer, gets an SDP answer + `Location` resource URL |
| `DELETE` | `/whep/{stream}/{session}` | Tear down one viewer |
| `POST` | `/whip/{stream}` | Edge pushes a stream in (SDP offer → answer) |
| `DELETE` | `/whip/{stream}/{session}` | Stop an ingest |
| `GET` | `/watch/{stream}` | Built-in minimal `<video>` + WHEP player page |
| `PUT` | `/origin/{stream}/{file}` | Edge CMAF/HLS upload (`.m3u8`/`.mpd`/`.m4s`) |
| `GET` | `/origin/{stream}/{file}` | Serve a cached segment/manifest (CDN or player) |
| `GET` | `/distribution/health` | Liveness |

**The signaling + origin listener is plain HTTP.** Browsers require a secure
context, so front it with a TLS-terminating reverse proxy / load balancer (the
`behind_proxy` pattern) presenting a CA cert on `public_base_url`'s hostname. The
DTLS/SRTP media path is independently encrypted regardless. Native in-relay TLS
is a planned follow-up.

## Access tokens

Short-lived, stateless HMAC-SHA256 tokens (same pattern as `authorize_tunnel`
bind tokens, plus an expiry). The manager mints them with a shared 64-hex
`token_secret`; the relay validates statelessly (no DB):

```
token  = "{exp}.{hex_hmac}"
hmac   = HMAC-SHA256(secret_bytes, "{scope}:{stream}:{exp}")
scope  ∈ { "viewer", "ingest" }
```

- `require_ingest_token` (default **true**) gates the write surfaces (WHIP + origin PUT).
- `require_viewer_token` (default false → public streams) gates WHEP.
- Viewers pass the token as `?token=…` (player reads it) or `Authorization: Bearer`.

## Scaling beyond one relay

A single relay handles roughly **hundreds to low-thousands** of concurrent WHEP
viewers per ~3 Mbps stream before NIC bandwidth or per-viewer SRTP CPU saturates
(order-of-magnitude — run a load test before committing capacity). Past that:

- **WHEP**: cascade origin-relay → regional-relay SFUs (reuses the manager's
  existing ordered primary/backup relay topology; see `distribution` cascade).
- **LL-HLS**: front the origin with any CDN — it inherits HTTP caching and scales
  to millions with zero per-viewer state.

There is **no** "no extra infrastructure at scale" free lunch — high viewer
counts need either a relay cascade (WHEP) or a CDN (LL-HLS).

### Cascade (roadmap)

A WHEP cascade adds regional edge-relays that **pull** a stream from an upstream
origin-relay and re-fan-out locally. The design reuses what's already here:

- A downstream relay runs a **WHEP client** (the vendored `WebrtcSession` in the
  `false`/non-ICE-Lite role) that connects to the upstream relay's
  `/whep/{stream}`, receives media, and republishes it to its own
  [`hub::DistributionHub`] — i.e. the downstream relay is "just another viewer"
  of the upstream, then an SFU to its own viewers.
- The manager assigns viewers to the **nearest** relay, reusing the ordered
  primary/backup relay topology (`tunnels` relay list) and the relay registry /
  health advertising already used for tunnel relay selection.

**Blocker to clear first**: the vendored `webrtc/session.rs` `add_h264`
workaround reuses payload type **111** as an H.264 RTX slot, which collides with
Opus (PT 111) when a *client* builds an offer **with audio** (str0m panics "Pt
locked multiple times: 111"). The server role (`accept_offer`, used by WHEP +
WHIP-in) is unaffected. Before shipping cascade, add a client-only session
constructor that either passes `None` for the RTX PT or picks RTX PTs outside
str0m 0.19's default map. (Same latent issue exists in bilbycast-edge's WHEP
*input*, which is video-first today.)

### Late-join & keyframes

The relay caches the last IDR access unit per stream (`hub.rs`), so a
late-joining viewer is primed immediately — this covers the common case
**without** any upstream signalling. An optional enhancement forwards a viewer
PLI to the WHIP-ingest source (the edge encoder) over an RTCP feedback channel
to force an on-demand IDR; it is not required given the cache and is a follow-up.

### Broadcast quality gates

The relay's fan-out is **passthrough** — it depacketizes and re-packetizes the
same H.264 + Opus elementary streams with **no transcode, no PCR regeneration,
no A/V remux**. The broadcast quality gates (wallclock rate, decode round-trip,
A/V drift, PCR_AC) therefore apply to the **edge's** WHIP-client output (which
does the AAC→Opus / HEVC→H.264 transcode and is already gated on ship), not to
the relay. No new gate runs are required for the relay's passthrough SFU.

## Configuration

Add a `distribution` block to the relay config (see
`../../testbed/configs/relay-distribution.json`):

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
    "origin_window_segments": 8
  }
}
```

- `public_ip` is advertised as the ICE host candidate in every WHEP answer — set
  it to the relay's reachable IP or viewers off the relay's host/LAN can't
  connect the media socket.
- `token_secret` must be the **same** 64-hex value the manager holds so its
  minted tokens validate.

A config block present on a plain (feature-off) build parses fine and is logged
as ignored at startup.

## Module layout (`src/distribution/`)

| File | Responsibility |
|------|----------------|
| `mod.rs` | Subsystem assembly, axum router, per-IP viewer cap + session reaper, `run_distribution` |
| `hub.rs` | Per-stream fan-out (`tokio::broadcast`) + lock-free keyframe cache |
| `es.rs` | Elementary-frame types + Annex-B NAL splitter |
| `whep.rs` | Per-viewer WHEP session + send loop (packetize → SRTP) |
| `whip_ingest.rs` | WHIP-in: terminate DTLS/SRTP, depacketize → access units → hub |
| `ingest.rs` | QUIC ES ingest (future lower-overhead edge path) |
| `origin.rs` | LL-HLS/CMAF HTTP origin + sliding-window cache |
| `token.rs` | Short-lived HMAC token mint/verify (viewer + ingest scopes) |
| `webrtc/` | Vendored str0m session wrapper + RFC 6184 H.264 packetizer |
| `player.html` | Built-in browser WHEP player |

## Testing

`cargo test --features viewer-distribution` runs unit tests plus
`tests/distribution.rs`, which includes **real-network** end-to-end coverage:

- **QUIC ES ingest** → hub → subscriber (`ingest_over_quic_delivers_frames_to_hub`).
- **WHEP** viewer completing ICE + DTLS + SRTP and receiving decrypted media
  from the hub (`whep_viewer_receives_encrypted_media_end_to_end`).
- **WHIP-in → hub**: a str0m WHIP client pushing H.264 over DTLS/SRTP, the relay
  depacketizing + reassembling access units
  (`whip_ingest_depacketizes_h264_into_hub`).
- Token scope/expiry, origin sliding window, per-IP cap, ingest gating.

Browser interop, cellular-hardware end-to-end, and multi-relay cascade at scale
remain to be verified on real infrastructure.
