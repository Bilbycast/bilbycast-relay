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
| `GET` | `/watch/{stream}` | Built-in minimal `<video>` + WHEP player page (live only) |
| `GET` | `/dvr/{stream}` | Browser DVR player: live, 60-min scrub-back, frame jog, shuttle |
| `GET` | `/dvr/hls.js` | Vendored hls.js, served to the DVR page |
| `PUT` | `/origin/{stream}/{file}` | Edge CMAF/HLS upload (`.m3u8`/`.mpd`/`.m4s`) |
| `GET` | `/origin/{stream}/{file}` | Serve a cached segment/manifest (CDN or player) |
| `GET` | `/distribution/health` | Liveness |

**The signaling + origin listener is plain HTTP.** Browsers require a secure
context, so front it with a TLS-terminating reverse proxy / load balancer (the
`behind_proxy` pattern) presenting a CA cert on `public_base_url`'s hostname. The
DTLS/SRTP media path is independently encrypted regardless. Native in-relay TLS
is a planned follow-up.

### Media source pin

The relay runs the **ICE-Lite server** role for WHEP viewers and WHIP ingest,
and neither str0m nor its ICE agent implements RFC 7675 consent freshness, so
once a session's DTLS handshake completes the relay **pins that session's media
ingress to the DTLS peer's IP** (`PeerPin`,
`src/distribution/webrtc/session.rs`). A datagram arriving from any other IP is
dropped before str0m sees it. This is the anti-reflection control: without it a
spoofed ICE binding can steer a session's SRTP fan-out at an unrelated victim.
Everything *before* `Connected` stays open — ICE and DTLS have to run from an
address nobody has learned yet.

The pin is on the IP only, so an ordinary NAT **port** rebind still passes. The
operational consequence worth knowing: **a viewer whose public IP changes
mid-session goes black** — a Wi-Fi → cellular handover, a CGNAT pool rotation —
and recovers only by re-POSTing its WHEP offer, which mints a new session. That
is not a relay fault and there is no per-session override. Mid-session IP
migration barely worked here before the pin either; making it *safe* rather than
merely absent needs a return-routability check (RFC 7675 consent, or a full
non-lite agent) that neither str0m nor its ICE agent implements today.

The first such drop in a WHEP session raises the warning event
`webrtc_offpath_source` and increments
`bilbycast_relay_distribution_offpath_sessions` — once per session, never per
datagram, so a reflection flood cannot amplify its own alarm.

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
- `require_origin_token` (default false) gates `GET /origin/{stream}/{file}` —
  the CMAF / LL-HLS tier — with the same `viewer`-scope credential.
- Viewers pass the token as `?token=…` or `Authorization: Bearer`. The built-in
  player reads `?token=` off the `/watch/{stream}` URL and forwards it as a
  Bearer header; `/whep` accepts the query form directly too, as a convenience
  for CLI and link-share clients.

### What `require_viewer_token` does *not* cover

**It gates WHEP only.** By default `GET /origin/{stream}/{file}` — the CMAF /
LL-HLS tier — performs no token check, deliberately: it is the CDN-facing half
of the surface and a CDN pulls it with no credential of the relay's. So with
that default, for any stream that also runs the LL-HLS tier, the viewer gate is
bypassable by fetching `/origin/{stream}/index.m3u8` directly. Do not read
"viewer token required" as "this stream is not readable without a credential".

Set **`require_origin_token`** to close it. It is off by default to preserve
the CDN case and is meant to be turned on per session, by the manager, for a
gated audience with no CDN in front. It accepts the same credential in either
form — `Authorization: Bearer` or `?token=` — because a segment fetch from
hls.js can set a header but the first manifest fetch on native HLS cannot. The
check runs before the store is consulted, so a rejected request cannot be used
to probe which streams or segments exist. Restricting the listener at the
network / reverse-proxy layer remains the option when no per-stream credential
is wanted at all.

#### One token covers a source and its renditions

A DVR viewer is watching one thing, but it is delivered as a *pair* —
`{stream}` for playback and `{stream}-proxy` for shuttle — at two encodings of
the same content. So a `viewer` token minted for a source also admits that
source's derived renditions, and the player takes a single `?token=`.

This is not incidental. Scoping a token to one exact name meant the main
rendition played while the first shuttle silently buffered nothing: the
proxy's fetches 403'd while `video.error` stayed `null`, so it read as a
broken transport rather than an auth failure.

The widening is **one-directional and closed**:

- A token for `show` admits `show` and `show-proxy`.
- A token for `show-proxy` admits **only** `show-proxy` — handing someone the
  low-resolution rendition does not hand them the full-resolution one.
- The suffix list (`RENDITION_SUFFIXES`, currently just `-proxy`) is a named,
  enumerable list, not open-ended prefix matching. `showx-proxy` and
  `other-proxy` are not reachable with a `show` token.
- **Ingest tokens are not widened at all.** Ingest is a write surface, and a
  token to publish a source must not also grant publishing its rendition,
  which is a different producer.
- Expiry is checked on both paths, so the fallback is not a way around it.

The consequence to be aware of: an unrelated stream *named* `show-proxy` is
readable with a `show` token. Rendition names are derived by convention, so
that is a naming choice rather than an accident — but it is why the suffix
list is closed and why the widening lives in `verify_viewer_token` alone
rather than being spread across callers.

### Risk of the URL-borne form

`?token=` is a bearer credential in a URL, and the signaling listener is plain
HTTP by design (see above) — fronted by a TLS-terminating proxy whose **default
access-log format records the full request line, query included** (nginx
`$request`, Apache `%r`, HAProxy, ALB, CloudFront). Viewer tokens are stateless
with **no revocation path**, and the manager's default TTL is **6 hours**. A
token lifted from a proxy log or from browser history is therefore replayable
against a live feed for up to that long. Mint short `ttl_secs` when handing out
query-form links, prefer the `Authorization: Bearer` form for programmatic
clients, and strip `token` from the query in your proxy's log format if you can.

## Browser DVR player (`/dvr/{stream}`)

A second player surface, distinct from `/watch`. Where `/watch` is WHEP —
sub-second but live-only, with no buffer, no seekable range and no
`playbackRate` — `/dvr` plays the LL-HLS origin and can therefore seek back
across the whole advertised window and step individual frames.

It expects **two renditions** of the same source:

| Rendition | Origin path | Encoding | Used for |
|---|---|---|---|
| main | `{stream}` | long-GOP | live, 1x, 0.25–4x forward, frame jog, and the still after a scrub |
| proxy | `{stream}-proxy` | low-res **all-intra** | shuttle, reverse, and the picture *while* a scrub thumb is held |
| thumbnails | `thumbs-*.jpg` + `thumbs.vtt` | sprite sheets | the preview under the thumb while dragging |

That split has moved twice on measurement and is worth reading as measured
rather than as designed — see **Which rendition does what, and why** below.

Override either with `?main=` / `?proxy=`. Other query parameters: `?token=`
(one token covers both renditions — see above; required only when
`require_origin_token` is on) and `?fps=` (frame-step size; defaults to 25).

The player does not leave the credential in the URL. Under MSE it attaches it
with hls.js's `xhrSetup` as a Bearer header and scrubs the query parameter via
`history.replaceState` on load, so a viewer copying the address out of the bar
is not handing out their credential with it. Native HLS (iOS Safari) hands
the URL straight to the media stack and cannot set headers, so there the query
form is kept.

### Which rendition does what, and why

**Frame jog runs on main, not the proxy.** The original design assumed long-GOP
video could not be stepped exactly. Measured against burnt-in timecode, that is
wrong — what broke stepping was seeking to frame *boundaries*, where the browser
may present either side. Seek to the midpoint of the target frame, `(i+0.5)/fps`,
and stepping is exact at full resolution.

**A held scrub runs on the proxy.** Measured on the target Android tablet with
`?selftest=1`, 50 seeks over 2 s inside the buffer:

| element | presented | rate |
|---|---|---|
| main 1920p | 13/50, 16/50, 18/50 | 6.1–8.5 fps |
| proxy 360p | 39/50, 40/50, 41/50 | 18.4–19.3 fps |

A drag on the main rendition there presents about one frame in four. **The same
test on a desktop shows no difference whatsoever (23.5 vs 23.5 fps)** — so this
is a property of the device, and a workstation measurement will tell you the
opposite of the truth. Releasing hands the still back to main, because a stopped
scrub is someone examining the frame they landed on.

**Neither rendition helps outside the buffer.** 40 seeks over 2 s on spans
neither element had visited: 0–1 frames presented, for *both*, at LAN speed, at
25 Mbit/s and at 8 Mbit/s alike. The cost there is the segment fetch, not the
decode — 2.0 MB per 2 s main segment against 656 KB for the proxy. That is what
the thumbnail track is for.

**Why the proxy is all-intra.** Frame-exact seeking works in a plain `<video>`
only when every frame is a random-access point. Encode it with `gop_size: 1` on
the edge's CMAF output. **NVENC cannot do this** — it refuses `gop_size: 1`
outright — so use `x264` for the proxy on NVENC hosts rather than `h264_auto`
(bilbycast-edge#125).

**Reverse playback** is a `requestAnimationFrame` loop stepping `currentTime`,
because negative `playbackRate` is unimplemented in every browser. The seek
rate stays at roughly the frame rate regardless of shuttle speed — at 8x the
player presents every 8th frame — which is what keeps it affordable on a
tablet.

### The scrub bar

**The bar spans the playlist window, not `video.seekable`.** They are different
and the gap grows: measured against a live 300 s window, the playlist summed to
exactly 300 s of `EXTINF` while `main.seekable` read `0.0–504.0`. MSE keeps
extending its seekable range as segments are appended while the server-side
window slides. Calibrated on `seekable`, the bar offered positions before the
oldest segment and after the live edge — around 40 % of it was footage the
origin had evicted and 30 % footage that had not happened, both showing nothing.
The window comes from hls.js (`fragments[0].start` + `totalduration`), falling
back to `seekable` for native HLS, which exposes no playlist.

**The lit part of the bar is `main.buffered`** — where a drag moves the real
picture with no fetch. It is capped by `backBufferLength`, so on a long window
it is a small fraction of the bar and *shrinks* as a proportion the longer a
session runs. Everything outside it is served by the thumbnail preview.

### How much of the window the bar shows (`VIEW`)

A whole-event window is hours long, so a 1000-step bar is seconds per step and a
cue point cannot be found by dragging at all. `VIEW` sets the span the bar
covers — `ALL`, 30m, 10m, 2m, 30s — trading reach for granularity. Measured on
the live feed: **30 s across the bar is 0.028 s per step**, comfortably under a
frame, against 0.33 s per step on a 5-minute window and ~9 s on a 2h30m one.

Two properties that decide whether it feels right:

* **The view is pinned while the thumb is held.** A view that re-centres on the
  playhead mid-drag slides the bar under the finger and snaps the thumb back to
  the middle — the operator drags, the picture moves, and the thumb ends up
  where it started. It is pinned on pointerdown and released on pointerup, after
  which it follows the playhead again. Verified: dragging to steps 200/400/600/
  800 reads back exactly those, with the clock advancing 6.00 s per 200 steps.
* **`viewRange()` is what the bar covers; `range(main)` is what exists.**
  Everything about live — how far behind, the badge, whether to snap — reads the
  whole window. Measured against the view instead, zooming in would report the
  viewer as closer to live than they are, which is a number an operator acts on.

A preset wider than the window collapses to the window, so `30m` on a
five-minute window is simply `ALL`.

**Reaching past the visible span.** Held in the outer eighth of the bar, the
view scrolls that way — the thumb stays put and the window moves under it. Its
own frame loop drives this rather than the `input` event, because a thumb held
still at the edge fires no further events and an implementation driven by
movement scrolls one step and stalls. The pan is clamped to the window so the
far ends stay reachable.

**The ruler.** Marks along the bar sit at round clock times, which does two
jobs: their spacing says how far the bar is zoomed without reading the buttons,
and because each is pinned to an absolute moment they drift left on their own as
the view follows the playhead. That motion is the passage of time, not an
animation over it — and it stops when the transport stops, which is also true.

At least three labelled marks are guaranteed at every zoom; a ruler showing one
time is a caption. The label interval is the largest round step that still gives
three, and minor marks subdivide it by a factor that always divides cleanly, so
a minor never lands beside a labelled one. Measured: 5 labels at `ALL` on a
five-minute window, 4 at `2m`, 3 at `30s`.

It runs on its own frame loop — `render` is 5 Hz, fine for a readout and visibly
steppy for something in motion — and skips the DOM entirely when nothing has
moved.

**The view is clamped to a live edge that advances continuously**, not to the
playlist end. The playlist end only moves when a segment lands, so clamping to
it made the marks stand still and then leap: measured while following one label,
still for 77 of 79 frames and then a 6.649 % jump — the 2 s segment duration on
a 30 s span, exactly. The smoothed value advances at real time and is capped by
the real end, settling about one segment behind. After the fix: zero still
frames at every zoom.

Two consequences worth knowing:

* The last second or two of the window is not reachable by dragging at a narrow
  zoom. `LIVE` still goes to the edge, and the playhead sits further back than
  that anyway.
* It is used for the **view only**. "How far behind live" still reads the real
  playlist end, or the figure would lag by a segment.

At `ALL` on a window that is still *growing*, the span itself changes and the
marks compress slightly as well as drift; once the window is full and rolling
its left edge also steps by a segment, which is invisible on a whole-event
window (0.02 % of the bar) and noticeable on a very short one.

Zooming in near the playhead also tends to fill the bar with buffered media, so
at the narrow presets the whole visible span is usually instant *and*
frame-exact. That is a consequence of the back buffer's size rather than a
designed property, and it does not hold for a viewer who has just joined.

### The two readouts

**Left: the time of day the frame was ingested**, as `HH:MM:SS:FF` in the
viewer's own timezone. **Right: how far behind live.** Between them they answer
the two questions an operator asks of a DVR — "when was that?" and "how far back
am I?"

The time of day comes from `#EXT-X-PROGRAM-DATE-TIME`; there is no other clock
to use, since hls.js zeroes its timeline at whichever fragment it loaded first.
A stream published without the tag, or played through native HLS which exposes
no playlist, falls back to elapsed-since-the-window-started rather than
inventing a time.

**What it is, precisely:** the wall clock the *edge* stamped when it closed that
segment. Two consequences worth knowing before trusting it as a house clock:

* **It lags true capture** by the ingest path — SRT latency, decode, encode,
  segmentation. Fixed for a given deployment, but not zero.
* **It is not frame-exact.** Measured on the live feed, consecutive segments
  arrive 2000.1 ms apart with a 6.6 ms standard deviation and an 18 ms worst
  case, against a 40 ms frame; and the displayed clock tracked real time to
  13 ms over a 20 s interval. So the frame field is right or one out, not
  arbitrary — but it is derived, not carried.

**A source carrying SMPTE 12M timecode would be authoritative** and frame-exact,
and the edge already decodes `pic_timing` SEI
(`engine::content_analysis::timecode`). The feed tested here emits `pic_timing`
on every frame but with 4-byte payloads and no clock timestamp, so there was
nothing to read. Worth revisiting for a plant that does embed it.

Note the right-hand figure is distance from the **playlist's** live edge, which
is itself behind real time by roughly a segment plus upload. So the time of day
at the live edge reads further back than the "behind live" figure suggests, and
both are correct.

### Scrub preview (thumbnail track)

Sprite sheets plus a WebVTT index, published by the edge beside the media
(bilbycast-edge#124). One sheet is about the size of one media segment and
covers a hundred positions, where seeking for a real frame costs a segment fetch
each time.

**Cue times are offsets from a UTC epoch declared in the index's own header**,
because the player and the generator share no other clock — hls.js zeroes its
timeline at whichever fragment it happened to load first, so a cue looked up by
`currentTime` would show a plausible frame from the wrong moment, differently
for every viewer. The player maps position → wall clock via
`#EXT-X-PROGRAM-DATE-TIME` on the playlist → offset from that epoch.

Two things the player must do, both of which were silently wrong first:

* **Fetch sheets with the credential.** A CSS `background-image` cannot carry an
  `Authorization` header, so a style pointed at the sheet URL 401s and paints
  the box's own background colour — every DOM assertion passing while the
  operator sees a black rectangle. Sheets go through `fetch` and the style gets
  a blob URL.
* **Refetch the index.** It is a rolling window like the playlist; fetched once
  and kept, it drifts out from under the bar and every position resolves outside
  its span.

### Self-test (`?selftest=1`)

The player carries its own measurement, because the question "what can this
device present?" cannot be answered from a workstation — and on this project the
workstation's answer was the opposite of the tablet's. It runs on a tap and
prints plainly enough to photograph: shuttle rate main vs proxy, scrub preview
coverage across the bar, the real drag path (including which element the picture
ended up on), and a token renewal.

The instrument is `requestVideoFrameCallback` — frames actually put on screen —
not `droppedVideoFrames`, which counts only what was discarded and reads clean
while the picture is frozen.

**Retention must exceed the window the edge advertises.** The playlist is a
sliding window; if `origin_retention_secs` is shorter than the edge's
`dvr_window_secs`, the manifest lists segments the origin has already evicted
and a viewer seeking to the back of the window gets 404s.

**Restart the edge whenever you restart the relay.** The origin is wiped on
relay startup, but the manifest addressing it is produced by the *edge* and
survives — so the playlist and the thumbnail index go on naming objects that
have been deleted, until the window rolls over. At a 5-minute window that heals
in 5 minutes; at the 2h30m window a whole-event DVR wants, it takes 2h30m, and
the scrub bar looks broken throughout with nothing to say why. Tracked as #6.

**Sizing a whole-event window.** The window costs relay disk, not device
memory — a viewer holds only `backBufferLength`, whatever the window. Measured
on live 1080p: main ~8 Mbit/s (2.0 MB per 2 s segment), proxy ~2.6 Mbit/s
(656 KB), sprite sheets negligible. A 2h30m event is therefore roughly **12 GB
per session**, and `origin_max_bytes_per_stream` must be raised to match or the
window silently truncates into the 404 case above. At 2 s segments that window
is also a ~4500-entry playlist, around 200 KB, refetched and reparsed by every
viewer on each reload.

hls.js is **vendored** and served from `/dvr/hls.js` rather than a CDN: relays
are often deployed where viewers have no route to the public internet, and
Android Chrome has no native HLS, so the page cannot function without it. See
`src/distribution/vendor/README.md`.

## Observability

`GET /metrics` on the REST listener (`:4480`, Bearer-gated when `api_token` is
set) exposes five distribution series. They are emitted only once the subsystem
has published a sample, so a plain forwarder build — or a relay with
distribution disabled — exposes none of them, and a dashboard should treat their
absence as "not running", not as zero.

| Metric | Type | Meaning |
|---|---|---|
| `bilbycast_relay_distribution_streams` | gauge | Streams currently published to the hub |
| `bilbycast_relay_distribution_viewers` | gauge | Connected WHEP viewers across all streams |
| `bilbycast_relay_distribution_bytes_out_total` | counter | Media bytes fanned out to viewers |
| `bilbycast_relay_distribution_origin_bytes` | gauge | Bytes currently held in the LL-HLS origin cache |
| `bilbycast_relay_distribution_offpath_sessions` | counter | WHEP sessions that had a datagram refused by the media source pin — a spoofed ICE reflection attempt, or a viewer whose IP changed mid-session. Counted once per session |

The same figures ride to the manager on the health payload's `distribution`
object, and the per-stream `StreamSnapshot` carries `offpath_sessions` too. A
relay is headless: `offpath_sessions` has no other local channel, and it is the
counter to look at first when a viewer reports going black.

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

### Cascade

A WHEP cascade adds regional relays that **pull** a stream from an upstream
origin-relay and re-fan-out locally — an origin feeds N regionals, each serving
nearby viewers. **Implemented** (`src/distribution/cascade.rs`):

- A downstream relay runs a **WHEP client** (the vendored `WebrtcSession` in the
  non-ICE-Lite role) that POSTs an SDP offer to the upstream relay's
  `/whep/{stream}`, completes ICE/DTLS/SRTP, receives media, and republishes it
  to its own [`hub::DistributionHub`] under a local stream name — the downstream
  relay is "just another viewer" of the upstream, then an SFU to its own viewers.
  Its own viewers, LL-HLS origin, and keyframe cache all work unchanged. It
  reconnects automatically if the upstream stream isn't live yet.
- Configure per source in the `distribution.cascade_sources` list:

  ```json
  "cascade_sources": [
    { "upstream_whep_url": "http://origin-relay:4485/whep/big-game",
      "local_stream": "big-game",
      "token": "<upstream viewer token, if the origin is gated>" }
  ]
  ```

  Relay-to-relay signalling uses plain `http://` on a trusted network in v1.

**Nearest-relay assignment** (which regional relay a given viewer connects to)
is manager orchestration — today the operator points viewers at the nearest
relay's `/watch/{stream}` (reusing the same relay-selection the manager already
does for tunnels). Automatic geo/latency-based viewer assignment is a follow-up
(it needs real multi-region relays + latency data to tune).

*(Historical note: the cascade WHEP-client offering audio previously tripped a
str0m PT-collision — the `add_h264` workaround reused PT 111, which is Opus's
default. Fixed in `webrtc/session.rs` by dropping the RTX slot on that one
H.264 profile; the workaround is now safe on both the server and client roles.)*

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

## Configuration — manager-managed

A `-distribution` binary **starts the subsystem by default** (opt out with
`distribution.enabled: false`) and comes up **idle + secure** (no streams, ingest
closed) until configured. In a managed deployment you don't hand-edit
`config.json` at all: from the manager's relay detail page, the **Configure
distribution** panel pushes the public IP/URL, auth gates, and cascade sources
(and the shared token secret) over the WS `configure_distribution` command. The
relay applies them to a live runtime cell **and persists them to `config.json`**,
so they survive a restart; the manager also re-pushes on reconnect.

The config block below is therefore only a **bootstrap** (or for standalone,
manager-less use). Ports/listeners are the only settings not runtime-changeable.
See `../../testbed/configs/relay-distribution.json`:

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
    "require_origin_token": false,
    "require_ingest_token": true,
    "max_viewers_per_ip": 256,
    "origin_window_segments": 8,
    "origin_retention_secs": 60,
    "origin_max_bytes_per_stream": 8589934592,
    "origin_storage_dir": "/var/lib/bilbycast/relay/origin"
  }
}
```

- `public_ip` is advertised as the ICE host candidate in every WHEP answer — set
  it to the relay's reachable IP or viewers off the relay's host/LAN can't
  connect the media socket.
- `token_secret` must be the **same** 64-hex value the manager holds so its
  minted tokens validate.
- `origin_retention_secs` sets **DVR depth** — how far back a browser can seek.
  Size it to the window the edge advertises in its playlist **plus headroom**.
  The playlist is a sliding window, so retaining less than the edge advertises
  produces 404s on seek for anyone parked mid-window. 60 s is a live-only
  default; a scrub-back surface wants minutes to hours.
- `origin_max_bytes_per_stream` is the safety bound, not the policy. A bitrate
  spike must not fill the volume just because the retention window has not
  elapsed. Hitting it evicts oldest-first and silently shortens the DVR window,
  so size it above what the retention window is expected to cost — roughly
  `bitrate × origin_retention_secs / 8`.
- `origin_window_segments` is now a **floor**, not the window: the minimum
  number of recent segments kept whatever the other two say. It stops a stalled
  or very-low-bitrate stream having its whole window aged out from under a live
  player.
- **Retention is manager-owned at runtime, and can be set per stream.** The
  four values above are only the node's starting policy;
  `configure_distribution` carries a live replacement plus per-stream
  overrides:

  ```jsonc
  {
    "origin_policy": { "retention_secs": 3900 },          // node default
    "origin_stream_policies": {                            // per stream
      "match-feed":       { "retention_secs": 7200 },
      "match-feed-proxy": { "retention_secs": 7200 }
    }
  }
  ```

  Every field within a policy is optional, and a per-stream entry is applied
  **on top of the resulting default** — so an override naming only
  `retention_secs` still inherits the node's byte bound and floor rather than
  zeroing them. This is what makes a DVR session possible without taxing the
  whole node: a 60-minute window on one feed, minutes on everything else.

  `origin_stream_policies` **replaces** the whole override set rather than
  merging into it. A merge would leave an ended session's window in force for
  the life of the relay, holding that stream's disk with nothing on any surface
  to say why. An empty object therefore means "clear every override", and is
  honoured as such.

  Values are bounded at the command handler, and `min_segments` is floored at 1
  in the store as well. Not decoration: a `max_bytes_per_stream` below one
  segment evicts each segment as it lands, and a `min_segments` of 0 lets a
  live stream be evicted to nothing between a player's manifest fetch and its
  segment fetch. Both present as a stream that accepts PUTs, serves a manifest,
  and cannot be played.

  Health reports the result per stream on `distribution.origin_streams[]` —
  segments, bytes, idle seconds, and whether an override is in force — because
  `origin_bytes` alone says the node is full but not which stream filled it.

- `origin_storage_dir` is **wiped on startup**. Segments from a previous run are
  unaddressable anyway, because the manifests referencing them are held in
  memory and die with the process. Point it at a volume with room for
  `origin_max_bytes_per_stream` times the number of live streams; the default is
  inside the packaged unit's `ReadWritePaths`.

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
| `cascade.rs` | Relay-to-relay: WHEP-client pull from an upstream relay → local hub |
| `ingest.rs` | QUIC ES ingest (future lower-overhead edge path) |
| `origin.rs` | LL-HLS/CMAF HTTP origin; manifests in memory, segments on disk, age- and size-bounded |
| `token.rs` | Short-lived HMAC token mint/verify (viewer + ingest scopes) |
| `webrtc/` | Vendored str0m session wrapper + RFC 6184 H.264 packetizer |
| `player.html` | Built-in browser WHEP player (live only) |
| `dvr.html` | Browser DVR player — main + all-intra proxy, jog / shuttle / reverse |
| `vendor/` | Vendored browser assets (hls.js); see `vendor/README.md` |

## Testing

`cargo test --features viewer-distribution` runs unit tests plus
`tests/distribution.rs`, which includes **real-network** end-to-end coverage:

- **QUIC ES ingest** → hub → subscriber (`ingest_over_quic_delivers_frames_to_hub`).
- **WHEP** viewer completing ICE + DTLS + SRTP and receiving decrypted media
  from the hub (`whep_viewer_receives_encrypted_media_end_to_end`).
- **WHIP-in → hub**: a str0m WHIP client pushing H.264 over DTLS/SRTP, the relay
  depacketizing + reassembling access units
  (`whip_ingest_depacketizes_h264_into_hub`).
- **Cascade**: an upstream relay serving WHEP + a downstream relay pulling it
  (real HTTP signalling + real ICE/DTLS/SRTP) and republishing to its own hub
  (`cascade_pulls_upstream_whep_and_republishes`).
- WHEP client offering **audio** no longer panics (PT-111 regression guard).
- Token scope/expiry, origin sliding window, per-IP cap, ingest gating.

Browser interop, cellular-hardware end-to-end, and multi-relay cascade **at
scale** (plus automatic nearest-relay viewer assignment) remain to be verified
on real infrastructure.
