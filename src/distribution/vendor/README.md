# Vendored browser assets

## `hls.min.js`

- **Upstream**: https://github.com/video-dev/hls.js
- **Version**: 1.6.16
- **Source**: `https://cdn.jsdelivr.net/npm/hls.js@1.6.16/dist/hls.min.js`
- **Licence**: Apache-2.0 (see upstream `LICENSE`)
- **Served at**: `GET /dvr/hls.js`, via `include_str!` from
  `distribution::dvr_hls_js`.

### Why vendored rather than a CDN reference

Two reasons, both load-bearing rather than stylistic:

1. **Relays are frequently deployed where viewers have no route to the public
   internet.** A CDN `<script src>` would leave the DVR page as a blank frame
   on exactly those installs, with the failure showing up only in the
   browser console.
2. **Android Chrome has no native HLS.** Android tablets are the primary
   target for the DVR surface, so hls.js is not a progressive enhancement
   there — without it the page cannot play anything at all. A dependency that
   the product cannot function without should not be fetched from a third
   party at run time.

The WHEP player (`player.html`) needs none of this — WebRTC is native — which
is why this is the first vendored browser asset in the tree.

### Updating

Replace the file, update the version above, and re-run
`cargo test --features viewer-distribution`. The
`vendored_hls_js_is_present_and_plausible` test is a smoke check on size and
contents; it will catch a truncated download or an error page saved by
mistake, but not a functional regression. Check the upstream changelog for
breaking changes to `Hls.Events` / the config keys used in `dvr.html`
(`backBufferLength`, `maxBufferLength`, `lowLatencyMode`).
