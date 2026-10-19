// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};

/// Manager connection configuration (same pattern as bilbycast-edge).
///
/// Multi-URL client-side failover: the relay tries `urls[0]` first,
/// rotates to `urls[1]` on WS close, and so on — 1-16 entries, each
/// must start with `wss://`. 5 s backoff between attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfig {
    /// Whether manager connection is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Ordered list of manager WebSocket URLs (each `wss://`, 1-16
    /// entries). The client tries them in order and rotates on WS
    /// close with a fixed 5 s backoff.
    pub urls: Vec<String>,

    /// Accept self-signed TLS certificates from the manager.
    /// Only enable this for development/testing. Default: false.
    /// Requires `BILBYCAST_ALLOW_INSECURE=1` env var as a safety guard.
    #[serde(default)]
    pub accept_self_signed_cert: bool,

    /// SHA-256 fingerprint of the manager's TLS certificate for certificate pinning.
    /// Format: hex-encoded with colons, e.g. "ab:cd:ef:01:23:...".
    /// When set, connections to servers with different certificates are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,

    /// One-time registration token (used on first connect, cleared after).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,

    /// Persistent node ID (assigned by manager during registration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// Persistent node secret (assigned by manager during registration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_secret: Option<String>,
}

/// Relay server configuration.
///
/// The relay is stateless and requires no authentication configuration.
/// It simply pairs edges by tunnel ID and forwards encrypted traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// QUIC listen address (e.g., "0.0.0.0:4433"). Legacy single-address
    /// field. Ignored on bind when [`quic_addrs`] is set; kept for
    /// backward compat with pre-dual-stack configs.
    #[serde(default = "default_quic_addr")]
    pub quic_addr: String,

    /// QUIC dual-stack listener addresses (e.g.
    /// `["0.0.0.0:4433", "[::]:4433"]`). When set, the relay binds one
    /// UDP socket per entry — v6 entries get `IPV6_V6ONLY=1` so they
    /// coexist with v4 listeners on the same port. Unset = fall back to
    /// `[quic_addr]`. Defaults are dual-stack on a fresh install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_addrs: Option<Vec<String>>,

    /// Publicly-reachable QUIC address that remote edges should dial.
    /// Distinct from the bind list above: a relay typically binds on
    /// `0.0.0.0` / `[::]` (any-interface) but lives behind a NAT,
    /// load-balancer, or cloud-instance public-IP mapping — the
    /// listen address is not what edges connect to. When set, this
    /// value is advertised in the relay's health payload and surfaces
    /// in the manager's tunnel-creation dropdown.
    ///
    /// Format: `host:port` where host is an IPv4 / IPv6 literal or a
    /// DNS name (e.g. `54.1.2.3:4433` or `relay.example.com:4433`).
    /// Unspecified addresses (`0.0.0.0`, `[::]`) are rejected — those
    /// are listen-only and meaningless to a remote dialer.
    ///
    /// When unset, the relay falls back to advertising `quic_addr`,
    /// which is fine only when relay + edges share a host / LAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_quic_addr: Option<String>,

    /// Enable the plain-UDP relay data plane (native SRT/RIST over relay,
    /// no QUIC). On by default — it only binds a UDP port and pairs edges
    /// by session UUID, exactly like the QUIC path but without QUIC's
    /// per-packet overhead or its congestion control fighting SRT/RIST ARQ.
    /// Set `false` to opt out (e.g. on a relay that should only carry QUIC
    /// tunnels). Bind failures are non-fatal: the relay logs and continues
    /// without the native plane (and stops advertising the `udp-relay`
    /// capability), so an upgrade never bricks a relay over a busy port.
    #[serde(default = "default_true")]
    pub udp_relay_enabled: bool,

    /// Plain-UDP relay dual-stack listener addresses (e.g.
    /// `["0.0.0.0:4434", "[::]:4434"]`). Same semantics as [`quic_addrs`]
    /// (one socket per entry, v6 entries get `IPV6_V6ONLY=1`). Unset =
    /// the dual-stack `:4434` default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_relay_addrs: Option<Vec<String>>,

    /// Publicly-reachable plain-UDP relay address remote edges dial for the
    /// native SRT/RIST path. Same role + rules as [`public_quic_addr`] but
    /// for the UDP plane; advertised in health and surfaced in the manager's
    /// native-relay tunnel-creation dropdown. Unspecified addresses are
    /// rejected (listen-only). When unset, the manager falls back to
    /// `public_quic_addr`'s host with the UDP port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_udp_addr: Option<String>,

    /// REST API listen address (e.g., "0.0.0.0:4480"). Legacy single-
    /// address field. Ignored on bind when [`api_addrs`] is set.
    #[serde(default = "default_api_addr")]
    pub api_addr: String,

    /// REST API dual-stack listener addresses. Same semantics as
    /// [`quic_addrs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_addrs: Option<Vec<String>>,

    /// Optional path to TLS certificate (PEM). If absent, self-signed cert is generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,

    /// Optional path to TLS private key (PEM). If absent, self-signed cert is generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,

    /// Optional Bearer token for REST API authentication.
    /// If set, all API endpoints (except /health) require `Authorization: Bearer <token>`.
    /// Must be 32-128 characters. If absent, the API is open (backwards compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,

    /// Require a pre-registered bind authorization for every tunnel bind.
    ///
    /// When `false` (default, backwards compatible), tunnels without a
    /// matching `authorize_tunnel` entry accept unauthenticated binds —
    /// useful for deployments mixing relays with old managers that don't
    /// send `authorize_tunnel`, or for standalone testing.
    ///
    /// When `true`, every bind must present a `bind_token` that matches
    /// a token pre-registered by the manager; unauthorized binds are
    /// rejected with `TunnelDown { reason: "bind authentication failed" }`.
    /// Recommended for production deployments managed exclusively by a
    /// modern bilbycast-manager.
    #[serde(default)]
    pub require_bind_auth: bool,

    /// Maximum simultaneous QUIC connections from a single source IP.
    /// Defaults to 64 — well above any realistic legitimate workload
    /// (a single edge typically holds ≤4 connections per relay) and
    /// catches the connection-flood DoS pattern from a misbehaving
    /// or compromised host. New connections from an IP at or above
    /// this cap are dropped at handshake.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,

    /// Maximum tunnel binds a single QUIC connection may establish.
    /// Defaults to 100 — far above any realistic edge workload.
    /// Excess `TunnelBind` messages on the same connection are
    /// rejected with `TunnelDown { reason: "per-connection tunnel
    /// limit exceeded" }` and surface as a `relay_dos_suspect`
    /// event to the manager.
    #[serde(default = "default_max_tunnels_per_connection")]
    pub max_tunnels_per_connection: u32,

    /// Optional manager connection for centralized monitoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<ManagerConfig>,

    /// Optional structured-JSON log shipper for SIEM / NMS pickup
    /// (Splunk, Skyline DataMiner, generic JSON-line ingesters). Mirrors
    /// the same envelope shape the edge ships, so a single SIEM pipeline
    /// can ingest events from edge + relay + manager unchanged. See
    /// [`LoggingConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingConfig>,

    /// Optional viewer-distribution subsystem (WHEP SFU + LL-HLS origin).
    /// Only takes effect when the binary is built with the
    /// `viewer-distribution` Cargo feature; a config block present on a
    /// plain (opaque-forwarder-only) build parses fine and is logged as
    /// ignored at startup. See [`DistributionConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<DistributionConfig>,
}

/// Viewer-distribution subsystem configuration.
///
/// This turns a relay into a public "distribution" node that terminates
/// browser WHEP sessions (sub-second WebRTC) and/or serves an LL-HLS origin
/// (CDN-scalable) from media an edge ships over the distribution ingest.
/// It is a deliberately stateful, media-terminating role, isolated behind
/// the `viewer-distribution` feature so pure-forwarder relays never carry
/// any of it. Default-off even when compiled in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DistributionConfig {
    /// Master switch. Defaults to **true** so the `-distribution` binary comes
    /// up as a distribution node with no hand-editing — the manager then
    /// configures it over WS. Set `false` to opt a distribution-capable binary
    /// out of the role. (A plain forwarder build ignores this block entirely.)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Browser-facing HTTP signaling + LL-HLS origin listener addresses
    /// (dual-stack, same shape as `quic_addrs`). Default `:4485`.
    ///
    /// This is **plain HTTP** — browsers require a secure context, so front
    /// it with a TLS-terminating reverse proxy / load balancer (the
    /// `behind_proxy` pattern) that presents a CA cert on `public_base_url`'s
    /// hostname. Native in-relay TLS is a follow-up (the DTLS/SRTP media
    /// path is independently encrypted regardless).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_addrs: Option<Vec<String>>,

    /// The relay's publicly-reachable IP, advertised as the ICE host
    /// candidate in every WHEP SDP answer so browsers can reach the media
    /// socket. Required for viewers outside the relay's own host/LAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,

    /// Public base URL (e.g. `https://relay.example.com`) the manager uses to
    /// build shareable viewer links (`{base}/watch/{stream}`). Informational
    /// on the relay; surfaced to the manager via health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,

    /// The viewer portal's URL. Two jobs, and the second one is easy to miss.
    ///
    /// 1. Offered to a viewer whose token has expired. Without it the player
    ///    can only say that access ended, because a viewer who arrived from
    ///    the portal has a dead token in their URL and reloading re-presents
    ///    it.
    /// 2. **It also gates token renewal.** The player's `scheduleRenewal()`
    ///    returns immediately when the substituted `PORTAL_URL` is empty
    ///    (`src/distribution/dvr.html`), so leaving this blank turns the
    ///    three-hour token into a hard limit however `player_origins` is
    ///    configured — silently, with nothing reported at either end.
    ///
    /// Set here or pushed by the manager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal_url: Option<String>,

    /// Distribution ingest (edge → relay) QUIC listener addresses. The edge
    /// ships browser-ready H.264+Opus elementary frames here. Default
    /// `:4486`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_addrs: Option<Vec<String>>,

    /// Shared HMAC-SHA256 secret (64 hex chars) the manager also gives the
    /// edge + viewers, used to validate short-lived ingest / viewer tokens.
    /// When unset, token checks are disabled (P0 / dev).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret: Option<String>,

    /// Require a valid signed viewer token on every WHEP request. Default
    /// false (public streams). Set true for token-gated distribution.
    #[serde(default)]
    pub require_viewer_token: bool,

    /// Require a valid signed viewer token on `GET /origin/{stream}/{file}`
    /// too — the CMAF / LL-HLS tier, not just WHEP. Default **false**, which
    /// is what makes the origin usable by a CDN: a CDN pulls with no
    /// credential of the relay's, and that is the point of having an HTTP
    /// origin at all.
    ///
    /// Turning it on closes a gap worth stating plainly: with it off, a
    /// `require_viewer_token` WHEP gate is bypassable on any stream that also
    /// runs the CMAF tier, by fetching `/origin/{stream}/index.m3u8`
    /// directly. Turn it on per session when the audience is gated and no CDN
    /// sits in front.
    #[serde(default)]
    pub require_origin_token: bool,

    /// Require a valid signed ingest token on every edge → relay ingest
    /// connection. Default true — the ingest is a write surface.
    #[serde(default = "default_true")]
    pub require_ingest_token: bool,

    /// Per-source-IP concurrent WHEP viewer cap (DoS mitigation on the
    /// public endpoint). Default 256.
    #[serde(default = "default_max_viewers_per_ip")]
    pub max_viewers_per_ip: u32,

    /// LL-HLS origin retention floor: the minimum number of recent media
    /// segments kept per stream, whatever `origin_retention_secs` and
    /// `origin_max_bytes_per_stream` say. Default 8.
    ///
    /// Since the origin became disk-backed this is a **floor**, not the
    /// policy — time is the policy. It stops a stalled or very-low-bitrate
    /// stream having its whole window aged out from under a live player.
    #[serde(default = "default_origin_window_segments")]
    pub origin_window_segments: usize,

    /// LL-HLS origin retention: how long a media segment is kept, in seconds.
    /// Default 60.
    ///
    /// This is the knob that sets DVR depth. Size it to the window the edge
    /// advertises in its playlist **plus headroom** — the playlist is a
    /// sliding window, so a viewer parked mid-window must not have the segment
    /// under them deleted. Retaining less than the edge advertises produces
    /// 404s on seek, which is the failure this pairing exists to prevent.
    #[serde(default = "default_origin_retention_secs")]
    pub origin_retention_secs: u64,

    /// LL-HLS origin safety bound: maximum bytes of media segments held per
    /// stream. Default 8 GiB.
    ///
    /// A bitrate spike must not fill the volume just because
    /// `origin_retention_secs` has not elapsed. Total disk is roughly this
    /// times the number of live streams; hitting it evicts oldest-first and
    /// silently shortens the DVR window, so size it above what the retention
    /// window is expected to cost.
    #[serde(default = "default_origin_max_bytes_per_stream")]
    pub origin_max_bytes_per_stream: u64,

    /// How long past `origin_retention_secs` a stream may sit without a PUT
    /// before it is reclaimed outright — segments, manifest, init and
    /// directory. Default 60.
    ///
    /// Here as well as on the pushed policy because it is one of the four
    /// node-wide storage knobs, and the only one that used to have nowhere to
    /// land: the manager could push it and the relay applied it, but
    /// `persist_distribution_config` had no field to write it back to, so it
    /// silently returned to 60 s on the next restart while its three siblings
    /// survived.
    #[serde(default = "default_origin_idle_grace_secs")]
    pub origin_idle_grace_secs: u64,

    /// Never let the origin volume fall below this many bytes free.
    /// Default 5 GiB. Set 0 to disable.
    ///
    /// The guard of last resort. `origin_retention_secs` and
    /// `origin_max_bytes_per_stream` are pushed by the manager, which sizes
    /// them from the DVR window an operator asked for and **cannot see this
    /// relay's disk** — no node health payload reports free space. A 2h30m
    /// window on a small volume is therefore a policy the manager will happily
    /// push and this relay will happily honour, until the volume fills.
    ///
    /// On the demo rig it did, and took the manager's Postgres down with it.
    /// The relay owns the disk, so the relay is the one that has to refuse.
    ///
    /// Bounded in `DistributionConfig::validate`: `0`, or 16 MiB to 1 TiB.
    /// A value outside that is fatal at startup rather than clamped — see the
    /// unit slips it catches at the check itself.
    #[serde(default = "default_origin_min_free_bytes")]
    pub origin_min_free_bytes: u64,

    /// Directory the origin writes media segments under. Defaults to
    /// `/var/lib/bilbycast/relay/origin` (inside the packaged unit's
    /// `ReadWritePaths`). **Adopted** on startup, not wiped: the segments left
    /// there by a previous run are indexed back into the window, so a relay
    /// restart no longer costs the DVR depth. Everything under it is evictable
    /// either way, so give it a directory of its own — `OriginStore::new`
    /// refuses a non-empty one that carries no `.bilbycast-origin` marker and
    /// does not carry the shape of a store written before that marker existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_storage_dir: Option<String>,

    /// Cascade sources: streams this (downstream/regional) relay pulls from an
    /// upstream relay's WHEP and re-fans-out locally. Empty by default. See
    /// [`CascadeSource`]. This is how WHEP scales past one relay's ceiling —
    /// an origin relay feeds N regional relays, each serving nearby viewers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cascade_sources: Vec<CascadeSource>,
}

/// A single cascade pull: this relay acts as a WHEP client of an upstream
/// relay and republishes the stream to its own hub under `local_stream`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CascadeSource {
    /// Upstream WHEP URL, e.g. `http://origin-relay:4485/whep/big-game`.
    /// Plain `http://` (relay-to-relay on a trusted network) in v1.
    pub upstream_whep_url: String,
    /// Local stream name to republish under (what downstream viewers watch).
    pub local_stream: String,
    /// Optional viewer token for the upstream (when the upstream is gated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Default for DistributionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            http_addrs: None,
            public_ip: None,
            public_base_url: None,
            portal_url: None,
            ingest_addrs: None,
            token_secret: None,
            require_viewer_token: false,
            require_origin_token: false,
            require_ingest_token: true,
            max_viewers_per_ip: default_max_viewers_per_ip(),
            origin_idle_grace_secs: default_origin_idle_grace_secs(),
            origin_window_segments: default_origin_window_segments(),
            origin_retention_secs: default_origin_retention_secs(),
            origin_max_bytes_per_stream: default_origin_max_bytes_per_stream(),
            origin_min_free_bytes: default_origin_min_free_bytes(),
            origin_storage_dir: None,
            cascade_sources: Vec::new(),
        }
    }
}

fn default_max_viewers_per_ip() -> u32 {
    256
}

fn default_origin_window_segments() -> usize {
    8
}

fn default_origin_retention_secs() -> u64 {
    60
}

/// 5 GiB, which is room for a couple of minutes of several renditions plus
/// whatever else shares the volume — enough that the operator gets a warning
/// and a shortened window rather than a full disk.
fn default_origin_min_free_bytes() -> u64 {
    5 * 1024 * 1024 * 1024
}

fn default_origin_max_bytes_per_stream() -> u64 {
    8 * 1024 * 1024 * 1024
}

fn default_origin_idle_grace_secs() -> u64 {
    60
}

/// Default origin storage root. Under the packaged unit's data root, which is
/// already in `ReadWritePaths`.
pub fn default_origin_storage_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/lib/bilbycast/relay/origin")
}

fn default_distribution_http_addrs() -> Vec<String> {
    vec!["0.0.0.0:4485".to_string(), "[::]:4485".to_string()]
}

fn default_distribution_ingest_addrs() -> Vec<String> {
    vec!["0.0.0.0:4486".to_string(), "[::]:4486".to_string()]
}

impl DistributionConfig {
    /// Effective HTTP signaling / origin bind addresses.
    pub fn effective_http_addrs(&self) -> Vec<String> {
        match &self.http_addrs {
            Some(a) if !a.is_empty() => a.clone(),
            _ => default_distribution_http_addrs(),
        }
    }

    /// Effective distribution ingest bind addresses.
    pub fn effective_ingest_addrs(&self) -> Vec<String> {
        match &self.ingest_addrs {
            Some(a) if !a.is_empty() => a.clone(),
            _ => default_distribution_ingest_addrs(),
        }
    }

    /// Parse the configured public IP (for ICE candidates), if any.
    pub fn public_ip_parsed(&self) -> Option<std::net::IpAddr> {
        self.public_ip.as_ref().and_then(|s| s.parse().ok())
    }

    fn validate(&self) -> anyhow::Result<()> {
        if let Some(ref addrs) = self.http_addrs {
            validate_addr_list(addrs, "distribution.http_addrs")?;
        }
        if let Some(ref addrs) = self.ingest_addrs {
            validate_addr_list(addrs, "distribution.ingest_addrs")?;
        }
        if let Some(ref ip) = self.public_ip {
            ip.parse::<std::net::IpAddr>().map_err(|e| {
                anyhow::anyhow!("distribution.public_ip '{ip}' is not a valid IP: {e}")
            })?;
        }
        if let Some(ref url) = self.portal_url {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                anyhow::bail!("distribution.portal_url must start with http:// or https://");
            }
            if url.len() > 2048 {
                anyhow::bail!("distribution.portal_url too long (max 2048 chars)");
            }
        }
        if let Some(ref url) = self.public_base_url {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                anyhow::bail!("distribution.public_base_url must start with http:// or https://");
            }
            if url.len() > 2048 {
                anyhow::bail!("distribution.public_base_url too long (max 2048 chars)");
            }
        }
        if let Some(ref secret) = self.token_secret
            && (secret.len() != 64 || !secret.chars().all(|c| c.is_ascii_hexdigit())) {
                anyhow::bail!("distribution.token_secret must be exactly 64 hex chars (32 bytes)");
            }
        // NB: token gates (`require_viewer_token` / `require_ingest_token`)
        // may be on with no `token_secret` in config — the manager pushes the
        // secret at runtime via `configure_distribution`. Until it arrives the
        // gated surfaces stay closed (fail-safe), so this is not a config error.
        if self.origin_window_segments == 0 || self.origin_window_segments > 64 {
            anyhow::bail!("distribution.origin_window_segments must be in 1..=64");
        }
        // 24 h ceiling: past that the operator almost certainly wants an
        // archive, not a live origin's sliding window.
        if self.origin_retention_secs == 0 || self.origin_retention_secs > 86_400 {
            anyhow::bail!("distribution.origin_retention_secs must be in 1..=86400");
        }
        if self.origin_idle_grace_secs > 86_400 {
            anyhow::bail!("distribution.origin_idle_grace_secs must be <= 86400");
        }
        if self.origin_max_bytes_per_stream < 16 * 1024 * 1024 {
            anyhow::bail!(
                "distribution.origin_max_bytes_per_stream must be at least 16 MiB (got {})",
                self.origin_max_bytes_per_stream
            );
        }
        // The free-space floor: `0` disables it, and anything else has to be
        // large enough to actually be one. A slip like `5` (meaning 5 GiB)
        // reads as configured in the file while a floor below a single
        // segment can never be what refuses a write — the guard would be
        // silently inert, which is precisely the failure it exists to end.
        // The 16 MiB pairing is the same "at least a segment's worth" bound
        // as the per-stream byte cap above. The 1 TiB ceiling catches the
        // other unit slip: a floor no plausible origin volume can satisfy
        // makes every sweep evict every stream down to its emergency keep,
        // collapsing the DVR window to nothing while warning each pass.
        if self.origin_min_free_bytes != 0 && self.origin_min_free_bytes < 16 * 1024 * 1024 {
            anyhow::bail!(
                "distribution.origin_min_free_bytes must be 0 (disabled) or at least 16 MiB (got {})",
                self.origin_min_free_bytes
            );
        }
        if self.origin_min_free_bytes > 1024 * 1024 * 1024 * 1024 {
            anyhow::bail!(
                "distribution.origin_min_free_bytes must be at most 1 TiB (got {})",
                self.origin_min_free_bytes
            );
        }
        // Everything under `origin_storage_dir` is evictable — the idle sweep
        // `remove_dir_all`s a whole stream, and the free-space floor evicts
        // across every stream it finds — so a typo here is destructive rather
        // than merely wrong. The startup wipe these bounds were originally
        // written for is gone (the window on disk is adopted now), which makes
        // them matter more rather than less: adoption pulls whatever it finds
        // *into* the store's bookkeeping, so the recursive delete moved from
        // startup to the sweep rather than going away. These bounds reject the
        // shapes a slip actually produces — a relative path, a filesystem
        // root, a top-level directory — and `OriginStore::new` refuses to
        // adopt a non-empty directory it cannot identify as its own.
        if let Some(dir) = &self.origin_storage_dir {
            let p = std::path::Path::new(dir);
            if dir.trim().is_empty() || !p.is_absolute() {
                anyhow::bail!(
                    "distribution.origin_storage_dir must be an absolute path (got {dir:?})"
                );
            }
            if p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                anyhow::bail!("distribution.origin_storage_dir must not contain '..' ({dir:?})");
            }
            let depth = p
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .count();
            if depth < 2 {
                anyhow::bail!(
                    "distribution.origin_storage_dir must be at least two levels deep — \
                     everything under it is evictable, and {dir:?} is a system directory"
                );
            }
        }
        if self.cascade_sources.len() > 64 {
            anyhow::bail!("distribution.cascade_sources: at most 64 entries");
        }
        // Loaded anyway — refusing would stop an existing relay booting on
        // upgrade — but said, because all but one of the entries are dropped.
        for stream in duplicate_local_streams(&self.cascade_sources) {
            tracing::warn!(
                "distribution.cascade_sources: local_stream '{stream}' appears more than once; \
                 only the last entry is pulled"
            );
        }
        for (i, src) in self.cascade_sources.iter().enumerate() {
            if !(src.upstream_whep_url.starts_with("http://")
                || src.upstream_whep_url.starts_with("https://"))
            {
                anyhow::bail!(
                    "distribution.cascade_sources[{i}].upstream_whep_url must start with http:// or https://"
                );
            }
            if src.upstream_whep_url.len() > 2048 {
                anyhow::bail!("distribution.cascade_sources[{i}].upstream_whep_url too long");
            }
            let s = src.local_stream.trim();
            if s.is_empty()
                || s.len() > 128
                || !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                anyhow::bail!(
                    "distribution.cascade_sources[{i}].local_stream must be 1..=128 chars of [A-Za-z0-9._-]"
                );
            }
        }
        Ok(())
    }
}

/// Structured-JSON log shipper configuration. See the
/// [`bilbycast-edge`] equivalent — the schema is identical so a single
/// SIEM pickup config works across edge + relay + manager.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_target: Option<JsonLogTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JsonLogTarget {
    Stdout {
        #[serde(default)]
        format: LogFormat,
    },
    File {
        path: String,
        #[serde(default)]
        format: LogFormat,
        #[serde(default = "default_max_size_mb")]
        max_size_mb: u32,
        #[serde(default = "default_max_backups")]
        max_backups: u32,
    },
    Syslog {
        addr: String,
        #[serde(default)]
        format: LogFormat,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Raw,
    Splunk,
    Dataminer,
}

fn default_max_size_mb() -> u32 {
    64
}

fn default_max_backups() -> u32 {
    5
}

fn default_true() -> bool {
    true
}

fn default_udp_relay_addrs() -> Vec<String> {
    vec!["0.0.0.0:4434".to_string(), "[::]:4434".to_string()]
}

fn default_max_connections_per_ip() -> u32 {
    64
}

fn default_max_tunnels_per_connection() -> u32 {
    100
}

fn default_quic_addr() -> String {
    "0.0.0.0:4433".to_string()
}

fn default_api_addr() -> String {
    "0.0.0.0:4480".to_string()
}

impl RelayConfig {
    /// Validate the relay configuration.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate socket addresses are parseable (legacy single-addr fields).
        self.quic_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid quic_addr '{}': {}", self.quic_addr, e))?;
        self.api_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid api_addr '{}': {}", self.api_addr, e))?;

        // Validate dual-stack address lists when present. Each entry must
        // parse as a SocketAddr; the list must be non-empty and entries
        // must be unique.
        if let Some(ref addrs) = self.quic_addrs {
            validate_addr_list(addrs, "quic_addrs")?;
        }
        if let Some(ref addrs) = self.api_addrs {
            validate_addr_list(addrs, "api_addrs")?;
        }

        // Validate the advertised public QUIC address if set. Must be
        // a parseable `host:port` and must not be an unspecified /
        // listen-only address — those would be useless to a remote
        // dialer and almost certainly an operator mistake.
        if let Some(ref addr) = self.public_quic_addr {
            validate_public_addr(addr, "public_quic_addr")?;
        }

        // Validate the plain-UDP relay listener addresses + advertised
        // public UDP address (same rules as the QUIC equivalents).
        if let Some(ref addrs) = self.udp_relay_addrs {
            validate_addr_list(addrs, "udp_relay_addrs")?;
        }
        if let Some(ref addr) = self.public_udp_addr {
            validate_public_addr(addr, "public_udp_addr")?;
        }

        // Validate API token length if set
        if let Some(ref token) = self.api_token
            && (token.len() < 32 || token.len() > 128) {
                anyhow::bail!("api_token must be 32-128 characters, got {}", token.len());
            }

        // Validate manager URL list if enabled (1..16, each wss://,
        // ≤2048 chars, unique — same rules as bilbycast-edge).
        if let Some(ref mgr) = self.manager
            && mgr.enabled {
                if mgr.urls.is_empty() {
                    anyhow::bail!(
                        "Manager urls[] cannot be empty when manager is enabled"
                    );
                }
                if mgr.urls.len() > 16 {
                    anyhow::bail!(
                        "Manager urls[] may contain at most 16 entries (got {})",
                        mgr.urls.len()
                    );
                }
                let mut seen = std::collections::HashSet::new();
                for (i, url) in mgr.urls.iter().enumerate() {
                    if !url.starts_with("wss://") {
                        anyhow::bail!(
                            "Manager urls[{i}] = {url:?} must use wss:// (TLS required)"
                        );
                    }
                    if url.len() > 2048 {
                        anyhow::bail!(
                            "Manager urls[{i}] must be at most 2048 characters"
                        );
                    }
                    if !seen.insert(url.as_str()) {
                        anyhow::bail!(
                            "Manager urls[{i}] = {url:?} is a duplicate"
                        );
                    }
                }
            }

        // Validate logging shipper if present
        if let Some(ref logging) = self.logging {
            validate_logging_config(logging)?;
        }

        // Validate the viewer-distribution subsystem block if present.
        if let Some(ref dist) = self.distribution {
            dist.validate()?;
        }

        Ok(())
    }
}

/// Validate a dual-stack listener address list: non-empty, every entry
/// parses as a `SocketAddr`, no duplicates. Empty/whitespace entries
/// are silently skipped.
fn validate_addr_list(entries: &[String], field: &str) -> anyhow::Result<()> {
    let mut seen: std::collections::HashSet<std::net::SocketAddr> =
        std::collections::HashSet::new();
    for raw in entries {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let addr: std::net::SocketAddr = trimmed.parse().map_err(|e| {
            anyhow::anyhow!("{field}: invalid socket address '{trimmed}': {e}")
        })?;
        if !seen.insert(addr) {
            anyhow::bail!("{field}: duplicate bind address '{trimmed}'");
        }
    }
    if seen.is_empty() {
        anyhow::bail!("{field}: bind address list must not be empty");
    }
    Ok(())
}

/// Validate the public-facing QUIC address advertised to remote edges.
///
/// Rules:
/// - Non-empty, ≤ 256 chars.
/// - Splits into `host:port` (rsplit on `:`, accounting for `[v6]:port`).
/// - Port parses as u16 and is non-zero.
/// - Host parses as IPv4 / IPv6 literal **or** is a syntactically valid
///   DNS name (1–253 chars, label rules — letters, digits, hyphens
///   inside labels). DNS resolution is not performed here; that happens
///   on the edge at connect time.
/// - IP literals must not be unspecified (`0.0.0.0`, `[::]`) — those are
///   listen-only.
fn validate_public_addr(raw: &str, field: &str) -> anyhow::Result<()> {
    let s = raw.trim();
    if s.is_empty() {
        anyhow::bail!("{field}: must not be empty");
    }
    if s.len() > 256 {
        anyhow::bail!("{field}: too long (max 256 chars)");
    }

    // Try the strict SocketAddr path first (covers IPv4 and bracketed IPv6).
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        if sa.ip().is_unspecified() {
            anyhow::bail!(
                "{field}: '{s}' is an unspecified (listen-only) address; \
                 set this to the address remote edges should dial"
            );
        }
        if sa.port() == 0 {
            anyhow::bail!("{field}: port must be non-zero");
        }
        return Ok(());
    }

    // Otherwise expect host:port where host is a DNS name.
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("{field}: '{s}' must be host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("{field}: invalid port '{port_str}'"))?;
    if port == 0 {
        anyhow::bail!("{field}: port must be non-zero");
    }
    if host.is_empty() || host.len() > 253 {
        anyhow::bail!("{field}: host '{host}' length must be 1..=253");
    }
    let label_ok = |label: &str| -> bool {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !host.split('.').all(label_ok) {
        anyhow::bail!(
            "{field}: host '{host}' is not a valid IPv4/IPv6 literal or DNS name"
        );
    }
    Ok(())
}

/// Validate the structured-JSON log shipper configuration. Mirrors the
/// edge-side validator so a single SIEM pickup config works across the
/// projects.
pub fn validate_logging_config(logging: &LoggingConfig) -> anyhow::Result<()> {
    let Some(ref target) = logging.json_target else {
        return Ok(());
    };
    match target {
        JsonLogTarget::Stdout { .. } => Ok(()),
        JsonLogTarget::File {
            path,
            max_size_mb,
            max_backups,
            ..
        } => {
            if path.is_empty() {
                anyhow::bail!("logging.json_target file: path cannot be empty");
            }
            if path.len() > 4096 {
                anyhow::bail!("logging.json_target file: path too long (max 4096 chars)");
            }
            if path.contains('\0') {
                anyhow::bail!("logging.json_target file: path must not contain NUL bytes");
            }
            if !(1..=4096).contains(max_size_mb) {
                anyhow::bail!(
                    "logging.json_target file: max_size_mb must be in 1..=4096 (got {})",
                    max_size_mb
                );
            }
            if *max_backups > 100 {
                anyhow::bail!(
                    "logging.json_target file: max_backups must be ≤ 100 (got {})",
                    max_backups
                );
            }
            Ok(())
        }
        JsonLogTarget::Syslog { addr, .. } => addr
            .parse::<std::net::SocketAddr>()
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("logging.json_target syslog addr '{}': {}", addr, e)),
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            quic_addr: default_quic_addr(),
            // Dual-stack by default for new installs. Existing configs
            // without this field keep `quic_addr`-only behaviour.
            quic_addrs: Some(vec![
                "0.0.0.0:4433".to_string(),
                "[::]:4433".to_string(),
            ]),
            api_addr: default_api_addr(),
            api_addrs: Some(vec![
                "0.0.0.0:4480".to_string(),
                "[::]:4480".to_string(),
            ]),
            public_quic_addr: None,
            udp_relay_enabled: true,
            udp_relay_addrs: Some(default_udp_relay_addrs()),
            public_udp_addr: None,
            tls_cert_path: None,
            tls_key_path: None,
            api_token: None,
            require_bind_auth: false,
            max_connections_per_ip: default_max_connections_per_ip(),
            max_tunnels_per_connection: default_max_tunnels_per_connection(),
            manager: None,
            logging: None,
            distribution: None,
        }
    }
}

impl RelayConfig {
    /// Resolve the effective list of QUIC bind addresses. Falls back to
    /// `[quic_addr]` when [`quic_addrs`] is unset or empty.
    pub fn effective_quic_addrs(&self) -> Vec<String> {
        match &self.quic_addrs {
            Some(addrs) if !addrs.is_empty() => addrs.clone(),
            _ => vec![self.quic_addr.clone()],
        }
    }

    /// Resolve the effective list of REST API bind addresses. Falls
    /// back to `[api_addr]` when [`api_addrs`] is unset or empty.
    pub fn effective_api_addrs(&self) -> Vec<String> {
        match &self.api_addrs {
            Some(addrs) if !addrs.is_empty() => addrs.clone(),
            _ => vec![self.api_addr.clone()],
        }
    }

    /// Resolve the effective plain-UDP relay bind addresses. Falls back to
    /// the dual-stack `:4434` default when [`udp_relay_addrs`] is unset or
    /// empty. Only meaningful when [`udp_relay_enabled`] is true.
    pub fn effective_udp_relay_addrs(&self) -> Vec<String> {
        match &self.udp_relay_addrs {
            Some(addrs) if !addrs.is_empty() => addrs.clone(),
            _ => default_udp_relay_addrs(),
        }
    }

    /// Is this relay running the native plain-UDP plane in the permissive
    /// bind-auth mode?
    ///
    /// Both halves of the shipped defaults, so a zero-config relay answers
    /// `true`: `require_bind_auth` defaults to `false` and `udp_relay_enabled`
    /// defaults to `true` (`#[serde(default = "default_true")]`) — which means
    /// a config that simply omits `udp_relay_enabled` is still in this posture.
    ///
    /// It matters because the two planes' consequences differ. On QUIC an
    /// unauthenticated `TunnelBind` lets a stranger *join* a tunnel; on the
    /// native plane the rendezvous latch turns a source address into a *send*
    /// target, so an unauthenticated `Register` can *move* a slot and redirect
    /// live media to the sender. It applies only to tunnels the manager has
    /// **not** pre-authorized — `TunnelRouter::verify_bind_token` still demands
    /// the exact HMAC for any tunnel carrying an `authorize_tunnel` entry, even
    /// in permissive mode.
    pub fn native_plane_accepts_unauthenticated(&self) -> bool {
        !self.require_bind_auth && self.udp_relay_enabled
    }
}

// ───────────────────────────────────────────────────────
// Redaction for the manager's `get_config`
// ───────────────────────────────────────────────────────

/// What `get_config` puts in place of a credential the relay holds.
///
/// It replaces a credential that is set in the config `get_config` serialises,
/// and a credential that is not set there stays absent. **That config is the
/// startup snapshot**, not the live one: a `token_secret` (or cascade source)
/// first pushed by `configure_distribution` after the relay started reads as
/// absent until the next restart, when the persisted copy is loaded. So the
/// marker means "this relay started with one", and absence means only "it did
/// not start with one" — not "there is none".
///
/// The same marker on the way back in means "keep what you have"
/// (`apply_configure_distribution`), never a value: see
/// [`is_redaction_marker`].
pub const REDACTED: &str = "***REDACTED***";

/// Is `s` the redaction marker rather than a credential?
pub fn is_redaction_marker(s: &str) -> bool {
    s == REDACTED
}

fn redact(field: &mut Option<String>) {
    if field.is_some() {
        *field = Some(REDACTED.to_string());
    }
}

/// Words that make a field or query-parameter name a credential.
const CREDENTIAL_WORDS: &[&str] = &[
    "secret", "secrets", "token", "tokens", "password", "passwd", "pass", "pwd",
    "passphrase", "psk", "bearer", "auth", "authorization", "hmac", "key", "keys",
    "apikey", "credential", "credentials", "sig", "signature",
];

/// Does `name` — a config field or a URL query key — name a credential?
///
/// By whole words (split on `_`, `-` and `.`, case-insensitive), so `author` or
/// `monkey` is not one and `stream_key`, `access_token` and `hmac` are. A name
/// whose last word is `path`, `file` or `dir` (`tls_key_path`) names where a
/// credential lives, not the credential, and is not one: the relay never sends
/// what a path points at.
pub fn is_credential_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(['_', '-', '.'])
        .filter(|w| !w.is_empty())
        .collect();
    if matches!(words.last(), Some(&("path" | "file" | "dir"))) {
        return false;
    }
    words.iter().any(|w| CREDENTIAL_WORDS.contains(w))
}

/// `url` with any credential it carries replaced by [`REDACTED`]: the userinfo
/// (`user:pass@`) as a whole, and the value of every query or fragment
/// parameter whose key [`is_credential_name`] (`?token=`, `?access_token=`,
/// `#access_token=`). Everything else is left byte for byte, so two URLs that
/// differ only in their credentials redact to the same string — which is what
/// lets a push carrying a redacted URL be matched back to the one it came from.
///
/// Idempotent: a redacted URL redacts to itself.
pub fn redact_url(url: &str) -> String {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let (before_query, query) = match before_fragment.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (before_fragment, None),
    };
    let mut out = String::with_capacity(url.len());
    match before_query.find("://") {
        Some(i) => {
            let (scheme, rest) = before_query.split_at(i + 3);
            let authority_end = rest.find('/').unwrap_or(rest.len());
            let (authority, path) = rest.split_at(authority_end);
            out.push_str(scheme);
            match authority.rfind('@') {
                Some(at) => {
                    out.push_str(REDACTED);
                    out.push_str(&authority[at..]);
                }
                None => out.push_str(authority),
            }
            out.push_str(path);
        }
        None => out.push_str(before_query),
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(&redact_params(q));
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(&redact_params(f));
    }
    out
}

fn redact_params(params: &str) -> String {
    params
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) if !value.is_empty() && is_credential_name(key) => {
                format!("{key}={REDACTED}")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Does `url` hold a redacted credential, i.e. did it come from `get_config`?
pub fn url_holds_marker(url: &str) -> bool {
    url.contains(REDACTED)
}

/// Each `local_stream` that appears more than once in `sources`, once.
///
/// The cascade supervisor keys its pulls by `local_stream`, so of several
/// entries for one stream only the **last** is pulled; the others are silently
/// dropped. A push carrying one is refused; a config file carrying one is still
/// loaded (refusing it would stop a relay booting on upgrade) and warned about.
pub fn duplicate_local_streams(sources: &[CascadeSource]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut dup = Vec::new();
    for s in sources {
        if !seen.insert(s.local_stream.as_str()) && !dup.contains(&s.local_stream) {
            dup.push(s.local_stream.clone());
        }
    }
    dup
}

// Every `redact_secrets` below destructures its struct **without `..`**, so a
// field added to any of them does not compile until somebody has decided
// whether it is a credential. That is the point: the old `get_config` named
// the two secrets it knew about and passed everything else through, which is
// how `distribution.token_secret` — the key every viewer and ingest token is
// signed with — went out to anyone with View on the relay.
//
// Paths are not credentials and are left alone; what a path points at never
// leaves the relay. URLs are left alone except for a credential carried in
// one ([`redact_url`]).

impl RelayConfig {
    /// This config as the manager's `get_config` may see it: every credential
    /// in the tree replaced by [`REDACTED`], everything else as it is.
    ///
    /// Only for what leaves the relay. `config.json` is written from the
    /// config itself (`update_config_file`), which must keep the real values —
    /// a relay that persisted the marker would lock itself out on restart.
    pub fn redacted_json(&self) -> serde_json::Value {
        let mut copy = self.clone();
        copy.redact_secrets();
        serde_json::to_value(&copy).unwrap_or_default()
    }

    fn redact_secrets(&mut self) {
        let RelayConfig {
            quic_addr: _,
            quic_addrs: _,
            public_quic_addr: _,
            udp_relay_enabled: _,
            udp_relay_addrs: _,
            public_udp_addr: _,
            api_addr: _,
            api_addrs: _,
            tls_cert_path: _,
            tls_key_path: _,
            api_token,
            require_bind_auth: _,
            max_connections_per_ip: _,
            max_tunnels_per_connection: _,
            manager,
            logging,
            distribution,
        } = self;
        redact(api_token);
        if let Some(manager) = manager {
            manager.redact_secrets();
        }
        if let Some(logging) = logging {
            logging.redact_secrets();
        }
        if let Some(distribution) = distribution {
            distribution.redact_secrets();
        }
    }
}

impl ManagerConfig {
    fn redact_secrets(&mut self) {
        let ManagerConfig {
            enabled: _,
            // Validated only as `wss://`, so one can carry a userinfo or a
            // query credential for whatever fronts the manager.
            urls,
            accept_self_signed_cert: _,
            // The SHA-256 of the manager's own certificate: public.
            cert_fingerprint: _,
            registration_token,
            node_id: _,
            node_secret,
        } = self;
        for url in urls {
            *url = redact_url(url);
        }
        redact(registration_token);
        redact(node_secret);
    }
}

impl LoggingConfig {
    fn redact_secrets(&mut self) {
        let LoggingConfig { json_target } = self;
        // One arm per variant, each naming every field: a credential added to
        // any target (a token for an HTTP shipper, say) does not compile here
        // until it has been redacted or waved through on purpose.
        match json_target {
            None => {}
            Some(JsonLogTarget::Stdout { format: _ }) => {}
            Some(JsonLogTarget::File { path: _, format: _, max_size_mb: _, max_backups: _ }) => {}
            Some(JsonLogTarget::Syslog { addr: _, format: _ }) => {}
        }
    }
}

impl DistributionConfig {
    fn redact_secrets(&mut self) {
        let DistributionConfig {
            enabled: _,
            http_addrs: _,
            public_ip: _,
            public_base_url: _,
            portal_url: _,
            ingest_addrs: _,
            token_secret,
            require_viewer_token: _,
            require_origin_token: _,
            require_ingest_token: _,
            max_viewers_per_ip: _,
            origin_window_segments: _,
            origin_retention_secs: _,
            origin_max_bytes_per_stream: _,
            origin_idle_grace_secs: _,
            origin_min_free_bytes: _,
            origin_storage_dir: _,
            cascade_sources,
        } = self;
        redact(token_secret);
        for source in cascade_sources {
            source.redact_secrets();
        }
    }
}

impl CascadeSource {
    fn redact_secrets(&mut self) {
        // The upstream's WHEP endpoint takes `?token=` as well as a Bearer
        // header, so the URL can carry the same credential `token` does.
        let CascadeSource { upstream_whep_url, local_stream: _, token } = self;
        *upstream_whep_url = redact_url(upstream_whep_url);
        redact(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addr_accepts_ipv4_and_ipv6_literals_and_dns_names() {
        assert!(validate_public_addr("54.1.2.3:4433", "f").is_ok());
        assert!(validate_public_addr("[2001:db8::1]:4433", "f").is_ok());
        assert!(validate_public_addr("relay.example.com:4433", "f").is_ok());
        assert!(validate_public_addr("relay1:4433", "f").is_ok());
    }

    #[test]
    fn public_addr_rejects_unspecified_listen_only_values() {
        let err = validate_public_addr("0.0.0.0:4433", "f").unwrap_err().to_string();
        assert!(err.contains("unspecified"), "got {err}");
        let err = validate_public_addr("[::]:4433", "f").unwrap_err().to_string();
        assert!(err.contains("unspecified"), "got {err}");
    }

    #[test]
    fn public_addr_rejects_malformed_input() {
        assert!(validate_public_addr("", "f").is_err());
        assert!(validate_public_addr("no-port", "f").is_err());
        assert!(validate_public_addr("host:0", "f").is_err());
        assert!(validate_public_addr("host:notaport", "f").is_err());
        assert!(validate_public_addr("-bad.example.com:4433", "f").is_err());
        assert!(validate_public_addr("bad-.example.com:4433", "f").is_err());
    }

    /// The startup warning fires on exactly one posture: permissive bind auth
    /// AND the native plane enabled. Strict bind auth, or a disabled plane,
    /// must stay quiet — a warning on every relay is a warning nobody reads.
    #[test]
    fn native_plane_unauthenticated_posture_is_both_halves() {
        let mut c = RelayConfig {
            require_bind_auth: false,
            udp_relay_enabled: true,
            ..RelayConfig::default()
        };
        assert!(c.native_plane_accepts_unauthenticated(), "permissive + plane on");

        c.udp_relay_enabled = false;
        assert!(!c.native_plane_accepts_unauthenticated(), "plane off — nothing to hijack");

        c.require_bind_auth = true;
        c.udp_relay_enabled = true;
        assert!(!c.native_plane_accepts_unauthenticated(), "strict bind auth");
    }

    /// `testbed/configs/relay-distribution.json`'s shape: it sets
    /// `require_bind_auth: false` and OMITS `udp_relay_enabled` entirely, which
    /// `#[serde(default = "default_true")]` resolves to `true`. It is therefore
    /// a THIRD exposed testbed config, not an unaffected one.
    #[test]
    fn omitted_udp_relay_enabled_still_counts_as_exposed() {
        let c: RelayConfig = serde_json::from_str(
            r#"{ "quic_addr": "0.0.0.0:4433", "api_addr": "0.0.0.0:4480", "require_bind_auth": false }"#,
        )
        .expect("parses");
        assert!(c.udp_relay_enabled, "omitted field defaults to true");
        assert!(c.native_plane_accepts_unauthenticated());
    }

    /// The free-space floor is bounded like every other distribution knob:
    /// `0` is the documented way to switch it off, but a non-zero value too
    /// small to cover a segment would read as configured while guarding
    /// nothing, and one no volume can satisfy would evict every stream on
    /// every sweep.
    #[test]
    fn origin_min_free_bytes_is_bounded() {
        let mut d = DistributionConfig::default();
        assert!(d.validate().is_ok(), "the shipped default is valid");

        d.origin_min_free_bytes = 0;
        assert!(d.validate().is_ok(), "0 disables the floor");

        d.origin_min_free_bytes = 5;
        let err = d.validate().unwrap_err().to_string();
        assert!(err.contains("origin_min_free_bytes"), "got {err}");

        d.origin_min_free_bytes = 2 * 1024 * 1024 * 1024 * 1024;
        let err = d.validate().unwrap_err().to_string();
        assert!(err.contains("origin_min_free_bytes"), "got {err}");

        d.origin_min_free_bytes = 5 * 1024 * 1024 * 1024;
        assert!(d.validate().is_ok(), "5 GiB, the default, is in range");
    }

    // ── get_config redaction ──
    //
    // The fixtures are written as full struct literals, never `..Default`, so a
    // field added to any of these structs (or to any log target) does not
    // compile here until it has a value — and a populated value is what the
    // tests below need to see it.

    const API_TOKEN: &str = "planted-api-token-0123456789abcdef0123456789";
    const REGISTRATION_TOKEN: &str = "planted-registration-token";
    const NODE_SECRET: &str = "planted-node-secret";
    const TOKEN_SECRET: &str = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7";
    const CASCADE_TOKEN_A: &str = "planted-cascade-token-a";
    const CASCADE_TOKEN_B: &str = "planted-cascade-token-b";
    const CASCADE_URL_TOKEN: &str = "planted-cascade-url-token";
    const CASCADE_USERINFO: &str = "planted-cascade-user:planted-cascade-pass";
    const MANAGER_USERINFO: &str = "planted-mgr-user:planted-mgr-pass";
    const MANAGER_URL_TOKEN: &str = "planted-mgr-access-token";

    /// Every credential the fixtures plant. A secret field added to the
    /// structs belongs here as well as in its `redact_secrets`.
    const PLANTED: &[&str] = &[
        API_TOKEN,
        REGISTRATION_TOKEN,
        NODE_SECRET,
        TOKEN_SECRET,
        CASCADE_TOKEN_A,
        CASCADE_TOKEN_B,
        CASCADE_URL_TOKEN,
        CASCADE_USERINFO,
        MANAGER_USERINFO,
        MANAGER_URL_TOKEN,
        // The password half on its own, in case only a user were stripped.
        "planted-cascade-pass",
        "planted-mgr-pass",
    ];

    /// Where `get_config` must show the bare marker, as JSON pointers into the
    /// fixtures.
    const SECRET_PATHS: &[&str] = &[
        "/api_token",
        "/manager/registration_token",
        "/manager/node_secret",
        "/distribution/token_secret",
        "/distribution/cascade_sources/0/token",
        "/distribution/cascade_sources/1/token",
    ];

    /// URLs that carry a credential, and what `get_config` must show for each.
    const URL_PATHS: &[(&str, &str)] = &[
        (
            "/manager/urls/1",
            "wss://***REDACTED***@manager2.example.com/ws/node?access_token=***REDACTED***&region=eu",
        ),
        (
            "/distribution/cascade_sources/0/upstream_whep_url",
            "http://origin-a.example.com:4485/whep/feed?v=2&token=***REDACTED***",
        ),
        (
            "/distribution/cascade_sources/1/upstream_whep_url",
            "http://***REDACTED***@origin-b.example.com/whep/feed2",
        ),
    ];

    /// One of every log target. A variant added later fails the match below
    /// until it is given a fixture here too.
    fn log_targets() -> Vec<JsonLogTarget> {
        let targets = vec![
            JsonLogTarget::Stdout { format: LogFormat::Raw },
            JsonLogTarget::File {
                path: "/var/log/bilbycast/relay.jsonl".into(),
                format: LogFormat::Splunk,
                max_size_mb: 64,
                max_backups: 5,
            },
            JsonLogTarget::Syslog { addr: "127.0.0.1:514".into(), format: LogFormat::Dataminer },
        ];
        for t in &targets {
            match t {
                JsonLogTarget::Stdout { .. }
                | JsonLogTarget::File { .. }
                | JsonLogTarget::Syslog { .. } => {}
            }
        }
        targets
    }

    fn populated_with(json_target: JsonLogTarget) -> RelayConfig {
        RelayConfig {
            quic_addr: "0.0.0.0:4433".into(),
            quic_addrs: Some(vec!["0.0.0.0:4433".into(), "[::]:4433".into()]),
            public_quic_addr: Some("relay.example.com:4433".into()),
            udp_relay_enabled: true,
            udp_relay_addrs: Some(vec!["0.0.0.0:4434".into()]),
            public_udp_addr: Some("relay.example.com:4434".into()),
            api_addr: "0.0.0.0:4480".into(),
            api_addrs: Some(vec!["0.0.0.0:4480".into()]),
            tls_cert_path: Some("/etc/bilbycast/relay/cert.pem".into()),
            tls_key_path: Some("/etc/bilbycast/relay/key.pem".into()),
            api_token: Some(API_TOKEN.into()),
            require_bind_auth: true,
            max_connections_per_ip: 64,
            max_tunnels_per_connection: 100,
            manager: Some(ManagerConfig {
                enabled: true,
                urls: vec![
                    "wss://manager.example.com/ws/node".into(),
                    format!(
                        "wss://{MANAGER_USERINFO}@manager2.example.com/ws/node?access_token={MANAGER_URL_TOKEN}&region=eu"
                    ),
                ],
                accept_self_signed_cert: false,
                cert_fingerprint: Some("ab:cd:ef".into()),
                registration_token: Some(REGISTRATION_TOKEN.into()),
                node_id: Some("node-1".into()),
                node_secret: Some(NODE_SECRET.into()),
            }),
            logging: Some(LoggingConfig { json_target: Some(json_target) }),
            distribution: Some(DistributionConfig {
                enabled: true,
                http_addrs: Some(vec!["0.0.0.0:4485".into()]),
                public_ip: Some("203.0.113.10".into()),
                public_base_url: Some("https://relay.example.com".into()),
                portal_url: Some("https://portal.example.com".into()),
                ingest_addrs: Some(vec!["0.0.0.0:4486".into()]),
                token_secret: Some(TOKEN_SECRET.into()),
                require_viewer_token: true,
                require_origin_token: true,
                require_ingest_token: true,
                max_viewers_per_ip: 256,
                origin_window_segments: 8,
                origin_retention_secs: 60,
                origin_max_bytes_per_stream: default_origin_max_bytes_per_stream(),
                origin_idle_grace_secs: 60,
                origin_min_free_bytes: default_origin_min_free_bytes(),
                origin_storage_dir: Some("/var/lib/bilbycast/relay/origin".into()),
                cascade_sources: vec![
                    CascadeSource {
                        upstream_whep_url: format!(
                            "http://origin-a.example.com:4485/whep/feed?v=2&token={CASCADE_URL_TOKEN}"
                        ),
                        local_stream: "feed".into(),
                        token: Some(CASCADE_TOKEN_A.into()),
                    },
                    CascadeSource {
                        upstream_whep_url: format!(
                            "http://{CASCADE_USERINFO}@origin-b.example.com/whep/feed2"
                        ),
                        local_stream: "feed2".into(),
                        token: Some(CASCADE_TOKEN_B.into()),
                    },
                ],
            }),
        }
    }

    /// The fully populated config, once per log target.
    fn fixtures() -> Vec<RelayConfig> {
        log_targets().into_iter().map(populated_with).collect()
    }

    /// Every string leaf of `v`, as (JSON pointer, value).
    fn string_leaves(v: &serde_json::Value, path: String, out: &mut Vec<(String, String)>) {
        match v {
            serde_json::Value::String(s) => out.push((path, s.clone())),
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    string_leaves(child, format!("{path}/{k}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    string_leaves(child, format!("{path}/{i}"), out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn the_fixtures_are_valid_configs() {
        for config in fixtures() {
            config.validate().expect("each fixture is a config a relay would run");
        }
    }

    /// The defect: `get_config` carried `distribution.token_secret` (the key
    /// every viewer and ingest token is signed with), the registration token
    /// and the cascade tokens in clear, to anyone with View on the relay — and
    /// a cascade URL carrying `?token=` went out whole.
    #[test]
    fn redacted_json_carries_no_credential() {
        for config in fixtures() {
            let text = config.redacted_json().to_string();
            for secret in PLANTED {
                assert!(!text.contains(secret), "get_config leaked {secret:?}: {text}");
            }
        }
    }

    /// The marker sits at exactly the credential paths, the URLs keep all but
    /// their credentials, and nothing else in the config is touched — the
    /// manager still sees the operational config.
    #[test]
    fn exactly_the_credential_fields_are_redacted() {
        for config in fixtures() {
            let plain = serde_json::to_value(&config).unwrap();
            let redacted = config.redacted_json();

            let mut plain_leaves = Vec::new();
            string_leaves(&plain, String::new(), &mut plain_leaves);
            let mut redacted_leaves = Vec::new();
            string_leaves(&redacted, String::new(), &mut redacted_leaves);
            assert_eq!(
                plain_leaves.iter().map(|(p, _)| p).collect::<Vec<_>>(),
                redacted_leaves.iter().map(|(p, _)| p).collect::<Vec<_>>(),
                "redaction must not add or drop a field"
            );

            let mut changed: Vec<&str> = plain_leaves
                .iter()
                .zip(&redacted_leaves)
                .filter(|((_, a), (_, b))| a != b)
                .map(|((p, _), _)| p.as_str())
                .collect();
            changed.sort_unstable();
            let mut expected: Vec<&str> = SECRET_PATHS.to_vec();
            expected.extend(URL_PATHS.iter().map(|(p, _)| *p));
            expected.sort_unstable();
            assert_eq!(changed, expected);

            for path in SECRET_PATHS {
                assert_eq!(redacted.pointer(path).and_then(|v| v.as_str()), Some(REDACTED), "{path}");
            }
            for (path, shown) in URL_PATHS {
                assert_eq!(redacted.pointer(path).and_then(|v| v.as_str()), Some(*shown), "{path}");
            }
            // Numbers and booleans come through untouched as well.
            assert_eq!(redacted["distribution"]["require_viewer_token"], true);
            assert_eq!(redacted["max_connections_per_ip"], 64);
        }
    }

    /// A backstop for a credential added later and waved through as `_`: any
    /// string field whose *name* says it is a credential must be the marker.
    #[test]
    fn no_field_named_like_a_credential_goes_out_in_clear() {
        for config in fixtures() {
            let redacted = config.redacted_json();
            let mut leaves = Vec::new();
            string_leaves(&redacted, String::new(), &mut leaves);
            let mut seen = 0;
            for (path, value) in &leaves {
                let name = path
                    .rsplit('/')
                    .find(|seg| seg.parse::<usize>().is_err())
                    .unwrap_or_default();
                if is_credential_name(name) {
                    seen += 1;
                    assert_eq!(value, REDACTED, "{path} looks like a credential and went out as {value:?}");
                }
            }
            assert_eq!(seen, SECRET_PATHS.len(), "the name check saw every credential path");
        }
    }

    #[test]
    fn credential_names_are_recognised_by_whole_word() {
        for name in [
            "token", "api_token", "token_secret", "node_secret", "registration_token",
            "access_token", "password", "passphrase", "psk", "bearer", "auth", "auth_token",
            "hmac", "hmac_key", "key", "stream_key", "apikey", "sig", "Signature", "X-Api-Key",
        ] {
            assert!(is_credential_name(name), "{name} is a credential");
        }
        for name in [
            // A path names where a credential lives, not the credential.
            "tls_key_path", "tls_cert_path", "listen_password_file", "key_dir",
            // Not a credential word, only containing one.
            "author", "monkey", "keystone", "passthrough", "tokenizer",
            "upstream_whep_url", "local_stream", "node_id", "cert_fingerprint", "v", "region",
        ] {
            assert!(!is_credential_name(name), "{name} is not a credential");
        }
    }

    #[test]
    fn redact_url_hides_credentials_and_nothing_else() {
        for (url, shown) in [
            ("http://h:4485/whep/feed", "http://h:4485/whep/feed"),
            ("http://h/whep/feed?v=2", "http://h/whep/feed?v=2"),
            ("http://h/whep/feed?token=abc", "http://h/whep/feed?token=***REDACTED***"),
            ("http://h/w?a=1&Token=abc&b=2", "http://h/w?a=1&Token=***REDACTED***&b=2"),
            ("http://h/w?access_token=abc", "http://h/w?access_token=***REDACTED***"),
            ("http://h/w#access_token=abc&s=1", "http://h/w#access_token=***REDACTED***&s=1"),
            ("http://u:p@h:80/w", "http://***REDACTED***@h:80/w"),
            ("wss://u@h/ws?x=1", "wss://***REDACTED***@h/ws?x=1"),
            // `@` in the path is not a userinfo.
            ("http://h/w/a@b", "http://h/w/a@b"),
            // Nothing to hide in an empty value or a bare key.
            ("http://h/w?token=&token", "http://h/w?token=&token"),
            ("http://h/w?ingest_token=abc", "http://h/w?ingest_token=***REDACTED***"),
        ] {
            assert_eq!(redact_url(url), shown, "{url}");
            assert_eq!(redact_url(shown), shown, "idempotent on {shown}");
        }
        assert!(url_holds_marker(&redact_url("http://h/w?token=abc")));
        assert!(!url_holds_marker("http://h/w?v=2"));
    }

    #[test]
    fn duplicate_local_streams_are_named_once_each() {
        let s = |stream: &str| CascadeSource {
            upstream_whep_url: format!("http://h/whep/{stream}"),
            local_stream: stream.into(),
            token: None,
        };
        assert!(duplicate_local_streams(&[s("a"), s("b")]).is_empty());
        assert_eq!(duplicate_local_streams(&[s("a"), s("b"), s("a"), s("a"), s("b")]), ["a", "b"]);
        // Loaded anyway, with a warning: refusing would stop a relay booting.
        let d = DistributionConfig { cascade_sources: vec![s("a"), s("a")], ..Default::default() };
        assert!(d.validate().is_ok());
    }

    /// Set-but-redacted and unset must stay distinguishable: the marker says
    /// the config held a credential, an absent key says it held none.
    #[test]
    fn an_unset_credential_stays_absent() {
        let mut config = fixtures().remove(0);
        config.api_token = None;
        let manager = config.manager.as_mut().unwrap();
        manager.registration_token = None;
        manager.node_secret = None;
        let dist = config.distribution.as_mut().unwrap();
        dist.token_secret = None;
        dist.cascade_sources[1].token = None;

        let out = config.redacted_json();
        for path in [
            "/api_token",
            "/manager/registration_token",
            "/manager/node_secret",
            "/distribution/token_secret",
            "/distribution/cascade_sources/1/token",
        ] {
            assert!(out.pointer(path).is_none(), "{path} is unset and must stay absent: {out}");
        }
        assert_eq!(
            out.pointer("/distribution/cascade_sources/0/token").and_then(|v| v.as_str()),
            Some(REDACTED),
            "the set one is still shown as set"
        );
    }

    /// Redaction is for what leaves the relay. The config itself, and so what
    /// `update_config_file` writes to `config.json`, keeps the real values —
    /// a relay that persisted the marker would lock itself out on restart.
    #[test]
    fn redacting_leaves_the_config_and_its_on_disk_form_alone() {
        for config in fixtures() {
            let _ = config.redacted_json();
            let on_disk = serde_json::to_string_pretty(&config).unwrap();
            for secret in PLANTED {
                assert!(on_disk.contains(secret), "{secret:?} must still be written to config.json");
            }
            assert!(!on_disk.contains(REDACTED));
        }
    }

    #[test]
    fn relay_config_validate_picks_up_bad_public_addr() {
        let mut c = RelayConfig {
            public_quic_addr: Some("0.0.0.0:4433".to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
        c.public_quic_addr = Some("54.1.2.3:4433".to_string());
        assert!(c.validate().is_ok());
        c.public_quic_addr = None;
        assert!(c.validate().is_ok());
    }
}
