// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

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
    /// Master switch. When false the subsystem does not start.
    #[serde(default)]
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

    /// Require a valid signed ingest token on every edge → relay ingest
    /// connection. Default true — the ingest is a write surface.
    #[serde(default = "default_true")]
    pub require_ingest_token: bool,

    /// Per-source-IP concurrent WHEP viewer cap (DoS mitigation on the
    /// public endpoint). Default 256.
    #[serde(default = "default_max_viewers_per_ip")]
    pub max_viewers_per_ip: u32,

    /// LL-HLS origin retention: how many recent media segments (+ their
    /// parts) to keep per stream in the in-memory sliding window. Default 8.
    #[serde(default = "default_origin_window_segments")]
    pub origin_window_segments: usize,

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
            enabled: false,
            http_addrs: None,
            public_ip: None,
            public_base_url: None,
            ingest_addrs: None,
            token_secret: None,
            require_viewer_token: false,
            require_ingest_token: true,
            max_viewers_per_ip: default_max_viewers_per_ip(),
            origin_window_segments: default_origin_window_segments(),
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
        if let Some(ref url) = self.public_base_url {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                anyhow::bail!("distribution.public_base_url must start with http:// or https://");
            }
            if url.len() > 2048 {
                anyhow::bail!("distribution.public_base_url too long (max 2048 chars)");
            }
        }
        if let Some(ref secret) = self.token_secret {
            if secret.len() != 64 || !secret.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!("distribution.token_secret must be exactly 64 hex chars (32 bytes)");
            }
        }
        if self.require_viewer_token && self.token_secret.is_none() {
            anyhow::bail!(
                "distribution.require_viewer_token=true requires distribution.token_secret to be set"
            );
        }
        if self.enabled && self.require_ingest_token && self.token_secret.is_none() {
            anyhow::bail!(
                "distribution.require_ingest_token=true requires distribution.token_secret to be set \
                 (set token_secret, or set require_ingest_token=false for an open dev ingest)"
            );
        }
        if self.origin_window_segments == 0 || self.origin_window_segments > 64 {
            anyhow::bail!("distribution.origin_window_segments must be in 1..=64");
        }
        if self.cascade_sources.len() > 64 {
            anyhow::bail!("distribution.cascade_sources: at most 64 entries");
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
        if let Some(ref token) = self.api_token {
            if token.len() < 32 || token.len() > 128 {
                anyhow::bail!("api_token must be 32-128 characters, got {}", token.len());
            }
        }

        // Validate manager URL list if enabled (1..16, each wss://,
        // ≤2048 chars, unique — same rules as bilbycast-edge).
        if let Some(ref mgr) = self.manager {
            if mgr.enabled {
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

    #[test]
    fn relay_config_validate_picks_up_bad_public_addr() {
        let mut c = RelayConfig::default();
        c.public_quic_addr = Some("0.0.0.0:4433".to_string());
        assert!(c.validate().is_err());
        c.public_quic_addr = Some("54.1.2.3:4433".to_string());
        assert!(c.validate().is_ok());
        c.public_quic_addr = None;
        assert!(c.validate().is_ok());
    }
}
