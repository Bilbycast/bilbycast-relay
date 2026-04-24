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
    /// QUIC listen address (e.g., "0.0.0.0:4433").
    #[serde(default = "default_quic_addr")]
    pub quic_addr: String,

    /// REST API listen address (e.g., "0.0.0.0:4480").
    #[serde(default = "default_api_addr")]
    pub api_addr: String,

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

    /// Optional manager connection for centralized monitoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<ManagerConfig>,
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
        // Validate socket addresses are parseable
        self.quic_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid quic_addr '{}': {}", self.quic_addr, e))?;
        self.api_addr.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid api_addr '{}': {}", self.api_addr, e))?;

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

        Ok(())
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            quic_addr: default_quic_addr(),
            api_addr: default_api_addr(),
            tls_cert_path: None,
            tls_key_path: None,
            api_token: None,
            require_bind_auth: false,
            manager: None,
        }
    }
}
