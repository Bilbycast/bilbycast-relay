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

        // Validate logging shipper if present
        if let Some(ref logging) = self.logging {
            validate_logging_config(logging)?;
        }

        Ok(())
    }
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
            api_addr: default_api_addr(),
            tls_cert_path: None,
            tls_key_path: None,
            api_token: None,
            require_bind_auth: false,
            max_connections_per_ip: default_max_connections_per_ip(),
            max_tunnels_per_connection: default_max_tunnels_per_connection(),
            manager: None,
            logging: None,
        }
    }
}
