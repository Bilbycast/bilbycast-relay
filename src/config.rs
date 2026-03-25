// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

use serde::{Deserialize, Serialize};

/// Manager connection configuration (same pattern as bilbycast-edge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfig {
    /// Whether manager connection is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// WebSocket URL of the manager (must be wss://).
    pub url: String,

    /// Accept self-signed TLS certificates from the manager.
    /// Only enable this for development/testing. Default: false.
    #[serde(default)]
    pub accept_self_signed_cert: bool,

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

        // Validate manager URL if enabled
        if let Some(ref mgr) = self.manager {
            if mgr.enabled && !mgr.url.starts_with("wss://") {
                anyhow::bail!("Manager URL must use wss:// (TLS required)");
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
            manager: None,
        }
    }
}
