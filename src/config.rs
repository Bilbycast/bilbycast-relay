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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// QUIC listen address (e.g., "0.0.0.0:4433").
    #[serde(default = "default_quic_addr")]
    pub quic_addr: String,

    /// REST API listen address (e.g., "0.0.0.0:4480").
    #[serde(default = "default_api_addr")]
    pub api_addr: String,

    /// Shared secret for HMAC token verification.
    /// Edge tokens are signed with this secret by the manager.
    pub shared_secret: String,

    /// Optional path to TLS certificate (PEM). If absent, self-signed cert is generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,

    /// Optional path to TLS private key (PEM). If absent, self-signed cert is generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,

    /// Maximum concurrent edge connections (default: 100).
    #[serde(default = "default_max_edges")]
    pub max_edges: usize,

    /// Maximum concurrent tunnels (default: 500).
    #[serde(default = "default_max_tunnels")]
    pub max_tunnels: usize,

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

fn default_max_edges() -> usize {
    100
}

fn default_max_tunnels() -> usize {
    500
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            quic_addr: default_quic_addr(),
            api_addr: default_api_addr(),
            shared_secret: String::new(),
            tls_cert_path: None,
            tls_key_path: None,
            max_edges: default_max_edges(),
            max_tunnels: default_max_tunnels(),
            manager: None,
        }
    }
}
