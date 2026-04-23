// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Manager WebSocket client for bilbycast-relay.
//!
//! Maintains a persistent outbound WebSocket connection to the manager,
//! forwarding relay stats (tunnels, edges, bandwidth) and executing commands.
//!
//! Authentication uses the same protocol as bilbycast-edge: first WebSocket
//! frame contains either registration_token or node_id + node_secret.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::config::{ManagerConfig, RelayConfig};
use crate::session::SessionContext;
use crate::stats::RelayStats;

use super::events::{Event, build_event_envelope, category};

/// Compute SHA-256 fingerprint of a DER-encoded certificate.
fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(cert_der);
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Certificate verifier that accepts any certificate (for self-signed cert support).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Certificate verifier with fingerprint pinning.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_fingerprint: String,
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        let actual = compute_cert_fingerprint(end_entity.as_ref());
        if actual != self.expected_fingerprint {
            tracing::error!(
                "Certificate fingerprint mismatch! Expected: {}, got: {}",
                self.expected_fingerprint, actual
            );
            return Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                self.expected_fingerprint, actual
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Start the manager client background task.
pub fn start_manager_client(
    config: ManagerConfig,
    ctx: Arc<SessionContext>,
    relay_stats: Arc<RelayStats>,
    relay_config: RelayConfig,
    config_path: PathBuf,
    event_rx: mpsc::UnboundedReceiver<Event>,
    event_sender: super::events::EventSender,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        manager_client_loop(config, ctx, relay_stats, relay_config, config_path, event_rx, event_sender).await;
    })
}

async fn manager_client_loop(
    mut config: ManagerConfig,
    ctx: Arc<SessionContext>,
    relay_stats: Arc<RelayStats>,
    relay_config: RelayConfig,
    config_path: PathBuf,
    mut event_rx: mpsc::UnboundedReceiver<Event>,
    event_sender: super::events::EventSender,
) {
    // Multi-URL failover: rotate on close, fixed 5 s backoff that
    // resets on successful auth. 1-16 URLs in config.urls.
    let fixed_backoff = Duration::from_secs(5);
    let mut cursor: usize = 0;

    loop {
        if config.urls.is_empty() {
            tracing::error!("Manager client started with no URLs — config.urls is empty");
            tokio::time::sleep(fixed_backoff).await;
            continue;
        }
        let current_url = config.urls[cursor % config.urls.len()].clone();
        tracing::info!(
            "Connecting to manager at {current_url} (url {} of {})",
            (cursor % config.urls.len()) + 1,
            config.urls.len(),
        );

        match try_connect(&current_url, &config, &ctx, &relay_stats, &relay_config, &config_path, &mut event_rx, &event_sender).await {
            Ok(ConnectResult::Closed) => {
                tracing::info!("Manager connection to {current_url} closed normally");
                event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, "Manager connection lost, rotating to next URL");
            }
            Ok(ConnectResult::Registered {
                node_id,
                node_secret,
            }) => {
                tracing::info!(
                    "Registered with manager as node_id={node_id}, persisting credentials"
                );
                config.registration_token = None;
                config.node_id = Some(node_id.clone());
                config.node_secret = Some(node_secret.clone());

                persist_credentials(&relay_config, &config_path, &node_id, &node_secret);
            }
            Err(e) => {
                tracing::warn!("Manager connection to {current_url} failed: {e}");
                event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, format!("Manager connection lost, rotating to next URL: {}", e));
            }
        }

        cursor = cursor.wrapping_add(1);
        tracing::info!(
            "Reconnecting to next manager URL in {}s...",
            fixed_backoff.as_secs()
        );
        tokio::time::sleep(fixed_backoff).await;
    }
}

enum ConnectResult {
    Closed,
    Registered {
        node_id: String,
        node_secret: String,
    },
}

async fn try_connect(
    current_url: &str,
    config: &ManagerConfig,
    ctx: &Arc<SessionContext>,
    relay_stats: &Arc<RelayStats>,
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    event_rx: &mut mpsc::UnboundedReceiver<Event>,
    event_sender: &super::events::EventSender,
) -> Result<ConnectResult, String> {
    // Enforce TLS — only wss:// connections are allowed
    if !current_url.starts_with("wss://") {
        return Err(
            "Manager URL must use wss:// (TLS). Plaintext ws:// connections are not allowed."
                .into(),
        );
    }

    let (ws_stream, _response) = if config.accept_self_signed_cert {
        // SECURITY: Require explicit env var to allow insecure connections.
        if std::env::var("BILBYCAST_ALLOW_INSECURE").as_deref() != Ok("1") {
            return Err(
                "accept_self_signed_cert is enabled but BILBYCAST_ALLOW_INSECURE=1 is not set. \
                 This is a security safeguard — self-signed cert mode disables ALL certificate \
                 validation, making the connection vulnerable to MITM attacks. Set \
                 BILBYCAST_ALLOW_INSECURE=1 to confirm this is intentional (dev/testing only)."
                    .into(),
            );
        }
        tracing::warn!(
            "SECURITY WARNING: accept_self_signed_cert is enabled — ALL TLS certificate \
             validation is disabled. This makes the connection vulnerable to man-in-the-middle \
             attacks. Do NOT use this in production."
        );
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(InsecureCertVerifier))
            .with_no_client_auth();
        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(tls_config));
        tokio_tungstenite::connect_async_tls_with_config(
            current_url,
            None,
            false,
            Some(connector),
        )
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?
    } else if let Some(ref fingerprint) = config.cert_fingerprint {
        // Certificate pinning: validate CA chain AND check fingerprint
        tracing::info!("Certificate pinning enabled (fingerprint: {}...)", &fingerprint[..fingerprint.len().min(11)]);
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let inner = rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
            .build()
            .map_err(|e| format!("Failed to build certificate verifier: {e}"))?;
        let verifier = PinnedCertVerifier {
            expected_fingerprint: fingerprint.clone(),
            inner,
        };
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
            .with_no_client_auth();
        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(tls_config));
        tokio_tungstenite::connect_async_tls_with_config(
            current_url,
            None,
            false,
            Some(connector),
        )
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?
    } else {
        tokio_tungstenite::connect_async(current_url)
            .await
            .map_err(|e| format!("WebSocket connect failed: {e}"))?
    };

    tracing::info!("WebSocket connected, sending auth...");

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Step 1: Send auth message
    let auth_msg = build_auth_message(config);
    if let Ok(json) = serde_json::to_string(&auth_msg) {
        ws_write
            .send(Message::Text(json.into()))
            .await
            .map_err(|e| format!("Failed to send auth: {e}"))?;
    }

    // Step 2: Wait for auth response (10s timeout)
    let auth_timeout = tokio::time::timeout(Duration::from_secs(10), ws_read.next()).await;

    let mut registered_creds: Option<(String, String)> = None;

    match auth_timeout {
        Ok(Some(Ok(Message::Text(text)))) => {
            let response: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("Invalid auth response: {e}"))?;

            match response["type"].as_str().unwrap_or("") {
                "auth_ok" => {
                    tracing::info!("Authenticated with manager");
                    event_sender.emit(super::events::EventSeverity::Info, category::MANAGER, "Connected to manager");
                }
                "register_ack" => {
                    let payload = &response["payload"];
                    let node_id = payload["node_id"].as_str().unwrap_or("").to_string();
                    let node_secret = payload["node_secret"].as_str().unwrap_or("").to_string();
                    tracing::info!("Registered with manager: node_id={node_id}");
                    event_sender.emit(super::events::EventSeverity::Info, category::MANAGER, "Connected to manager");

                    if !node_id.is_empty() && !node_secret.is_empty() {
                        persist_credentials(relay_config, config_path, &node_id, &node_secret);
                        registered_creds = Some((node_id, node_secret));
                    }
                }
                "auth_error" => {
                    let msg = response["message"].as_str().unwrap_or("Unknown auth error");
                    event_sender.emit(super::events::EventSeverity::Critical, category::MANAGER, format!("Manager authentication failed: {}", msg));
                    return Err(format!("Auth rejected: {msg}"));
                }
                other => {
                    return Err(format!("Unexpected auth response type: {other}"));
                }
            }
        }
        Ok(Some(Ok(_))) => return Err("Unexpected non-text auth response".into()),
        Ok(Some(Err(e))) => return Err(format!("WebSocket error during auth: {e}")),
        Ok(None) => return Err("Connection closed during auth".into()),
        Err(_) => return Err("Auth response timeout (10s)".into()),
    }

    // Send initial health
    let health = build_health_message(ctx, relay_stats, relay_config);
    if let Ok(json) = serde_json::to_string(&health) {
        let _ = ws_write.send(Message::Text(json.into())).await;
    }

    // Main loop: stats every 1s, health every 15s, handle incoming commands
    let mut stats_interval = tokio::time::interval(Duration::from_secs(1));
    stats_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut health_interval = tokio::time::interval(Duration::from_secs(15));
    health_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = stats_interval.tick() => {
                let envelope = serde_json::json!({
                    "type": "stats",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": build_stats_payload(ctx, relay_stats)
                });
                if let Ok(json) = serde_json::to_string(&envelope) {
                    if ws_write.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }

            _ = health_interval.tick() => {
                let envelope = build_health_message(ctx, relay_stats, relay_config);
                if let Ok(json) = serde_json::to_string(&envelope) {
                    if ws_write.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }

            msg = ws_read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_manager_message(&text, ctx, relay_config, config_path, &mut ws_write).await;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_write.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        return Err(format!("WebSocket error: {e}"));
                    }
                    _ => {}
                }
            }

            // Forward queued events to the manager
            Some(event) = event_rx.recv() => {
                let envelope = build_event_envelope(&event);
                if let Ok(json) = serde_json::to_string(&envelope) {
                    if ws_write.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    if let Some((node_id, node_secret)) = registered_creds {
        return Ok(ConnectResult::Registered {
            node_id,
            node_secret,
        });
    }

    Ok(ConnectResult::Closed)
}

// ───────────────────────────────────────────────────────
// Message builders
// ───────────────────────────────────────────────────────

/// WebSocket protocol version. Sent in auth payload so the manager can detect mismatches.
const WS_PROTOCOL_VERSION: u32 = 1;

fn build_auth_message(config: &ManagerConfig) -> serde_json::Value {
    if let (Some(node_id), Some(node_secret)) = (&config.node_id, &config.node_secret) {
        serde_json::json!({
            "type": "auth",
            "payload": {
                "node_id": node_id,
                "node_secret": node_secret,
                "software_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": WS_PROTOCOL_VERSION
            }
        })
    } else if let Some(token) = &config.registration_token {
        serde_json::json!({
            "type": "auth",
            "payload": {
                "registration_token": token,
                "software_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": WS_PROTOCOL_VERSION
            }
        })
    } else {
        serde_json::json!({
            "type": "auth",
            "payload": {}
        })
    }
}

fn build_stats_payload(ctx: &SessionContext, relay_stats: &RelayStats) -> serde_json::Value {
    let tunnel_infos = ctx.router.list_tunnels();
    let (total_tunnels, active_tunnels) = ctx.router.counts();
    let connected_edges = ctx.edge_connections.len();

    let total_bytes_ingress: u64 = tunnel_infos.iter().map(|t| t.stats.bytes_ingress).sum();
    let total_bytes_egress: u64 = tunnel_infos.iter().map(|t| t.stats.bytes_egress).sum();
    let total_bytes_forwarded = total_bytes_ingress + total_bytes_egress;
    let total_tcp_streams: u64 = tunnel_infos.iter().map(|t| t.stats.tcp_streams_total).sum();
    let active_tcp_streams: u64 = tunnel_infos.iter().map(|t| t.stats.tcp_streams_active).sum();
    let total_udp_datagrams: u64 = tunnel_infos.iter().map(|t| t.stats.udp_datagrams_total).sum();

    // Update peaks
    relay_stats.update_peaks(active_tunnels as u64, connected_edges as u64);

    // Compute current throughput
    let total_bandwidth_bps = relay_stats.compute_bandwidth_bps(total_bytes_forwarded);

    // Build edges list
    let edges: Vec<serde_json::Value> = ctx
        .edge_connections
        .iter()
        .map(|entry| {
            serde_json::json!({
                "edge_id": entry.key(),
                "remote_addr": entry.value().remote_address().to_string()
            })
        })
        .collect();

    serde_json::json!({
        "tunnels": tunnel_infos,
        "edges": edges,
        "connected_edges": connected_edges,
        "active_tunnels": active_tunnels,
        "total_tunnels": total_tunnels,
        "total_bytes_ingress": total_bytes_ingress,
        "total_bytes_egress": total_bytes_egress,
        "total_bytes_forwarded": total_bytes_forwarded,
        "total_bandwidth_bps": total_bandwidth_bps,
        "total_tcp_streams": total_tcp_streams,
        "active_tcp_streams": active_tcp_streams,
        "total_udp_datagrams": total_udp_datagrams,
        "peak_tunnels": relay_stats.peak_tunnels.load(std::sync::atomic::Ordering::Relaxed),
        "peak_edges": relay_stats.peak_edges.load(std::sync::atomic::Ordering::Relaxed),
        "connections_total": relay_stats.connections_total.load(std::sync::atomic::Ordering::Relaxed),
        "uptime_secs": relay_stats.uptime_secs()
    })
}

fn build_health_message(
    ctx: &SessionContext,
    relay_stats: &RelayStats,
    relay_config: &RelayConfig,
) -> serde_json::Value {
    let (total_tunnels, active_tunnels) = ctx.router.counts();
    let tunnel_infos = ctx.router.list_tunnels();
    let total_bytes_ingress: u64 = tunnel_infos.iter().map(|t| t.stats.bytes_ingress).sum();
    let total_bytes_egress: u64 = tunnel_infos.iter().map(|t| t.stats.bytes_egress).sum();

    serde_json::json!({
        "type": "health",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "payload": {
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": relay_stats.uptime_secs(),
            "connected_edges": ctx.edge_connections.len(),
            "active_tunnels": active_tunnels,
            "total_tunnels": total_tunnels,
            "total_bytes_forwarded": total_bytes_ingress + total_bytes_egress,
            "peak_tunnels": relay_stats.peak_tunnels.load(std::sync::atomic::Ordering::Relaxed),
            "peak_edges": relay_stats.peak_edges.load(std::sync::atomic::Ordering::Relaxed),
            "connections_total": relay_stats.connections_total.load(std::sync::atomic::Ordering::Relaxed),
            "api_addr": relay_config.api_addr,
            "quic_addr": relay_config.quic_addr
        }
    })
}

// ───────────────────────────────────────────────────────
// Command handling
// ───────────────────────────────────────────────────────

async fn handle_manager_message<S>(
    text: &str,
    ctx: &Arc<SessionContext>,
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    ws_write: &mut futures_util::stream::SplitSink<S, Message>,
) where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let envelope: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Invalid message from manager: {e}");
            return;
        }
    };

    let msg_type = envelope["type"].as_str().unwrap_or("");
    let payload = &envelope["payload"];

    match msg_type {
        "ping" => {
            let pong = serde_json::json!({
                "type": "pong",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "payload": null
            });
            if let Ok(json) = serde_json::to_string(&pong) {
                let _ = ws_write.send(Message::Text(json.into())).await;
            }
        }
        "command" => {
            let command_id = payload["command_id"].as_str().unwrap_or("unknown");
            let action = &payload["action"];
            let action_type = action["type"].as_str().unwrap_or("");

            // get_config sends a config_response, not a command_ack
            if action_type == "get_config" {
                tracing::info!("Manager command: get_config");
                let mut config_json = serde_json::to_value(relay_config).unwrap_or_default();
                // Redact secrets
                if let Some(mgr) = config_json.get_mut("manager") {
                    if let Some(obj) = mgr.as_object_mut() {
                        if obj.contains_key("node_secret") {
                            obj.insert(
                                "node_secret".to_string(),
                                serde_json::json!("***REDACTED***"),
                            );
                        }
                    }
                }
                if config_json.get("api_token").is_some() {
                    config_json["api_token"] = serde_json::json!("***REDACTED***");
                }
                let response = serde_json::json!({
                    "type": "config_response",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": config_json
                });
                if let Ok(json) = serde_json::to_string(&response) {
                    let _ = ws_write.send(Message::Text(json.into())).await;
                }
                return;
            }

            // rotate_secret is handled inline (needs config_path for persistence)
            if action_type == "rotate_secret" {
                let result = if let Some(new_secret) = action["new_secret"].as_str() {
                    if new_secret.is_empty() {
                        Err("Empty new_secret".to_string())
                    } else {
                        tracing::info!("Manager command: rotate_secret — updating node authentication secret");
                        // Persist new secret to config file
                        let mut updated = relay_config.clone();
                        if let Some(ref mut mgr) = updated.manager {
                            mgr.node_secret = Some(new_secret.to_string());
                        }
                        if let Ok(json) = serde_json::to_string_pretty(&updated) {
                            if let Err(e) = std::fs::write(config_path, &json) {
                                tracing::warn!("Failed to persist rotated secret: {e}");
                                ctx.event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, format!("Credential persistence failed: {}", e));
                            }
                        }
                        tracing::info!("Node secret rotated and persisted");
                        ctx.event_sender.emit(super::events::EventSeverity::Info, category::MANAGER, "Secret rotated successfully");
                        Ok(())
                    }
                } else {
                    Err("Missing new_secret".to_string())
                };

                let ack = serde_json::json!({
                    "type": "command_ack",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": {
                        "command_id": command_id,
                        "success": result.is_ok(),
                        "error": result.err()
                    }
                });
                if let Ok(json) = serde_json::to_string(&ack) {
                    let _ = ws_write.send(Message::Text(json.into())).await;
                }
                return;
            }

            let result = execute_command(action_type, action, ctx).await;

            // For list commands, include data in the ack
            let ack = match &result {
                Ok(Some(data)) => serde_json::json!({
                    "type": "command_ack",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": {
                        "command_id": command_id,
                        "success": true,
                        "data": data
                    }
                }),
                Ok(None) => serde_json::json!({
                    "type": "command_ack",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": {
                        "command_id": command_id,
                        "success": true
                    }
                }),
                Err(e) => serde_json::json!({
                    "type": "command_ack",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": {
                        "command_id": command_id,
                        "success": false,
                        "error": e
                    }
                }),
            };
            if let Ok(json) = serde_json::to_string(&ack) {
                let _ = ws_write.send(Message::Text(json.into())).await;
            }
        }
        "register_ack" => {
            tracing::debug!("Late register_ack received, ignoring");
        }
        _ => {
            tracing::debug!("Unknown message type from manager: {msg_type}");
        }
    }
}

async fn execute_command(
    action_type: &str,
    action: &serde_json::Value,
    ctx: &Arc<SessionContext>,
) -> Result<Option<serde_json::Value>, String> {
    match action_type {
        "disconnect_edge" => {
            let edge_id = action["edge_id"]
                .as_str()
                .ok_or("Missing edge_id")?;
            tracing::info!("Manager command: disconnect_edge '{edge_id}'");

            if let Some((_, conn)) = ctx.edge_connections.remove(edge_id) {
                conn.close(0u32.into(), b"disconnected by manager");
                // Session cleanup (tunnel teardown, peer notification) is handled
                // by the session task detecting the connection closure.
                Ok(None)
            } else {
                Err(format!("Edge '{edge_id}' is not connected"))
            }
        }
        "close_tunnel" => {
            let tunnel_id_str = action["tunnel_id"]
                .as_str()
                .ok_or("Missing tunnel_id")?;
            let tunnel_id: Uuid = tunnel_id_str
                .parse()
                .map_err(|e| format!("Invalid UUID: {e}"))?;
            tracing::info!("Manager command: close_tunnel '{tunnel_id}'");

            // Find the tunnel and unbind both sides
            let tunnel_info = ctx
                .router
                .list_tunnels()
                .into_iter()
                .find(|t| t.tunnel_id == tunnel_id);

            if let Some(info) = tunnel_info {
                if let Some(ref ingress_id) = info.ingress_edge_id {
                    ctx.router.unbind(&tunnel_id, ingress_id);
                }
                if let Some(ref egress_id) = info.egress_edge_id {
                    ctx.router.unbind(&tunnel_id, egress_id);
                }
                Ok(None)
            } else {
                Err(format!("Tunnel '{tunnel_id}' not found"))
            }
        }
        "list_tunnels" => {
            tracing::info!("Manager command: list_tunnels");
            let tunnels = ctx.router.list_tunnels();
            let data = serde_json::to_value(&tunnels).unwrap_or_default();
            Ok(Some(data))
        }
        "list_edges" => {
            tracing::info!("Manager command: list_edges");
            let edges: Vec<serde_json::Value> = ctx
                .edge_connections
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "edge_id": entry.key(),
                        "remote_addr": entry.value().remote_address().to_string()
                    })
                })
                .collect();
            Ok(Some(serde_json::json!(edges)))
        }
        "authorize_tunnel" => {
            let tunnel_id_str = action["tunnel_id"]
                .as_str()
                .ok_or("Missing tunnel_id")?;
            let tunnel_id: Uuid = tunnel_id_str
                .parse()
                .map_err(|e| format!("Invalid UUID: {e}"))?;
            let ingress_token = action["ingress_token"]
                .as_str()
                .ok_or("Missing ingress_token")?
                .to_string();
            let egress_token = action["egress_token"]
                .as_str()
                .ok_or("Missing egress_token")?
                .to_string();
            tracing::info!("Manager command: authorize_tunnel '{tunnel_id}'");
            ctx.router
                .authorize_tunnel(tunnel_id, ingress_token, egress_token);
            Ok(None)
        }
        "revoke_tunnel" => {
            let tunnel_id_str = action["tunnel_id"]
                .as_str()
                .ok_or("Missing tunnel_id")?;
            let tunnel_id: Uuid = tunnel_id_str
                .parse()
                .map_err(|e| format!("Invalid UUID: {e}"))?;
            tracing::info!("Manager command: revoke_tunnel '{tunnel_id}'");
            ctx.router.revoke_tunnel(&tunnel_id);
            Ok(None)
        }
        _ => Err(format!("Unknown relay command: {action_type}")),
    }
}

// ───────────────────────────────────────────────────────
// Credential persistence
// ───────────────────────────────────────────────────────

fn persist_credentials(
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    node_id: &str,
    node_secret: &str,
) {
    let mut config = relay_config.clone();
    if let Some(ref mut mgr) = config.manager {
        mgr.registration_token = None;
        mgr.node_id = Some(node_id.to_string());
        mgr.node_secret = Some(node_secret.to_string());
    }
    if let Ok(json) = serde_json::to_string_pretty(&config) {
        if let Err(e) = std::fs::write(config_path, &json) {
            tracing::warn!("Failed to persist manager credentials: {e}");
        } else {
            tracing::info!(
                "Manager credentials saved to {}",
                config_path.display()
            );
        }
    }
}
