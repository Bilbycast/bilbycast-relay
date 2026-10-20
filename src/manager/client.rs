// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

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
use crate::distribution_control::DistributionControl;
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
#[allow(clippy::too_many_arguments)]
pub fn start_manager_client(
    config: ManagerConfig,
    ctx: Arc<SessionContext>,
    relay_stats: Arc<RelayStats>,
    relay_config: RelayConfig,
    config_path: PathBuf,
    event_rx: mpsc::Receiver<Event>,
    event_sender: super::events::EventSender,
    distribution_control: Option<Arc<DistributionControl>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        manager_client_loop(
            config,
            ctx,
            relay_stats,
            relay_config,
            config_path,
            event_rx,
            event_sender,
            distribution_control,
            connect_to_manager,
        )
        .await;
    })
}

/// The reconnect loop. `connect` opens the WebSocket for one attempt —
/// [`connect_to_manager`] in the relay, an in-memory stream in the tests —
/// and [`run_session`] runs it.
#[allow(clippy::too_many_arguments)]
async fn manager_client_loop<C, F, S>(
    config: ManagerConfig,
    ctx: Arc<SessionContext>,
    relay_stats: Arc<RelayStats>,
    relay_config: RelayConfig,
    config_path: PathBuf,
    mut event_rx: mpsc::Receiver<Event>,
    event_sender: super::events::EventSender,
    distribution_control: Option<Arc<DistributionControl>>,
    mut connect: C,
) where
    C: FnMut(String, ManagerConfig) -> F,
    F: std::future::Future<Output = Result<tokio_tungstenite::WebSocketStream<S>, String>>,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Multi-URL failover: rotate to the next manager URL on each close/error;
    // constant 5 s backoff between attempts (no delay while connected; never
    // accumulates). 1-16 URLs in config.urls.
    let fixed_backoff = Duration::from_secs(5);
    let mut cursor: usize = 0;
    // Made once, before the loop, and handed to every session: a session
    // records here what it learns about the credentials — a registration, a
    // rotated secret, which candidate secret the manager accepted — and the
    // next attempt must authenticate with that, not with the startup config.
    let mut creds = LinkCredentials::new(config);

    // Surface manager-link state on the relay's OWN local REST/metrics
    // (purely local observability — no WS-protocol change). A configured
    // manager means the reconnect loop is running, so the local surface
    // reports `reconnecting` whenever the link is down.
    relay_stats
        .manager_configured
        .store(true, std::sync::atomic::Ordering::Relaxed);

    loop {
        let urls = &creds.config.urls;
        if urls.is_empty() {
            tracing::error!("Manager client started with no URLs — config.urls is empty");
            tokio::time::sleep(fixed_backoff).await;
            continue;
        }
        let current_url = urls[cursor % urls.len()].clone();
        // For the log only: a manager URL may carry a credential for whatever
        // fronts the manager (a userinfo, a `?token=`).
        let shown_url = crate::config::redact_url(&current_url);
        tracing::info!(
            "Connecting to manager at {shown_url} (url {} of {})",
            (cursor % urls.len()) + 1,
            urls.len(),
        );

        let ended = match connect(current_url, creds.config.clone()).await {
            Ok(ws_stream) => run_session(ws_stream, &mut creds, &ctx, &relay_stats, &relay_config, &config_path, &mut event_rx, &event_sender, distribution_control.as_ref()).await,
            Err(e) => Err(e),
        };
        match ended {
            Ok(()) => {
                tracing::info!("Manager connection to {shown_url} closed normally");
                event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, "Manager connection lost, rotating to next URL");
            }
            Err(e) => {
                tracing::warn!("Manager connection to {shown_url} failed: {e}");
                event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, format!("Manager connection lost, rotating to next URL: {}", e));
            }
        }

        // The link is down again (an attempt only ends on close/error).
        // Stamp the disconnect for the local manager-link surface.
        relay_stats.mark_manager_disconnected();

        cursor = cursor.wrapping_add(1);
        tracing::info!(
            "Reconnecting to next manager URL in {}s...",
            fixed_backoff.as_secs()
        );
        tokio::time::sleep(fixed_backoff).await;
    }
}

/// How many secrets the relay keeps besides the one it presents.
///
/// Each is one refused authentication at worst, and the manager locks a node
/// out after five refusals in 60 s (`NodeAuthLimiter`). Four fallbacks means
/// the right secret is reached on the fifth attempt at the latest, before the
/// lockout would refuse it too.
const MAX_FALLBACK_SECRETS: usize = 4;

/// What the reconnect loop authenticates with, carried from one connection to
/// the next.
///
/// The connection that learns of a change — a registration, a rotated secret,
/// which of several candidate secrets the manager accepted — updates this in
/// place, so the change survives however that connection ends. Registration
/// used to hand its credentials back in the `Ok` value a session ended with,
/// and a connection reset, the usual way a WebSocket ends, comes back as
/// `Err`: the credentials were dropped, and the relay presented its consumed
/// registration token at every reconnect until it was restarted.
struct LinkCredentials {
    /// The connection settings. `node_secret` is the secret presented at the
    /// next authentication.
    config: ManagerConfig,
    /// Secrets the manager may hold instead of `config.node_secret`, the most
    /// likely first. Empty except between a rotation and the first
    /// authentication that shows which secret the manager stored.
    fallback_secrets: Vec<String>,
}

impl LinkCredentials {
    fn new(config: ManagerConfig) -> Self {
        Self {
            config,
            fallback_secrets: Vec::new(),
        }
    }

    /// The manager registered the relay and issued these credentials.
    fn registered(&mut self, node_id: String, node_secret: String) {
        self.config.registration_token = None;
        self.config.node_id = Some(node_id);
        self.config.node_secret = Some(node_secret);
        self.fallback_secrets.clear();
    }

    /// The relay saved `new_secret` and answered the `rotate_secret` that
    /// carried it. `ack_sent` is whether that answer was written to the
    /// connection.
    ///
    /// The relay cannot know whether the manager stored the new secret. The
    /// manager stores it only once it reads a successful acknowledgement, so it
    /// keeps the old one when the acknowledgement is lost with the connection,
    /// arrives after the manager's 10 s wait, or its database write fails. A
    /// relay that simply switched to the new secret would be refused at its
    /// next reconnect in each of those cases, and keep being refused. A relay
    /// that kept the old one — as this one did, until a restart read the file
    /// — is refused whenever the rotation did land. So it keeps both, presents
    /// the likelier one first and falls back to the other ([`Self::rejected`])
    /// until an authentication settles it ([`Self::accepted`]).
    ///
    /// The likelier one is the new secret when the acknowledgement left, and
    /// the old one when it did not, since then the manager cannot have read it.
    ///
    /// The fallbacks live in memory only. A relay restarted before its next
    /// authentication presents the secret in the file, with nothing to fall
    /// back to. When the acknowledgement did not leave, the handler has put
    /// the secret presented first back in the file, since this rotation
    /// cannot have reached the manager. When it did, the file holds the new
    /// one: right whenever the manager stored that rotation, and locked out
    /// when it did not.
    fn rotated(&mut self, new_secret: String, ack_sent: bool) {
        if ack_sent {
            if let Some(previous) = self.config.node_secret.replace(new_secret) {
                self.fallback_secrets.insert(0, previous);
            }
        } else {
            self.fallback_secrets.push(new_secret);
        }
        // Oldest last, and the least likely: it is the manager's only if every
        // rotation since was lost.
        self.fallback_secrets.truncate(MAX_FALLBACK_SECRETS);
    }

    /// The manager refused `config.node_secret`. Present the next candidate at
    /// the next attempt.
    ///
    /// The refused secret goes to the back rather than away. A refusal is not
    /// always a verdict on the secret: the manager also answers `auth_error`
    /// while a node is locked out and when its database read fails.
    fn rejected(&mut self) {
        if self.fallback_secrets.is_empty() {
            return;
        }
        let next = self.fallback_secrets.remove(0);
        if let Some(refused) = self.config.node_secret.replace(next) {
            self.fallback_secrets.push(refused);
        }
    }

    /// The manager accepted `config.node_secret`. Returns whether this settled
    /// which secret it holds, in which case the caller saves it: the config
    /// file holds the secret presented first after the rotation, and the
    /// manager may have accepted another.
    fn accepted(&mut self) -> bool {
        let settled = !self.fallback_secrets.is_empty();
        self.fallback_secrets.clear();
        settled
    }
}

/// Open the WebSocket to the manager at `current_url`, over TLS as `config`
/// asks. It takes its arguments by value so the reconnect loop can take it as
/// a plain function; the loop hands it a copy of the credentials it holds.
async fn connect_to_manager(
    current_url: String,
    config: ManagerConfig,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    let current_url = current_url.as_str();
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

    Ok(ws_stream)
}

/// One manager session over an established WebSocket: authenticate, then pump
/// stats, health, events and commands until the connection ends.
///
/// Separate from [`connect_to_manager`] so the tests can drive it over an
/// in-memory stream; `connect_to_manager` only enforces `wss://` and builds
/// the TLS connection.
#[allow(clippy::too_many_arguments)]
async fn run_session<T>(
    ws_stream: tokio_tungstenite::WebSocketStream<T>,
    creds: &mut LinkCredentials,
    ctx: &Arc<SessionContext>,
    relay_stats: &Arc<RelayStats>,
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    event_rx: &mut mpsc::Receiver<Event>,
    event_sender: &super::events::EventSender,
    distribution_control: Option<&Arc<DistributionControl>>,
) -> Result<(), String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Step 1: Send auth message
    let auth_msg = build_auth_message(&creds.config);
    if let Ok(json) = serde_json::to_string(&auth_msg) {
        ws_write
            .send(Message::Text(json.into()))
            .await
            .map_err(|e| format!("Failed to send auth: {e}"))?;
    }

    // Step 2: Wait for auth response (10s timeout)
    let auth_timeout = tokio::time::timeout(Duration::from_secs(10), ws_read.next()).await;

    match auth_timeout {
        Ok(Some(Ok(Message::Text(text)))) => {
            let response: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("Invalid auth response: {e}"))?;

            match response["type"].as_str().unwrap_or("") {
                "auth_ok" => {
                    tracing::info!("Authenticated with manager");
                    relay_stats.mark_manager_connected();
                    event_sender.emit(super::events::EventSeverity::Info, category::MANAGER, "Connected to manager");
                    if creds.accepted()
                        && let Some(secret) = &creds.config.node_secret
                    {
                        // The file holds the secret presented first after the
                        // rotation, which the manager may never have stored.
                        // Save the one it just accepted, so a restart presents
                        // it too.
                        match persist_node_secret(relay_config, config_path, &creds.config, secret) {
                            Ok(()) => tracing::info!(
                                "Manager accepted a node secret after a rotation; saved it to {}",
                                config_path.display()
                            ),
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to save the node secret the manager accepted: {e}; \
                                     after a restart the relay may present one the manager does not hold"
                                );
                                event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, format!("Credential persistence failed: {}", e));
                            }
                        }
                    }
                }
                "register_ack" => {
                    let payload = &response["payload"];
                    let node_id = payload["node_id"].as_str().unwrap_or("").to_string();
                    let node_secret = payload["node_secret"].as_str().unwrap_or("").to_string();
                    tracing::info!("Registered with manager: node_id={node_id}");
                    relay_stats.mark_manager_connected();
                    event_sender.emit(super::events::EventSeverity::Info, category::MANAGER, "Connected to manager");

                    if !node_id.is_empty() && !node_secret.is_empty() {
                        persist_credentials(relay_config, config_path, &node_id, &node_secret);
                        creds.registered(node_id, node_secret);
                    }
                }
                "auth_error" => {
                    let msg = response["message"].as_str().unwrap_or("Unknown auth error");
                    event_sender.emit(super::events::EventSeverity::Critical, category::MANAGER, format!("Manager authentication failed: {}", msg));
                    creds.rejected();
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
    let health = build_health_message(ctx, relay_stats, relay_config, distribution_control);
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
                if let Ok(json) = serde_json::to_string(&envelope)
                    && ws_write.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
            }

            _ = health_interval.tick() => {
                let envelope = build_health_message(ctx, relay_stats, relay_config, distribution_control);
                if let Ok(json) = serde_json::to_string(&envelope)
                    && ws_write.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
            }

            msg = ws_read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_manager_message(&text, ctx, relay_config, config_path, &mut ws_write, distribution_control, creds).await;
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
                if let Ok(json) = serde_json::to_string(&envelope)
                    && ws_write.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
            }
        }
    }

    Ok(())
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
    // Native plain-UDP plane (native SRT/RIST over relay + individual bonded
    // legs). Streamed alongside the QUIC tunnels — previously only the aggregate
    // count crossed the wire (in the 15s health), so a relay forwarding bond
    // legs showed no per-leg rows. The relay stays opaque: each session carries
    // only the tunnel UUID + post-NAT addrs (no edge identity, no bond grouping)
    // — the manager joins the UUID to its tunnel table for a friendly name.
    let udp_sessions = ctx.udp_sessions.list();
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

    let mut stats = serde_json::json!({
        "tunnels": tunnel_infos,
        "udp_sessions": udp_sessions,
        "udp_sessions_total": ctx.udp_sessions.count(),
        "udp_sessions_active": ctx.udp_sessions.active_count(),
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
    });

    // Viewer-distribution telemetry (present only when the subsystem runs) —
    // lets the manager dashboard show live viewer counts per relay.
    if let Some(d) = relay_stats.distribution_snapshot() {
        stats["distribution"] = serde_json::json!({
            "streams": d.streams,
            "viewers": d.viewers,
            "bytes_out": d.bytes_out,
            "origin_bytes": d.origin_bytes,
            // Additive JSON field on an existing stats message — the manager
            // parses this object loosely, so an older manager simply ignores
            // it. No wire-format or protocol-version change.
            "offpath_sessions": d.offpath_sessions,
        });
    }

    stats
}

/// Parse one origin retention policy patch, bounding every field.
///
/// The bounds are not decoration. `max_bytes_per_stream` below one segment
/// evicts each segment as it lands, which presents as a stream that accepts
/// PUTs and serves an empty window — healthy-looking and unplayable. A
/// retention of zero does the same by age.
fn parse_origin_policy_patch(
    v: &serde_json::Value,
) -> Result<crate::distribution_control::OriginPolicyPatch, String> {
    let obj = v.as_object().ok_or_else(|| "must be an object".to_string())?;
    for k in obj.keys() {
        if !matches!(
            k.as_str(),
            "retention_secs" | "max_bytes_per_stream" | "min_segments" | "idle_grace_secs"
        ) {
            return Err(format!("unknown field '{k}'"));
        }
    }
    let num = |name: &str| -> Result<Option<u64>, String> {
        match obj.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(x) => x
                .as_u64()
                .ok_or_else(|| format!("{name} must be a non-negative integer"))
                .map(Some),
        }
    };

    let mut patch = crate::distribution_control::OriginPolicyPatch::default();

    if let Some(n) = num("retention_secs")? {
        // 24 h ceiling: the DVR feature asks for 60 minutes, and a runaway
        // value here fills the volume rather than erroring.
        if !(1..=86_400).contains(&n) {
            return Err("retention_secs must be 1..=86400".to_string());
        }
        patch.retention_secs = Some(n);
    }
    if let Some(n) = num("max_bytes_per_stream")? {
        // 16 MiB floor comfortably exceeds one 2 s segment of high-bitrate HD.
        if n < 16 * 1024 * 1024 {
            return Err("max_bytes_per_stream must be at least 16 MiB".to_string());
        }
        patch.max_bytes_per_stream = Some(n);
    }
    if let Some(n) = num("min_segments")? {
        if !(1..=64).contains(&n) {
            return Err("min_segments must be 1..=64".to_string());
        }
        patch.min_segments = Some(n as usize);
    }
    if let Some(n) = num("idle_grace_secs")? {
        if n > 86_400 {
            return Err("idle_grace_secs must be <= 86400".to_string());
        }
        patch.idle_grace_secs = Some(n);
    }
    if patch.is_empty() {
        return Err("no recognised fields".to_string());
    }
    Ok(patch)
}

/// Undo `get_config`'s redaction on a cascade source pushed back with it.
///
/// A source carries the marker if its `token` is the marker or its
/// `upstream_whep_url` holds one (a `?token=` or a userinfo, see
/// [`crate::config::redact_url`]). It is matched against the source this relay
/// **runs** for the same `local_stream` — the last entry for that stream, which
/// is the one the cascade supervisor keeps — and only when that source redacts
/// to exactly the URL pushed. The real URL and the real token then come back
/// from it. The marker is not a credential: pulled with it, the upstream would
/// refuse every retry, silently.
///
/// With nothing to restore from (a new source, an upstream that changed, a
/// source with no token to keep), the push is refused rather than run with the
/// marker as its credential.
fn restore_redacted_cascade_source(
    src: &mut crate::config::CascadeSource,
    current: &[crate::config::CascadeSource],
) -> Result<(), String> {
    use crate::config::{is_redaction_marker, redact_url, url_holds_marker};
    let url_redacted = url_holds_marker(&src.upstream_whep_url);
    let token_redacted = src.token.as_deref().is_some_and(is_redaction_marker);
    if !url_redacted && !token_redacted {
        return Ok(());
    }
    let nothing_to_keep = || {
        format!(
            "'{}' carries the redaction marker, but this relay runs no source for it that \
             redacts to {} — send the credential itself",
            src.local_stream, src.upstream_whep_url
        )
    };
    let running = current
        .iter()
        .rev()
        .find(|c| c.local_stream == src.local_stream)
        .filter(|c| redact_url(&c.upstream_whep_url) == src.upstream_whep_url)
        .ok_or_else(nothing_to_keep)?;
    let token = if token_redacted {
        Some(running.token.clone().ok_or_else(nothing_to_keep)?)
    } else {
        src.token.clone()
    };
    if url_redacted {
        src.upstream_whep_url = running.upstream_whep_url.clone();
    }
    src.token = token;
    Ok(())
}

/// Parse a pushed `cascade_sources` list into what the relay will run: each
/// entry deserialised, every redaction marker restored, the result through the
/// same validator config load uses (`config::validate_cascade_sources`), and
/// no `local_stream` twice. Reads the current set; applies nothing.
fn parse_cascade_sources(
    arr: &[serde_json::Value],
    current: &[crate::config::CascadeSource],
) -> Result<Vec<crate::config::CascadeSource>, String> {
    let mut sources = Vec::with_capacity(arr.len());
    for v in arr {
        let src: crate::config::CascadeSource = serde_json::from_value(v.clone())
            .map_err(|e| format!("invalid cascade source: {e}"))?;
        sources.push(src);
    }
    // The supervisor keys pulls by `local_stream` and keeps the last, so a
    // second entry would be acked and silently never pulled.
    if let Some(stream) = crate::config::duplicate_local_streams(&sources).first() {
        return Err(format!(
            "cascade_sources: local_stream '{stream}' appears more than once"
        ));
    }
    for (i, src) in sources.iter_mut().enumerate() {
        restore_redacted_cascade_source(src, current)
            .map_err(|e| format!("cascade_sources[{i}]: {e}"))?;
    }
    // After the restore, so what is checked is what would run. A pushed source
    // used to skip every check a config file gets — a scheme the pull cannot
    // dial, a stream name no viewer URL can present, any number of entries.
    crate::config::validate_cascade_sources(&sources, "cascade_sources")
        .map_err(|e| e.to_string())?;
    Ok(sources)
}

/// Apply a manager `configure_distribution` command onto the runtime control
/// cell (secret / gates / public IP+URL / storage policy / cascade sources).
/// Partial: only the fields present in the action are changed.
///
/// **All or nothing.** Every key is parsed, validated and (for a redaction
/// marker) restored before anything is applied, so a refused push changes
/// nothing. It used to apply the secret and the gates first and refuse a bad
/// cascade source or policy after — leaving a new secret live, acked as a
/// failure, and never persisted, so the relay lost it at its next restart.
fn apply_configure_distribution(
    control: Option<&Arc<DistributionControl>>,
    action: &serde_json::Value,
) -> Result<(), String> {
    let Some(control) = control else {
        return Err(
            "this relay is not a viewer-distribution node (built without the feature, or role disabled)"
                .to_string(),
        );
    };
    use crate::distribution_control::DistUpdate;

    // ── Parse and validate everything first: only this half may refuse. ──
    let mut update = DistUpdate::default();
    // `get_config` shows a set secret as the redaction marker. A push that
    // carries the marker back is "keep the one you have" — never a value, and
    // never a reason to abort the rest of the push.
    if let Some(s) = action
        .get("token_secret")
        .and_then(|v| v.as_str())
        .filter(|s| !crate::config::is_redaction_marker(s))
    {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("token_secret must be exactly 64 hex chars".to_string());
        }
        update.token_secret = Some(s.to_string());
    }
    if let Some(b) = action.get("require_viewer_token").and_then(|v| v.as_bool()) {
        update.require_viewer_token = Some(b);
    }
    if let Some(b) = action.get("require_origin_token").and_then(|v| v.as_bool()) {
        update.require_origin_token = Some(b);
    }
    if let Some(b) = action.get("require_ingest_token").and_then(|v| v.as_bool()) {
        update.require_ingest_token = Some(b);
    }
    // An empty string is "the operator left the box blank", not a value.
    //
    // The manager's own validators admit `""` for these three (each is guarded
    // by `!v.is_empty() &&`) and its Distribution tab sends all three keys on
    // every save, so a blank Public IP arrived here as `""` — and rejecting it
    // aborts the WHOLE command, so the token secret, the gates and the cascade
    // sources in the same push were not applied either. The ordinary case of
    // saving that form with one box empty silently applied nothing.
    let non_empty = |k: &str| -> Option<String> {
        action
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    if let Some(s) = non_empty("public_ip") {
        match s.parse() {
            Ok(ip) => update.public_ip = Some(ip),
            Err(_) => return Err(format!("invalid public_ip '{s}'")),
        }
    }
    if let Some(s) = non_empty("portal_url") {
        if !s.starts_with("http://") && !s.starts_with("https://") {
            return Err("portal_url must start with http:// or https://".to_string());
        }
        update.portal_url = Some(s);
    }
    if let Some(s) = non_empty("public_base_url") {
        if !(s.starts_with("http://") || s.starts_with("https://")) {
            return Err("public_base_url must start with http:// or https://".to_string());
        }
        update.public_base_url = Some(s);
    }

    // Storage policy: node-wide default plus per-stream overrides. Both
    // optional, so a push that only rotates the token secret leaves retention
    // exactly as it was.
    let mut origin_update = crate::distribution_control::OriginPolicyUpdate::default();
    let mut origin_touched = false;
    if let Some(v) = action.get("origin_policy") {
        let patch = parse_origin_policy_patch(v).map_err(|e| format!("origin_policy: {e}"))?;
        origin_update.default = Some(patch);
        origin_touched = true;
    }
    if let Some(v) = action.get("origin_stream_policies") {
        let obj = v
            .as_object()
            .ok_or_else(|| "origin_stream_policies must be an object keyed by stream id".to_string())?;
        let mut per_stream = Vec::with_capacity(obj.len());
        for (stream, pv) in obj {
            // Same sanitiser the request path uses. A length check alone
            // accepts a name no request can ever present — the override is
            // then stored, acked as applied, reported on the health tick and
            // matches nothing, so the session's window silently never applies.
            if crate::distribution_control::sanitize_stream_id(stream).as_deref() != Some(stream.as_str()) {
                return Err(format!("invalid stream id '{stream}'"));
            }
            let patch = parse_origin_policy_patch(pv)
                .map_err(|e| format!("origin_stream_policies['{stream}']: {e}"))?;
            per_stream.push((stream.clone(), patch));
        }
        // An empty object is meaningful: it clears every override.
        origin_update.per_stream = Some(per_stream);
        origin_touched = true;
    }

    let cascade = match action.get("cascade_sources").and_then(|v| v.as_array()) {
        Some(arr) => Some(parse_cascade_sources(arr, &control.cascade_now())?),
        None => None,
    };

    // ── Apply. Everything above has been accepted. ──
    control.apply(update);
    if origin_touched {
        control.set_origin_policy(origin_update);
    }
    if let Some(sources) = cascade {
        control.set_cascade(sources);
    }

    // Streams to drop outright. Applied after the policy above, so a push that
    // both re-states the override set and retires a session's streams does the
    // two in the order the manager meant them.
    if let Some(list) = action.get("drop_origin_streams").and_then(|v| v.as_array()) {
        for name in list.iter().filter_map(|v| v.as_str()) {
            // The origin sanitises its own stream ids; this only forwards.
            control.drop_stream(name);
        }
    }

    // Streams whose session is over but whose clips are not. The media goes,
    // the clips stay until the manager sends the stream to
    // `drop_origin_streams` at the end of their own retention.
    if let Some(list) = action.get("retire_origin_streams").and_then(|v| v.as_array()) {
        for name in list.iter().filter_map(|v| v.as_str()) {
            control.retire_stream(name);
        }
    }

    tracing::info!("configure_distribution applied from manager");
    Ok(())
}

/// The whole `configure_distribution` command as the handler runs it: apply,
/// and persist to `config.json` only what was applied, so the config survives a
/// relay restart without the manager having to re-push.
fn configure_distribution(
    control: Option<&Arc<DistributionControl>>,
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    action: &serde_json::Value,
) -> Result<(), String> {
    apply_configure_distribution(control, action)?;
    persist_distribution_config(control, relay_config, config_path);
    Ok(())
}

/// Rewrite the config file, changing only what `edit` touches.
///
/// **Read from disk, not from the startup snapshot.** Three separate places
/// persist to this one file — registration credentials, a rotated secret, and
/// the distribution config the manager pushes — and each used to rebuild the
/// whole file from the `RelayConfig` captured at startup. Whichever wrote last
/// silently reverted the others.
///
/// That was not theoretical. A relay registers, writes its `node_secret` and
/// clears the consumed `registration_token`; the manager then pushes a
/// distribution config, which rewrites the file from the startup snapshot —
/// restoring the burnt registration token and erasing the secret. The relay
/// keeps running, because it is already authenticated. On its next restart it
/// presents a token the manager has already consumed, is refused with
/// "Invalid registration token", and never reconnects. It goes on forwarding
/// media while being invisible to the manager, until an operator notices and
/// reissues a token by hand.
///
/// Falling back to the in-memory config when the file cannot be read keeps the
/// old behaviour for the case it was written for — a file that is missing or
/// unparseable — rather than refusing to persist at all.
fn update_config_file(
    config_path: &PathBuf,
    fallback: &RelayConfig,
    edit: impl FnOnce(&mut RelayConfig),
) -> Result<(), String> {
    if config_path.as_os_str().is_empty() {
        return Ok(()); // running without a config file — nothing to persist to
    }
    let mut config = match std::fs::read_to_string(config_path)
        .ok()
        .and_then(|t| serde_json::from_str::<RelayConfig>(&t).ok())
    {
        Some(on_disk) => on_disk,
        None => {
            tracing::warn!(
                "could not re-read {config_path:?}; persisting from the in-memory config, \
                 which may drop changes another writer made since startup"
            );
            fallback.clone()
        }
    };
    edit(&mut config);
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(config_path, &json).map_err(|e| e.to_string())
}

/// Persist the current runtime distribution config into the relay's config.json
/// so it survives a restart without the manager having to re-push. Best-effort:
/// a write failure is logged, not fatal (the manager re-pushes on reconnect).
fn persist_distribution_config(
    control: Option<&Arc<DistributionControl>>,
    relay_config: &RelayConfig,
    config_path: &PathBuf,
) {
    let Some(control) = control else { return };
    if config_path.as_os_str().is_empty() {
        return; // running without a config file — nothing to persist to
    }
    let rt = control.load();
    let cascade = control.cascade_now();
    let origin_policy = control.origin_policy_now();
    if let Err(e) = update_config_file(config_path, relay_config, |config| {
        let dcfg = config
            .distribution
            .get_or_insert_with(crate::config::DistributionConfig::default);
        dcfg.enabled = true;
        dcfg.token_secret = rt.token_secret.clone();
        dcfg.require_viewer_token = rt.require_viewer_token;
        // The origin gate persists alongside its two siblings. Omitting it
        // made it the only gate that did not survive a restart — and because
        // `require_viewer_token` did, an operator inspecting the file after a
        // restart saw a gated session and concluded correctly for WHEP and
        // wrongly for the CMAF tier, which is the exact bypass the gate exists
        // to close. It fails OPEN, so the omission was silent.
        dcfg.require_origin_token = rt.require_origin_token;
        dcfg.require_ingest_token = rt.require_ingest_token;
        dcfg.public_ip = rt.public_ip.map(|ip| ip.to_string());
        dcfg.public_base_url = rt.public_base_url.clone();
        dcfg.portal_url = rt.portal_url.clone();
        dcfg.cascade_sources = cascade;
        // The node-wide storage policy persists too: it is the floor every
        // stream falls back to, and losing it silently narrows the window on
        // the next restart.
        //
        // Per-stream overrides deliberately do NOT persist. They belong to a
        // session, and a session that ended while the relay was down must not
        // come back holding that stream's disk at the widened window with
        // nothing left referencing it.
        if let Some(d) = &origin_policy.default {
            if let Some(v) = d.retention_secs {
                dcfg.origin_retention_secs = v;
            }
            if let Some(v) = d.max_bytes_per_stream {
                dcfg.origin_max_bytes_per_stream = v;
            }
            if let Some(v) = d.min_segments {
                dcfg.origin_window_segments = v;
            }
            if let Some(v) = d.idle_grace_secs {
                dcfg.origin_idle_grace_secs = v;
            }
        }
    }) {
        tracing::warn!("failed to persist distribution config to {config_path:?}: {e}");
    }
}

fn build_health_message(
    ctx: &SessionContext,
    relay_stats: &RelayStats,
    relay_config: &RelayConfig,
    distribution_control: Option<&Arc<DistributionControl>>,
) -> serde_json::Value {
    let (total_tunnels, active_tunnels) = ctx.router.counts();
    let tunnel_infos = ctx.router.list_tunnels();
    let total_bytes_ingress: u64 = tunnel_infos.iter().map(|t| t.stats.bytes_ingress).sum();
    let total_bytes_egress: u64 = tunnel_infos.iter().map(|t| t.stats.bytes_egress).sum();

    // Capability bits the manager UI gates on. "udp-relay" => native SRT/RIST
    // (no-QUIC) tunnels. "viewer-distribution" => WHEP SFU + LL-HLS origin.
    let mut capabilities: Vec<&str> = Vec::new();
    if relay_config.udp_relay_enabled {
        capabilities.push("udp-relay");
    }
    let dist_snapshot = relay_stats.distribution_snapshot();
    if dist_snapshot.is_some() {
        capabilities.push("viewer-distribution");
        // "origin-policy" => this build understands `require_origin_token`,
        // `origin_policy` and `origin_stream_policies` on
        // `configure_distribution`. A relay that predates them advertises
        // `viewer-distribution` just the same and **acks the push anyway** —
        // unknown keys are ignored, so the manager records a gate or a
        // retention window as applied when nothing was. The bit is what lets
        // the manager refuse instead of reporting a success it cannot see is
        // false.
        capabilities.push("origin-policy");
    }

    let mut payload = serde_json::json!({
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
        "quic_addr": relay_config.quic_addr,
        // Advertised address remote edges should dial (distinct
        // from the bind list). Omitted when unset — manager UI
        // falls back to `quic_addr` for legacy single-host setups.
        "public_quic_addr": relay_config.public_quic_addr,
        // Native plain-UDP relay (SRT/RIST without QUIC). Advertised so the
        // manager can offer the native-relay endpoint + gate the UI on it.
        "public_udp_addr": relay_config.public_udp_addr,
        "udp_sessions_total": ctx.udp_sessions.count(),
        "udp_sessions_active": ctx.udp_sessions.active_count(),
        "capabilities": capabilities
    });

    // Distribution telemetry + advertised viewer base URL, when the subsystem
    // is running. Lets the manager render live viewer counts and build
    // shareable viewer links.
    if let Some(d) = dist_snapshot {
        let viewers = relay_stats.viewer_metrics();
        payload["distribution"] = serde_json::json!({
            "streams": d.streams,
            "viewers": d.viewers,
            "bytes_out": d.bytes_out,
            "origin_bytes": d.origin_bytes,
            "offpath_sessions": d.offpath_sessions,
            // Per-stream breakdown of origin_bytes, so an operator watching a
            // volume fill can see *which* stream is spending it and whether a
            // retention override put it there. Rides health (15 s), not stats
            // (1 s): it changes on the scale of a segment, and a list on every
            // stats tick is bandwidth for nothing. Additive — an older manager
            // parses the object loosely and ignores it.
            "origin_streams": d.origin_streams,
            // What each viewer's player last reported about its playback —
            // buffer ahead, stalls, reconnects, bandwidth estimate — bounded
            // (`origin::metrics::MAX_REPORTED`) and shared fairly across
            // streams. The manager joins each to a portal login by `client`
            // and shows it on the DVR Sessions page. Additive, as above.
            "viewer_metrics": viewers.reports,
            // Per stream, how many clients hold a live report and how many of
            // them made the list, so a cut reads as a cut on the manager and
            // not as viewers who stopped reporting.
            "viewer_metrics_streams": viewers.streams,
        });
    }
    // Advertised viewer base URL — the runtime (manager-pushed) value wins over
    // the config bootstrap so the manager's relay card + viewer links track the
    // live setting.
    let base_url = distribution_control
        .and_then(|c| c.load().public_base_url.clone())
        .or_else(|| relay_config.distribution.as_ref().and_then(|d| d.public_base_url.clone()));
    if let Some(base) = base_url {
        payload["distribution_base_url"] = serde_json::json!(base);
    }

    serde_json::json!({
        "type": "health",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "payload": payload
    })
}

/// The `new_secret` of a `rotate_secret` command, if it is one the relay may
/// persist. `get_config`'s redaction marker is not a secret: persisting it
/// would lock the relay out at its next restart.
fn rotated_secret(action: &serde_json::Value) -> Result<&str, String> {
    match action["new_secret"].as_str() {
        None => Err("Missing new_secret".to_string()),
        Some("") => Err("Empty new_secret".to_string()),
        Some(s) if crate::config::is_redaction_marker(s) => {
            Err("new_secret is the redaction marker, not a secret".to_string())
        }
        Some(s) => Ok(s),
    }
}

/// The `config_response` the relay answers `get_config` with.
///
/// Every credential in the config is redacted ([`RelayConfig::redacted_json`]).
/// On the manager, reading a node's config needs only View on it, so anything
/// this carries in clear is handed to every user a relay is shared with — and
/// `distribution.token_secret` is the key the manager signs every viewer and
/// ingest token with, installation-wide.
fn build_config_response(relay_config: &RelayConfig) -> serde_json::Value {
    serde_json::json!({
        "type": "config_response",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "payload": relay_config.redacted_json()
    })
}

// ───────────────────────────────────────────────────────
// Command handling
// ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_manager_message<S>(
    text: &str,
    ctx: &Arc<SessionContext>,
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    ws_write: &mut futures_util::stream::SplitSink<S, Message>,
    distribution_control: Option<&Arc<DistributionControl>>,
    creds: &mut LinkCredentials,
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
                let response = build_config_response(relay_config);
                if let Ok(json) = serde_json::to_string(&response) {
                    let _ = ws_write.send(Message::Text(json.into())).await;
                }
                return;
            }

            // rotate_secret is handled inline: it writes to config_path, and it
            // changes the secret the next reconnect presents.
            //
            // The order is save, answer, adopt. A secret the relay could not
            // save is refused: the manager is told so and keeps the old secret,
            // which the relay goes on presenting. Answering success for it
            // instead would have the manager store a secret the file does not
            // hold, and the relay would be locked out at its next restart. The
            // answer is sent before the secret is adopted because whether it
            // left decides which secret the relay presents first — see
            // `LinkCredentials::rotated`, which also keeps the old secret for an
            // answer the manager never reads.
            if action_type == "rotate_secret" {
                let result = rotated_secret(action).and_then(|new_secret| {
                    tracing::info!("Manager command: rotate_secret — updating node authentication secret");
                    // Through the shared helper: rotating must not revert the
                    // distribution config the manager pushed since startup.
                    match persist_node_secret(relay_config, config_path, &creds.config, new_secret) {
                        Ok(()) => Ok(new_secret.to_string()),
                        Err(e) => {
                            tracing::warn!("Failed to persist rotated secret: {e}");
                            ctx.event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, format!("Credential persistence failed: {}", e));
                            Err(format!("The relay could not save the new secret, so it keeps its current one: {e}"))
                        }
                    }
                });

                let ack = serde_json::json!({
                    "type": "command_ack",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": {
                        "command_id": command_id,
                        "success": result.is_ok(),
                        "error": result.as_ref().err()
                    }
                });
                let ack_sent = match serde_json::to_string(&ack) {
                    Ok(json) => ws_write.send(Message::Text(json.into())).await.is_ok(),
                    Err(_) => false,
                };
                if let Ok(new_secret) = result {
                    if ack_sent {
                        tracing::info!("Node secret rotated and persisted; the next authentication presents it");
                        ctx.event_sender.emit(super::events::EventSeverity::Info, category::MANAGER, "Secret rotated successfully");
                    } else {
                        // The manager cannot have read an answer that never
                        // left, so this rotation changed nothing there, and the
                        // file goes back to the secret the relay presents
                        // first. The answer failed because the connection did,
                        // so the relay may stay unconnected for a while —
                        // through a manager outage, say — and a restart in that
                        // time would otherwise present the new secret from the
                        // file with nothing to fall back to.
                        tracing::warn!(
                            "Node secret rotated and persisted, but the acknowledgement did not reach the \
                             manager; the relay keeps presenting the previous secret first"
                        );
                        if let Some(previous) = &creds.config.node_secret
                            && let Err(e) = persist_node_secret(relay_config, config_path, &creds.config, previous)
                        {
                            tracing::warn!(
                                "Failed to put the previous node secret back in the config file: {e}; \
                                 a restart before the next authentication would present one the manager \
                                 does not hold"
                            );
                            ctx.event_sender.emit(super::events::EventSeverity::Warning, category::MANAGER, format!("Credential persistence failed: {}", e));
                        }
                    }
                    creds.rotated(new_secret, ack_sent);
                }
                return;
            }

            // configure_distribution updates the runtime distribution config
            // (secret, gates, public IP/URL, cascade sources) — the manager
            // owns the operational policy so the operator never hand-edits the
            // relay's config.json.
            if action_type == "configure_distribution" {
                let result =
                    configure_distribution(distribution_control, relay_config, config_path, action);
                let ack = serde_json::json!({
                    "type": "command_ack",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "payload": {
                        "command_id": command_id,
                        "success": result.is_ok(),
                        "error": result.err(),
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

            // Authoritatively drop the tunnel by id. force_remove_tunnel works
            // even for identified edges (edge_id != connection_id), where the
            // old unbind-by-edge_id path silently no-opped and left the entry
            // lingering in `waiting_ingress`. Notify any still-bound peer so it
            // learns the tunnel is gone (matches connection-loss cleanup).
            match ctx.router.force_remove_tunnel(&tunnel_id) {
                Some(affected) => {
                    for connection_id in affected {
                        crate::session::notify_tunnel_down(
                            ctx,
                            &connection_id,
                            tunnel_id,
                            "tunnel closed by manager",
                        )
                        .await;
                    }
                    Ok(None)
                }
                None => Err(format!("Tunnel '{tunnel_id}' not found")),
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
        "list_udp_sessions" => {
            // Native plain-UDP relay sessions (SRT/RIST without QUIC).
            tracing::info!("Manager command: list_udp_sessions");
            let sessions = ctx.udp_sessions.list();
            let data = serde_json::to_value(&sessions).unwrap_or_default();
            Ok(Some(data))
        }
        "close_udp_session" => {
            let tunnel_id_str = action["tunnel_id"]
                .as_str()
                .ok_or("Missing tunnel_id")?;
            let tunnel_id: Uuid = tunnel_id_str
                .parse()
                .map_err(|e| format!("Invalid UUID: {e}"))?;
            tracing::info!("Manager command: close_udp_session '{tunnel_id}'");
            if ctx.udp_sessions.remove(&tunnel_id) {
                Ok(None)
            } else {
                Err(format!("Native-UDP session '{tunnel_id}' not found"))
            }
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
    match update_config_file(config_path, relay_config, |config| {
        if let Some(ref mut mgr) = config.manager {
            mgr.registration_token = None;
            mgr.node_id = Some(node_id.to_string());
            mgr.node_secret = Some(node_secret.to_string());
        }
    }) {
        Ok(()) => tracing::info!("Manager credentials saved to {}", config_path.display()),
        Err(e) => tracing::warn!("Failed to persist manager credentials: {e}"),
    }
}

/// Save `node_secret` as the relay's manager secret, with the identity it is
/// the secret of — `identity`'s node ID and registration token, which are the
/// ones the relay authenticates with now — and leave the rest of the file as
/// it is.
///
/// The identity is written too, not only the secret, because the file is not
/// always what gets edited: when it cannot be re-read, `update_config_file`
/// edits the startup config instead, and for a relay that registered since it
/// started that still holds the consumed registration token and no node ID. A
/// restart would then present the token, and be refused.
fn persist_node_secret(
    relay_config: &RelayConfig,
    config_path: &PathBuf,
    identity: &ManagerConfig,
    node_secret: &str,
) -> Result<(), String> {
    update_config_file(config_path, relay_config, |config| {
        if let Some(ref mut mgr) = config.manager {
            mgr.registration_token = identity.registration_token.clone();
            mgr.node_id = identity.node_id.clone();
            mgr.node_secret = Some(node_secret.to_string());
        }
    })
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use crate::config::{DistributionConfig, ManagerConfig, RelayConfig};
    use crate::distribution_control::{DistributionControl, RuntimeDistConfig};

    fn registered_config() -> RelayConfig {
        let manager = Some(ManagerConfig {
            enabled: true,
            urls: vec!["wss://m.example/ws/node".into()],
            accept_self_signed_cert: false,
            cert_fingerprint: None,
            registration_token: Some("one-time-token".into()),
            node_id: None,
            node_secret: None,
        });
        RelayConfig { manager, ..Default::default() }
    }

    /// Registering then receiving a distribution push must leave BOTH on disk.
    ///
    /// This is the sequence that broke it. Each writer rebuilt the whole file
    /// from the config captured at startup, so the distribution push restored
    /// the burnt registration token and erased the secret registration had
    /// just written. The relay kept running — it was already authenticated —
    /// and could never reconnect after a restart, having been left holding a
    /// credential the manager had already consumed.
    #[test]
    fn a_distribution_push_does_not_revert_the_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.json");
        let startup = registered_config();
        std::fs::write(&path, serde_json::to_string_pretty(&startup).unwrap()).unwrap();

        // 1. Registration lands.
        persist_credentials(&startup, &path, "node-1", "the-secret");
        let after_reg: RelayConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let m = after_reg.manager.as_ref().unwrap();
        assert_eq!(m.node_secret.as_deref(), Some("the-secret"));
        assert_eq!(m.registration_token, None, "the used token must be cleared");

        // 2. The manager pushes a distribution config. `startup` is passed on
        //    purpose — it is the stale snapshot the old code always used.
        let control = DistributionControl::new(
            RuntimeDistConfig::from_config(&DistributionConfig::default(), None),
            vec![],
        );
        control.apply(crate::distribution_control::DistUpdate {
            public_base_url: Some("https://relay.example".into()),
            ..Default::default()
        });
        persist_distribution_config(Some(&control), &startup, &path);

        // 3. Both must be on disk.
        let after_push: RelayConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let m = after_push.manager.as_ref().unwrap();
        assert_eq!(
            m.node_secret.as_deref(),
            Some("the-secret"),
            "the distribution push erased the node secret"
        );
        assert_eq!(
            m.registration_token, None,
            "the distribution push restored a registration token the manager has consumed"
        );
        assert_eq!(
            after_push
                .distribution
                .as_ref()
                .and_then(|d| d.public_base_url.as_deref()),
            Some("https://relay.example"),
            "the push itself did not land"
        );
    }

    /// ...and the other way round: persisting credentials must not throw away
    /// a distribution config that arrived before registration completed.
    #[test]
    fn registering_does_not_revert_a_distribution_push() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.json");
        let startup = registered_config();

        let with_dist = RelayConfig {
            distribution: Some(DistributionConfig {
                public_base_url: Some("https://relay.example".into()),
                ..Default::default()
            }),
            ..startup.clone()
        };
        std::fs::write(&path, serde_json::to_string_pretty(&with_dist).unwrap()).unwrap();

        persist_credentials(&startup, &path, "node-1", "the-secret");

        let after: RelayConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            after.distribution.as_ref().and_then(|d| d.public_base_url.as_deref()),
            Some("https://relay.example"),
            "registering discarded the distribution config already on disk"
        );
        assert_eq!(
            after.manager.as_ref().unwrap().node_secret.as_deref(),
            Some("the-secret")
        );
    }

    /// An unreadable file falls back to the in-memory config rather than
    /// refusing to persist — the case the old code was written for.
    #[test]
    fn an_unreadable_file_still_gets_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.json");
        std::fs::write(&path, "{ this is not json").unwrap();

        persist_credentials(&registered_config(), &path, "node-1", "the-secret");

        let after: RelayConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            after.manager.as_ref().unwrap().node_secret.as_deref(),
            Some("the-secret")
        );
    }

    /// No config file (CLI-only relay) must not create one.
    #[test]
    fn no_config_file_means_nothing_to_write() {
        let empty = PathBuf::new();
        persist_credentials(&registered_config(), &empty, "node-1", "s");
        assert!(!std::path::Path::new("").exists());
    }
}

#[cfg(test)]
mod manager_contract_tests {
    use super::*;
    use crate::config::DistributionConfig;
    use crate::distribution_control::{DistributionControl, RuntimeDistConfig};

    /// The relay must accept **the exact body bilbycast-manager builds**.
    ///
    /// This JSON is not hand-written: it is the literal output of
    /// `manager_core::db::dvr_sessions::relay_push_body`, captured from
    /// `cargo test -p manager-core dump_contract -- --nocapture`. The two
    /// sides were written independently, and a field-name disagreement here
    /// would not error — `apply_configure_distribution` applies what it
    /// recognises and ignores the rest, so a mismatch presents as a retention
    /// window that is stored, reported as pushed, and never takes effect.
    #[test]
    fn the_managers_dvr_push_is_understood() {
        let cfg = DistributionConfig::default();
        let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);

        let from_manager = serde_json::json!({
            "type": "configure_distribution",
            "token_secret": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "origin_stream_policies": {
                "e2e":       { "retention_secs": 300 },
                "e2e-proxy": { "retention_secs": 300 }
            },
            // `true`, because that is what the manager sends. `relay_push_body`
            // carries it unconditionally (migration 0063 — every DVR feed is
            // gated), so a fixture pinning `false` pins a body the manager has
            // never produced, and the one field whose value actually matters
            // here would go unchecked.
            "require_origin_token": true
        });

        apply_configure_distribution(Some(&control), &from_manager)
            .expect("the relay must accept the manager's push");
        assert!(
            control.load().require_origin_token,
            "the gate the manager always sends must actually engage"
        );

        // Applied, not merely parsed.
        let mut rx = control.subscribe_origin();
        let update = rx.borrow_and_update().clone();
        let per = update.per_stream.expect("per-stream overrides must arrive");
        assert_eq!(per.len(), 2, "both renditions must be carried");
        let names: Vec<&str> = per.iter().map(|(s, _)| s.as_str()).collect();
        assert!(names.contains(&"e2e") && names.contains(&"e2e-proxy"));
        assert_eq!(
            per[0].1.retention_secs,
            Some(300),
            "the window must survive the wire"
        );
    }

    /// A blank box on the Distribution tab must not abort the whole push.
    ///
    /// The manager admits `""` for `public_ip`, `public_base_url` and
    /// `portal_url` and its form sends all three keys on every save, so the
    /// ordinary case of leaving one empty used to return `Err` — which aborts
    /// `apply_configure_distribution` entirely, so the token secret and the
    /// gates in the same command were not applied either. Silently: the
    /// manager reports `success: true, pushed: false` at most.
    #[test]
    fn a_blank_field_does_not_abort_the_rest_of_the_push() {
        let cfg = DistributionConfig::default();
        let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);

        apply_configure_distribution(
            Some(&control),
            &serde_json::json!({
                "type": "configure_distribution",
                "public_ip": "",
                "portal_url": "",
                "public_base_url": "https://relay.example.com",
                "require_viewer_token": true,
                "token_secret": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            }),
        )
        .expect("a blank field must not abort the push");

        let rt = control.load();
        assert_eq!(
            rt.public_base_url.as_deref(),
            Some("https://relay.example.com"),
            "the field that WAS filled in must land"
        );
        assert!(rt.require_viewer_token, "the gate in the same push must land");
        assert!(rt.token_secret.is_some(), "the secret in the same push must land");
        assert!(rt.public_ip.is_none(), "a blank field stays unset");

        // A non-empty but malformed value is still refused.
        assert!(
            apply_configure_distribution(
                Some(&control),
                &serde_json::json!({ "type": "configure_distribution", "public_ip": "not-an-ip" }),
            )
            .is_err()
        );
    }

    /// `portal_url` must survive the wire, and a bad one must be refused.
    ///
    /// The relay renders this as a link a viewer is invited to click, so the
    /// consequence of the manager and the relay disagreeing about the field
    /// name is not a warning — it is a page that quietly reverts to telling a
    /// portal viewer to reload, which is the one thing that cannot help them.
    #[test]
    fn the_managers_portal_url_is_understood() {
        let cfg = DistributionConfig::default();
        let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
        assert_eq!(control.load().portal_url, None, "starts unset");

        apply_configure_distribution(
            Some(&control),
            &serde_json::json!({
                "type": "configure_distribution",
                "portal_url": "https://portal.example.com"
            }),
        )
        .expect("the relay must accept a portal url from the manager");
        assert_eq!(
            control.load().portal_url.as_deref(),
            Some("https://portal.example.com"),
            "the portal url did not reach the live config"
        );

        // A scheme-less or `javascript:` value must not reach a page that
        // presents it as the way back in. Checked on both sides on purpose.
        for bad in ["javascript:alert(1)", "portal.example.com", "//evil.example"] {
            assert!(
                apply_configure_distribution(
                    Some(&control),
                    &serde_json::json!({ "type": "configure_distribution", "portal_url": bad }),
                )
                .is_err(),
                "accepted {bad}"
            );
        }
        // ...and the refusal left the good one in place rather than clearing it.
        assert_eq!(
            control.load().portal_url.as_deref(),
            Some("https://portal.example.com")
        );
    }

    /// The gate is a separate field and must also land.
    #[test]
    fn the_managers_gate_flag_is_understood() {
        let cfg = DistributionConfig::default();
        let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
        apply_configure_distribution(
            Some(&control),
            &serde_json::json!({
                "type": "configure_distribution",
                "require_origin_token": true,
                "origin_stream_policies": {}
            }),
        )
        .expect("accepted");
        assert!(control.load().require_origin_token, "the gate must be applied");

        // An empty override object is meaningful: it clears the set. It must
        // arrive as Some(empty), not None, or the last session to stop would
        // never get its window released.
        let mut rx = control.subscribe_origin();
        let update = rx.borrow_and_update().clone();
        assert_eq!(update.per_stream, Some(Vec::new()));
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use crate::config::{CascadeSource, DistributionConfig, ManagerConfig, REDACTED};
    use crate::distribution_control::{DistributionControl, RuntimeDistConfig};

    const TOKEN_SECRET: &str = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7";

    fn source(stream: &str, url: &str, token: Option<&str>) -> CascadeSource {
        CascadeSource {
            upstream_whep_url: url.into(),
            local_stream: stream.into(),
            token: token.map(str::to_string),
        }
    }

    /// The handler's own response, not just the helper: what the manager
    /// stores for `GET /api/v1/nodes/{id}/config`, which needs only View.
    #[test]
    fn get_config_response_carries_no_credential() {
        let config = RelayConfig {
            api_token: Some("planted-api-token-0123456789abcdef0123456789".into()),
            manager: Some(ManagerConfig {
                enabled: true,
                urls: vec!["wss://m.example/ws/node".into()],
                accept_self_signed_cert: false,
                cert_fingerprint: None,
                registration_token: Some("planted-registration-token".into()),
                node_id: Some("node-1".into()),
                node_secret: Some("planted-node-secret".into()),
            }),
            distribution: Some(DistributionConfig {
                token_secret: Some(TOKEN_SECRET.into()),
                cascade_sources: vec![source(
                    "feed",
                    "http://origin.example/whep/feed?token=planted-url-token",
                    Some("planted-cascade-token"),
                )],
                ..Default::default()
            }),
            ..Default::default()
        };

        let response = build_config_response(&config);
        assert_eq!(response["type"], "config_response");
        let text = response.to_string();
        for secret in [
            "planted-api-token-0123456789abcdef0123456789",
            "planted-registration-token",
            "planted-node-secret",
            TOKEN_SECRET,
            "planted-cascade-token",
            "planted-url-token",
        ] {
            assert!(!text.contains(secret), "get_config leaked {secret:?}");
        }
        let payload = &response["payload"];
        assert_eq!(payload["distribution"]["token_secret"], REDACTED);
        assert_eq!(payload["manager"]["registration_token"], REDACTED);
        assert_eq!(payload["distribution"]["cascade_sources"][0]["token"], REDACTED);
        // Still the config the manager needs to show.
        assert_eq!(payload["manager"]["node_id"], "node-1");
        assert_eq!(
            payload["distribution"]["cascade_sources"][0]["upstream_whep_url"],
            "http://origin.example/whep/feed?token=***REDACTED***"
        );
    }

    /// A push that carries the marker back as `token_secret` keeps the secret
    /// the relay holds — and the rest of the push still lands. Before, the
    /// marker failed the 64-hex check and aborted the whole command.
    #[test]
    fn a_redacted_token_secret_keeps_the_one_the_relay_holds() {
        let cfg = DistributionConfig { token_secret: Some(TOKEN_SECRET.into()), ..Default::default() };
        let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);

        apply_configure_distribution(
            Some(&control),
            &serde_json::json!({
                "type": "configure_distribution",
                "token_secret": REDACTED,
                "require_viewer_token": true,
            }),
        )
        .expect("the marker means keep, not a bad value");

        let rt = control.load();
        assert_eq!(rt.token_secret.as_deref(), Some(TOKEN_SECRET), "the real secret must survive");
        assert!(rt.require_viewer_token, "the rest of the push must land");
    }

    /// The same for a cascade source's upstream token, matched on the source
    /// it belongs to. With nothing to keep, the source is refused rather than
    /// pulled with the marker as its credential.
    #[test]
    fn a_redacted_cascade_token_keeps_that_sources_token() {
        let url = "https://origin.example/whep/feed";
        let control = DistributionControl::new(
            RuntimeDistConfig::from_config(&DistributionConfig::default(), None),
            vec![source("feed", url, Some("the-upstream-token"))],
        );

        apply_configure_distribution(
            Some(&control),
            &serde_json::json!({
                "type": "configure_distribution",
                "cascade_sources": [
                    { "upstream_whep_url": url, "local_stream": "feed", "token": REDACTED },
                    { "upstream_whep_url": "https://other.example/whep/x", "local_stream": "x" },
                ],
            }),
        )
        .expect("a marker on a known source is accepted");
        let now = control.cascade_now();
        assert_eq!(now[0].token.as_deref(), Some("the-upstream-token"));
        assert_eq!(now[1].token, None);

        for (stream, upstream) in [
            ("new-feed", url),                            // a source the relay never had
            ("feed", "https://moved.example/whep/feed"), // the upstream changed
            ("x", "https://other.example/whep/x"),       // a source with no token to keep
        ] {
            let err = apply_configure_distribution(
                Some(&control),
                &serde_json::json!({
                    "type": "configure_distribution",
                    "cascade_sources": [
                        { "upstream_whep_url": upstream, "local_stream": stream, "token": REDACTED }
                    ],
                }),
            )
            .expect_err("nothing to keep: refuse rather than pull with the marker");
            assert!(err.contains("redaction marker"), "{err}");
        }
        assert!(
            control.cascade_now().iter().all(|s| s.token.as_deref() != Some(REDACTED)),
            "the marker never becomes a source's token"
        );
    }

    #[test]
    fn rotate_secret_refuses_the_marker() {
        assert_eq!(
            rotated_secret(&serde_json::json!({ "type": "rotate_secret", "new_secret": "fresh" })),
            Ok("fresh")
        );
        for bad in [
            serde_json::json!({ "type": "rotate_secret", "new_secret": REDACTED }),
            serde_json::json!({ "type": "rotate_secret", "new_secret": "" }),
            serde_json::json!({ "type": "rotate_secret" }),
        ] {
            assert!(rotated_secret(&bad).is_err(), "{bad}");
        }
    }

    fn control_with(
        cfg: &DistributionConfig,
        cascade: Vec<CascadeSource>,
    ) -> Arc<DistributionControl> {
        DistributionControl::new(RuntimeDistConfig::from_config(cfg, None), cascade)
    }

    fn push(control: &Arc<DistributionControl>, action: serde_json::Value) -> Result<(), String> {
        apply_configure_distribution(Some(control), &action)
    }

    /// A source exactly as `get_config` showed it — the token in its URL and
    /// its header token both redacted — comes back as the real one.
    #[test]
    fn a_source_pushed_back_as_shown_gets_its_real_url_and_token() {
        let real_url = "http://origin.example:4485/whep/feed?v=2&token=the-url-token";
        let control =
            control_with(&DistributionConfig::default(), vec![source("feed", real_url, Some("the-header-token"))]);
        let shown = crate::config::redact_url(real_url);
        assert!(!shown.contains("the-url-token"));

        push(
            &control,
            serde_json::json!({
                "type": "configure_distribution",
                "cascade_sources": [{ "upstream_whep_url": shown, "local_stream": "feed", "token": REDACTED }],
            }),
        )
        .expect("the source as shown is accepted");
        assert_eq!(control.cascade_now(), vec![source("feed", real_url, Some("the-header-token"))]);

        // A redacted URL with a fresh header token: the URL comes back, the
        // new token is kept.
        push(
            &control,
            serde_json::json!({
                "type": "configure_distribution",
                "cascade_sources": [{ "upstream_whep_url": shown, "local_stream": "feed", "token": "a-new-token" }],
            }),
        )
        .expect("a fresh token beside a redacted URL is accepted");
        assert_eq!(control.cascade_now(), vec![source("feed", real_url, Some("a-new-token"))]);
    }

    /// A redacted URL is only ever matched to the source it was shown for.
    #[test]
    fn a_redacted_url_with_nothing_to_restore_from_is_refused() {
        let real_url = "http://origin.example/whep/feed?token=the-url-token";
        let control = control_with(&DistributionConfig::default(), vec![source("feed", real_url, None)]);
        for (stream, url) in [
            // another stream's URL
            ("other", "http://origin.example/whep/feed?token=***REDACTED***"),
            // the upstream moved
            ("feed", "http://moved.example/whep/feed?token=***REDACTED***"),
            // a userinfo the source never had
            ("feed", "http://***REDACTED***@origin.example/whep/feed?token=***REDACTED***"),
        ] {
            let err = push(
                &control,
                serde_json::json!({
                    "type": "configure_distribution",
                    "cascade_sources": [{ "upstream_whep_url": url, "local_stream": stream }],
                }),
            )
            .expect_err("nothing to restore from: refuse rather than pull with the marker");
            assert!(err.contains("redaction marker"), "{err}");
        }
        assert_eq!(control.cascade_now(), vec![source("feed", real_url, None)], "unchanged");
    }

    /// Two entries for one `local_stream` would be acked and one silently never
    /// pulled — the supervisor keys pulls by stream. Refused on the push.
    #[test]
    fn a_push_naming_one_stream_twice_is_refused() {
        let control = control_with(&DistributionConfig::default(), vec![]);
        let err = push(
            &control,
            serde_json::json!({
                "type": "configure_distribution",
                "require_viewer_token": true,
                "cascade_sources": [
                    { "upstream_whep_url": "http://a.example/whep/feed", "local_stream": "feed" },
                    { "upstream_whep_url": "http://b.example/whep/feed", "local_stream": "feed" },
                ],
            }),
        )
        .expect_err("a duplicate local_stream is refused");
        assert!(err.contains("'feed' appears more than once"), "{err}");
        assert!(control.cascade_now().is_empty());
        assert!(!control.load().require_viewer_token, "a refused push applies nothing");
    }

    /// A config file may still hold two entries for a stream (it is loaded
    /// with a warning). The supervisor runs the **last**, so that is the one a
    /// marker is restored from.
    #[test]
    fn the_restore_follows_the_entry_the_supervisor_runs() {
        let a = "http://a.example/whep/feed";
        let b = "http://b.example/whep/feed";
        let control = control_with(
            &DistributionConfig::default(),
            vec![source("feed", a, Some("token-a")), source("feed", b, Some("token-b"))],
        );
        let marker_for = |url: &str| {
            serde_json::json!({
                "type": "configure_distribution",
                "cascade_sources": [{ "upstream_whep_url": url, "local_stream": "feed", "token": REDACTED }],
            })
        };
        assert!(push(&control, marker_for(a)).is_err(), "the shadowed entry is not what runs");
        push(&control, marker_for(b)).expect("the running entry restores");
        assert_eq!(control.cascade_now(), vec![source("feed", b, Some("token-b"))]);
    }

    /// A refused push applies nothing — not the secret, not the gates, not the
    /// storage policy — and so leaves `config.json` as it was. Before, the new
    /// secret went live and the refusal skipped the persist, so the relay ran
    /// on a secret it would forget at its next restart.
    #[test]
    fn a_refused_push_leaves_the_old_secret_live_and_on_disk() {
        const NEW_SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.json");
        let startup = RelayConfig {
            distribution: Some(DistributionConfig {
                token_secret: Some(TOKEN_SECRET.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        std::fs::write(&path, serde_json::to_string_pretty(&startup).unwrap()).unwrap();
        let control = control_with(startup.distribution.as_ref().unwrap(), vec![]);
        let on_disk = || -> Option<String> {
            let c: RelayConfig =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            c.distribution.and_then(|d| d.token_secret)
        };

        let refused = serde_json::json!({
            "type": "configure_distribution",
            "token_secret": NEW_SECRET,
            "require_viewer_token": true,
            "origin_policy": { "retention_secs": 600 },
            "cascade_sources": [
                { "upstream_whep_url": "http://up.example/whep/new", "local_stream": "new", "token": REDACTED }
            ],
        });
        configure_distribution(Some(&control), &startup, &path, &refused)
            .expect_err("an unrestorable marker refuses the push");
        let rt = control.load();
        assert_eq!(rt.token_secret.as_deref(), Some(TOKEN_SECRET), "the old secret stays live");
        assert!(!rt.require_viewer_token, "the gate in the refused push is not applied");
        assert!(
            control.subscribe_origin().borrow().default.is_none(),
            "the storage policy in the refused push is not applied"
        );
        assert!(control.cascade_now().is_empty());
        assert_eq!(on_disk().as_deref(), Some(TOKEN_SECRET), "and the old secret stays on disk");

        // The same push without the bad row lands, live and on disk.
        let mut accepted = refused.clone();
        accepted["cascade_sources"] = serde_json::json!([]);
        configure_distribution(Some(&control), &startup, &path, &accepted).expect("accepted");
        assert_eq!(control.load().token_secret.as_deref(), Some(NEW_SECRET));
        assert_eq!(on_disk().as_deref(), Some(NEW_SECRET));
    }

    /// A pushed cascade list that config load would refuse is refused whole:
    /// the error names the entry and the reason, and nothing in the push —
    /// not the secret, not the gate, not the list — is applied.
    fn assert_push_refused(sources: serde_json::Value, reason: &str) {
        const NEW_SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let kept = source("feed", "http://origin.example/whep/feed", None);
        let control = control_with(
            &DistributionConfig { token_secret: Some(TOKEN_SECRET.into()), ..Default::default() },
            vec![kept.clone()],
        );
        let err = push(
            &control,
            serde_json::json!({
                "type": "configure_distribution",
                "token_secret": NEW_SECRET,
                "require_viewer_token": true,
                "cascade_sources": sources,
            }),
        )
        .expect_err("config load refuses this list, so the push must too");
        assert!(err.contains(reason), "{err}");
        let rt = control.load();
        assert_eq!(rt.token_secret.as_deref(), Some(TOKEN_SECRET), "{err}: secret applied");
        assert!(!rt.require_viewer_token, "{err}: gate applied");
        assert_eq!(control.cascade_now(), vec![kept], "{err}: list applied");
    }

    fn entry(url: &str, stream: &str) -> serde_json::Value {
        serde_json::json!({ "upstream_whep_url": url, "local_stream": stream })
    }

    #[test]
    fn a_pushed_source_with_a_scheme_the_pull_cannot_use_is_refused() {
        assert_push_refused(
            serde_json::json!([
                entry("http://ok.example/whep/a", "a"),
                entry("ftp://up.example/whep/b", "b"),
            ]),
            "cascade_sources[1].upstream_whep_url must start with http:// or https://",
        );
    }

    #[test]
    fn a_pushed_source_with_an_overlong_url_is_refused() {
        let long = format!("http://up.example/whep/{}", "x".repeat(2048));
        assert_push_refused(
            serde_json::json!([entry(&long, "a")]),
            "cascade_sources[0].upstream_whep_url too long",
        );
    }

    #[test]
    fn a_pushed_source_with_an_empty_stream_name_is_refused() {
        assert_push_refused(
            serde_json::json!([entry("http://up.example/whep/a", "  ")]),
            "cascade_sources[0].local_stream must be 1..=128 chars of [A-Za-z0-9._-]",
        );
    }

    #[test]
    fn a_pushed_source_with_a_stream_name_outside_the_charset_is_refused() {
        assert_push_refused(
            serde_json::json!([entry("http://up.example/whep/a", "../etc")]),
            "cascade_sources[0].local_stream must be 1..=128 chars of [A-Za-z0-9._-]",
        );
    }

    #[test]
    fn a_pushed_source_with_an_overlong_stream_name_is_refused() {
        assert_push_refused(
            serde_json::json!([entry("http://up.example/whep/a", &"s".repeat(129))]),
            "cascade_sources[0].local_stream must be 1..=128 chars of [A-Za-z0-9._-]",
        );
    }

    #[test]
    fn a_push_with_more_than_64_sources_is_refused() {
        let many: Vec<serde_json::Value> = (0..65)
            .map(|i| entry(&format!("http://up.example/whep/s{i}"), &format!("s{i}")))
            .collect();
        assert_push_refused(serde_json::json!(many), "cascade_sources: at most 64 entries (got 65)");
    }

    /// The validator is the one config load uses, so a list it accepts on load
    /// is accepted on a push — duplicates aside, which load warns about and a
    /// push refuses.
    #[test]
    fn a_push_accepts_what_config_load_accepts() {
        let control = control_with(&DistributionConfig::default(), vec![]);
        let list: Vec<CascadeSource> = (0..64)
            .map(|i| source(&format!("s{i}"), &format!("https://up.example/whep/s{i}"), None))
            .collect();
        let loads = |sources: &[CascadeSource]| {
            RelayConfig {
                distribution: Some(DistributionConfig {
                    cascade_sources: sources.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            }
            .validate()
            .is_ok()
        };
        assert!(loads(&list));
        push(
            &control,
            serde_json::json!({ "type": "configure_distribution", "cascade_sources": list }),
        )
        .expect("what load accepts, a push accepts");
        assert_eq!(control.cascade_now().len(), 64);

        let twice = vec![source("a", "http://x.example/whep/a", None), source("a", "http://y.example/whep/a", None)];
        assert!(loads(&twice), "load takes duplicates, with a warning");
        assert!(push(
            &control,
            serde_json::json!({ "type": "configure_distribution", "cascade_sources": twice }),
        )
        .is_err());
    }
}

#[cfg(test)]
mod rotation_tests {
    //! The credentials a session hands the next one, driven through the real
    //! session loop and command handler against a fake manager on the other
    //! end of an in-memory WebSocket. `connect_to_manager` adds only the
    //! `wss://` check and the TLS connection in front of `run_session`.
    use super::*;
    use crate::config::{ManagerConfig, RelayConfig};
    use tokio::io::DuplexStream;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    type Ws = WebSocketStream<DuplexStream>;

    const OLD: &str = "old-secret";
    const NEW: &str = "new-secret";

    fn manager_config(node_secret: Option<&str>, registration_token: Option<&str>) -> ManagerConfig {
        ManagerConfig {
            enabled: true,
            urls: vec!["wss://m.example/ws/node".into()],
            accept_self_signed_cert: false,
            cert_fingerprint: None,
            registration_token: registration_token.map(str::to_string),
            node_id: node_secret.map(|_| "node-1".to_string()),
            node_secret: node_secret.map(str::to_string),
        }
    }

    /// The relay's end: its config file, and what `manager_client_loop` hands
    /// every session.
    struct Relay {
        _dir: tempfile::TempDir,
        config_path: PathBuf,
        relay_config: RelayConfig,
        ctx: Arc<SessionContext>,
        relay_stats: Arc<RelayStats>,
        event_sender: crate::manager::events::EventSender,
        event_rx: mpsc::Receiver<Event>,
    }

    impl Relay {
        /// A relay whose config file holds `manager`.
        fn new(manager: ManagerConfig) -> Self {
            Self::at("relay.json", manager)
        }

        /// A relay whose config file is at `file` inside a fresh directory —
        /// a path under a directory that does not exist cannot be written.
        fn at(file: &str, manager: ManagerConfig) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join(file);
            let relay_config = RelayConfig { manager: Some(manager), ..Default::default() };
            if config_path.parent().is_some_and(|p| p.exists()) {
                std::fs::write(&config_path, serde_json::to_string_pretty(&relay_config).unwrap())
                    .unwrap();
            }
            let relay_stats = Arc::new(RelayStats::new());
            let (event_sender, event_rx) = crate::manager::event_channel();
            let ctx = crate::server::create_session_context(
                relay_stats.clone(),
                event_sender.clone(),
                false,
                64,
                100,
            );
            Self { _dir: dir, config_path, relay_config, ctx, relay_stats, event_sender, event_rx }
        }

        fn credentials(&self) -> LinkCredentials {
            LinkCredentials::new(self.relay_config.manager.clone().unwrap())
        }

        fn secret_on_disk(&self) -> Option<String> {
            let text = std::fs::read_to_string(&self.config_path).ok()?;
            serde_json::from_str::<RelayConfig>(&text).ok()?.manager?.node_secret
        }

        /// One session with `manager` playing the other end. Returns how the
        /// session ended and what `manager` returned.
        async fn session<F, Fut, R>(&mut self, creds: &mut LinkCredentials, manager: F) -> (Result<(), String>, R)
        where
            F: FnOnce(Ws) -> Fut,
            Fut: std::future::Future<Output = R>,
        {
            let (relay_io, manager_io) = tokio::io::duplex(1 << 20);
            let relay_ws = WebSocketStream::from_raw_socket(relay_io, Role::Client, None).await;
            let manager_ws = answer(manager_io).await;
            let session = run_session(
                relay_ws,
                creds,
                &self.ctx,
                &self.relay_stats,
                &self.relay_config,
                &self.config_path,
                &mut self.event_rx,
                &self.event_sender,
                None,
            );
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(session, manager(manager_ws))
            })
            .await
            .expect("the session did not end")
        }
    }

    /// The manager's end of a connection the relay opened.
    async fn answer(io: DuplexStream) -> Ws {
        WebSocketStream::from_raw_socket(io, Role::Server, None).await
    }

    async fn recv(ws: &mut Ws) -> serde_json::Value {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
                Some(Ok(_)) => continue,
                other => panic!("the relay's connection ended: {other:?}"),
            }
        }
    }

    async fn send(ws: &mut Ws, value: serde_json::Value) {
        ws.send(Message::Text(value.to_string().into())).await.unwrap();
    }

    fn auth_ok() -> serde_json::Value {
        serde_json::json!({ "type": "auth_ok" })
    }

    /// What the manager answers a secret it does not hold.
    fn auth_error() -> serde_json::Value {
        serde_json::json!({ "type": "auth_error", "message": "Invalid node secret" })
    }

    /// The manager's half of an authentication: answer `reply`, and return
    /// what the relay presented.
    async fn authenticate(ws: &mut Ws, reply: serde_json::Value) -> serde_json::Value {
        let auth = recv(ws).await;
        assert_eq!(auth["type"], "auth", "{auth}");
        send(ws, reply).await;
        auth["payload"].clone()
    }

    fn rotate_command(new_secret: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "command",
            "payload": {
                "command_id": "rotate-1",
                "action": { "type": "rotate_secret", "new_secret": new_secret }
            }
        })
    }

    /// Send `rotate_secret`, as `POST /api/v1/nodes/{id}/rotate-secret` does,
    /// and return the relay's acknowledgement.
    async fn rotate(ws: &mut Ws, new_secret: &str) -> serde_json::Value {
        send(ws, rotate_command(new_secret)).await;
        loop {
            let msg = recv(ws).await;
            if msg["type"] == "command_ack" && msg["payload"]["command_id"] == "rotate-1" {
                return msg["payload"].clone();
            }
        }
    }

    /// End the connection the way a reset does: the relay's read fails, so
    /// the session returns `Err`, not `Ok`. Then wait for the relay to hang up.
    async fn break_connection(mut ws: Ws) {
        use tokio::io::AsyncWriteExt;
        // A frame with every reserved bit set, which no peer may send.
        ws.get_mut().write_all(&[0xF1, 0x00]).await.unwrap();
        while let Some(Ok(_)) = ws.next().await {}
    }

    /// The relay used to save the rotated secret and acknowledge it — so the
    /// manager stored it — and go on presenting the old one, refused at every
    /// reconnect until a restart read the file. The connection is broken
    /// rather than closed, because a session that returns `Err` is the path on
    /// which a credential handed back in the result would be lost.
    #[tokio::test]
    async fn a_rotated_secret_is_presented_at_the_next_reconnect() {
        let mut relay = Relay::new(manager_config(Some(OLD), None));
        let mut creds = relay.credentials();

        let (ended, ack) = relay
            .session(&mut creds, |mut ws| async move {
                let shown = authenticate(&mut ws, auth_ok()).await;
                assert_eq!(shown["node_secret"], OLD);
                let ack = rotate(&mut ws, NEW).await;
                break_connection(ws).await;
                ack
            })
            .await;
        assert_eq!(ack["success"], true, "{ack}");
        assert!(ended.unwrap_err().contains("WebSocket error"));
        assert_eq!(relay.secret_on_disk().as_deref(), Some(NEW));

        let (_, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_ok()).await })
            .await;
        assert_eq!(shown["node_id"], "node-1");
        assert_eq!(
            shown["node_secret"], NEW,
            "the reconnect presented the secret the manager replaced"
        );
        assert_eq!(relay.secret_on_disk().as_deref(), Some(NEW));
    }

    /// An acknowledgement the manager never read — lost with the connection,
    /// or later than its 10 s wait — leaves the manager on the old secret.
    /// The relay is refused once with the new one, falls back to the old one,
    /// and saves it, so a restart presents it too.
    #[tokio::test]
    async fn a_rotation_the_manager_did_not_store_falls_back_to_the_previous_secret() {
        let mut relay = Relay::new(manager_config(Some(OLD), None));
        let mut creds = relay.credentials();

        let (_, ack) = relay
            .session(&mut creds, |mut ws| async move {
                authenticate(&mut ws, auth_ok()).await;
                rotate(&mut ws, NEW).await
            })
            .await;
        assert_eq!(ack["success"], true, "{ack}");

        let (ended, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_error()).await })
            .await;
        assert_eq!(shown["node_secret"], NEW, "the likelier secret goes first");
        assert!(ended.unwrap_err().contains("Auth rejected"));

        let (_, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_ok()).await })
            .await;
        assert_eq!(shown["node_secret"], OLD, "the refused secret was presented again");
        assert_eq!(
            relay.secret_on_disk().as_deref(),
            Some(OLD),
            "a restart would present the secret the manager refused"
        );

        // Settled: nothing left to fall back to, and the next connection
        // presents the accepted secret straight away.
        assert!(creds.fallback_secrets.is_empty());
        let (_, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_ok()).await })
            .await;
        assert_eq!(shown["node_secret"], OLD);
    }

    /// A secret the relay cannot save is refused. Acknowledging it would have
    /// the manager store a secret the file does not hold, and the relay would
    /// be locked out at its next restart.
    #[tokio::test]
    async fn a_secret_that_cannot_be_saved_is_refused_and_the_old_one_kept() {
        let mut relay = Relay::at("missing/relay.json", manager_config(Some(OLD), None));
        let mut creds = relay.credentials();

        let (_, ack) = relay
            .session(&mut creds, |mut ws| async move {
                authenticate(&mut ws, auth_ok()).await;
                rotate(&mut ws, NEW).await
            })
            .await;
        assert_eq!(ack["success"], false, "{ack}");
        let error = ack["error"].as_str().unwrap();
        assert!(error.contains("could not save the new secret"), "{error}");

        let (_, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_ok()).await })
            .await;
        assert_eq!(shown["node_secret"], OLD);
        assert!(creds.fallback_secrets.is_empty(), "a refused secret is not a candidate");
    }

    /// When the acknowledgement could not even be written, the manager cannot
    /// have read it: the old secret goes first, and the file goes straight
    /// back to it. The connection that failed may stay down — a manager
    /// outage, say — and a restart in that time must not present the new one.
    #[tokio::test]
    async fn an_acknowledgement_that_never_left_puts_the_previous_secret_first() {
        let mut relay = Relay::new(manager_config(Some(OLD), None));
        let mut creds = relay.credentials();

        let (relay_io, manager_io) = tokio::io::duplex(1 << 20);
        let relay_ws = WebSocketStream::from_raw_socket(relay_io, Role::Client, None).await;
        drop(manager_io);
        let (mut ws_write, _ws_read) = relay_ws.split();
        handle_manager_message(
            &rotate_command(NEW).to_string(),
            &relay.ctx,
            &relay.relay_config,
            &relay.config_path,
            &mut ws_write,
            None,
            &mut creds,
        )
        .await;
        assert_eq!(
            relay.secret_on_disk().as_deref(),
            Some(OLD),
            "a restart now would present a secret the manager never read"
        );

        let (_, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_ok()).await })
            .await;
        assert_eq!(shown["node_secret"], OLD);
        assert_eq!(relay.secret_on_disk().as_deref(), Some(OLD));
    }

    /// The file holds what a restart presents, so a saved secret takes the
    /// identity it belongs to with it. A file that cannot be re-read is
    /// rewritten from the startup config, and for a relay that registered
    /// since it started that config still holds the consumed registration
    /// token and no node ID.
    #[tokio::test]
    async fn a_secret_saved_over_an_unreadable_file_keeps_the_identity_it_belongs_to() {
        let mut relay = Relay::new(manager_config(None, Some("one-time-token")));
        let mut creds = relay.credentials();

        let (_, ()) = relay
            .session(&mut creds, |mut ws| async move {
                let register_ack = serde_json::json!({
                    "type": "register_ack",
                    "payload": { "node_id": "node-9", "node_secret": "issued-secret" }
                });
                authenticate(&mut ws, register_ack).await;
            })
            .await;
        std::fs::write(&relay.config_path, "{ not json").unwrap();

        let (_, ack) = relay
            .session(&mut creds, |mut ws| async move {
                authenticate(&mut ws, auth_ok()).await;
                rotate(&mut ws, NEW).await
            })
            .await;
        assert_eq!(ack["success"], true, "{ack}");

        let text = std::fs::read_to_string(&relay.config_path).unwrap();
        let on_disk = serde_json::from_str::<RelayConfig>(&text).unwrap().manager.unwrap();
        let after_restart = build_auth_message(&on_disk)["payload"].clone();
        assert_eq!(after_restart["node_id"], "node-9", "{after_restart}");
        assert_eq!(after_restart["node_secret"], NEW, "{after_restart}");
        assert!(on_disk.registration_token.is_none(), "the consumed token was written back");
    }

    /// The reconnect loop itself, not only one session, carries what a session
    /// learned: the credentials outlive each attempt. This is where the relay
    /// was locked out — the loop kept authenticating with the config it
    /// started with, whatever the session before had been told.
    #[tokio::test(start_paused = true)]
    async fn the_reconnect_loop_presents_a_rotated_secret_at_its_next_attempt() {
        let relay = Relay::new(manager_config(Some(OLD), None));
        let manager = relay.relay_config.manager.clone().unwrap();

        // Each attempt gets a fresh in-memory connection, whose manager end
        // comes out here.
        let (manager_end, mut accepted) = mpsc::unbounded_channel();
        let connect = move |_url: String, _config: ManagerConfig| {
            let (relay_io, manager_io) = tokio::io::duplex(1 << 20);
            let _ = manager_end.send(manager_io);
            async move { Ok(WebSocketStream::from_raw_socket(relay_io, Role::Client, None).await) }
        };
        let client = manager_client_loop(
            manager,
            relay.ctx.clone(),
            relay.relay_stats.clone(),
            relay.relay_config.clone(),
            relay.config_path.clone(),
            relay.event_rx,
            relay.event_sender.clone(),
            None,
            connect,
        );

        let fake_manager = async {
            let mut ws = answer(accepted.recv().await.unwrap()).await;
            let shown = authenticate(&mut ws, auth_ok()).await;
            assert_eq!(shown["node_secret"], OLD);
            let ack = rotate(&mut ws, NEW).await;
            assert_eq!(ack["success"], true, "{ack}");
            break_connection(ws).await;

            // The loop waits out its backoff (on the paused clock) and dials again.
            let mut ws = answer(accepted.recv().await.unwrap()).await;
            authenticate(&mut ws, auth_ok()).await
        };
        let shown = tokio::select! {
            _ = client => panic!("the reconnect loop never returns"),
            shown = fake_manager => shown,
        };
        assert_eq!(
            shown["node_secret"], NEW,
            "the reconnect presented the secret the manager replaced"
        );
    }

    /// Registration had the same flaw, handing its credentials back in the
    /// session's `Ok` value: a reset after `register_ack` dropped them, and
    /// the relay presented its consumed registration token until a restart.
    #[tokio::test]
    async fn a_registration_survives_a_reset_connection() {
        let mut relay = Relay::new(manager_config(None, Some("one-time-token")));
        let mut creds = relay.credentials();

        let (ended, shown) = relay
            .session(&mut creds, |mut ws| async move {
                let register_ack = serde_json::json!({
                    "type": "register_ack",
                    "payload": { "node_id": "node-9", "node_secret": "issued-secret" }
                });
                let shown = authenticate(&mut ws, register_ack).await;
                break_connection(ws).await;
                shown
            })
            .await;
        assert_eq!(shown["registration_token"], "one-time-token");
        assert!(ended.unwrap_err().contains("WebSocket error"));

        let (_, shown) = relay
            .session(&mut creds, |mut ws| async move { authenticate(&mut ws, auth_ok()).await })
            .await;
        assert_eq!(shown["node_id"], "node-9");
        assert_eq!(shown["node_secret"], "issued-secret");
        assert!(shown.get("registration_token").is_none(), "{shown}");
    }

    /// Two rotations in one session, the second never stored: the manager holds
    /// the first. Every secret issued since the last accepted one stays a
    /// candidate, newest first, and a refusal moves one to the back rather
    /// than dropping it.
    #[test]
    fn every_secret_since_the_last_accepted_one_is_tried_newest_first() {
        let mut creds = LinkCredentials::new(manager_config(Some("s0"), None));
        creds.rotated("s1".into(), true);
        creds.rotated("s2".into(), true);

        let mut presented = Vec::new();
        for _ in 0..4 {
            presented.push(creds.config.node_secret.clone().unwrap());
            creds.rejected();
        }
        assert_eq!(presented, ["s2", "s1", "s0", "s2"]);

        assert!(creds.accepted(), "accepting settles which secret the manager holds");
        assert!(creds.fallback_secrets.is_empty());
        assert!(!creds.accepted(), "nothing was open the second time");
    }

    /// The manager locks a node out after five refusals in 60 s. However many
    /// rotations go unconfirmed, the relay reaches the last candidate on its
    /// fifth attempt at the latest.
    #[test]
    fn the_candidates_stay_inside_the_managers_lockout() {
        let mut creds = LinkCredentials::new(manager_config(Some("s0"), None));
        for i in 1..=10 {
            creds.rotated(format!("s{i}"), true);
        }
        assert_eq!(creds.config.node_secret.as_deref(), Some("s10"));
        assert_eq!(creds.fallback_secrets, ["s9", "s8", "s7", "s6"]);
        // The one presented plus its fallbacks, so at most four refusals.
        let candidates = 1 + creds.fallback_secrets.len();
        assert!(candidates <= 5, "{candidates} candidates would run into the lockout");
    }
}
