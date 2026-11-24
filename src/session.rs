// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-edge-connection session handling.
//!
//! Each edge connects via QUIC and immediately sends tunnel bind messages.
//! The relay is stateless — no authentication required. It pairs edges by
//! tunnel ID and forwards encrypted traffic between them.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use quinn::Connection;
use uuid::Uuid;

use crate::manager::events::{EventSender, EventSeverity, category};
use crate::protocol::*;
use crate::stats::RelayStats;
use crate::tunnel_router::{BindResult, TunnelEndpoint, TunnelRouter};

/// Counter for generating unique connection IDs.
static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Shared state accessible to all sessions.
pub struct SessionContext {
    pub router: Arc<TunnelRouter>,
    /// Native plain-UDP relay sessions (no QUIC). Shares the QUIC path's
    /// `router` bind-token registry for auth; carries its own source-address
    /// rendezvous pairing. Populated by [`crate::udp_relay::serve_udp_relay`].
    pub udp_sessions: Arc<crate::udp_relay::UdpSessionRouter>,
    /// Map of connection_id -> Connection for sending notifications.
    pub edge_connections: DashMap<String, Connection>,
    /// Per-IP connection counter — bounds the total active QUIC
    /// connections from any single source IP (DoS mitigation). Atomic
    /// so the increment + check is race-free across the spawn-per-
    /// connection model. Entries are removed when their counter drops
    /// to zero on disconnect.
    pub connections_by_ip: DashMap<IpAddr, Arc<AtomicU32>>,
    /// Global relay stats for peak tracking and connection counting.
    pub relay_stats: Arc<RelayStats>,
    /// Event sender for forwarding operational events to the manager.
    pub event_sender: EventSender,
    /// Per-IP connection cap from `RelayConfig::max_connections_per_ip`.
    pub max_connections_per_ip: u32,
    /// Per-connection tunnel-bind cap from
    /// `RelayConfig::max_tunnels_per_connection`.
    pub max_tunnels_per_connection: u32,
}

/// Handle a new QUIC connection from an edge node.
pub async fn handle_edge_connection(ctx: Arc<SessionContext>, connection: Connection) {
    let remote = connection.remote_address();
    let remote_ip = remote.ip();

    // Per-IP connection cap — DoS mitigation. Increment first, then
    // compare against the cap; if exceeded, decrement and reject.
    // This is race-safe under spawn-per-connection because we never
    // skip the decrement on rejection.
    let ip_counter = ctx
        .connections_by_ip
        .entry(remote_ip)
        .or_insert_with(|| Arc::new(AtomicU32::new(0)))
        .clone();
    let active = ip_counter.fetch_add(1, Ordering::Relaxed) + 1;
    if active > ctx.max_connections_per_ip {
        ip_counter.fetch_sub(1, Ordering::Relaxed);
        tracing::warn!(
            "Rejecting QUIC connection from {remote}: per-IP cap of {} exceeded ({} active)",
            ctx.max_connections_per_ip,
            active
        );
        ctx.event_sender.emit_with_details(
            EventSeverity::Warning,
            category::EDGE,
            format!(
                "Connection rejected: per-IP cap exceeded ({} active from {})",
                active, remote_ip
            ),
            serde_json::json!({
                "error_code": "relay_dos_suspect",
                "remote_addr": remote.to_string(),
                "remote_ip": remote_ip.to_string(),
                "active_connections": active,
                "cap": ctx.max_connections_per_ip,
            }),
        );
        // Closing the connection without finishing the handshake; quinn
        // will tear it down. We deliberately don't open the control bi.
        connection.close(0u32.into(), b"per-ip connection cap exceeded");
        return;
    }

    let connection_id = format!(
        "conn-{}-{}",
        CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed),
        remote
    );
    tracing::info!("New QUIC connection from {remote} (id: {connection_id})");
    ctx.event_sender.emit_with_details(EventSeverity::Info, category::EDGE, format!("Edge connected from {}", remote), serde_json::json!({ "remote_addr": remote.to_string() }));
    ctx.relay_stats
        .connections_total
        .fetch_add(1, Ordering::Relaxed);

    // Open the control bi-stream (edge initiates it)
    let (mut send, mut recv) = match connection.accept_bi().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to accept control stream from {remote}: {e}");
            ctx.event_sender.emit_with_details(EventSeverity::Warning, category::EDGE, format!("Edge connection failed: control stream error from {}", remote), serde_json::json!({ "remote_addr": remote.to_string() }));
            // Decrement the per-IP counter on early exit.
            decrement_ip_counter(&ctx, &remote_ip);
            return;
        }
    };

    // Register connection
    ctx.edge_connections
        .insert(connection_id.clone(), connection.clone());

    // Process control messages + data streams + UDP datagrams concurrently.
    // The identified edge_id (set via Identify message, used for reporting)
    // is owned by `handle_control_stream` since no other branch reads it.
    let ctrl_ctx = ctx.clone();
    let ctrl_conn = connection.clone();
    let ctrl_edge = connection_id.clone();

    let data_ctx = ctx.clone();
    let data_conn = connection.clone();
    let data_edge = connection_id.clone();

    let dgram_ctx = ctx.clone();
    let dgram_conn = connection.clone();
    let dgram_edge = connection_id.clone();

    tokio::select! {
        // Control stream message loop
        r = handle_control_stream(&ctrl_ctx, &ctrl_conn, &ctrl_edge, &mut send, &mut recv) => {
            if let Err(e) = r {
                tracing::debug!("Control stream ended for '{ctrl_edge}': {e}");
            }
        }
        // Accept incoming data streams (TCP tunnel connections from this edge)
        r = handle_data_streams(&data_ctx, &data_conn, &data_edge) => {
            if let Err(e) = r {
                tracing::debug!("Data stream handler ended for '{data_edge}': {e}");
            }
        }
        // Forward UDP datagrams
        r = handle_udp_datagrams(&dgram_ctx, &dgram_conn, &dgram_edge) => {
            if let Err(e) = r {
                tracing::debug!("UDP datagram handler ended for '{dgram_edge}': {e}");
            }
        }
        // Connection closed
        _ = connection.closed() => {
            tracing::info!("Connection '{connection_id}' closed");
        }
    }

    // Cleanup: remove edge and notify peers
    tracing::info!("Connection '{connection_id}' disconnected from {remote}");
    ctx.event_sender.emit_with_details(EventSeverity::Info, category::EDGE, format!("Edge disconnected from {}", remote), serde_json::json!({ "remote_addr": remote.to_string() }));
    ctx.edge_connections.remove(&connection_id);
    decrement_ip_counter(&ctx, &remote_ip);

    let affected = ctx.router.remove_edge(&connection_id);
    for (tunnel_id, peer_edge_id) in affected {
        let tunnel_id_str = tunnel_id.to_string();
        ctx.event_sender.emit_with_id(EventSeverity::Warning, category::TUNNEL, "Tunnel down: edge disconnected", &tunnel_id_str);
        if let Some(peer_id) = peer_edge_id {
            notify_tunnel_down(&ctx, &peer_id, tunnel_id, "peer disconnected").await;
        }
    }
}

/// Decrement the per-IP connection counter, removing the map entry when
/// it drops to zero. Safe to call exactly once per accepted-and-then-
/// rejected or disconnected connection.
fn decrement_ip_counter(ctx: &Arc<SessionContext>, ip: &IpAddr) {
    if let Some(entry) = ctx.connections_by_ip.get(ip) {
        let prev = entry.fetch_sub(1, Ordering::Relaxed);
        // If we just dropped to zero, remove the entry. Use remove_if
        // to avoid a TOCTOU between the load and remove.
        if prev == 1 {
            drop(entry);
            ctx.connections_by_ip
                .remove_if(ip, |_, counter| counter.load(Ordering::Relaxed) == 0);
        }
    }
}

async fn handle_control_stream(
    ctx: &Arc<SessionContext>,
    connection: &Connection,
    connection_id: &str,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<()> {
    // Identified edge_id (set via Identify message, used for reporting).
    // Falls back to connection_id if not set. Owned locally — no other
    // task in this session needs to read it, so no Mutex is required.
    let mut identified_id: Option<String> = None;

    // Per-connection tunnel-bind counter for the DoS cap. Increments on
    // every accepted bind, decrements on Unbind, and on edge disconnect
    // the entire counter is dropped with this function. The cap comes
    // from `RelayConfig::max_tunnels_per_connection`.
    let mut active_binds_on_this_conn: u32 = 0;

    loop {
        let parsed = read_message_resilient::<EdgeMessage>(recv).await?;

        let msg = match parsed {
            ParsedMessage::Known(msg) => msg,
            ParsedMessage::Unknown { msg_type } => {
                tracing::debug!(
                    "Unknown message type '{msg_type}' from '{connection_id}', ignoring"
                );
                continue;
            }
        };

        match msg {
            EdgeMessage::Identify { edge_id: provided_id } => {
                if provided_id.len() > 64 {
                    tracing::warn!(
                        "Connection '{connection_id}' sent Identify with edge_id too long ({} chars), ignoring",
                        provided_id.len()
                    );
                    continue;
                }
                tracing::info!(
                    "Connection '{connection_id}' identified as '{provided_id}'"
                );
                identified_id = Some(provided_id);
            }

            EdgeMessage::TunnelBind {
                tunnel_id,
                direction,
                protocol,
                bind_token,
            } => {
                // Per-connection tunnel-bind cap — DoS mitigation.
                // Checked BEFORE bind-token verification so a malicious
                // connection spamming bogus tunnel IDs can't exhaust
                // memory just by failing fast.
                if active_binds_on_this_conn >= ctx.max_tunnels_per_connection {
                    tracing::warn!(
                        "Connection '{connection_id}' bind rejected for tunnel {tunnel_id} — per-connection tunnel cap of {} exceeded",
                        ctx.max_tunnels_per_connection
                    );
                    ctx.event_sender.emit_with_id_and_details(
                        EventSeverity::Warning,
                        category::TUNNEL,
                        "Tunnel bind rejected: per-connection cap exceeded",
                        &tunnel_id.to_string(),
                        serde_json::json!({
                            "error_code": "relay_dos_suspect",
                            "remote_addr": connection.remote_address().to_string(),
                            "active_binds": active_binds_on_this_conn,
                            "cap": ctx.max_tunnels_per_connection,
                        }),
                    );
                    write_message(
                        send,
                        &RelayMessage::TunnelDown {
                            tunnel_id,
                            reason: "per-connection tunnel limit exceeded".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }

                // Verify bind token before allowing the bind
                if !ctx.router.verify_bind_token(&tunnel_id, direction, bind_token.as_deref()) {
                    tracing::warn!(
                        "Connection '{connection_id}' bind rejected for tunnel {tunnel_id} — invalid bind_token"
                    );
                    ctx.event_sender.emit_with_id_and_details(EventSeverity::Warning, category::TUNNEL, "Tunnel bind rejected: invalid token", &tunnel_id.to_string(), serde_json::json!({ "remote_addr": connection.remote_address().to_string() }));
                    write_message(
                        send,
                        &RelayMessage::TunnelDown {
                            tunnel_id,
                            reason: "bind authentication failed".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }

                // Use identified edge_id for reporting, connection_id for internal lookups
                let edge_id = identified_id
                    .clone()
                    .unwrap_or_else(|| connection_id.to_string());

                tracing::info!(
                    "Connection '{connection_id}' (edge '{edge_id}') binding tunnel {tunnel_id} as {direction:?} ({protocol:?})"
                );

                let endpoint = TunnelEndpoint {
                    edge_id,
                    connection_id: connection_id.to_string(),
                    direction,
                    connection: connection.clone(),
                };

                // Bind accepted — bump the per-connection counter.
                active_binds_on_this_conn = active_binds_on_this_conn.saturating_add(1);

                match ctx.router.bind(tunnel_id, protocol, endpoint) {
                    BindResult::Active => {
                        tracing::info!("Tunnel {tunnel_id} is now active (both sides bound)");
                        ctx.event_sender.emit_with_id_and_details(EventSeverity::Info, category::TUNNEL, "Tunnel active (both sides bound)", &tunnel_id.to_string(), serde_json::json!({ "direction": format!("{:?}", direction) }));

                        // Notify this edge
                        write_message(send, &RelayMessage::TunnelReady { tunnel_id }).await?;

                        // Notify peer (use connection_id for DashMap lookup)
                        let peer_dir = match direction {
                            TunnelDirection::Ingress => TunnelDirection::Egress,
                            TunnelDirection::Egress => TunnelDirection::Ingress,
                        };
                        if let Some(entry) = ctx.router.tunnel(&tunnel_id) {
                            let peer_connection_id = match peer_dir {
                                TunnelDirection::Egress => {
                                    entry.egress.as_ref().map(|e| e.connection_id.clone())
                                }
                                TunnelDirection::Ingress => {
                                    entry.ingress.as_ref().map(|e| e.connection_id.clone())
                                }
                            };
                            drop(entry);
                            if let Some(peer_id) = peer_connection_id {
                                notify_tunnel_ready(ctx, &peer_id, tunnel_id).await;
                            }
                        }
                    }
                    BindResult::Waiting => {
                        tracing::info!("Tunnel {tunnel_id} waiting for peer");
                        ctx.event_sender.emit_with_id_and_details(EventSeverity::Info, category::TUNNEL, format!("Tunnel waiting: {:?} side bound", direction), &tunnel_id.to_string(), serde_json::json!({ "direction": format!("{:?}", direction) }));
                        write_message(send, &RelayMessage::TunnelWaiting { tunnel_id }).await?;
                    }
                }
            }

            EdgeMessage::TunnelUnbind { tunnel_id } => {
                tracing::info!("Connection '{connection_id}' unbinding tunnel {tunnel_id}");
                ctx.event_sender.emit_with_id(EventSeverity::Info, category::TUNNEL, "Tunnel unbound by edge", &tunnel_id.to_string());
                // Decrement the per-connection counter (saturating at 0
                // so an unmatched Unbind from a buggy edge can't take
                // the counter negative — important if the cap is later
                // checked against an underflowed u32).
                active_binds_on_this_conn = active_binds_on_this_conn.saturating_sub(1);
                if let Some(peer_id) = ctx.router.unbind(&tunnel_id, connection_id) {
                    notify_tunnel_down(ctx, &peer_id, tunnel_id, "peer unbound").await;
                }
            }

            EdgeMessage::Ping => {
                write_message(send, &RelayMessage::Pong).await?;
            }

            EdgeMessage::Hello { protocol_version, software_version } => {
                tracing::info!(
                    "Connection '{connection_id}' hello: protocol v{protocol_version}, software {software_version}"
                );
                if protocol_version != TUNNEL_PROTOCOL_VERSION {
                    tracing::warn!(
                        "Protocol version mismatch with '{connection_id}': edge={protocol_version}, relay={TUNNEL_PROTOCOL_VERSION}"
                    );
                    ctx.event_sender.emit_with_details(EventSeverity::Warning, category::EDGE, format!(
                        "Protocol version mismatch with '{}': edge={}, relay={}",
                        connection_id, protocol_version, TUNNEL_PROTOCOL_VERSION
                    ), serde_json::json!({ "edge_version": protocol_version, "relay_version": TUNNEL_PROTOCOL_VERSION }));
                }
                write_message(
                    send,
                    &RelayMessage::HelloAck {
                        protocol_version: TUNNEL_PROTOCOL_VERSION,
                        software_version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                )
                .await?;
            }
        }
    }
}

/// Accept and forward data streams (TCP tunnel connections) from this edge.
async fn handle_data_streams(
    ctx: &Arc<SessionContext>,
    connection: &Connection,
    edge_id: &str,
) -> Result<()> {
    loop {
        let (send, mut recv) = connection.accept_bi().await?;

        let ctx = ctx.clone();
        let edge_id = edge_id.to_string();

        tokio::spawn(async move {
            if let Err(e) = forward_tcp_stream(&ctx, &edge_id, send, &mut recv).await {
                tracing::debug!("TCP stream forwarding ended for '{edge_id}': {e}");
            }
        });
    }
}

/// Forward a single TCP stream from one edge to the peer through the relay.
async fn forward_tcp_stream(
    ctx: &Arc<SessionContext>,
    connection_id: &str,
    mut from_send: quinn::SendStream,
    from_recv: &mut quinn::RecvStream,
) -> Result<()> {
    // Read the stream header to identify the tunnel
    let header: StreamHeader = read_stream_header(from_recv).await?;
    let tunnel_id = header.tunnel_id;

    tracing::debug!("TCP stream for tunnel {tunnel_id} from connection '{connection_id}'");

    // Determine direction of this edge in the tunnel
    let from_direction = {
        let entry = ctx.router.tunnel(&tunnel_id).context("tunnel not found")?;
        if entry
            .ingress
            .as_ref()
            .is_some_and(|e| e.connection_id == connection_id)
        {
            TunnelDirection::Ingress
        } else {
            TunnelDirection::Egress
        }
    };

    // Get peer connection
    let (peer_conn, stats) = ctx
        .router
        .get_peer_connection(&tunnel_id, from_direction)
        .context("peer not connected for tunnel")?;

    // Open a new bi-stream to the peer
    let (mut peer_send, mut peer_recv) = peer_conn.open_bi().await?;

    // Write stream header to peer
    write_stream_header(&mut peer_send, &header).await?;

    stats.tcp_streams_total.fetch_add(1, Ordering::Relaxed);
    stats.tcp_streams_active.fetch_add(1, Ordering::Relaxed);

    // Bidirectional copy
    let stats_a = stats.clone();
    let stats_b = stats.clone();
    let copy_a = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = from_recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            peer_send.write_all(&buf[..n]).await?;
            stats_a.bytes_ingress.fetch_add(n as u64, Ordering::Relaxed);
        }
        peer_send.finish()?;
        Ok::<_, anyhow::Error>(())
    };

    let copy_b = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = peer_recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            from_send.write_all(&buf[..n]).await?;
            stats_b.bytes_egress.fetch_add(n as u64, Ordering::Relaxed);
        }
        from_send.finish()?;
        Ok::<_, anyhow::Error>(())
    };

    // Run both directions concurrently
    let _ = tokio::join!(copy_a, copy_b);

    stats.tcp_streams_active.fetch_sub(1, Ordering::Relaxed);
    tracing::debug!("TCP stream for tunnel {tunnel_id} finished");
    Ok(())
}

/// Receive QUIC datagrams from this edge and forward to the peer edge.
/// Datagrams carry UDP tunnel data with a 16-byte tunnel_id prefix.
async fn handle_udp_datagrams(
    ctx: &Arc<SessionContext>,
    connection: &Connection,
    connection_id: &str,
) -> Result<()> {
    loop {
        let datagram = connection.read_datagram().await?;

        let Some((tunnel_id, payload)) = decode_udp_datagram(&datagram) else {
            tracing::debug!("Malformed UDP datagram from '{connection_id}' (too short)");
            continue;
        };

        // Determine this edge's direction in the tunnel
        let from_direction = {
            let Some(entry) = ctx.router.tunnel(&tunnel_id) else {
                tracing::debug!("UDP datagram for unknown tunnel {tunnel_id} from '{connection_id}'");
                continue;
            };
            if entry
                .ingress
                .as_ref()
                .is_some_and(|e| e.connection_id == connection_id)
            {
                TunnelDirection::Ingress
            } else {
                TunnelDirection::Egress
            }
        };

        // Look up peer connection and stats
        let Some((peer_conn, stats)) = ctx.router.get_peer_connection(&tunnel_id, from_direction)
        else {
            tracing::debug!("No peer for UDP tunnel {tunnel_id}");
            continue;
        };

        // Forward the full datagram (with tunnel_id prefix) to the peer
        match peer_conn.send_datagram(datagram.clone()) {
            Ok(()) => {
                stats
                    .udp_datagrams_total
                    .fetch_add(1, Ordering::Relaxed);
                let bytes = payload.len() as u64;
                match from_direction {
                    TunnelDirection::Ingress => {
                        stats.bytes_ingress.fetch_add(bytes, Ordering::Relaxed);
                    }
                    TunnelDirection::Egress => {
                        stats.bytes_egress.fetch_add(bytes, Ordering::Relaxed);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Failed to forward UDP datagram for tunnel {tunnel_id}: {e}");
            }
        }
    }
}

/// How long a notification to an edge may take to leave. Best effort, like
/// the notification itself.
///
/// Opening the stream waits for the edge to allow another one, and writing it
/// waits on the edge's flow control: an edge that has stopped taking streams
/// but still answers keep-alives holds both for ever. The callers await this
/// inline — another edge's control loop and its cleanup, the REST tunnel
/// delete, and the manager's `close_tunnel`, whose session writes nothing to
/// the manager meanwhile — so one such edge must not hold them for longer
/// than this.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Send `msg` to an edge on a stream of its own (the edge's control stream
/// belongs to its session task). Best effort: a missing or closed connection,
/// or one that takes longer than [`NOTIFY_TIMEOUT`], is ignored.
async fn notify_edge(ctx: &Arc<SessionContext>, edge_id: &str, msg: &RelayMessage) {
    // A clone of the handle, not the map's `Ref`: a `Ref` held across the
    // awaits below holds its shard's lock with it, and an edge connecting or
    // disconnecting meanwhile — an insert or remove in that shard — would
    // block a runtime thread until the notification ended.
    let Some(conn) = ctx.edge_connections.get(edge_id).map(|c| c.clone()) else {
        return;
    };
    let notify = async {
        if let Ok(mut send) = conn.open_uni().await {
            let _ = write_message(&mut send, msg).await;
            let _ = send.finish();
        }
    };
    if tokio::time::timeout(NOTIFY_TIMEOUT, notify).await.is_err() {
        tracing::debug!(
            "Notification to edge '{edge_id}' did not leave within {}s; dropped",
            NOTIFY_TIMEOUT.as_secs()
        );
    }
}

/// Send a TunnelReady notification to an edge.
async fn notify_tunnel_ready(ctx: &Arc<SessionContext>, edge_id: &str, tunnel_id: Uuid) {
    notify_edge(ctx, edge_id, &RelayMessage::TunnelReady { tunnel_id }).await;
}

/// Send a TunnelDown notification to an edge.
///
/// `edge_id` here is the `edge_connections` key, i.e. the endpoint's
/// `connection_id` (the value returned by `TunnelRouter::force_remove_tunnel`
/// and `remove_edge`). Best effort, as [`notify_edge`] says.
pub(crate) async fn notify_tunnel_down(
    ctx: &Arc<SessionContext>,
    edge_id: &str,
    tunnel_id: Uuid,
    reason: &str,
) {
    let msg = RelayMessage::TunnelDown {
        tunnel_id,
        reason: reason.to_string(),
    };
    notify_edge(ctx, edge_id, &msg).await;
}

#[cfg(test)]
pub(crate) mod test_relay {
    //! A relay running the real session code over QUIC on loopback, and edges
    //! to reach it.
    use super::*;
    use rustls::pki_types::CertificateDer;
    use std::net::SocketAddr;

    /// The relay's address, the certificate an edge must trust to reach it,
    /// and its state.
    pub(crate) fn start_relay() -> (SocketAddr, CertificateDer<'static>, Arc<SessionContext>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key.into())
            .unwrap();
        tls.alpn_protocols = vec![ALPN_RELAY.to_vec()];
        let server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (event_sender, _events) = crate::manager::event_channel();
        let ctx = crate::server::create_session_context(Arc::new(RelayStats::new()), event_sender, false, 64, 100);
        let accept_ctx = ctx.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let ctx = accept_ctx.clone();
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        handle_edge_connection(ctx, connection).await;
                    }
                });
            }
        });
        (addr, cert_der, ctx)
    }

    /// An edge's endpoint, connection and control stream. It allows the relay
    /// `uni_streams` streams of the relay's own, which is what notifications
    /// arrive on.
    pub(crate) async fn edge(
        relay: SocketAddr,
        cert: &CertificateDer<'static>,
        uni_streams: u32,
    ) -> (quinn::Endpoint, Connection, quinn::SendStream, quinn::RecvStream) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN_RELAY.to_vec()];
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(uni_streams.into());
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);
        let connection = endpoint.connect(relay, "localhost").unwrap().await.unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        (endpoint, connection, send, recv)
    }
}

#[cfg(test)]
mod notify_tests {
    //! Notifications from one edge's session to another.
    use super::test_relay::{edge, start_relay};
    use super::*;

    /// An edge that has stopped taking streams but still answers keep-alives
    /// held the relay's notification to it for ever — and with it the control
    /// loop of the edge whose bind set it off, which answered nothing more.
    #[tokio::test]
    async fn an_edge_that_takes_no_streams_does_not_hold_up_its_peer() {
        let (relay, cert, _ctx) = start_relay();
        let tunnel_id = Uuid::new_v4();
        let bind = |direction| EdgeMessage::TunnelBind {
            tunnel_id,
            direction,
            protocol: TunnelProtocol::Tcp,
            bind_token: None,
        };

        // It allows the relay no streams, so a notification to it never opens.
        let (_deaf_endpoint, _deaf, mut deaf_send, mut deaf_recv) = edge(relay, &cert, 0).await;
        write_message(&mut deaf_send, &bind(TunnelDirection::Ingress)).await.unwrap();
        let waiting: RelayMessage = read_message(&mut deaf_recv).await.unwrap();
        assert!(matches!(waiting, RelayMessage::TunnelWaiting { .. }), "{waiting:?}");

        let (_endpoint, _peer, mut send, mut recv) = edge(relay, &cert, 100).await;
        write_message(&mut send, &bind(TunnelDirection::Egress)).await.unwrap();
        let ready: RelayMessage = read_message(&mut recv).await.unwrap();
        assert!(matches!(ready, RelayMessage::TunnelReady { .. }), "{ready:?}");

        // This edge's control loop is now notifying the deaf one.
        write_message(&mut send, &EdgeMessage::Ping).await.unwrap();
        let pong = tokio::time::timeout(NOTIFY_TIMEOUT * 3, read_message::<RelayMessage>(&mut recv))
            .await
            .expect("the control loop is still held by the notification")
            .unwrap();
        assert!(matches!(pong, RelayMessage::Pong), "{pong:?}");
    }
}

#[cfg(test)]
mod tunnel_counter_tests {
    //! The relay-wide counters, fed by real edges.
    use super::test_relay::{edge, start_relay};
    use super::*;
    use crate::stats::TunnelTotals;
    use tokio::time::{Instant, sleep, timeout};

    const WAIT: Duration = Duration::from_secs(10);

    fn bind(tunnel_id: Uuid, direction: TunnelDirection, protocol: TunnelProtocol) -> EdgeMessage {
        EdgeMessage::TunnelBind { tunnel_id, direction, protocol, bind_token: None }
    }

    /// Send `msg` and wait until the relay has handled it.
    async fn send_and_settle(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        msg: &EdgeMessage,
    ) {
        write_message(send, msg).await.unwrap();
        write_message(send, &EdgeMessage::Ping).await.unwrap();
        loop {
            if let RelayMessage::Pong = read_message(recv).await.unwrap() {
                return;
            }
        }
    }

    /// Wait for the totals to reach `want`: a task counts after it has sent.
    async fn settle(ctx: &SessionContext, want: TunnelTotals, what: &str) {
        let until = Instant::now() + WAIT;
        while ctx.router.totals() != want && Instant::now() < until {
            sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(ctx.router.totals(), want, "{what}");
    }

    async fn wait_for(what: &str, done: impl Fn() -> bool) {
        let until = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < until, "{what}");
            sleep(Duration::from_millis(2)).await;
        }
    }

    /// Datagrams through a tunnel that is unbound, bound again under its id,
    /// removed by force, and lost with its edges: each leaves the totals as
    /// they were, and the tunnel's own figures start again.
    #[tokio::test]
    async fn datagram_totals_outlive_the_tunnel() {
        let (relay, cert, ctx) = start_relay();
        let (_e1, ingress, mut in_tx, mut in_rx) = edge(relay, &cert, 100).await;
        let (_e2, egress, mut out_tx, mut out_rx) = edge(relay, &cert, 100).await;
        let id = Uuid::new_v4();
        let udp = TunnelProtocol::Udp;
        let totals = |bytes_ingress, bytes_egress, udp_datagrams_total| TunnelTotals {
            bytes_ingress,
            bytes_egress,
            tcp_streams_total: 0,
            udp_datagrams_total,
        };
        let row = || {
            let rows = ctx.router.list_tunnels();
            assert_eq!(rows.len(), 1);
            (rows[0].stats.bytes_ingress, rows[0].stats.bytes_egress, rows[0].stats.udp_datagrams_total)
        };

        send_and_settle(&mut in_tx, &mut in_rx, &bind(id, TunnelDirection::Ingress, udp)).await;
        send_and_settle(&mut out_tx, &mut out_rx, &bind(id, TunnelDirection::Egress, udp)).await;
        ingress.send_datagram(encode_udp_datagram(&id, &[1; 100]).into()).unwrap();
        timeout(WAIT, egress.read_datagram()).await.unwrap().unwrap();
        egress.send_datagram(encode_udp_datagram(&id, &[2; 30]).into()).unwrap();
        timeout(WAIT, ingress.read_datagram()).await.unwrap().unwrap();
        settle(&ctx, totals(100, 30, 2), "one datagram each way").await;
        assert_eq!(row(), (100, 30, 2));

        let unbind = EdgeMessage::TunnelUnbind { tunnel_id: id };
        send_and_settle(&mut out_tx, &mut out_rx, &unbind).await;
        assert_eq!(ctx.router.counts(), (1, 0));
        assert_eq!(ctx.router.totals(), totals(100, 30, 2), "one side unbound");
        send_and_settle(&mut in_tx, &mut in_rx, &unbind).await;
        assert_eq!(ctx.router.counts(), (0, 0));
        assert_eq!(ctx.router.totals(), totals(100, 30, 2), "both sides unbound");

        send_and_settle(&mut in_tx, &mut in_rx, &bind(id, TunnelDirection::Ingress, udp)).await;
        send_and_settle(&mut out_tx, &mut out_rx, &bind(id, TunnelDirection::Egress, udp)).await;
        assert_eq!(ctx.router.totals(), totals(100, 30, 2), "bound again");
        assert_eq!(row(), (0, 0, 0), "the tunnel's own figures start again");
        ingress.send_datagram(encode_udp_datagram(&id, &[3; 7]).into()).unwrap();
        timeout(WAIT, egress.read_datagram()).await.unwrap().unwrap();
        settle(&ctx, totals(107, 30, 3), "a datagram on the second tunnel").await;
        assert_eq!(row(), (7, 0, 1));

        assert_eq!(ctx.router.force_remove_tunnel(&id).map(|peers| peers.len()), Some(2));
        assert_eq!(ctx.router.counts(), (0, 0));
        assert_eq!(ctx.router.totals(), totals(107, 30, 3), "removed by force");

        send_and_settle(&mut in_tx, &mut in_rx, &bind(id, TunnelDirection::Ingress, udp)).await;
        send_and_settle(&mut out_tx, &mut out_rx, &bind(id, TunnelDirection::Egress, udp)).await;
        egress.send_datagram(encode_udp_datagram(&id, &[4; 1000]).into()).unwrap();
        timeout(WAIT, ingress.read_datagram()).await.unwrap().unwrap();
        settle(&ctx, totals(107, 1030, 4), "a datagram on the third tunnel").await;
        ingress.close(0u32.into(), b"");
        egress.close(0u32.into(), b"");
        wait_for("both edges gone", || ctx.router.counts() == (0, 0)).await;
        assert_eq!(ctx.router.totals(), totals(107, 1030, 4), "lost with its edges");
    }

    /// A TCP stream outlives the tunnel it was opened on: what it carries
    /// after the tunnel was removed is in the totals, and it is out of the
    /// gauge of the streams open on the tunnels held now.
    #[tokio::test]
    async fn a_stream_counts_after_its_tunnel_is_removed() {
        let (relay, cert, ctx) = start_relay();
        let (_e1, ingress, mut in_tx, mut in_rx) = edge(relay, &cert, 100).await;
        let (_e2, egress, mut out_tx, mut out_rx) = edge(relay, &cert, 100).await;
        let id = Uuid::new_v4();
        let tcp = TunnelProtocol::Tcp;
        let totals = |bytes_ingress, bytes_egress| TunnelTotals {
            bytes_ingress,
            bytes_egress,
            tcp_streams_total: 1,
            udp_datagrams_total: 0,
        };
        let active = || -> u64 {
            ctx.router.list_tunnels().iter().map(|t| t.stats.tcp_streams_active).sum()
        };

        send_and_settle(&mut in_tx, &mut in_rx, &bind(id, TunnelDirection::Ingress, tcp)).await;
        send_and_settle(&mut out_tx, &mut out_rx, &bind(id, TunnelDirection::Egress, tcp)).await;
        let (mut a_tx, mut a_rx) = ingress.open_bi().await.unwrap();
        let header = StreamHeader { tunnel_id: id, stream_type: StreamType::Tcp };
        write_stream_header(&mut a_tx, &header).await.unwrap();
        a_tx.write_all(&[1; 500]).await.unwrap();
        let (mut b_tx, mut b_rx) = timeout(WAIT, egress.accept_bi()).await.unwrap().unwrap();
        read_stream_header(&mut b_rx).await.unwrap();
        b_tx.write_all(&[2; 60]).await.unwrap();
        settle(&ctx, totals(500, 60), "before the tunnel is removed").await;
        assert_eq!(active(), 1);

        ctx.router.force_remove_tunnel(&id).unwrap();
        assert_eq!(ctx.router.totals(), totals(500, 60), "the tunnel is removed");
        assert_eq!(active(), 0, "no tunnel is held");
        a_tx.write_all(&[3; 4000]).await.unwrap();
        b_tx.write_all(&[4; 20]).await.unwrap();
        settle(&ctx, totals(4500, 80), "counted after the tunnel was removed").await;

        // Another removal folds in the tunnels nothing holds any more: not
        // this one, while its stream runs.
        let other = Uuid::new_v4();
        send_and_settle(&mut in_tx, &mut in_rx, &bind(other, TunnelDirection::Ingress, tcp)).await;
        ctx.router.force_remove_tunnel(&other).unwrap();
        a_tx.write_all(&[5; 8]).await.unwrap();
        a_tx.finish().unwrap();
        b_tx.finish().unwrap();
        a_rx.read_to_end(1 << 16).await.unwrap();
        b_rx.read_to_end(1 << 16).await.unwrap();
        settle(&ctx, totals(4508, 80), "the stream ended").await;
    }
}
