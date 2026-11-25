// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-edge-connection session handling.
//!
//! Each edge connects via QUIC and immediately sends tunnel bind messages.
//! The relay is stateless — no authentication required. It pairs edges by
//! tunnel ID and forwards encrypted traffic between them. It takes a tunnel's
//! traffic only from the two connections bound to it, each as the side it bound
//! ([`TunnelRouter::route`]).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use quinn::Connection;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::manager::events::{EventSender, EventSeverity, category};
use crate::protocol::*;
use crate::stats::RelayStats;
use crate::tunnel_router::{
    BindResult, GivenBack, NoRoute, Route, TokenDigest, TunnelEndpoint, TunnelRouter,
};
use crate::util::IpCounts;

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
    /// connections from any single source IP (DoS mitigation).
    pub connections_by_ip: IpCounts,
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

    // Per-IP connection cap — DoS mitigation. Checked and counted in one step.
    // Every way out below this one gives the count back.
    if let Err(active) = ctx.connections_by_ip.add(remote_ip, ctx.max_connections_per_ip) {
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
            ctx.connections_by_ip.remove(remote_ip);
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
    ctx.connections_by_ip.remove(remote_ip);

    let affected = ctx.router.remove_edge(&connection_id);
    for (tunnel_id, peer_edge_id) in affected {
        let tunnel_id_str = tunnel_id.to_string();
        ctx.event_sender.emit_with_id(EventSeverity::Warning, category::TUNNEL, "Tunnel down: edge disconnected", &tunnel_id_str);
        if let Some(peer_id) = peer_edge_id {
            notify_peer_gone(&ctx, &peer_id, tunnel_id, PEER_DISCONNECTED).await;
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

    // The sides this connection has asked for, for the DoS cap
    // (`RelayConfig::max_tunnels_per_connection`). It has bound no others. Once
    // there are as many as the cap, those it was refused, has unbound or lost
    // with their tunnel are taken out, and those another connection took over,
    // but for the ones the router remembers it had. So neither this nor what the
    // router holds for the connection is ever larger than the cap.
    let mut bound: HashSet<(Uuid, TunnelDirection)> = HashSet::new();

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
                let side = (tunnel_id, direction);
                let cap = ctx.max_tunnels_per_connection as usize;
                if bound.len() >= cap {
                    bound.retain(|(id, direction)| {
                        ctx.router.has_bound(id, *direction, connection_id)
                    });
                }
                if bound.len() >= cap && !bound.contains(&side) {
                    tracing::warn!(
                        "Connection '{connection_id}' bind rejected for tunnel {tunnel_id} — per-connection tunnel cap of {cap} exceeded"
                    );
                    ctx.event_sender.emit_with_id_and_details(
                        EventSeverity::Warning,
                        category::TUNNEL,
                        "Tunnel bind rejected: per-connection cap exceeded",
                        &tunnel_id.to_string(),
                        serde_json::json!({
                            "error_code": "relay_dos_suspect",
                            "remote_addr": connection.remote_address().to_string(),
                            "active_binds": bound.len(),
                            "cap": cap,
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
                    shown: bind_token.as_deref().map(TokenDigest::of),
                };

                bound.insert(side);
                match ctx.router.bind(tunnel_id, protocol, endpoint) {
                    BindResult::Refused => {
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
                    }
                    BindResult::Active => {
                        tracing::info!("Tunnel {tunnel_id} is now active (both sides bound)");
                        ctx.event_sender.emit_with_id_and_details(EventSeverity::Info, category::TUNNEL, "Tunnel active (both sides bound)", &tunnel_id.to_string(), serde_json::json!({ "direction": format!("{:?}", direction) }));

                        // Notify this edge
                        write_message(send, &RelayMessage::TunnelReady { tunnel_id }).await?;

                        // Notify peer (use connection_id for DashMap lookup)
                        if let Some(peer_id) = peer_connection_id(ctx, &tunnel_id, direction) {
                            notify_tunnel_ready(ctx, &peer_id, tunnel_id).await;
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
                if let Some(peer_id) = ctx.router.unbind(&tunnel_id, connection_id) {
                    notify_peer_gone(ctx, &peer_id, tunnel_id, PEER_UNBOUND).await;
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

/// The code a data stream is reset and stopped with when its opener is not
/// bound to the tunnel it names.
const STREAM_NOT_BOUND: u32 = 1;

/// Forward a single TCP stream from one edge to the peer through the relay.
///
/// The opener must be bound to the tunnel when the stream's header arrives. A
/// stream that is forwarded runs to its end, whoever holds the side by then.
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

    let Route { peer, stats, .. } = match ctx.router.route(&tunnel_id, connection_id) {
        Ok(route) => route,
        Err(why) => {
            if why == NoRoute::NotBound {
                // Only dropped, it would end at the opener like one that finished.
                let _ = from_send.reset(STREAM_NOT_BOUND.into());
                let _ = from_recv.stop(STREAM_NOT_BOUND.into());
            }
            anyhow::bail!("not forwarded on tunnel {tunnel_id}: {why:?}");
        }
    };

    // Open a new bi-stream to the peer
    let (mut peer_send, mut peer_recv) = peer.open_bi().await?;

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

        let Route { from, peer, stats } = match ctx.router.route(&tunnel_id, connection_id) {
            Ok(route) => route,
            Err(why) => {
                tracing::debug!("UDP datagram for tunnel {tunnel_id} from '{connection_id}' dropped: {why:?}");
                continue;
            }
        };

        // Forward the full datagram (with tunnel_id prefix) to the peer
        match peer.send_datagram(datagram.clone()) {
            Ok(()) => {
                stats
                    .udp_datagrams_total
                    .fetch_add(1, Ordering::Relaxed);
                let bytes = payload.len() as u64;
                match from {
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
///
/// `stands` says whether the message is still true, and is asked with the
/// stream open. An edge takes these streams in the order they were opened. So
/// what is true at the end is on the last stream written: whoever made it true
/// opened theirs after, and one opened later still finds its message untrue.
async fn notify_edge(
    ctx: &Arc<SessionContext>,
    edge_id: &str,
    msg: &RelayMessage,
    stands: impl FnOnce() -> bool,
) {
    // A clone of the handle, not the map's `Ref`: a `Ref` held across the
    // awaits below holds its shard's lock with it, and an edge connecting or
    // disconnecting meanwhile — an insert or remove in that shard — would
    // block a runtime thread until the notification ended.
    let Some(conn) = ctx.edge_connections.get(edge_id).map(|c| c.clone()) else {
        return;
    };
    let notify = async {
        if let Ok(mut send) = conn.open_uni().await
            && stands()
        {
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

/// The connection that holds the side opposite `direction`.
fn peer_connection_id(
    ctx: &SessionContext,
    tunnel_id: &Uuid,
    direction: TunnelDirection,
) -> Option<String> {
    let peer = match direction {
        TunnelDirection::Ingress => TunnelDirection::Egress,
        TunnelDirection::Egress => TunnelDirection::Ingress,
    };
    ctx.router.tunnel(tunnel_id)?.side(peer).map(|e| e.connection_id.clone())
}

fn is_active(ctx: &SessionContext, tunnel_id: &Uuid) -> bool {
    ctx.router.tunnel(tunnel_id).is_some_and(|tunnel| tunnel.is_active())
}

/// Send a TunnelReady notification to an edge, unless the tunnel has lost a
/// side by the time the edge is told.
async fn notify_tunnel_ready(ctx: &Arc<SessionContext>, edge_id: &str, tunnel_id: Uuid) {
    let msg = RelayMessage::TunnelReady { tunnel_id };
    notify_edge(ctx, edge_id, &msg, || is_active(ctx, &tunnel_id)).await;
}

/// Tell an edge that the other side of its tunnel is gone, unless it is bound
/// again by the time the edge is told.
async fn notify_peer_gone(ctx: &Arc<SessionContext>, edge_id: &str, tunnel_id: Uuid, reason: &str) {
    let msg = RelayMessage::TunnelDown { tunnel_id, reason: reason.to_string() };
    notify_edge(ctx, edge_id, &msg, || !is_active(ctx, &tunnel_id)).await;
}

/// Send a TunnelDown notification to the edges whose own bind of a tunnel went
/// with it. The `reason` is not one of those that are about a peer.
///
/// `edges` are `edge_connections` keys, i.e. the `connection_id`s returned by
/// `TunnelRouter::force_remove_tunnel`. They are told all at once: there may be
/// any number, and each best effort, as [`notify_edge`] says.
pub(crate) async fn notify_removed(
    ctx: &Arc<SessionContext>,
    edges: Vec<String>,
    tunnel_id: Uuid,
    reason: &'static str,
) {
    let mut told = JoinSet::new();
    for edge in edges {
        let ctx = ctx.clone();
        told.spawn(async move {
            let msg = RelayMessage::TunnelDown { tunnel_id, reason: reason.to_string() };
            notify_edge(&ctx, &edge, &msg, || true).await;
        });
    }
    told.join_all().await;
}

/// Register a tunnel's bind tokens, and report the sides that change hands by
/// it. The edges are told by a task of their own: the manager's session awaits
/// this, and one that takes no streams must not hold it.
pub(crate) fn authorize_tunnel(
    ctx: &Arc<SessionContext>,
    tunnel_id: Uuid,
    ingress_token: &str,
    egress_token: &str,
) {
    for given in ctx.router.authorize_tunnel(tunnel_id, ingress_token, egress_token) {
        let GivenBack { direction, connection_id, to, from } = given;
        tracing::warn!(
            "Tunnel {tunnel_id}: {direction:?} side given back to '{connection_id}', which showed its token; held by {from:?}"
        );
        ctx.event_sender.emit_with_id_and_details(
            EventSeverity::Warning,
            category::TUNNEL,
            "Tunnel side given back to the edge that showed its token",
            &tunnel_id.to_string(),
            serde_json::json!({
                "error_code": "relay_unproven_holder_replaced",
                "transport": "quic",
                "direction": format!("{direction:?}"),
                "remote_addr": to.to_string(),
                "held_by": from.map(|held_by| held_by.to_string()),
            }),
        );
        // It was told nothing while another held its side, so it is told how
        // the tunnel stands, and so is its peer if that has it up again.
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match peer_connection_id(&ctx, &tunnel_id, direction) {
                Some(peer) => {
                    notify_tunnel_ready(&ctx, &connection_id, tunnel_id).await;
                    notify_tunnel_ready(&ctx, &peer, tunnel_id).await;
                }
                None => notify_peer_gone(&ctx, &connection_id, tunnel_id, PEER_DISCONNECTED).await,
            }
        });
    }
}

#[cfg(test)]
pub(crate) mod test_relay {
    //! A relay running the real session code over QUIC on loopback, and edges
    //! to reach it.
    use super::*;
    use crate::manager::events::Event;
    use rustls::pki_types::CertificateDer;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    /// The relay's address, the certificate an edge must trust to reach it,
    /// and its state.
    pub(crate) fn start_relay() -> (SocketAddr, CertificateDer<'static>, Arc<SessionContext>) {
        start_relay_with(false, 64)
    }

    /// [`start_relay`] with its bind-auth policy and its per-IP cap.
    pub(crate) fn start_relay_with(
        require_bind_auth: bool,
        max_connections_per_ip: u32,
    ) -> (SocketAddr, CertificateDer<'static>, Arc<SessionContext>) {
        let (relay, cert, ctx, _) = start_relay_capped(require_bind_auth, max_connections_per_ip, 100);
        (relay, cert, ctx)
    }

    /// [`start_relay_with`] a per-connection tunnel cap, and the events raised.
    pub(crate) fn start_relay_capped(
        require_bind_auth: bool,
        max_connections_per_ip: u32,
        max_tunnels_per_connection: u32,
    ) -> (SocketAddr, CertificateDer<'static>, Arc<SessionContext>, mpsc::Receiver<Event>) {
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
        let (event_sender, events) = crate::manager::event_channel();
        let ctx = crate::server::create_session_context(
            Arc::new(RelayStats::new()),
            event_sender,
            require_bind_auth,
            max_connections_per_ip,
            max_tunnels_per_connection,
        );
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
        (addr, cert_der, ctx, events)
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

    /// The relay's id for an edge's connection, and the address it has it
    /// come from.
    pub(crate) fn relayed(ctx: &SessionContext, edge: &Connection) -> (String, SocketAddr) {
        // The same at both ends of a connection, and of no other.
        let key = |connection: &Connection| {
            let mut key = [0; 16];
            connection.export_keying_material(&mut key, b"which", b"").unwrap();
            key
        };
        let found = ctx.edge_connections.iter().find(|relayed| key(relayed) == key(edge)).unwrap();
        (found.key().clone(), found.remote_address())
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
mod removed_tests {
    //! Who is told that a tunnel was removed.
    use super::bound_sender_tests::Edge;
    use super::test_relay::start_relay;
    use super::*;
    use tokio::time::Instant;
    use TunnelDirection::{Egress, Ingress};

    /// Every connection whose bind went with it, the ones the side was taken
    /// from too. Those that take no streams hold up neither the others nor the
    /// caller, however many there are.
    #[tokio::test]
    async fn every_edge_that_had_bound_it_is_told_at_once() {
        let (relay, cert, ctx) = start_relay();
        let id = Uuid::new_v4();
        let mut deaf = Vec::new();
        for n in 0..4 {
            let mut edge = Edge::connect_taking(relay, &cert, 0).await;
            edge.bind(id, Ingress, Some(&format!("token {n}"))).await;
            deaf.push(edge);
        }
        let mut displaced = Edge::connect(relay, &cert).await;
        displaced.bind(id, Ingress, Some("token")).await;
        let mut holder = Edge::connect(relay, &cert).await;
        holder.bind(id, Ingress, None).await;
        // It has unbound, so it has nothing to lose.
        let mut unbound = Edge::connect(relay, &cert).await;
        unbound.bind(id, Egress, Some("token")).await;
        assert!(holder.notice().await.is_some(), "that the other side bound");
        unbound.unbind(id).await;
        assert!(holder.notice().await.is_some(), "and left");

        let edges = ctx.router.force_remove_tunnel(&id).unwrap();
        assert_eq!(edges.len(), 6);
        let since = Instant::now();
        let told = tokio::spawn({
            let ctx = ctx.clone();
            async move { notify_removed(&ctx, edges, id, "a reason").await }
        });
        for edge in [&displaced, &holder] {
            match edge.notice().await {
                Some(RelayMessage::TunnelDown { tunnel_id, reason }) => {
                    assert_eq!((tunnel_id, &reason[..]), (id, "a reason"));
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(!told.is_finished());
        told.await.unwrap();
        let took = since.elapsed();
        assert!(took >= NOTIFY_TIMEOUT && took < NOTIFY_TIMEOUT * 2, "{took:?}");
        let notice = tokio::time::timeout(Duration::from_millis(100), unbound.connection.accept_uni());
        assert!(notice.await.is_err(), "it has nothing to be told");
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

#[cfg(test)]
mod bound_sender_tests {
    //! Who may send into a tunnel: a connection that holds one of its sides.
    use super::test_relay::{edge, start_relay, start_relay_with};
    use super::*;
    use crate::stats::TunnelTotals;
    use quinn::{Endpoint, ReadError, RecvStream, SendStream};
    use rustls::pki_types::CertificateDer;
    use std::net::SocketAddr;
    use tokio::time::{Instant, sleep, timeout};
    use TunnelDirection::{Egress, Ingress};

    const WAIT: Duration = Duration::from_secs(10);

    pub(super) async fn soon<T>(what: &str, work: impl Future<Output = T>) -> T {
        timeout(WAIT, work).await.unwrap_or_else(|_| panic!("{what} did not happen"))
    }

    pub(super) struct Edge {
        _endpoint: Endpoint,
        pub(super) connection: Connection,
        send: SendStream,
        recv: RecvStream,
    }

    /// A data stream, as its opener or the edge it was opened to has it.
    type Stream = (SendStream, RecvStream);

    impl Edge {
        pub(super) async fn connect(relay: SocketAddr, cert: &CertificateDer<'static>) -> Self {
            Self::connect_taking(relay, cert, 100).await
        }

        /// [`Self::connect`], allowing the relay `notices` streams at a time.
        pub(super) async fn connect_taking(
            relay: SocketAddr,
            cert: &CertificateDer<'static>,
            notices: u32,
        ) -> Self {
            let (_endpoint, connection, send, recv) = edge(relay, cert, notices).await;
            Self { _endpoint, connection, send, recv }
        }

        /// Send `msg`, and wait until the relay has handled it. Returns its
        /// answers.
        pub(super) async fn tell(&mut self, msg: &EdgeMessage) -> Vec<RelayMessage> {
            write_message(&mut self.send, msg).await.unwrap();
            self.settle().await
        }

        /// Wait until the relay has handled what this edge has sent it.
        /// Returns its answers.
        pub(super) async fn settle(&mut self) -> Vec<RelayMessage> {
            write_message(&mut self.send, &EdgeMessage::Ping).await.unwrap();
            let mut answers = Vec::new();
            loop {
                match soon("an answer", read_message(&mut self.recv)).await.unwrap() {
                    RelayMessage::Pong => return answers,
                    answer => answers.push(answer),
                }
            }
        }

        /// Ask for a side. Returns why it was refused, if it was.
        pub(super) async fn ask(
            &mut self,
            tunnel_id: Uuid,
            direction: TunnelDirection,
            token: Option<&str>,
        ) -> Option<String> {
            let answers = self
                .tell(&EdgeMessage::TunnelBind {
                    tunnel_id,
                    direction,
                    protocol: TunnelProtocol::Udp,
                    bind_token: token.map(str::to_owned),
                })
                .await;
            match &answers[..] {
                [RelayMessage::TunnelDown { tunnel_id: id, reason }] if *id == tunnel_id => {
                    Some(reason.clone())
                }
                [RelayMessage::TunnelReady { .. } | RelayMessage::TunnelWaiting { .. }] => None,
                other => panic!("{other:?}"),
            }
        }

        pub(super) async fn bind(
            &mut self,
            tunnel_id: Uuid,
            direction: TunnelDirection,
            token: Option<&str>,
        ) {
            assert_eq!(self.ask(tunnel_id, direction, token).await, None);
        }

        /// The next message on a stream of the relay's own. `None` if the
        /// stream carries none.
        pub(super) async fn notice(&self) -> Option<RelayMessage> {
            let mut recv = soon("a notice", self.connection.accept_uni()).await.unwrap();
            soon("its message", read_message(&mut recv)).await.ok()
        }

        pub(super) async fn unbind(&mut self, tunnel_id: Uuid) {
            self.tell(&EdgeMessage::TunnelUnbind { tunnel_id }).await;
        }

        /// Send a datagram, and wait until the relay has handled it.
        pub(super) async fn datagram(&mut self, id: Uuid, payload: &str) {
            let datagram = encode_udp_datagram(&id, payload.as_bytes());
            self.connection.send_datagram(datagram.into()).unwrap();
            self.settle().await;
        }

        /// The next datagram to reach this edge.
        pub(super) async fn read(&self, id: Uuid) -> String {
            let datagram = soon("a datagram", self.connection.read_datagram()).await.unwrap();
            let (from, payload) = decode_udp_datagram(&datagram).unwrap();
            assert_eq!(from, id);
            String::from_utf8(payload.to_vec()).unwrap()
        }

        /// Open a data stream that begins with `payload`.
        pub(super) async fn open(&self, id: Uuid, payload: &str) -> Stream {
            let (mut send, recv) = self.connection.open_bi().await.unwrap();
            let header = StreamHeader { tunnel_id: id, stream_type: StreamType::Tcp };
            write_stream_header(&mut send, &header).await.unwrap();
            send.write_all(payload.as_bytes()).await.unwrap();
            (send, recv)
        }

        /// The next data stream opened to this edge, which begins with `payload`.
        pub(super) async fn accept(&self, id: Uuid, payload: &str) -> Stream {
            let (send, mut recv) = soon("a stream", self.connection.accept_bi()).await.unwrap();
            assert_eq!(read_stream_header(&mut recv).await.unwrap().tunnel_id, id);
            assert_reads(&mut recv, payload).await;
            (send, recv)
        }

        /// Send a datagram and open a stream that must go nowhere, and be told
        /// so of the stream.
        pub(super) async fn is_refused(&mut self, id: Uuid) {
            self.datagram(id, "refused").await;
            let (send, mut recv) = self.open(id, "refused").await;
            let code = STREAM_NOT_BOUND.into();
            let read = soon("an end to the stream", recv.read(&mut [0; 16])).await;
            assert_eq!(read, Err(ReadError::Reset(code)));
            assert_eq!(soon("a stop", send.stopped()).await, Ok(Some(code)));
        }
    }

    pub(super) async fn assert_reads(recv: &mut RecvStream, payload: &str) {
        let mut buf = vec![0; payload.len()];
        soon("the stream's data", recv.read_exact(&mut buf)).await.unwrap();
        assert_eq!(buf, payload.as_bytes());
    }

    /// A datagram and a stream each way between the two ends of a tunnel. Each
    /// edge reads the first to have reached it: one that was refused and came
    /// through all the same would be ahead of it.
    pub(super) async fn assert_passes(id: Uuid, ingress: &mut Edge, egress: &mut Edge) {
        ingress.datagram(id, "from ingress").await;
        assert_eq!(egress.read(id).await, "from ingress");
        egress.datagram(id, "from egress").await;
        assert_eq!(ingress.read(id).await, "from egress");
        for (opener, other) in [(&*ingress, &*egress), (&*egress, &*ingress)] {
            let mut near = opener.open(id, "there").await;
            let mut far = other.accept(id, "there").await;
            far.0.write_all(b"back").await.unwrap();
            assert_reads(&mut near.1, "back").await;
        }
    }

    /// What `n` rounds of [`assert_passes`] count: 12 + 11 bytes of datagrams,
    /// and of each stream 5 from its opener and 4 back.
    fn passes(n: u64) -> TunnelTotals {
        TunnelTotals {
            bytes_ingress: n * (12 + 5 + 5),
            bytes_egress: n * (11 + 4 + 4),
            tcp_streams_total: n * 2,
            udp_datagrams_total: n * 2,
        }
    }

    /// Wait for the totals to reach `want`: a task counts after it has sent.
    async fn assert_counted(ctx: &SessionContext, want: TunnelTotals, what: &str) {
        let until = Instant::now() + WAIT;
        while ctx.router.totals() != want && Instant::now() < until {
            sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(ctx.router.totals(), want, "{what}");
    }

    /// A connection that knows a tunnel's id and has bound nothing sends
    /// nothing into it, whichever of its sides are bound and whether binding
    /// takes a token or not. The two edges that bound it send both ways.
    #[tokio::test]
    async fn an_unbound_connection_sends_nothing() {
        for require_bind_auth in [false, true] {
            let (relay, cert, ctx) = start_relay_with(require_bind_auth, 64);
            let id = Uuid::new_v4();
            let (ingress_token, egress_token) = match require_bind_auth {
                true => (Some("ingress token"), Some("egress token")),
                false => (None, None),
            };
            if let (Some(ingress), Some(egress)) = (ingress_token, egress_token) {
                ctx.router.authorize_tunnel(id, ingress, egress);
            }
            let mut stranger = Edge::connect(relay, &cert).await;
            stranger.is_refused(id).await;

            let mut ingress = Edge::connect(relay, &cert).await;
            ingress.bind(id, Ingress, ingress_token).await;
            stranger.is_refused(id).await;

            let mut egress = Edge::connect(relay, &cert).await;
            egress.bind(id, Egress, egress_token).await;
            stranger.is_refused(id).await;

            if require_bind_auth {
                for direction in [Ingress, Egress] {
                    let answers = stranger
                        .tell(&EdgeMessage::TunnelBind {
                            tunnel_id: id,
                            direction,
                            protocol: TunnelProtocol::Udp,
                            bind_token: Some("wrong".into()),
                        })
                        .await;
                    assert!(matches!(answers[..], [RelayMessage::TunnelDown { .. }]), "{answers:?}");
                    stranger.is_refused(id).await;
                }
            }

            ingress.unbind(id).await;
            stranger.is_refused(id).await;
            ingress.bind(id, Ingress, ingress_token).await;
            assert_counted(&ctx, passes(0), "nothing was sent by either edge").await;
            assert_passes(id, &mut ingress, &mut egress).await;
            stranger.is_refused(id).await;
            assert_passes(id, &mut ingress, &mut egress).await;
            assert_counted(&ctx, passes(2), "what the two edges sent").await;
        }
    }

    /// A connection bound to one tunnel sends nothing into another, whichever
    /// side it holds of its own, and goes on sending into its own.
    #[tokio::test]
    async fn a_connection_bound_to_another_tunnel_sends_nothing() {
        let (relay, cert, ctx) = start_relay();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut edges = Vec::new();
        for (id, direction) in [(a, Ingress), (a, Egress), (b, Ingress), (b, Egress)] {
            let mut edge = Edge::connect(relay, &cert).await;
            edge.bind(id, direction, None).await;
            edges.push(edge);
        }
        let [a_in, a_out, b_in, b_out] = &mut edges[..] else { unreachable!() };
        for (edge, other) in [(&mut *a_in, b), (&mut *a_out, b), (&mut *b_in, a), (&mut *b_out, a)] {
            edge.is_refused(other).await;
            edge.is_refused(Uuid::new_v4()).await;
        }
        assert_counted(&ctx, passes(0), "refused").await;
        assert_passes(a, a_in, a_out).await;
        assert_passes(b, b_in, b_out).await;
        assert_counted(&ctx, passes(2), "each its own").await;
    }

    /// A side that a newer connection takes over is the newer one's, to send
    /// on and to be sent to, until the older binds it again: the newer one
    /// leaving does not give it back. A stream that was open before goes on.
    #[tokio::test]
    async fn a_side_that_is_taken_over_is_the_newer_connections() {
        for side in [Ingress, Egress] {
            let (relay, cert, ctx) = start_relay();
            let id = Uuid::new_v4();
            let other_side = if side == Ingress { Egress } else { Ingress };
            let mut other = Edge::connect(relay, &cert).await;
            other.bind(id, other_side, None).await;
            let mut old = Edge::connect(relay, &cert).await;
            old.bind(id, side, None).await;
            let mut old_stream = old.open(id, "before").await;
            let mut other_stream = other.accept(id, "before").await;

            let mut new = Edge::connect(relay, &cert).await;
            new.bind(id, side, None).await;
            old.is_refused(id).await;
            old_stream.0.write_all(b"after").await.unwrap();
            assert_reads(&mut other_stream.1, "after").await;
            other_stream.0.write_all(b"and back").await.unwrap();
            assert_reads(&mut old_stream.1, "and back").await;
            let kept = TunnelTotals {
                bytes_ingress: 11,
                bytes_egress: 8,
                tcp_streams_total: 1,
                udp_datagrams_total: 0,
            };
            assert_counted(&ctx, kept, "the stream opened before").await;

            let totals = |n| TunnelTotals {
                bytes_ingress: kept.bytes_ingress + passes(n).bytes_ingress,
                bytes_egress: kept.bytes_egress + passes(n).bytes_egress,
                tcp_streams_total: kept.tcp_streams_total + passes(n).tcp_streams_total,
                udp_datagrams_total: passes(n).udp_datagrams_total,
            };
            let pass = async |new: &mut Edge, other: &mut Edge| match side {
                Ingress => assert_passes(id, new, other).await,
                Egress => assert_passes(id, other, new).await,
            };
            pass(&mut new, &mut other).await;
            old.unbind(id).await;
            pass(&mut new, &mut other).await;
            assert_counted(&ctx, totals(2), "the newer connection's").await;
            new.unbind(id).await;
            old.is_refused(id).await;
            new.bind(id, side, None).await;
            pass(&mut new, &mut other).await;

            old.bind(id, side, None).await;
            new.is_refused(id).await;
            pass(&mut old, &mut other).await;
            new.connection.close(0u32.into(), b"");
            soon("the newer connection's end", async {
                while ctx.edge_connections.len() > 2 {
                    sleep(Duration::from_millis(2)).await;
                }
            })
            .await;
            pass(&mut old, &mut other).await;
            assert_counted(&ctx, totals(5), "the older connection's again").await;
        }
    }

    /// A connection sends on a tunnel from its bind to its unbind, however
    /// often it binds, and no longer than the tunnel is held.
    #[tokio::test]
    async fn a_connection_sends_from_its_bind_to_its_unbind() {
        let (relay, cert, ctx) = start_relay();
        let id = Uuid::new_v4();
        let mut ingress = Edge::connect(relay, &cert).await;
        let mut egress = Edge::connect(relay, &cert).await;
        ingress.is_refused(id).await;
        for _ in 0..2 {
            ingress.bind(id, Ingress, None).await;
            egress.bind(id, Egress, None).await;
        }
        assert_passes(id, &mut ingress, &mut egress).await;

        egress.unbind(id).await;
        egress.is_refused(id).await;
        egress.bind(id, Egress, None).await;
        ingress.unbind(id).await;
        ingress.is_refused(id).await;
        ingress.bind(id, Ingress, None).await;
        assert_counted(&ctx, passes(1), "refused while unbound").await;
        assert_passes(id, &mut ingress, &mut egress).await;

        // Removed by force, under two edges that know of it only if they have
        // read its `TunnelDown`. One coming back does not let the other send.
        ctx.router.force_remove_tunnel(&id).unwrap();
        ingress.is_refused(id).await;
        egress.is_refused(id).await;
        ingress.bind(id, Ingress, None).await;
        egress.is_refused(id).await;
        egress.bind(id, Egress, None).await;
        ingress.unbind(id).await;
        ingress.bind(id, Egress, None).await;
        egress.is_refused(id).await;
        egress.bind(id, Ingress, None).await;
        assert_counted(&ctx, passes(2), "refused while removed").await;
        assert_passes(id, &mut egress, &mut ingress).await;
        assert_counted(&ctx, passes(3), "the sides changed over").await;
    }

    /// What the relay logs, as `(level, message)`.
    #[derive(Clone, Default)]
    struct Log(Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Log {
        fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let meta = event.metadata();
            if meta.target().starts_with("bilbycast_relay") {
                let mut message = Message(String::new());
                event.record(&mut message);
                self.0.lock().unwrap().push((*meta.level(), message.0));
            }
        }
    }

    /// Refusing a sender logs at debug and nothing above: one that sends on
    /// and on must not fill the log.
    #[tokio::test]
    async fn refusing_a_sender_logs_at_debug() {
        use tracing_subscriber::layer::SubscriberExt;
        let (relay, cert, ctx) = start_relay();
        let id = Uuid::new_v4();
        let mut ingress = Edge::connect(relay, &cert).await;
        ingress.bind(id, Ingress, None).await;
        let mut stranger = Edge::connect(relay, &cert).await;
        stranger.settle().await;
        let log = Log::default();
        let guard = || tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        // A first pass registers the callsites against a subscriber: one first
        // hit by a parallel test with none installed can cache "never"
        // process-wide, and the next subscriber's registration rebuilds it.
        drop({
            let warm = guard();
            stranger.is_refused(id).await;
            ingress.is_refused(Uuid::new_v4()).await;
            warm
        });
        let _guard = guard();
        log.0.lock().unwrap().clear();
        for _ in 0..20 {
            stranger.is_refused(id).await;
            stranger.is_refused(Uuid::new_v4()).await;
        }
        stranger.settle().await;
        let log = log.0.lock().unwrap();
        for (level, message) in log.iter() {
            assert_eq!(*level, tracing::Level::DEBUG, "{message}");
        }
        for what in ["UDP datagram for tunnel", "TCP stream forwarding ended"] {
            let refused = log.iter().filter(|(_, m)| m.starts_with(what) && m.ends_with("NotBound"));
            assert_eq!(refused.count(), 40, "{what}: {log:#?}");
        }
        assert_eq!(ctx.router.totals(), passes(0));
    }

    /// One connection that binds both sides sends as ingress, to itself.
    #[tokio::test]
    async fn a_connection_that_holds_both_sides_sends_as_ingress() {
        let (relay, cert, ctx) = start_relay();
        let id = Uuid::new_v4();
        let mut both = Edge::connect(relay, &cert).await;
        both.bind(id, Egress, None).await;
        both.bind(id, Ingress, None).await;
        both.datagram(id, "to itself").await;
        assert_eq!(both.read(id).await, "to itself");
        let mut near = both.open(id, "there").await;
        let mut far = both.accept(id, "there").await;
        far.0.write_all(b"back").await.unwrap();
        assert_reads(&mut near.1, "back").await;
        let totals = TunnelTotals {
            bytes_ingress: 9 + 5,
            bytes_egress: 4,
            tcp_streams_total: 1,
            udp_datagrams_total: 1,
        };
        assert_counted(&ctx, totals, "as ingress").await;
    }

    /// A bound edge whose peer is not there sends nowhere, and its stream is
    /// not refused: it ends as it always has, empty.
    #[tokio::test]
    async fn a_bound_connection_without_a_peer_is_not_refused() {
        for side in [Ingress, Egress] {
            let (relay, cert, ctx) = start_relay();
            let id = Uuid::new_v4();
            let mut alone = Edge::connect(relay, &cert).await;
            alone.bind(id, side, None).await;
            alone.datagram(id, "to nobody").await;
            let (send, mut recv) = alone.open(id, "to nobody").await;
            assert_eq!(soon("an end to the stream", recv.read(&mut [0; 16])).await, Ok(None));
            assert_eq!(soon("a stop", send.stopped()).await, Ok(Some(0u32.into())));
            assert_counted(&ctx, passes(0), "to nobody").await;

            let mut peer = Edge::connect(relay, &cert).await;
            match side {
                Ingress => {
                    peer.bind(id, Egress, None).await;
                    assert_passes(id, &mut alone, &mut peer).await;
                }
                Egress => {
                    peer.bind(id, Ingress, None).await;
                    assert_passes(id, &mut peer, &mut alone).await;
                }
            }
            assert_counted(&ctx, passes(1), "its peer is there").await;
        }
    }
}

#[cfg(test)]
mod shown_token_tests {
    //! Tokens that come after the binds they are for.
    use super::bound_sender_tests::{Edge, assert_passes, assert_reads, soon};
    use super::test_relay::{relayed, start_relay, start_relay_capped, start_relay_with};
    use super::*;
    use crate::manager::events::Event;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use TunnelDirection::{Egress, Ingress};

    const INGRESS: &str = "ingress token";
    const EGRESS: &str = "egress token";

    /// A side, its token, and the other side and its.
    const SIDES: [(TunnelDirection, &str, TunnelDirection, &str); 2] =
        [(Ingress, INGRESS, Egress, EGRESS), (Egress, EGRESS, Ingress, INGRESS)];

    fn authorize(ctx: &Arc<SessionContext>, id: Uuid) {
        authorize_tunnel(ctx, id, INGRESS, EGRESS);
    }

    async fn passes(id: Uuid, side: TunnelDirection, one: &mut Edge, other: &mut Edge) {
        match side {
            Ingress => assert_passes(id, one, other).await,
            Egress => assert_passes(id, other, one).await,
        }
    }

    /// The sides given back, as the events say it.
    fn given_back(events: &mut mpsc::Receiver<Event>) -> Vec<serde_json::Value> {
        std::iter::from_fn(|| events.try_recv().ok())
            .filter(|event| event.message.starts_with("Tunnel side given back"))
            .map(|event| {
                assert_eq!(event.severity, EventSeverity::Warning);
                assert_eq!(event.category, category::TUNNEL);
                event.details.unwrap()
            })
            .collect()
    }

    fn ready(notice: Option<RelayMessage>) -> bool {
        matches!(notice, Some(RelayMessage::TunnelReady { .. }))
    }

    fn down(notice: Option<RelayMessage>) -> String {
        match notice {
            Some(RelayMessage::TunnelDown { reason, .. }) => reason,
            other => panic!("{other:?}"),
        }
    }

    async fn gone(ctx: &SessionContext, left: usize) {
        soon("the edge's end", async {
            while ctx.edge_connections.len() > left {
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
    }

    /// An edge bound its side with the right token while none was registered,
    /// and others without it took the side from it. When the token comes the
    /// side is the edge's again: it binds nothing, sends at once, and a stream
    /// it had open was never cut.
    #[tokio::test]
    async fn the_token_gives_a_side_back_to_the_edge_that_showed_it() {
        for (side, token, other_side, other_token) in SIDES {
            for strangers in [vec![None], vec![Some("wrong")], vec![Some(other_token), None]] {
                let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 100);
                let id = Uuid::new_v4();
                let mut other = Edge::connect(relay, &cert).await;
                other.bind(id, other_side, Some(other_token)).await;
                let mut real = Edge::connect(relay, &cert).await;
                real.bind(id, side, Some(token)).await;
                assert!(ready(other.notice().await), "the edge bound");
                let mut near = real.open(id, "before").await;
                let mut far = other.accept(id, "before").await;

                let mut held = Vec::new();
                for shown in &strangers {
                    let mut stranger = Edge::connect(relay, &cert).await;
                    stranger.bind(id, side, *shown).await;
                    assert!(ready(other.notice().await), "a stranger bound");
                    held.push(stranger);
                }
                real.is_refused(id).await;
                let stranger = held.last_mut().unwrap();
                passes(id, side, stranger, &mut other).await;
                let (to, from) = (real.connection.clone(), stranger.connection.clone());

                authorize(&ctx, id);
                passes(id, side, &mut real, &mut other).await;
                near.0.write_all(b"after").await.unwrap();
                assert_reads(&mut far.1, "after").await;
                for stranger in &mut held {
                    stranger.is_refused(id).await;
                    for shown in &strangers {
                        let refused = stranger.ask(id, side, *shown).await;
                        assert_eq!(refused.as_deref(), Some("bind authentication failed"));
                    }
                }
                passes(id, side, &mut real, &mut other).await;
                assert!(ready(real.notice().await), "the edge is told the tunnel is up");
                assert!(ready(other.notice().await), "and so is the other");
                let addr = |edge: &Connection| relayed(&ctx, edge).1.to_string();
                let told = given_back(&mut events);
                assert_eq!(told.len(), 1, "{told:?}");
                assert_eq!(
                    told[0],
                    serde_json::json!({
                        "error_code": "relay_unproven_holder_replaced",
                        "transport": "quic",
                        "direction": format!("{side:?}"),
                        "remote_addr": addr(&to),
                        "held_by": addr(&from),
                    })
                );
                authorize(&ctx, id);
                passes(id, side, &mut real, &mut other).await;
                assert_eq!(given_back(&mut events).len(), 0, "once");
            }
        }
    }

    /// Of several connections that showed the token the last one to bind has
    /// the side back, and a clone that took it from another keeps it.
    #[tokio::test]
    async fn of_two_edges_that_showed_the_token_the_last_has_the_side() {
        for (side, token, other_side, other_token) in SIDES {
            let (relay, cert, ctx) = start_relay();
            let id = Uuid::new_v4();
            let mut edges = Vec::new();
            for (side, token) in [
                (other_side, Some(other_token)),
                (side, Some(token)),
                (side, Some(token)),
                (side, None),
            ] {
                let mut edge = Edge::connect(relay, &cert).await;
                edge.bind(id, side, token).await;
                edges.push(edge);
            }
            let [other, first, last, stranger] = &mut edges[..] else { unreachable!() };
            authorize(&ctx, id);
            passes(id, side, last, other).await;
            first.is_refused(id).await;
            stranger.is_refused(id).await;
            first.bind(id, side, Some(token)).await;
            authorize(&ctx, id);
            passes(id, side, first, other).await;
            last.is_refused(id).await;
        }
    }

    /// A holder that showed the right token before there was one to show keeps
    /// its side when it comes, however often, and is told nothing. No datagram
    /// is lost to it.
    #[tokio::test]
    async fn a_holder_that_showed_the_token_is_not_interrupted() {
        let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 100);
        let id = Uuid::new_v4();
        let mut ingress = Edge::connect(relay, &cert).await;
        ingress.bind(id, Ingress, Some(INGRESS)).await;
        let mut egress = Edge::connect(relay, &cert).await;
        egress.bind(id, Egress, Some(EGRESS)).await;
        assert!(ready(ingress.notice().await), "the peer bound");
        let mut near = ingress.open(id, "before").await;
        let mut far = egress.accept(id, "before").await;
        for n in 0..500 {
            if n % 5 == 0 {
                authorize(&ctx, id);
            }
            let payload = format!("datagram {n}");
            egress.datagram(id, &payload).await;
            assert_eq!(ingress.read(id).await, payload);
        }
        near.0.write_all(b"after").await.unwrap();
        assert_reads(&mut far.1, "after").await;
        assert_passes(id, &mut ingress, &mut egress).await;
        assert_eq!(given_back(&mut events).len(), 0);
        for edge in [&ingress, &egress] {
            let told = tokio::time::timeout(Duration::from_millis(100), edge.connection.accept_uni());
            assert!(told.await.is_err(), "told something");
        }
    }

    /// No holder is cut off by a token it has not shown, or not shown yet: one
    /// with no token, one with the token from before a rotation the manager
    /// could not tell it of, whichever edges it took the side from. It has the
    /// side until an edge binds it with the token.
    #[tokio::test]
    async fn no_holder_is_cut_off_for_want_of_the_token() {
        for (side, token, other_side, other_token) in SIDES {
            for shown in [None, Some("the token before")] {
                let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 100);
                let id = Uuid::new_v4();
                let mut other = Edge::connect(relay, &cert).await;
                other.bind(id, other_side, Some(other_token)).await;
                // Neither of these has shown the token of this side.
                let mut older = Edge::connect(relay, &cert).await;
                older.bind(id, side, Some(other_token)).await;
                older.bind(id, other_side, Some(token)).await;
                other.bind(id, other_side, Some(other_token)).await;
                let mut holder = Edge::connect(relay, &cert).await;
                holder.bind(id, side, shown).await;
                for _ in 0..3 {
                    authorize(&ctx, id);
                    passes(id, side, &mut holder, &mut other).await;
                }
                older.is_refused(id).await;
                assert_eq!(
                    holder.ask(id, side, shown).await.as_deref(),
                    Some("bind authentication failed"),
                );
                passes(id, side, &mut holder, &mut other).await;
                assert_eq!(given_back(&mut events).len(), 0);

                let mut real = Edge::connect(relay, &cert).await;
                real.bind(id, side, Some(token)).await;
                passes(id, side, &mut real, &mut other).await;
                holder.is_refused(id).await;
                authorize(&ctx, id);
                passes(id, side, &mut real, &mut other).await;
            }
        }
    }

    /// The token of a rotation is the one that counts: the holder of the old
    /// one keeps the side, and an edge that showed the new one before it came
    /// has it when it does.
    #[tokio::test]
    async fn the_token_that_counts_is_the_one_registered() {
        let (relay, cert, ctx) = start_relay();
        let id = Uuid::new_v4();
        let mut other = Edge::connect(relay, &cert).await;
        other.bind(id, Egress, Some(EGRESS)).await;
        let mut new = Edge::connect(relay, &cert).await;
        new.bind(id, Ingress, Some("the new token")).await;
        let mut old = Edge::connect(relay, &cert).await;
        old.bind(id, Ingress, Some(INGRESS)).await;
        authorize(&ctx, id);
        assert_passes(id, &mut old, &mut other).await;
        authorize_tunnel(&ctx, id, "the new token", EGRESS);
        assert_passes(id, &mut new, &mut other).await;
        old.is_refused(id).await;
        authorize(&ctx, id);
        assert_passes(id, &mut old, &mut other).await;
        new.is_refused(id).await;
    }

    /// The stranger that took the side has left when the token comes. The edge
    /// has its side back, and both are told how the tunnel stands.
    #[tokio::test]
    async fn a_side_left_empty_goes_back_too() {
        for (side, token, other_side, other_token) in SIDES {
            for by_unbind in [true, false] {
                let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 100);
                let id = Uuid::new_v4();
                let mut other = Edge::connect(relay, &cert).await;
                other.bind(id, other_side, Some(other_token)).await;
                let mut real = Edge::connect(relay, &cert).await;
                real.bind(id, side, Some(token)).await;
                assert!(ready(other.notice().await));
                let mut stranger = Edge::connect(relay, &cert).await;
                stranger.bind(id, side, None).await;
                assert!(ready(other.notice().await));
                match by_unbind {
                    true => stranger.unbind(id).await,
                    false => stranger.connection.close(0u32.into(), b""),
                }
                let reason = if by_unbind { "peer unbound" } else { "peer disconnected" };
                assert_eq!(down(other.notice().await), reason);
                real.is_refused(id).await;

                authorize(&ctx, id);
                assert!(ready(other.notice().await), "the tunnel is up again");
                assert!(ready(real.notice().await));
                passes(id, side, &mut real, &mut other).await;
                let told = given_back(&mut events);
                assert_eq!(told.len(), 1);
                assert_eq!(told[0]["held_by"], serde_json::Value::Null);
            }
        }
    }

    /// Both sides are empty when the token comes: the stranger had both, or one
    /// and the edge on the other has left as well. The tunnel is in no list
    /// meanwhile, and nothing passes. Then each edge that showed its token has
    /// its side back, and one that has to bind again finds it there.
    #[tokio::test]
    async fn a_tunnel_left_empty_goes_back_too() {
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum By {
            Unbind,
            Disconnect,
            TheOther,
        }
        for (side, token, other_side, other_token) in SIDES {
            for by in [By::Unbind, By::Disconnect, By::TheOther] {
                let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 100);
                let id = Uuid::new_v4();
                let mut other = Edge::connect(relay, &cert).await;
                other.bind(id, other_side, Some(other_token)).await;
                let mut real = Edge::connect(relay, &cert).await;
                real.bind(id, side, Some(token)).await;
                let mut stranger = Edge::connect(relay, &cert).await;
                stranger.bind(id, side, None).await;
                if by == By::TheOther {
                    other.connection.close(0u32.into(), b"");
                    soon("the other's end", async {
                        while ctx.router.counts() == (1, 1) {
                            sleep(Duration::from_millis(2)).await;
                        }
                    })
                    .await;
                } else {
                    stranger.bind(id, other_side, None).await;
                }
                match by {
                    By::Disconnect => {
                        stranger.connection.close(0u32.into(), b"");
                        gone(&ctx, 2).await;
                        soon("the stranger's end", async {
                            while ctx.router.counts() != (0, 0) {
                                sleep(Duration::from_millis(2)).await;
                            }
                        })
                        .await;
                    }
                    _ => stranger.unbind(id).await,
                }
                assert_eq!((ctx.router.counts(), ctx.router.list_tunnels().len()), ((0, 0), 0));
                real.is_refused(id).await;
                let mut back = 2;
                if by == By::TheOther {
                    back = 1;
                    other = Edge::connect(relay, &cert).await;
                    other.bind(id, other_side, Some(other_token)).await;
                } else {
                    other.is_refused(id).await;
                }

                authorize(&ctx, id);
                passes(id, side, &mut real, &mut other).await;
                assert_eq!((ctx.router.counts(), ctx.router.list_tunnels().len()), ((1, 1), 1));
                let told = given_back(&mut events);
                assert_eq!(told.len(), back, "{by:?}: {told:?}");
                assert!(told.iter().all(|t| t["held_by"].is_null()), "{told:?}");

                // Nothing is kept of it once its edges have left.
                real.unbind(id).await;
                other.unbind(id).await;
                assert!(ctx.router.tunnel(&id).is_none());
            }
        }
    }

    /// Two edges of one configuration: the newer one took the side with the
    /// token the older had shown, and leaves. The side is not the older one's
    /// again, whether the tokens came before the binds or after, and whoever
    /// took it from the newer one meanwhile.
    #[tokio::test]
    async fn a_side_is_not_given_back_to_an_edge_that_its_own_token_took_it_from() {
        for (side, token, other_side, other_token) in SIDES {
            for (strict, with_stranger) in [(true, false), (false, false), (false, true)] {
                for by_unbind in [true, false] {
                    let (relay, cert, ctx, mut events) = start_relay_capped(strict, 64, 100);
                    let id = Uuid::new_v4();
                    if strict {
                        authorize(&ctx, id);
                    }
                    let mut other = Edge::connect(relay, &cert).await;
                    other.bind(id, other_side, Some(other_token)).await;
                    let mut older = Edge::connect(relay, &cert).await;
                    older.bind(id, side, Some(token)).await;
                    let mut newer = Edge::connect(relay, &cert).await;
                    newer.bind(id, side, Some(token)).await;
                    let mut stranger = Edge::connect(relay, &cert).await;
                    if with_stranger {
                        stranger.bind(id, side, None).await;
                    }
                    match by_unbind {
                        true => newer.unbind(id).await,
                        false => {
                            newer.connection.close(0u32.into(), b"");
                            gone(&ctx, 3).await;
                            // Its end is handled after it has left `edge_connections`.
                            sleep(Duration::from_millis(50)).await;
                        }
                    }
                    for _ in 0..2 {
                        authorize(&ctx, id);
                        older.is_refused(id).await;
                        assert_eq!(given_back(&mut events).len(), 0);
                    }
                    if with_stranger {
                        passes(id, side, &mut stranger, &mut other).await;
                    }
                    older.bind(id, side, Some(token)).await;
                    passes(id, side, &mut older, &mut other).await;
                }
            }
        }
    }

    /// An edge that has its side back with nobody on the other is told so: it
    /// was not when the other left.
    #[tokio::test]
    async fn an_edge_given_its_side_back_learns_that_its_peer_has_gone() {
        let (relay, cert, ctx) = start_relay();
        let id = Uuid::new_v4();
        let mut other = Edge::connect(relay, &cert).await;
        other.bind(id, Egress, Some(EGRESS)).await;
        let mut real = Edge::connect(relay, &cert).await;
        real.bind(id, Ingress, Some(INGRESS)).await;
        let mut stranger = Edge::connect(relay, &cert).await;
        stranger.bind(id, Ingress, None).await;
        other.connection.close(0u32.into(), b"");
        assert_eq!(down(stranger.notice().await), "peer disconnected");
        authorize(&ctx, id);
        assert_eq!(down(real.notice().await), "peer disconnected");
        let mut other = Edge::connect(relay, &cert).await;
        other.bind(id, Egress, Some(EGRESS)).await;
        assert!(ready(real.notice().await));
        assert_passes(id, &mut real, &mut other).await;
    }

    /// A side is not given back to an edge that unbound it or is gone, nor
    /// after the tunnel was removed. Removing one it no longer held raises no
    /// tunnel-down event.
    #[tokio::test]
    async fn a_side_is_not_given_back_to_an_edge_that_gave_it_up() {
        #[derive(Debug, PartialEq)]
        enum By {
            Unbind,
            Disconnect,
            Removal,
        }
        for by in [By::Unbind, By::Disconnect, By::Removal] {
            let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 100);
            let id = Uuid::new_v4();
            let mut other = Edge::connect(relay, &cert).await;
            other.bind(id, Egress, Some(EGRESS)).await;
            let mut real = Edge::connect(relay, &cert).await;
            real.bind(id, Ingress, Some(INGRESS)).await;
            let mut stranger = Edge::connect(relay, &cert).await;
            stranger.bind(id, Ingress, None).await;
            match by {
                By::Unbind => real.unbind(id).await,
                By::Disconnect => {
                    real.connection.close(0u32.into(), b"");
                    gone(&ctx, 2).await;
                    // Its end is handled after it has left `edge_connections`.
                    sleep(Duration::from_millis(50)).await;
                }
                By::Removal => {
                    ctx.router.force_remove_tunnel(&id).unwrap();
                    other.bind(id, Egress, Some(EGRESS)).await;
                    stranger.bind(id, Ingress, None).await;
                }
            }
            authorize(&ctx, id);
            assert_passes(id, &mut stranger, &mut other).await;
            let raised: Vec<String> =
                std::iter::from_fn(|| events.try_recv().ok()).map(|e| e.message).collect();
            for message in ["Tunnel side given back", "Tunnel down"] {
                assert!(!raised.iter().any(|m| m.starts_with(message)), "{by:?}: {raised:?}");
            }
        }
    }

    /// A bind that is refused changes nothing: it makes no tunnel, takes no
    /// side, and does not lose the edge the side it holds.
    #[tokio::test]
    async fn a_refused_bind_changes_nothing() {
        for require_bind_auth in [false, true] {
            let (relay, cert, ctx) = start_relay_with(require_bind_auth, 64);
            let id = Uuid::new_v4();
            authorize(&ctx, id);
            let mut stranger = Edge::connect(relay, &cert).await;
            for (shown, side) in [(None, Ingress), (Some(EGRESS), Ingress), (Some(INGRESS), Egress)] {
                let refused = stranger.ask(id, side, shown).await;
                assert_eq!(refused.as_deref(), Some("bind authentication failed"));
                assert_eq!(ctx.router.counts(), (0, 0));
            }
            let mut ingress = Edge::connect(relay, &cert).await;
            ingress.bind(id, Ingress, Some(INGRESS)).await;
            let mut egress = Edge::connect(relay, &cert).await;
            egress.bind(id, Egress, Some(EGRESS)).await;
            for side in [Ingress, Egress] {
                assert!(stranger.ask(id, side, Some("wrong")).await.is_some());
            }
            assert!(ingress.ask(id, Ingress, None).await.is_some());
            assert_passes(id, &mut ingress, &mut egress).await;
            // The sides were taken from nobody, so nothing goes back.
            ctx.router.revoke_tunnel(&id);
            authorize(&ctx, id);
            assert_passes(id, &mut ingress, &mut egress).await;
        }
    }
}

#[cfg(test)]
mod tunnel_cap_tests {
    //! The cap on one connection's tunnels.
    use super::bound_sender_tests::{Edge, soon};
    use super::test_relay::{relayed, start_relay_capped};
    use super::*;
    use TunnelDirection::{Egress, Ingress};

    const FULL: Option<&str> = Some("per-connection tunnel limit exceeded");

    async fn ask(edge: &mut Edge, id: Uuid, side: TunnelDirection) -> Option<String> {
        edge.ask(id, side, None).await
    }

    /// Unbinding a tunnel the connection never bound, or has unbound already,
    /// makes no room for another.
    #[tokio::test]
    async fn an_unbind_of_nothing_makes_no_room() {
        let (relay, cert, ctx, mut events) = start_relay_capped(false, 64, 3);
        let mut edge = Edge::connect(relay, &cert).await;
        let mut other = Edge::connect(relay, &cert).await;
        let theirs = Uuid::new_v4();
        other.bind(theirs, Ingress, None).await;
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            edge.bind(*id, Ingress, None).await;
        }
        for _ in 0..5 {
            edge.unbind(Uuid::new_v4()).await;
            edge.unbind(theirs).await;
            assert_eq!(ask(&mut edge, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
        }
        edge.unbind(ids[0]).await;
        edge.unbind(ids[0]).await;
        edge.bind(Uuid::new_v4(), Ingress, None).await;
        assert_eq!(ask(&mut edge, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
        assert_eq!(ctx.router.counts().0, 4);
        let refused = std::iter::from_fn(|| events.try_recv().ok())
            .filter(|e| e.message == "Tunnel bind rejected: per-connection cap exceeded")
            .last()
            .unwrap()
            .details
            .unwrap();
        assert_eq!((&refused["active_binds"], &refused["cap"]), (&3.into(), &3.into()));
    }

    /// Binding a side again counts it no more than once, below the cap and at
    /// it, and a bind that is refused does not count.
    #[tokio::test]
    async fn a_side_counts_once_however_often_it_is_bound() {
        let (relay, cert, ctx, _events) = start_relay_capped(false, 64, 2);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        ctx.router.authorize_tunnel(b, "token", "token");
        let mut edge = Edge::connect(relay, &cert).await;
        for _ in 0..5 {
            edge.bind(a, Ingress, None).await;
            let refused = edge.ask(b, Ingress, Some("wrong")).await;
            assert_eq!(refused.as_deref(), Some("bind authentication failed"));
        }
        for _ in 0..5 {
            edge.bind(b, Ingress, Some("token")).await;
            edge.bind(a, Ingress, None).await;
            assert_eq!(ask(&mut edge, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
        }
        // Refused, and bound all the same.
        assert!(edge.ask(b, Ingress, Some("wrong")).await.is_some());
        assert_eq!(ask(&mut edge, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
    }

    /// Both sides of a tunnel count as two, and one unbind gives both back.
    #[tokio::test]
    async fn both_sides_of_a_tunnel_count_as_two() {
        let (relay, cert, _ctx, _events) = start_relay_capped(false, 64, 2);
        let id = Uuid::new_v4();
        let mut edge = Edge::connect(relay, &cert).await;
        edge.bind(id, Ingress, None).await;
        edge.bind(id, Egress, None).await;
        assert_eq!(ask(&mut edge, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
        edge.unbind(id).await;
        edge.bind(Uuid::new_v4(), Ingress, None).await;
        edge.bind(Uuid::new_v4(), Egress, None).await;
        assert_eq!(ask(&mut edge, id, Ingress).await.as_deref(), FULL);
    }

    /// A side that another connection has taken over counts for both while the
    /// router remembers who had it, whatever becomes of the other: that is for
    /// as long as it can go back. Each gives its own back.
    #[tokio::test]
    async fn a_side_taken_over_counts_while_it_can_go_back() {
        let (relay, cert, _ctx, _events) = start_relay_capped(false, 64, 1);
        for (shown, by, counts) in [
            (Some("token"), None, true),
            (Some("token"), Some("another"), true),
            (Some("token"), Some("token"), false),
            (None, None, false),
            (None, Some("token"), false),
        ] {
            for the_newer_leaves in [false, true] {
                let id = Uuid::new_v4();
                let mut old = Edge::connect(relay, &cert).await;
                old.bind(id, Ingress, shown).await;
                let mut new = Edge::connect(relay, &cert).await;
                new.bind(id, Ingress, by).await;
                assert_eq!(ask(&mut new, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
                if the_newer_leaves {
                    new.unbind(id).await;
                    new.bind(Uuid::new_v4(), Ingress, None).await;
                }
                if counts {
                    assert_eq!(ask(&mut old, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
                    old.unbind(id).await;
                }
                old.bind(Uuid::new_v4(), Ingress, None).await;
                assert_eq!(ask(&mut old, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
            }
        }
    }

    /// A tunnel removed by force gives its sides back, to both edges.
    #[tokio::test]
    async fn a_tunnel_removed_by_force_makes_room() {
        let (relay, cert, ctx, _events) = start_relay_capped(false, 64, 1);
        let mut edge = Edge::connect(relay, &cert).await;
        for _ in 0..3 {
            let id = Uuid::new_v4();
            edge.bind(id, Ingress, None).await;
            assert_eq!(ask(&mut edge, Uuid::new_v4(), Ingress).await.as_deref(), FULL);
            ctx.router.force_remove_tunnel(&id).unwrap();
        }
        edge.bind(Uuid::new_v4(), Ingress, None).await;
        assert_eq!(ctx.router.counts().0, 1);
    }

    /// Three connections bind, unbind and lose what they like, mostly the same
    /// few tunnels. A bind is refused when the connection has bound as many
    /// sides as the cap and this is another, and never else.
    #[tokio::test]
    async fn the_cap_is_on_what_the_connection_has_bound() {
        const CAP: u32 = 4;
        let (relay, cert, ctx, _events) = start_relay_capped(false, 64, CAP);
        let ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        let sides: Vec<_> = ids.iter().flat_map(|id| [(*id, Ingress), (*id, Egress)]).collect();
        let mut edges = Vec::new();
        for _ in 0..3 {
            let mut edge = Edge::connect(relay, &cert).await;
            edge.settle().await;
            let connection = edge.connection.clone();
            tokio::spawn(async move { while connection.accept_uni().await.is_ok() {} });
            edges.push(edge);
        }
        let names: Vec<String> = edges.iter().map(|e| relayed(&ctx, &e.connection).0).collect();
        let mut seed = 1u64;
        let mut random = |n: usize| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as usize % n
        };
        let (mut taken, mut refused) = (0, 0);
        for _ in 0..1500 {
            let at = random(3);
            let has = |id: &Uuid, side| ctx.router.has_bound(id, side, &names[at]);
            match random(10) {
                0..7 => {
                    let (id, side) = sides[random(sides.len())];
                    let held = sides.iter().filter(|(id, side)| has(id, *side)).count();
                    let room = has(&id, side) || held < CAP as usize;
                    let shown = [None, Some("a"), Some("b"), Some("c")][random(4)];
                    let answer = edges[at].ask(id, side, shown).await;
                    assert_eq!(answer.is_none(), room, "{held} bound: {answer:?}");
                    if room { taken += 1 } else { refused += 1 }
                }
                7..9 => edges[at].unbind(ids[random(ids.len())]).await,
                _ => {
                    ctx.router.force_remove_tunnel(&ids[random(ids.len())]);
                }
            }
        }
        assert!(taken > 200 && refused > 100, "{taken} taken, {refused} refused");
        // Nothing is kept for connections that have left.
        for edge in &edges {
            edge.connection.close(0u32.into(), b"");
        }
        soon("the end of every tunnel", async {
            while ids.iter().any(|id| ctx.router.tunnel(id).is_some()) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
    }
}

#[cfg(test)]
mod notice_order_tests {
    //! What an edge is told last of its tunnel is how the tunnel stands.
    use super::bound_sender_tests::{Edge, soon};
    use super::test_relay::start_relay;
    use super::*;
    use tokio::time::{sleep, timeout};
    use TunnelDirection::{Egress, Ingress};

    /// The notices an edge has not read, the empty ones left out.
    async fn unread(edge: &Edge) -> Vec<RelayMessage> {
        let mut all = Vec::new();
        while let Ok(stream) = timeout(Duration::from_millis(300), edge.connection.accept_uni()).await {
            let mut stream = stream.unwrap();
            all.extend(read_message::<RelayMessage>(&mut stream).await.ok());
        }
        all
    }

    async fn until(what: &str, done: impl Fn() -> bool) {
        soon(what, async {
            while !done() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
    }

    /// An edge takes one notice at a time and has one waiting, so the next are
    /// held back: that its peer left, and that it is back. Whichever gets
    /// through first, the edge is not left believing the first.
    #[tokio::test]
    async fn a_peer_that_is_back_is_not_reported_gone() {
        for _ in 0..20 {
            let (relay, cert, ctx) = start_relay();
            let id = Uuid::new_v4();
            let mut edge = Edge::connect_taking(relay, &cert, 1).await;
            edge.bind(id, Ingress, None).await;
            let mut peer = Edge::connect(relay, &cert).await;
            peer.bind(id, Egress, None).await;
            let active = || ctx.router.counts().1 == 1;
            assert!(active());
            peer.connection.close(0u32.into(), b"");
            until("the peer's end", || !active()).await;
            // Its session is telling the edge, and cannot yet.
            sleep(Duration::from_millis(5)).await;
            let mut back = Edge::connect(relay, &cert).await;
            let bind = EdgeMessage::TunnelBind {
                tunnel_id: id,
                direction: Egress,
                protocol: TunnelProtocol::Udp,
                bind_token: None,
            };
            let told = tokio::spawn(async move { (back.tell(&bind).await, back) });
            until("the peer's return", active).await;
            sleep(Duration::from_millis(5)).await;
            let notices = unread(&edge).await;
            assert!(
                notices.iter().all(|n| matches!(n, RelayMessage::TunnelReady { .. })),
                "{notices:?}"
            );
            assert_eq!(notices.len(), 2, "that it bound, and that it is back: {notices:?}");
            drop(told.await.unwrap());
        }
    }

    /// The reverse: the edge is to be told that the tunnel is up, and cannot
    /// be yet, and its peer leaves.
    #[tokio::test]
    async fn a_peer_that_has_left_is_not_reported_back() {
        for _ in 0..20 {
            let (relay, cert, ctx) = start_relay();
            let id = Uuid::new_v4();
            let mut edge = Edge::connect_taking(relay, &cert, 1).await;
            edge.bind(id, Egress, None).await;
            let mut real = Edge::connect(relay, &cert).await;
            real.bind(id, Ingress, Some("token")).await;
            let mut stranger = Edge::connect(relay, &cert).await;
            // Held up telling the edge, which has the first notice waiting.
            let bind = EdgeMessage::TunnelBind {
                tunnel_id: id,
                direction: Ingress,
                protocol: TunnelProtocol::Udp,
                bind_token: None,
            };
            let told = tokio::spawn(async move { (stranger.tell(&bind).await, stranger) });
            until("the stranger's bind", || {
                ctx.router.tunnel(&id).unwrap().ingress.as_ref().unwrap().shown.is_none()
            })
            .await;
            authorize_tunnel(&ctx, id, "token", "another");
            sleep(Duration::from_millis(5)).await;
            real.connection.close(0u32.into(), b"");
            until("the peer's end", || ctx.router.counts().1 == 0).await;
            sleep(Duration::from_millis(5)).await;
            let notices = unread(&edge).await;
            let last = notices.last();
            assert!(
                matches!(last, Some(RelayMessage::TunnelDown { reason, .. }) if reason == "peer disconnected"),
                "{notices:?}"
            );
            assert_eq!(notices.len(), 2, "that it bound, and that it left: {notices:?}");
            drop(told.await.unwrap());
        }
    }
}

#[cfg(test)]
mod per_ip_cap_tests {
    //! The cap on one address's connections, over real ones.
    use super::test_relay::{edge, start_relay_with};
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{Instant, sleep};

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    async fn assert_held(ctx: &SessionContext, want: Option<u32>, what: &str) {
        let until = Instant::now() + Duration::from_secs(10);
        while ctx.connections_by_ip.held(HOST) != want && Instant::now() < until {
            sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(ctx.connections_by_ip.held(HOST), want, "{what}");
    }

    #[tokio::test]
    async fn a_full_cap_frees_up() {
        let (relay, cert, ctx) = start_relay_with(false, 2);
        assert_held(&ctx, None, "nobody").await;
        // One that has not opened its control stream, as far as the relay can
        // tell, and one that has.
        let (_e1, silent, _s1, _r1) = edge(relay, &cert, 100).await;
        let (_e2, talking, mut send, mut recv) = edge(relay, &cert, 100).await;
        write_message(&mut send, &EdgeMessage::Ping).await.unwrap();
        let pong: RelayMessage = read_message(&mut recv).await.unwrap();
        assert!(matches!(pong, RelayMessage::Pong), "{pong:?}");
        assert_held(&ctx, Some(2), "the cap").await;

        let (_e3, refused, _s3, _r3) = edge(relay, &cert, 100).await;
        match refused.closed().await {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.reason, "per-ip connection cap exceeded")
            }
            other => panic!("{other:?}"),
        }
        assert_held(&ctx, Some(2), "one refused").await;

        silent.close(0u32.into(), b"");
        assert_held(&ctx, Some(1), "closed before its control stream").await;
        let (_e4, third, mut send, mut recv) = edge(relay, &cert, 100).await;
        write_message(&mut send, &EdgeMessage::Ping).await.unwrap();
        let pong: RelayMessage = read_message(&mut recv).await.unwrap();
        assert!(matches!(pong, RelayMessage::Pong), "{pong:?}");
        assert_held(&ctx, Some(2), "room for another").await;

        talking.close(0u32.into(), b"");
        assert_held(&ctx, Some(1), "closed with a session").await;
        third.close(0u32.into(), b"");
        assert_held(&ctx, None, "the last one closed").await;
    }

    /// Connections open and close on every thread, at a cap they never pass
    /// between them: none is refused, and the count ends at those held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_count_ends_at_the_connections_held() {
        let (relay, cert, ctx) = start_relay_with(false, 64);
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(edge(relay, &cert, 100).await);
        }
        let mut tasks = tokio::task::JoinSet::new();
        for task in 0..4 {
            let cert = cert.clone();
            tasks.spawn(async move {
                for round in 0..15 {
                    let (_endpoint, connection, mut send, mut recv) = edge(relay, &cert, 100).await;
                    if (task + round) % 2 == 0 {
                        write_message(&mut send, &EdgeMessage::Ping).await.unwrap();
                        let pong: RelayMessage = read_message(&mut recv).await.unwrap();
                        assert!(matches!(pong, RelayMessage::Pong), "{pong:?}");
                    }
                    connection.close(0u32.into(), b"");
                }
            });
        }
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
        assert_held(&ctx, Some(3), "the three held").await;
        held.clear();
        assert_held(&ctx, None, "none held").await;
    }
}
