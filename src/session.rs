// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Per-edge-connection session handling.
//!
//! Each edge connects via QUIC and immediately sends tunnel bind messages.
//! The relay is stateless — no authentication required. It pairs edges by
//! tunnel ID and forwards encrypted traffic between them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use dashmap::DashMap;
use quinn::Connection;
use uuid::Uuid;

use crate::protocol::*;
use crate::stats::RelayStats;
use crate::tunnel_router::{BindResult, TunnelEndpoint, TunnelRouter};

/// Counter for generating unique connection IDs.
static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Shared state accessible to all sessions.
pub struct SessionContext {
    pub router: Arc<TunnelRouter>,
    /// Map of connection_id -> Connection for sending notifications.
    pub edge_connections: DashMap<String, Connection>,
    /// Global relay stats for peak tracking and connection counting.
    pub relay_stats: Arc<RelayStats>,
}

/// Handle a new QUIC connection from an edge node.
pub async fn handle_edge_connection(ctx: Arc<SessionContext>, connection: Connection) {
    let remote = connection.remote_address();
    let connection_id = format!(
        "conn-{}-{}",
        CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed),
        remote
    );
    tracing::info!("New QUIC connection from {remote} (id: {connection_id})");
    ctx.relay_stats
        .connections_total
        .fetch_add(1, Ordering::Relaxed);

    // Open the control bi-stream (edge initiates it)
    let (mut send, mut recv) = match connection.accept_bi().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to accept control stream from {remote}: {e}");
            return;
        }
    };

    // Register connection
    ctx.edge_connections
        .insert(connection_id.clone(), connection.clone());

    // Identified edge_id (set via Identify message, used for reporting).
    // Falls back to connection_id if not set.
    let identified_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Process control messages + data streams + UDP datagrams concurrently
    let ctrl_ctx = ctx.clone();
    let ctrl_conn = connection.clone();
    let ctrl_edge = connection_id.clone();
    let ctrl_identified = identified_id.clone();

    let data_ctx = ctx.clone();
    let data_conn = connection.clone();
    let data_edge = connection_id.clone();

    let dgram_ctx = ctx.clone();
    let dgram_conn = connection.clone();
    let dgram_edge = connection_id.clone();

    tokio::select! {
        // Control stream message loop
        r = handle_control_stream(&ctrl_ctx, &ctrl_conn, &ctrl_edge, &ctrl_identified, &mut send, &mut recv) => {
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
    ctx.edge_connections.remove(&connection_id);

    let affected = ctx.router.remove_edge(&connection_id);
    for (tunnel_id, peer_edge_id) in affected {
        if let Some(peer_id) = peer_edge_id {
            notify_tunnel_down(&ctx, &peer_id, tunnel_id, "peer disconnected").await;
        }
    }
}

async fn handle_control_stream(
    ctx: &Arc<SessionContext>,
    connection: &Connection,
    connection_id: &str,
    identified_id: &Arc<Mutex<Option<String>>>,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<()> {
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
                *identified_id.lock().unwrap() = Some(provided_id);
            }

            EdgeMessage::TunnelBind {
                tunnel_id,
                direction,
                protocol,
                bind_token,
            } => {
                // Verify bind token before allowing the bind
                if !ctx.router.verify_bind_token(&tunnel_id, direction, bind_token.as_deref()) {
                    tracing::warn!(
                        "Connection '{connection_id}' bind rejected for tunnel {tunnel_id} — invalid bind_token"
                    );
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
                    .lock()
                    .unwrap()
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

                match ctx.router.bind(tunnel_id, protocol, endpoint) {
                    BindResult::Active => {
                        tracing::info!("Tunnel {tunnel_id} is now active (both sides bound)");

                        // Notify this edge
                        write_message(send, &RelayMessage::TunnelReady { tunnel_id }).await?;

                        // Notify peer (use connection_id for DashMap lookup)
                        let peer_dir = match direction {
                            TunnelDirection::Ingress => TunnelDirection::Egress,
                            TunnelDirection::Egress => TunnelDirection::Ingress,
                        };
                        if let Some(entry) = ctx.router.tunnels_ref().get(&tunnel_id) {
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
                        write_message(send, &RelayMessage::TunnelWaiting { tunnel_id }).await?;
                    }
                }
            }

            EdgeMessage::TunnelUnbind { tunnel_id } => {
                tracing::info!("Connection '{connection_id}' unbinding tunnel {tunnel_id}");
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
        let entry = ctx
            .router
            .tunnels_ref()
            .get(&tunnel_id)
            .context("tunnel not found")?;
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
            let Some(entry) = ctx.router.tunnels_ref().get(&tunnel_id) else {
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

/// Send a TunnelReady notification to an edge via its control stream.
async fn notify_tunnel_ready(ctx: &Arc<SessionContext>, edge_id: &str, tunnel_id: Uuid) {
    if let Some(conn) = ctx.edge_connections.get(edge_id) {
        // We need to send on the existing control stream, but we don't have
        // access to it here. Instead, open a new uni stream for notifications.
        if let Ok(mut send) = conn.open_uni().await {
            let msg = RelayMessage::TunnelReady { tunnel_id };
            let _ = write_message(&mut send, &msg).await;
            let _ = send.finish();
        }
    }
}

/// Send a TunnelDown notification to an edge.
async fn notify_tunnel_down(
    ctx: &Arc<SessionContext>,
    edge_id: &str,
    tunnel_id: Uuid,
    reason: &str,
) {
    if let Some(conn) = ctx.edge_connections.get(edge_id) {
        if let Ok(mut send) = conn.open_uni().await {
            let msg = RelayMessage::TunnelDown {
                tunnel_id,
                reason: reason.to_string(),
            };
            let _ = write_message(&mut send, &msg).await;
            let _ = send.finish();
        }
    }
}
