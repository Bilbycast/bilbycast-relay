// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! REST API for relay health, status, and tunnel monitoring.
//!
//! If `api_token` is configured, all endpoints except `/health` require
//! `Authorization: Bearer <token>`. Otherwise, all endpoints are open.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Serialize;
use uuid::Uuid;

use crate::session::SessionContext;
use crate::stats::{ManagerLinkStatus, RelayStats};
use crate::tunnel_router::TunnelInfo;

pub struct ApiState {
    pub ctx: Arc<SessionContext>,
    pub relay_stats: Arc<RelayStats>,
    /// Optional Bearer token for API authentication.
    pub api_token: Option<String>,
}

/// Middleware that checks Bearer token on all routes except /health.
async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    // No token configured — allow all requests (backwards compatible)
    let Some(ref expected_token) = state.api_token else {
        return next.run(request).await;
    };

    // Extract Bearer token from Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let provided_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");

    if !crate::util::constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Unauthorized — valid Bearer token required"})),
        )
            .into_response();
    }

    next.run(request).await
}

pub fn create_router(state: Arc<ApiState>) -> Router {
    // /health is always public
    let public = Router::new().route("/health", get(health));

    // All other routes require auth (if api_token is configured)
    let authenticated = Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/api/v1/tunnels", get(list_tunnels))
        .route("/api/v1/tunnels/{id}", delete(delete_tunnel))
        .route("/api/v1/udp-sessions", get(list_udp_sessions))
        .route("/api/v1/udp-sessions/{id}", delete(delete_udp_session))
        .route("/api/v1/bond-bridges", get(list_bond_bridges))
        .route("/api/v1/bond-bridges/{id}", delete(delete_bond_bridge))
        .route("/api/v1/edges", get(list_edges))
        .route("/api/v1/stats", get(relay_stats))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    public.merge(authenticated).with_state(state)
}

// ── /health ──

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
    connected_edges: usize,
    total_tunnels: usize,
    active_tunnels: usize,
    /// Native plain-UDP relay sessions (SRT/RIST without QUIC).
    udp_sessions_total: usize,
    udp_sessions_active: usize,
    /// Manager-link state. Omitted when no manager is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    manager: Option<ManagerLinkStatus>,
}

async fn health(State(state): State<Arc<ApiState>>) -> Json<HealthResponse> {
    let (total, active) = state.ctx.router.counts();
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.relay_stats.uptime_secs(),
        connected_edges: state.ctx.edge_connections.len(),
        total_tunnels: total,
        active_tunnels: active,
        udp_sessions_total: state.ctx.udp_sessions.count(),
        udp_sessions_active: state.ctx.udp_sessions.active_count(),
        manager: state.relay_stats.manager_link_status(),
    })
}

// ── /api/v1/stats ──

#[derive(Serialize)]
struct RelayStatsResponse {
    uptime_secs: u64,
    connected_edges: usize,
    total_tunnels: usize,
    active_tunnels: usize,
    total_bytes_ingress: u64,
    total_bytes_egress: u64,
    total_bytes_forwarded: u64,
    total_bandwidth_bps: u64,
    total_tcp_streams: u64,
    active_tcp_streams: u64,
    total_udp_datagrams: u64,
    peak_tunnels: u64,
    peak_edges: u64,
    connections_total: u64,
    /// Manager-link state. Omitted when no manager is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    manager: Option<ManagerLinkStatus>,
}

async fn relay_stats(State(state): State<Arc<ApiState>>) -> Json<RelayStatsResponse> {
    let tunnel_infos = state.ctx.router.list_tunnels();
    let (total_tunnels, active_tunnels) = state.ctx.router.counts();
    let connected_edges = state.ctx.edge_connections.len();

    let totals = aggregate_tunnel_stats(&tunnel_infos);

    // Update peaks
    state
        .relay_stats
        .update_peaks(active_tunnels as u64, connected_edges as u64);

    let total_forwarded = totals.bytes_ingress + totals.bytes_egress;
    let bandwidth_bps = state.relay_stats.compute_bandwidth_bps(total_forwarded);

    Json(RelayStatsResponse {
        uptime_secs: state.relay_stats.uptime_secs(),
        connected_edges,
        total_tunnels,
        active_tunnels,
        total_bytes_ingress: totals.bytes_ingress,
        total_bytes_egress: totals.bytes_egress,
        total_bytes_forwarded: total_forwarded,
        total_bandwidth_bps: bandwidth_bps,
        total_tcp_streams: totals.tcp_streams_total,
        active_tcp_streams: totals.tcp_streams_active,
        total_udp_datagrams: totals.udp_datagrams_total,
        peak_tunnels: state.relay_stats.peak_tunnels.load(Ordering::Relaxed),
        peak_edges: state.relay_stats.peak_edges.load(Ordering::Relaxed),
        connections_total: state.relay_stats.connections_total.load(Ordering::Relaxed),
        manager: state.relay_stats.manager_link_status(),
    })
}

// ── /api/v1/tunnels ──

#[derive(Serialize)]
struct TunnelsResponse {
    tunnels: Vec<TunnelInfo>,
}

async fn list_tunnels(State(state): State<Arc<ApiState>>) -> Json<TunnelsResponse> {
    Json(TunnelsResponse {
        tunnels: state.ctx.router.list_tunnels(),
    })
}

// ── DELETE /api/v1/tunnels/{id} ──

/// `DELETE /api/v1/tunnels/{id}` — administrative escape hatch to tear down a
/// tunnel directly on the relay, for when the manager (the normal cleanup path
/// over the WS control channel) is unavailable.
///
/// **Fail-closed:** this destructive route only works when `api_token` is
/// configured. With no token the relay's read-only API is open-by-default
/// (`auth_middleware` lets everything through), and an open DELETE would let
/// anyone reachable on the API port tear down tunnels — so it returns `403`
/// when no token is set. When a token *is* set the middleware has already
/// verified the Bearer token before this handler runs.
///
/// Semantics match a user-initiated delete: **revoke** the bind authorization
/// (so a reconnecting edge can't immediately re-bind) **and** force-remove the
/// live tunnel entry (so it stops showing in `waiting_ingress` / forwarding).
/// Reuses the same `revoke_tunnel` + `force_remove_tunnel` primitives as the WS
/// `close_tunnel`/`revoke_tunnel` commands so behaviour is identical.
async fn delete_tunnel(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Refuse destructive mutation on an unauthenticated API.
    if state.api_token.is_none() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "tunnel deletion requires api_token to be configured"
            })),
        )
            .into_response();
    }

    // Tunnel IDs must be valid UUIDs (per the relay's tunnel-isolation rule).
    let tunnel_id: Uuid = match id.parse() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid tunnel id (must be a UUID): {e}")
                })),
            )
                .into_response();
        }
    };

    // Block re-bind first, then drop the live entry.
    state.ctx.router.revoke_tunnel(&tunnel_id);
    match state.ctx.router.force_remove_tunnel(&tunnel_id) {
        Some(affected) => {
            let peers_notified = affected.len();
            for connection_id in affected {
                crate::session::notify_tunnel_down(
                    &state.ctx,
                    &connection_id,
                    tunnel_id,
                    "tunnel deleted via relay REST API",
                )
                .await;
            }
            tracing::info!("REST: deleted tunnel '{tunnel_id}' ({peers_notified} peer(s) notified)");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "deleted": true,
                    "tunnel_id": tunnel_id.to_string(),
                    "peers_notified": peers_notified,
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("tunnel '{tunnel_id}' not found") })),
        )
            .into_response(),
    }
}

// ── /api/v1/udp-sessions (native SRT/RIST over relay, no QUIC) ──

#[derive(Serialize)]
struct UdpSessionsResponse {
    sessions: Vec<crate::udp_relay::UdpSessionInfo>,
}

async fn list_udp_sessions(State(state): State<Arc<ApiState>>) -> Json<UdpSessionsResponse> {
    Json(UdpSessionsResponse {
        sessions: state.ctx.udp_sessions.list(),
    })
}

/// `DELETE /api/v1/udp-sessions/{id}` — administrative teardown of a native-UDP
/// relay session. Fail-closed (requires `api_token`), mirroring `delete_tunnel`.
async fn delete_udp_session(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.api_token.is_none() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "session deletion requires api_token to be configured"
            })),
        )
            .into_response();
    }
    let tunnel_id: Uuid = match id.parse() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid session id (must be a UUID): {e}")
                })),
            )
                .into_response();
        }
    };
    if state.ctx.udp_sessions.remove(&tunnel_id) {
        tracing::info!("REST: deleted native-UDP session '{tunnel_id}'");
        (
            StatusCode::OK,
            Json(serde_json::json!({ "deleted": true, "tunnel_id": tunnel_id.to_string() })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("session '{tunnel_id}' not found") })),
        )
            .into_response()
    }
}

// ── /api/v1/bond-bridges (bonding-via-relay) ──

#[derive(Serialize)]
struct BondBridgesResponse {
    bridges: Vec<crate::bond_bridge::BondBridgeInfo>,
}

async fn list_bond_bridges(State(state): State<Arc<ApiState>>) -> Json<BondBridgesResponse> {
    Json(BondBridgesResponse {
        bridges: state.ctx.bond_bridges.list(),
    })
}

/// `DELETE /api/v1/bond-bridges/{id}` — tear down a relay-hosted bond bridge.
/// Fail-closed (requires `api_token`), mirroring `delete_tunnel`.
async fn delete_bond_bridge(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.api_token.is_none() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "bond bridge deletion requires api_token to be configured"
            })),
        )
            .into_response();
    }
    if state.ctx.bond_bridges.stop(&id) {
        tracing::info!("REST: deleted bond bridge '{id}'");
        (StatusCode::OK, Json(serde_json::json!({ "deleted": true, "id": id }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("bond bridge '{id}' not found") })),
        )
            .into_response()
    }
}

// ── /api/v1/edges ──

#[derive(Serialize)]
struct EdgeInfo {
    edge_id: String,
    remote_addr: String,
}

#[derive(Serialize)]
struct EdgesResponse {
    edges: Vec<EdgeInfo>,
}

async fn list_edges(State(state): State<Arc<ApiState>>) -> Json<EdgesResponse> {
    let edges: Vec<EdgeInfo> = state
        .ctx
        .edge_connections
        .iter()
        .map(|entry| EdgeInfo {
            edge_id: entry.key().clone(),
            remote_addr: entry.value().remote_address().to_string(),
        })
        .collect();
    Json(EdgesResponse { edges })
}

// ── /metrics (Prometheus) ──

async fn prometheus_metrics(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    use std::fmt::Write;
    let mut out = String::with_capacity(8192);

    let version = env!("CARGO_PKG_VERSION");
    let uptime = state.relay_stats.uptime_secs();
    let edges_connected = state.ctx.edge_connections.len();
    let (total_tunnels, active_tunnels) = state.ctx.router.counts();
    let tunnels = state.ctx.router.list_tunnels();
    let totals = aggregate_tunnel_stats(&tunnels);

    // Update peaks
    state
        .relay_stats
        .update_peaks(active_tunnels as u64, edges_connected as u64);

    let total_forwarded = totals.bytes_ingress + totals.bytes_egress;

    // ── Relay-level metrics ──

    let _ = writeln!(out, "# HELP bilbycast_relay_info Relay server information.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_info gauge");
    let _ = writeln!(out, "bilbycast_relay_info{{version=\"{version}\"}} 1");
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_uptime_seconds Relay uptime in seconds.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_uptime_seconds gauge");
    let _ = writeln!(out, "bilbycast_relay_uptime_seconds {uptime}");
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_edges_connected Number of connected edge nodes.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_edges_connected gauge");
    let _ = writeln!(out, "bilbycast_relay_edges_connected {edges_connected}");
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_tunnels_total Total number of tunnels (active + pending).");
    let _ = writeln!(out, "# TYPE bilbycast_relay_tunnels_total gauge");
    let _ = writeln!(out, "bilbycast_relay_tunnels_total {total_tunnels}");
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_tunnels_active Number of active tunnels.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_tunnels_active gauge");
    let _ = writeln!(out, "bilbycast_relay_tunnels_active {active_tunnels}");
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_bytes_forwarded_total Total bytes forwarded (ingress + egress) across all tunnels.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_bytes_forwarded_total counter");
    let _ = writeln!(out, "bilbycast_relay_bytes_forwarded_total {total_forwarded}");
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_bytes_ingress_total Total bytes received from ingress edges.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_bytes_ingress_total counter");
    let _ = writeln!(out, "bilbycast_relay_bytes_ingress_total {}", totals.bytes_ingress);
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_bytes_egress_total Total bytes sent to egress edges.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_bytes_egress_total counter");
    let _ = writeln!(out, "bilbycast_relay_bytes_egress_total {}", totals.bytes_egress);
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_tcp_streams_total Total TCP streams forwarded.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_tcp_streams_total counter");
    let _ = writeln!(out, "bilbycast_relay_tcp_streams_total {}", totals.tcp_streams_total);
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_tcp_streams_active Currently active TCP streams being forwarded.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_tcp_streams_active gauge");
    let _ = writeln!(out, "bilbycast_relay_tcp_streams_active {}", totals.tcp_streams_active);
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_udp_datagrams_total Total UDP datagrams forwarded.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_udp_datagrams_total counter");
    let _ = writeln!(out, "bilbycast_relay_udp_datagrams_total {}", totals.udp_datagrams_total);
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_connections_total Total QUIC connections accepted since startup.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_connections_total counter");
    let _ = writeln!(out, "bilbycast_relay_connections_total {}", state.relay_stats.connections_total.load(Ordering::Relaxed));
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_peak_tunnels Peak number of simultaneous active tunnels.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_peak_tunnels gauge");
    let _ = writeln!(out, "bilbycast_relay_peak_tunnels {}", state.relay_stats.peak_tunnels.load(Ordering::Relaxed));
    let _ = writeln!(out);

    let _ = writeln!(out, "# HELP bilbycast_relay_peak_edges Peak number of simultaneous connected edges.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_peak_edges gauge");
    let _ = writeln!(out, "bilbycast_relay_peak_edges {}", state.relay_stats.peak_edges.load(Ordering::Relaxed));
    let _ = writeln!(out);

    // ── Native plain-UDP relay (SRT/RIST without QUIC) ──
    let udp_sessions = state.ctx.udp_sessions.list();
    let udp_active = udp_sessions.iter().filter(|s| s.status == "active").count();
    let udp_bytes: u64 = udp_sessions.iter().map(|s| s.bytes_ingress + s.bytes_egress).sum();
    let udp_datagrams: u64 = udp_sessions.iter().map(|s| s.datagrams).sum();
    let _ = writeln!(out, "# HELP bilbycast_relay_udp_sessions_total Native plain-UDP relay sessions (active + waiting).");
    let _ = writeln!(out, "# TYPE bilbycast_relay_udp_sessions_total gauge");
    let _ = writeln!(out, "bilbycast_relay_udp_sessions_total {}", udp_sessions.len());
    let _ = writeln!(out);
    let _ = writeln!(out, "# HELP bilbycast_relay_udp_sessions_active Native plain-UDP relay sessions with both sides latched.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_udp_sessions_active gauge");
    let _ = writeln!(out, "bilbycast_relay_udp_sessions_active {udp_active}");
    let _ = writeln!(out);
    let _ = writeln!(out, "# HELP bilbycast_relay_udp_bytes_forwarded_total Total bytes forwarded over the native plain-UDP relay.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_udp_bytes_forwarded_total counter");
    let _ = writeln!(out, "bilbycast_relay_udp_bytes_forwarded_total {udp_bytes}");
    let _ = writeln!(out);
    let _ = writeln!(out, "# HELP bilbycast_relay_udp_datagrams_forwarded_total Total datagrams forwarded over the native plain-UDP relay.");
    let _ = writeln!(out, "# TYPE bilbycast_relay_udp_datagrams_forwarded_total counter");
    let _ = writeln!(out, "bilbycast_relay_udp_datagrams_forwarded_total {udp_datagrams}");
    let _ = writeln!(out);

    // Manager-link state (local observability only). Emitted when a
    // manager is configured: 1 = WS link up, 0 = down/reconnecting.
    if let Some(link) = state.relay_stats.manager_link_status() {
        let _ = writeln!(out, "# HELP bilbycast_relay_manager_connected Whether the manager WebSocket link is currently up (1) or down (0).");
        let _ = writeln!(out, "# TYPE bilbycast_relay_manager_connected gauge");
        let _ = writeln!(out, "bilbycast_relay_manager_connected {}", if link.connected { 1 } else { 0 });
        let _ = writeln!(out);

        let _ = writeln!(out, "# HELP bilbycast_relay_manager_disconnected_seconds Seconds since the manager link went down (0 while connected).");
        let _ = writeln!(out, "# TYPE bilbycast_relay_manager_disconnected_seconds gauge");
        let _ = writeln!(out, "bilbycast_relay_manager_disconnected_seconds {}", link.disconnected_secs);
        let _ = writeln!(out);
    }

    // ── Per-tunnel metrics ──

    if !tunnels.is_empty() {
        let _ = writeln!(out, "# HELP bilbycast_relay_tunnel_bytes_ingress Total bytes received for a tunnel.");
        let _ = writeln!(out, "# TYPE bilbycast_relay_tunnel_bytes_ingress counter");
        for t in &tunnels {
            let _ = writeln!(
                out,
                "bilbycast_relay_tunnel_bytes_ingress{{tunnel_id=\"{}\",protocol=\"{}\"}} {}",
                t.tunnel_id, t.protocol, t.stats.bytes_ingress
            );
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "# HELP bilbycast_relay_tunnel_bytes_egress Total bytes sent for a tunnel.");
        let _ = writeln!(out, "# TYPE bilbycast_relay_tunnel_bytes_egress counter");
        for t in &tunnels {
            let _ = writeln!(
                out,
                "bilbycast_relay_tunnel_bytes_egress{{tunnel_id=\"{}\",protocol=\"{}\"}} {}",
                t.tunnel_id, t.protocol, t.stats.bytes_egress
            );
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "# HELP bilbycast_relay_tunnel_tcp_streams_total Total TCP streams forwarded for a tunnel.");
        let _ = writeln!(out, "# TYPE bilbycast_relay_tunnel_tcp_streams_total counter");
        for t in &tunnels {
            let _ = writeln!(
                out,
                "bilbycast_relay_tunnel_tcp_streams_total{{tunnel_id=\"{}\",protocol=\"{}\"}} {}",
                t.tunnel_id, t.protocol, t.stats.tcp_streams_total
            );
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "# HELP bilbycast_relay_tunnel_tcp_streams_active Currently active TCP streams for a tunnel.");
        let _ = writeln!(out, "# TYPE bilbycast_relay_tunnel_tcp_streams_active gauge");
        for t in &tunnels {
            let _ = writeln!(
                out,
                "bilbycast_relay_tunnel_tcp_streams_active{{tunnel_id=\"{}\",protocol=\"{}\"}} {}",
                t.tunnel_id, t.protocol, t.stats.tcp_streams_active
            );
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "# HELP bilbycast_relay_tunnel_udp_datagrams_total Total UDP datagrams forwarded for a tunnel.");
        let _ = writeln!(out, "# TYPE bilbycast_relay_tunnel_udp_datagrams_total counter");
        for t in &tunnels {
            let _ = writeln!(
                out,
                "bilbycast_relay_tunnel_udp_datagrams_total{{tunnel_id=\"{}\",protocol=\"{}\"}} {}",
                t.tunnel_id, t.protocol, t.stats.udp_datagrams_total
            );
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "# HELP bilbycast_relay_tunnel_uptime_seconds Tunnel uptime in seconds.");
        let _ = writeln!(out, "# TYPE bilbycast_relay_tunnel_uptime_seconds gauge");
        for t in &tunnels {
            let _ = writeln!(
                out,
                "bilbycast_relay_tunnel_uptime_seconds{{tunnel_id=\"{}\",protocol=\"{}\"}} {}",
                t.tunnel_id, t.protocol, t.stats.uptime_secs
            );
        }
        let _ = writeln!(out);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, out)
}

// ── Helpers ──

/// Aggregate stats across all tunnels.
struct AggregateTunnelStats {
    bytes_ingress: u64,
    bytes_egress: u64,
    tcp_streams_total: u64,
    tcp_streams_active: u64,
    udp_datagrams_total: u64,
}

fn aggregate_tunnel_stats(tunnels: &[TunnelInfo]) -> AggregateTunnelStats {
    let mut agg = AggregateTunnelStats {
        bytes_ingress: 0,
        bytes_egress: 0,
        tcp_streams_total: 0,
        tcp_streams_active: 0,
        udp_datagrams_total: 0,
    };
    for t in tunnels {
        agg.bytes_ingress += t.stats.bytes_ingress;
        agg.bytes_egress += t.stats.bytes_egress;
        agg.tcp_streams_total += t.stats.tcp_streams_total;
        agg.tcp_streams_active += t.stats.tcp_streams_active;
        agg.udp_datagrams_total += t.stats.udp_datagrams_total;
    }
    agg
}
