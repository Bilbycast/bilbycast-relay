// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! REST API for relay health, status, and tunnel monitoring.
//!
//! If `api_token` is configured, all endpoints except `/health` require
//! `Authorization: Bearer <token>`. Otherwise, all endpoints are open.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::session::SessionContext;
use crate::stats::RelayStats;
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

    if provided_token != expected_token.as_str() {
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
