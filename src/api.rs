// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! REST API for relay health, status, and tunnel monitoring.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
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
}

pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(prometheus_metrics))
        .route("/api/v1/tunnels", get(list_tunnels))
        .route("/api/v1/edges", get(list_edges))
        .with_state(state)
}

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

#[derive(Serialize)]
struct TunnelsResponse {
    tunnels: Vec<TunnelInfo>,
}

async fn list_tunnels(State(state): State<Arc<ApiState>>) -> Json<TunnelsResponse> {
    Json(TunnelsResponse {
        tunnels: state.ctx.router.list_tunnels(),
    })
}

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

/// Prometheus metrics endpoint — hand-crafted text exposition format.
async fn prometheus_metrics(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    use std::fmt::Write;
    let mut out = String::with_capacity(4096);

    let version = env!("CARGO_PKG_VERSION");
    let uptime = state.relay_stats.uptime_secs();
    let edges_connected = state.ctx.edge_connections.len();
    let (total_tunnels, active_tunnels) = state.ctx.router.counts();

    // Application info
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

    // Per-tunnel metrics
    let tunnels = state.ctx.router.list_tunnels();
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
