//! REST API for relay health, status, and tunnel monitoring.

use std::sync::Arc;

use axum::extract::State;
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
