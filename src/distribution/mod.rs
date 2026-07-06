// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Viewer-distribution subsystem: a WHEP SFU + LL-HLS origin co-located in
//! the relay binary but hard-isolated behind the `viewer-distribution`
//! feature. The stateless opaque forwarder never links or runs any of this.
//!
//! Architecture:
//! - An **edge** ships browser-ready H.264+Opus elementary frames for a named
//!   stream over the distribution **ingest** ([`ingest`]).
//! - Those frames land in the [`hub::DistributionHub`], one fan-out point per
//!   stream, with a lock-free keyframe cache for instant late-join.
//! - Browser **viewers** connect over **WHEP** ([`whep`]); each gets an
//!   independent str0m DTLS/SRTP session fed from the hub. Fan-out (1→N) and
//!   media termination happen here, on the public relay — never on the NAT'd,
//!   uplink-capped edge.
//! - The same ingest also feeds a **LL-HLS origin** ([`origin`]) for
//!   CDN-scalable, non-WebRTC browser reach.

pub mod es;
pub mod hub;
pub mod ingest;
pub mod origin;
pub mod token;
pub mod webrtc;
pub mod whep;
pub mod whip_ingest;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

use crate::config::DistributionConfig;
use crate::manager::events::EventSender;

use self::hub::DistributionHub;
use self::origin::OriginStore;

/// Shared state for the distribution subsystem's HTTP surface.
pub struct DistributionState {
    pub hub: Arc<DistributionHub>,
    pub origin: Arc<OriginStore>,
    pub config: DistributionConfig,
    /// The relay's public IP for WHEP ICE candidates.
    pub public_ip: Option<std::net::IpAddr>,
    /// Root cancel token for the subsystem.
    pub cancel: CancellationToken,
    /// Live viewer sessions, keyed by session id — for targeted DELETE.
    pub sessions: DashMap<String, ViewerSession>,
    /// Live WHIP ingest sessions, keyed by session id.
    pub ingests: DashMap<String, CancellationToken>,
    /// Concurrent viewer count per source IP (public-endpoint DoS cap).
    pub viewers_by_ip: DashMap<IpAddr, AtomicU32>,
    pub events: EventSender,
}

/// A live viewer session tracked for teardown + per-IP accounting.
pub struct ViewerSession {
    pub cancel: CancellationToken,
    pub ip: IpAddr,
}

/// Run the whole viewer-distribution subsystem: the ingest listener + the
/// browser-facing HTTP signaling / origin listeners. Returns when the
/// subsystem's cancel token fires or every listener dies.
pub async fn run_distribution(
    config: DistributionConfig,
    hub: Arc<DistributionHub>,
    cancel: CancellationToken,
    events: EventSender,
    relay_stats: Arc<crate::stats::RelayStats>,
) -> Result<()> {
    let origin = Arc::new(OriginStore::new(config.origin_window_segments));
    let public_ip = config.public_ip_parsed();

    // Telemetry: periodically publish hub + origin counters onto RelayStats so
    // the manager-client health builder (and the local REST/metrics surface)
    // can report per-relay viewer counts. Off the request path.
    {
        let hub = hub.clone();
        let origin = origin.clone();
        let stats = relay_stats.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {
                        let bytes_out: u64 =
                            hub.snapshot().iter().map(|s| s.bytes_out).sum();
                        stats.set_distribution(
                            hub.stream_count() as u64,
                            hub.total_viewers(),
                            bytes_out,
                            origin.total_bytes(),
                        );
                    }
                }
            }
        });
    }

    let state = Arc::new(DistributionState {
        hub: hub.clone(),
        origin: origin.clone(),
        config: config.clone(),
        public_ip,
        cancel: cancel.clone(),
        sessions: DashMap::new(),
        ingests: DashMap::new(),
        viewers_by_ip: DashMap::new(),
        events: events.clone(),
    });

    // Start the edge→relay ingest listener (browser-ready ES over QUIC).
    let ingest_cancel = cancel.clone();
    let ingest_hub = hub.clone();
    let ingest_config = config.clone();
    let ingest_events = events.clone();
    let ingest_handle = tokio::spawn(async move {
        if let Err(e) =
            ingest::run_ingest(ingest_config, ingest_hub, ingest_events, ingest_cancel).await
        {
            tracing::error!("distribution ingest listener stopped: {e:#}");
        }
    });

    // Start the browser-facing HTTP signaling + origin listeners.
    let router = build_router(state.clone());
    let http_entries = config.effective_http_addrs();
    let mut http_addrs: Vec<SocketAddr> = Vec::with_capacity(http_entries.len());
    for raw in &http_entries {
        let addr: SocketAddr = raw
            .parse()
            .with_context(|| format!("invalid distribution.http bind address '{raw}'"))?;
        http_addrs.push(addr);
    }

    let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    for addr in http_addrs {
        let router = router.clone();
        let http_cancel = cancel.clone();
        set.spawn(async move {
            match crate::build_tcp_listener(addr) {
                Ok(listener) => {
                    tracing::info!("distribution HTTP (WHEP signaling + LL-HLS origin) listening on {addr}");
                    let make_svc = router.into_make_service_with_connect_info::<SocketAddr>();
                    let served = axum::serve(listener, make_svc)
                        .with_graceful_shutdown(async move { http_cancel.cancelled().await });
                    if let Err(e) = served.await {
                        tracing::error!("distribution HTTP on {addr}: {e}");
                    }
                }
                Err(e) => tracing::error!("failed to bind distribution HTTP on {addr}: {e}"),
            }
        });
    }

    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = set.join_next() => {}
        _ = ingest_handle => {}
    }
    Ok(())
}

/// Build the axum router for the distribution HTTP surface.
fn build_router(state: Arc<DistributionState>) -> Router {
    Router::new()
        .route("/distribution/health", get(health))
        // WHEP: viewer POSTs an SDP offer, gets an SDP answer + a resource URL.
        .route("/whep/{stream_id}", post(whep_offer))
        .route("/whep/{stream_id}/{session_id}", delete(whep_delete))
        // WHIP ingest: an edge POSTs an SDP offer to push a stream in.
        .route("/whip/{stream_id}", post(whip_ingest_offer))
        .route("/whip/{stream_id}/{session_id}", delete(whip_ingest_delete))
        // Minimal built-in player page.
        .route("/watch/{stream_id}", get(watch_page))
        // LL-HLS origin (Tier 1) — see origin.rs for the route handlers.
        .merge(origin::routes())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Validate + normalize a stream id from the URL path. Streams are named by
/// the manager; keep the character set tight to avoid path/URL abuse.
pub fn sanitize_stream_id(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        Some(s.to_string())
    } else {
        None
    }
}

/// `POST /whep/{stream_id}` — accept a viewer's SDP offer, return the answer.
async fn whep_offer(
    State(st): State<Arc<DistributionState>>,
    Path(stream_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Some(stream_id) = sanitize_stream_id(&stream_id) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };

    // Optional viewer-token gate (P2).
    if st.config.require_viewer_token {
        if let Err(resp) = check_viewer_token(&st, &stream_id, &headers) {
            return resp;
        }
    }

    if body.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "empty SDP offer").into_response();
    }

    // Per-IP concurrent-viewer cap (public-endpoint DoS control).
    let ip = peer.ip();
    let cap = st.config.max_viewers_per_ip;
    {
        let entry = st.viewers_by_ip.entry(ip).or_insert_with(|| AtomicU32::new(0));
        if entry.load(Ordering::Relaxed) >= cap {
            st.events.emit_with_details(
                crate::manager::events::EventSeverity::Warning,
                crate::manager::events::category::DISTRIBUTION,
                format!("per-IP viewer cap ({cap}) reached from {ip}"),
                serde_json::json!({ "ip": ip.to_string(), "cap": cap }),
            );
            return (StatusCode::TOO_MANY_REQUESTS, "per-IP viewer cap reached").into_response();
        }
        entry.fetch_add(1, Ordering::Relaxed);
    }

    match whep::create_and_spawn_viewer(
        st.hub.clone(),
        stream_id.clone(),
        &body,
        st.public_ip,
        st.cancel.clone(),
    )
    .await
    {
        Ok(handle) => {
            st.sessions.insert(
                handle.session_id.clone(),
                ViewerSession { cancel: handle.cancel.clone(), ip },
            );
            // Reaper: when this viewer's token fires (natural end OR DELETE),
            // drop the session record and release the per-IP slot.
            let reap = Arc::clone(&st);
            let sid = handle.session_id.clone();
            let watch = handle.cancel.clone();
            tokio::spawn(async move {
                watch.cancelled().await;
                reap.sessions.remove(&sid);
                if let Some(c) = reap.viewers_by_ip.get(&ip) {
                    c.fetch_sub(1, Ordering::Relaxed);
                }
            });

            let location = format!("/whep/{stream_id}/{}", handle.session_id);
            (
                StatusCode::CREATED,
                [
                    (header::CONTENT_TYPE, "application/sdp".to_string()),
                    (header::LOCATION, location),
                ],
                handle.answer_sdp,
            )
                .into_response()
        }
        Err(e) => {
            // Setup failed — release the slot we reserved.
            if let Some(c) = st.viewers_by_ip.get(&ip) {
                c.fetch_sub(1, Ordering::Relaxed);
            }
            tracing::warn!("WHEP setup failed for stream '{stream_id}': {e:#}");
            (StatusCode::BAD_REQUEST, format!("WHEP setup failed: {e}")).into_response()
        }
    }
}

/// `DELETE /whep/{stream_id}/{session_id}` — tear down exactly this viewer.
async fn whep_delete(
    State(st): State<Arc<DistributionState>>,
    Path((_stream_id, session_id)): Path<(String, String)>,
) -> Response {
    // Cancel the session; the reaper spawned at offer time removes the record
    // and releases the per-IP slot.
    match st.sessions.get(&session_id) {
        Some(s) => {
            s.cancel.cancel();
            StatusCode::OK.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `POST /whip/{stream_id}` — accept an edge's WHIP ingest offer.
async fn whip_ingest_offer(
    State(st): State<Arc<DistributionState>>,
    Path(stream_id): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Some(stream_id) = sanitize_stream_id(&stream_id) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };

    // Ingest is a write surface — token-gate it unless explicitly disabled.
    if st.config.require_ingest_token {
        let Some(ref secret) = st.config.token_secret else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "ingest token gate misconfigured").into_response();
        };
        let ok = bearer(&headers)
            .map(|t| token::verify_ingest_token(secret, &stream_id, &t).is_ok())
            .unwrap_or(false);
        if !ok {
            return (StatusCode::UNAUTHORIZED, "ingest token required").into_response();
        }
    }

    if body.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "empty SDP offer").into_response();
    }

    match whip_ingest::create_and_spawn_ingest(
        st.hub.clone(),
        stream_id.clone(),
        &body,
        st.public_ip,
        st.cancel.clone(),
    )
    .await
    {
        Ok(handle) => {
            st.ingests.insert(handle.session_id.clone(), handle.cancel.clone());
            let reap = Arc::clone(&st);
            let sid = handle.session_id.clone();
            let watch = handle.cancel.clone();
            tokio::spawn(async move {
                watch.cancelled().await;
                reap.ingests.remove(&sid);
            });
            st.events.emit_with_details(
                crate::manager::events::EventSeverity::Info,
                crate::manager::events::category::DISTRIBUTION,
                format!("WHIP ingest opened for stream '{stream_id}'"),
                serde_json::json!({ "stream": stream_id }),
            );
            let location = format!("/whip/{stream_id}/{}", handle.session_id);
            (
                StatusCode::CREATED,
                [
                    (header::CONTENT_TYPE, "application/sdp".to_string()),
                    (header::LOCATION, location),
                ],
                handle.answer_sdp,
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("WHIP ingest setup failed for stream '{stream_id}': {e:#}");
            (StatusCode::BAD_REQUEST, format!("WHIP ingest setup failed: {e}")).into_response()
        }
    }
}

/// `DELETE /whip/{stream_id}/{session_id}` — stop a WHIP ingest.
async fn whip_ingest_delete(
    State(st): State<Arc<DistributionState>>,
    Path((_stream_id, session_id)): Path<(String, String)>,
) -> Response {
    match st.ingests.get(&session_id) {
        Some(c) => {
            c.cancel();
            StatusCode::OK.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Extract a Bearer token from the Authorization header.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Validate a viewer token supplied via `?token=` query or `Authorization:
/// Bearer`. Returns Err(response) on rejection.
fn check_viewer_token(
    st: &DistributionState,
    stream_id: &str,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let Some(ref secret) = st.config.token_secret else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "token gate misconfigured").into_response());
    };
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let Some(tok) = bearer else {
        return Err((StatusCode::UNAUTHORIZED, "viewer token required").into_response());
    };
    match token::verify_viewer_token(secret, stream_id, &tok) {
        Ok(()) => Ok(()),
        Err(e) => Err((StatusCode::FORBIDDEN, format!("viewer token rejected: {e}")).into_response()),
    }
}

/// Minimal built-in WHEP player page.
async fn watch_page(Path(stream_id): Path<String>) -> Response {
    let Some(stream_id) = sanitize_stream_id(&stream_id) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    let html = player_html(&stream_id);
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

/// Render the built-in player. `stream_id` is already sanitized (alnum/-/_/.)
/// so direct interpolation is safe.
fn player_html(stream_id: &str) -> String {
    include_str!("player.html").replace("__STREAM_ID__", stream_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_accepts_reasonable_ids() {
        assert_eq!(sanitize_stream_id("my-stream_01.hd").as_deref(), Some("my-stream_01.hd"));
        assert_eq!(sanitize_stream_id("  trimmed  ").as_deref(), Some("trimmed"));
    }

    #[test]
    fn sanitize_rejects_abuse() {
        assert!(sanitize_stream_id("").is_none());
        assert!(sanitize_stream_id("../etc/passwd").is_none());
        assert!(sanitize_stream_id("a/b").is_none());
        assert!(sanitize_stream_id("has space").is_none());
        assert!(sanitize_stream_id(&"x".repeat(200)).is_none());
    }
}
