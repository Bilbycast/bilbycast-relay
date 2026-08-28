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

pub mod cascade;
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
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

use crate::config::DistributionConfig;
use crate::distribution_control::DistributionControl;
use crate::manager::events::EventSender;

use self::hub::DistributionHub;
use self::origin::OriginStore;

/// Shared state for the distribution subsystem's HTTP surface.
pub struct DistributionState {
    pub hub: Arc<DistributionHub>,
    pub origin: Arc<OriginStore>,
    /// Static config (listeners, origin window, per-IP cap) — set at startup.
    pub config: DistributionConfig,
    /// Runtime config the manager can push (secret, gates, public IP/URL).
    pub control: Arc<DistributionControl>,
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

impl DistributionState {
    /// Construct subsystem state with empty session/ingest registries. Shared
    /// by `run_distribution` and integration tests. `control` carries the
    /// runtime-overridable config (built from `config` at startup; the manager
    /// may later push updates onto it).
    pub fn new(
        hub: Arc<DistributionHub>,
        origin: Arc<OriginStore>,
        config: DistributionConfig,
        control: Arc<DistributionControl>,
        cancel: CancellationToken,
        events: EventSender,
    ) -> Arc<Self> {
        Arc::new(Self {
            hub,
            origin,
            config,
            control,
            cancel,
            sessions: DashMap::new(),
            ingests: DashMap::new(),
            viewers_by_ip: DashMap::new(),
            events,
        })
    }

    /// The relay's currently-advertised public IP for WHEP ICE candidates.
    pub fn public_ip(&self) -> Option<std::net::IpAddr> {
        self.control.load().public_ip
    }
}

/// Run the whole viewer-distribution subsystem: the ingest listener + the
/// browser-facing HTTP signaling / origin listeners. Returns when the
/// subsystem's cancel token fires or every listener dies.
pub async fn run_distribution(
    config: DistributionConfig,
    control: Arc<DistributionControl>,
    hub: Arc<DistributionHub>,
    cancel: CancellationToken,
    events: EventSender,
    relay_stats: Arc<crate::stats::RelayStats>,
) -> Result<()> {
    let origin_cfg = crate::distribution::origin::OriginConfig {
        root: config
            .origin_storage_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(crate::config::default_origin_storage_dir),
        retention: std::time::Duration::from_secs(config.origin_retention_secs),
        max_bytes_per_stream: config.origin_max_bytes_per_stream,
        min_segments: config.origin_window_segments,
        min_free_bytes: config.origin_min_free_bytes,
        idle_grace: std::time::Duration::from_secs(60),
    };
    tracing::info!(
        root = %origin_cfg.root.display(),
        retention_secs = config.origin_retention_secs,
        max_bytes_per_stream = config.origin_max_bytes_per_stream,
        min_segments = config.origin_window_segments,
        min_free_bytes = config.origin_min_free_bytes,
        "distribution origin: disk-backed store"
    );
    let origin = Arc::new(OriginStore::new(origin_cfg)?);

    // Storage policy from the manager. The bootstrap values above are only a
    // seed; from here the manager owns retention, and a DVR session can widen
    // the window for its own stream without holding every other stream's disk
    // for the same hour.
    {
        let origin = origin.clone();
        let cancel = cancel.clone();
        let mut rx = control.subscribe_origin();
        // The drop queue, taken once — the origin store is its only consumer.
        let mut drops = control.take_drops();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    // A stream the manager says nothing will want again: a
                    // deleted session's. Retention would hold it until the
                    // *node default* expired, which is unrelated to the window
                    // that session asked for.
                    Some(stream) = async {
                        match drops.as_mut() {
                            Some(rx) => rx.recv().await,
                            // Nothing to receive from; park this arm for good
                            // rather than spinning on a ready `None`.
                            None => std::future::pending().await,
                        }
                    } => {
                        origin.remove_stream(&stream).await;
                        tracing::info!(
                            stream = %stream,
                            "distribution origin: stream dropped at the manager's request"
                        );
                    }
                    changed = rx.changed() => {
                        if changed.is_err() {
                            break; // control dropped
                        }
                        let update = rx.borrow_and_update().clone();
                        origin.apply_policy_update(&update);
                        let d = origin.default_policy();
                        tracing::info!(
                            retention_secs = d.retention.as_secs(),
                            max_bytes_per_stream = d.max_bytes_per_stream,
                            min_segments = d.min_segments,
                            idle_grace_secs = d.idle_grace.as_secs(),
                            stream_overrides = update
                                .per_stream
                                .as_ref()
                                .map(|v| v.len())
                                .unwrap_or(0),
                            "distribution origin: storage policy updated by manager"
                        );
                    }
                }
            }
        });
    }

    // Retention sweep. Eviction is otherwise driven only by arriving segments,
    // so a stream whose producer stops keeps its disk indefinitely — past
    // retention, still serving its manifest, reclaimed only by a restart.
    {
        let origin = origin.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => origin.sweep().await,
                }
            }
        });
    }

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
                        let snap = hub.snapshot();
                        let bytes_out: u64 = snap.iter().map(|s| s.bytes_out).sum();
                        let offpath: u64 = snap.iter().map(|s| s.offpath_sessions).sum();
                        stats.set_distribution(
                            hub.stream_count() as u64,
                            hub.total_viewers(),
                            bytes_out,
                            origin.total_bytes(),
                            offpath,
                            origin
                                .usage()
                                .into_iter()
                                .map(|u| crate::stats::OriginStreamUsage {
                                    stream: u.stream,
                                    segments: u.segments as u64,
                                    bytes: u.bytes,
                                    idle_secs: u.idle_secs,
                                    policy_overridden: u.policy_overridden,
                                })
                                .collect(),
                        );
                    }
                }
            }
        });
    }

    let state = DistributionState::new(
        hub.clone(),
        origin.clone(),
        config.clone(),
        control.clone(),
        cancel.clone(),
        events.clone(),
    );

    // Cascade supervisor: reconcile the running WHEP-client pulls against the
    // (manager-updatable) cascade source list.
    {
        let hub = hub.clone();
        let control = control.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            cascade::run_cascade_supervisor(hub, control, cancel).await;
        });
    }

    // Start the edge→relay ingest listener (browser-ready ES over QUIC).
    let ingest_cancel = cancel.clone();
    let ingest_hub = hub.clone();
    let ingest_config = config.clone();
    let ingest_control = control.clone();
    let ingest_events = events.clone();
    let ingest_handle = tokio::spawn(async move {
        if let Err(e) = ingest::run_ingest(
            ingest_config,
            ingest_control,
            ingest_hub,
            ingest_events,
            ingest_cancel,
        )
        .await
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

/// Build the axum router for the distribution HTTP surface. `pub` so
/// integration tests can serve an upstream distribution node.
pub fn build_router(state: Arc<DistributionState>) -> Router {
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
        // Browser DVR surface: live + scrub-back + frame jog / shuttle.
        // The literal `hls.js` route must be registered before the
        // `{stream_id}` one it would otherwise be captured by.
        .route("/dvr/hls.js", get(dvr_hls_js))
        .route("/dvr/{stream_id}", get(dvr_page))
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
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Some(stream_id) = sanitize_stream_id(&stream_id) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };

    // Optional viewer-token gate (runtime, manager-overridable).
    if st.control.load().require_viewer_token
        && let Err(resp) = check_viewer_token(&st, &stream_id, &headers, query.as_deref())
    {
        return resp;
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
        st.public_ip(),
        st.cancel.clone(),
        st.events.clone(),
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
    let rt = st.control.load();
    if rt.require_ingest_token {
        let Some(ref secret) = rt.token_secret else {
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
        st.public_ip(),
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
///
/// An empty value (`"Bearer "` exactly, or `"Bearer   "`) is treated as *no*
/// credential rather than as the empty one. Proxies do inject blank
/// `Authorization` headers, and because the viewer lookup is header-first via
/// `.or_else`, returning `Some("")` here would swallow the fallthrough and
/// 403 a client that supplied a perfectly good `?token=` — defeating the query
/// path in exactly the mixed-client case it exists for. A *non-empty* junk
/// header still loses (403, no fallthrough): an explicit credential outranks a
/// URL, by design.
///
/// Measured caveat, so nobody over-credits this: through the axum/hyper stack
/// the empty case is **unreachable**, because hyper trims trailing optional
/// whitespace off a header value — a wire header of exactly `"Bearer "`
/// arrives as `"Bearer"`, which fails `strip_prefix("Bearer ")` and already
/// falls through. An end-to-end test of it passes with or without this filter
/// and was therefore not written. The filter is defence in depth for direct
/// callers of this helper and for a future non-hyper front end; it is unit
/// tested, not integration tested, and that is the honest boundary.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Pull `token` out of a raw query string (`"a=1&token=xyz"`). First
/// occurrence wins — `?token=&token=<valid>` therefore fails closed rather
/// than trying the next pair, which is the right direction for a credential.
///
/// The `?` is already stripped by axum's `RawQuery` extractor, so this takes
/// the query body only.
///
/// No percent-decoding: a viewer token is `"{exp}.{hmac}"` — decimal digits, a
/// dot, and lowercase hex — and nothing in that set is percent-encoded by a
/// conforming client. Decoding would only widen what we accept.
fn token_from_query(raw: Option<&str>) -> Option<String> {
    raw?.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == "token")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

/// Validate a viewer token supplied via `Authorization: Bearer` **or** the
/// `?token=` query parameter. Returns Err(response) on rejection.
///
/// **Why both forms — and what this is *not*.** An earlier version of this
/// comment claimed a browser driving WHEP cannot attach a request header, so
/// `require_viewer_token` was unreachable in its own documented deployment.
/// That is false, and the contradicting code is in this directory:
/// `player.html` reads `?token=` off the `/watch/{stream}` URL and forwards it
/// as `Authorization: Bearer` on its `fetch("/whep/…")`. WHEP is by definition
/// a POST of `Content-Type: application/sdp` carrying an SDP body, so no
/// `<video>` element or plain redirect can drive it at all — the client that
/// rationale was built around cannot exist, and the manager accordingly mints
/// `whep_url` with **no** token. The gate worked before this change.
///
/// The surviving justification is narrower and honest: accepting `?token=` on
/// `/whep` is a convenience for CLI and link-share clients, and it makes the
/// two documented forms consistent with `docs/distribution.md`. It closed no
/// hole. The header is checked first so an explicit credential always outranks
/// a URL.
///
/// **Residual risk this introduces.** `?token=` is a bearer credential carried
/// in a URL, on a listener that is plain HTTP by design and documented as
/// requiring a TLS-terminating reverse proxy in front — and every default
/// proxy access-log format (nginx `$request`, Apache `%r`, HAProxy, ALB,
/// CloudFront) records the full request line including the query. Viewer
/// tokens are stateless with no revocation path, and the manager's default TTL
/// is 6 hours, so a token lifted from a proxy log or browser history is
/// replayable against a live feed for that long. The honest counterweight: the
/// token was already URL-borne on the `/watch` page request, so the marginal
/// logging exposure is one extra line per session — what actually changed is
/// that URL-borne credentials became a supported `/whep` API contract rather
/// than a player-page convention. Prefer a short `ttl_secs` when minting links
/// for the query form.
///
/// **Scope.** This is the shared viewer-credential check. `require_viewer_token`
/// applies it to the WHEP tier; `require_origin_token` applies it to
/// `GET /origin/{stream}/{file}` (the CMAF/LL-HLS tier), which is
/// unauthenticated unless that second flag is on — see the note on
/// `origin::origin_get` and `docs/distribution.md`.
pub(super) fn check_viewer_token(
    st: &DistributionState,
    stream_id: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<(), Response> {
    let rt = st.control.load();
    let Some(ref secret) = rt.token_secret else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "token gate misconfigured").into_response());
    };
    let Some(tok) = bearer(headers).or_else(|| token_from_query(query)) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "viewer token required (Authorization: Bearer <token> or ?token=<token>)",
        )
            .into_response());
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

/// Browser DVR player page.
///
/// Distinct from `/watch` (WHEP, sub-second, live-only): this one plays the
/// LL-HLS origin, so it can seek back over the whole advertised window and
/// step frames. It expects **two** renditions — a main one under `stream_id`
/// and an all-intra proxy under `{stream_id}-proxy` (override with
/// `?main=` / `?proxy=`). The proxy is what makes frame-exact jog and reverse
/// shuttle possible; see `WEB_DVR_PLAYER_PLAN.md`.
async fn dvr_page(
    State(st): State<Arc<DistributionState>>,
    Path(stream_id): Path<String>,
) -> Response {
    let Some(stream_id) = sanitize_stream_id(&stream_id) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    // Where an expired viewer goes next. From the relay's own config, never
    // from the request — the page offers it as a link, and a link taken from
    // the URL that asked for the page is a phishing hop with extra steps.
    // Quotes and backslashes are stripped rather than escaped: the value is a
    // URL and cannot legitimately contain either, so anything that does is not
    // a URL we should be sending a viewer to.
    let portal = st
        .control
        .load()
        .portal_url
        .clone()
        .filter(|u| {
            (u.starts_with("http://") || u.starts_with("https://"))
                && !u.bytes().any(|b| matches!(b, b'"' | b'\\' | b'<' | b'>'))
        })
        .unwrap_or_default();
    let html = include_str!("dvr.html")
        .replace("__STREAM_ID__", &stream_id)
        .replace("__PORTAL_URL__", &portal);
    // The page is an app shell that changes with the build. Without this a
    // browser will happily serve a cached copy after an upgrade, so a fixed
    // player looks unfixed. (`/dvr/hls.js` stays immutable — it is versioned.)
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, must-revalidate"),
        ],
        html,
    )
        .into_response()
}

/// Vendored hls.js, served to the DVR page.
///
/// It is vendored rather than pulled from a CDN because the relay is often
/// deployed where viewers have no route to the public internet, and because a
/// player that silently stops working when a CDN changes is not a broadcast
/// tool. Android Chrome has no native HLS, so this is not optional there.
async fn dvr_hls_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        include_str!("vendor/hls.min.js"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DVR page must carry the stream id through and leave no placeholder
    /// behind — a stray `__STREAM_ID__` would have the player fetch a
    /// literally-named stream and show nothing, with no error anywhere.
    #[test]
    fn dvr_page_interpolates_stream_id() {
        let html = include_str!("dvr.html").replace("__STREAM_ID__", "bigshow");
        assert!(!html.contains("__STREAM_ID__"), "placeholder left in page");
        assert!(html.contains("bigshow"));
        // The proxy rendition is what makes frame jog work; the page must
        // derive it rather than silently play only the main one.
        assert!(html.contains("-proxy"), "page does not reference a proxy rendition");
    }

    /// Pull the body of a JS function out of the page.
    ///
    /// A string assertion on a script is a poor substitute for running it, but
    /// the alternative is no coverage at all on the part of the player an
    /// operator touches most, and both failures below are silent in a browser.
    fn js_fn<'a>(html: &'a str, name: &str) -> &'a str {
        let after = html
            .split(&format!("function {name}"))
            .nth(1)
            .unwrap_or_else(|| panic!("{name} not found in dvr.html"));
        after
            .split("
  }")
            .next()
            .unwrap_or_else(|| panic!("{name} has no body"))
    }

    /// The shaded part of the scrub bar must describe the element a scrub
    /// actually seeks.
    ///
    /// The shading tells the operator which positions respond immediately.
    /// Deriving it from the proxy, or from whichever element happens to be on
    /// screen, would light up a region that does not respond — a confident
    /// wrong answer, which is worse than no shading at all. Nothing in the
    /// browser would report it: the bar would simply lie.
    #[test]
    fn the_scrubbable_shading_describes_the_element_a_scrub_seeks() {
        let html = include_str!("dvr.html");
        let shade = js_fn(html, "renderCached");
        assert!(
            shade.contains("main.buffered"),
            "shading is not derived from main's buffer: {shade}"
        );
        assert!(
            !shade.contains("proxy.buffered") && !shade.contains("activeVideo"),
            "shading follows an element a scrub does not seek: {shade}"
        );

        // The shading describes `main.buffered` even while a held scrub is
        // showing the proxy, and that is correct: the bar is calibrated on
        // main's clock, and the lit part is where *the video* is instant when
        // the thumb is released. It must not follow the picture.
        assert!(
            js_fn(html, "renderCached").contains("range(main)")
                || html.contains("renderCached(r)"),
            "the shading no longer describes main's window"
        );
    }

    /// The scrub preview must locate its frame through wall clock.
    ///
    /// The player and the thumbnail generator share no clock: hls.js zeroes
    /// its timeline at whichever fragment it happened to load first, so the
    /// same position means a different time to two viewers who joined
    /// minutes apart. Looking a cue up by `currentTime` would therefore show
    /// a plausible frame from the wrong moment — wrong by an amount nobody
    /// can see, and different for every viewer.
    #[test]
    fn the_scrub_preview_locates_its_frame_by_wall_clock() {
        let html = include_str!("dvr.html");
        let cue_at = js_fn(html, "cueAt");
        assert!(
            cue_at.contains("wallClockAt("),
            "cue lookup does not go through wall clock: {cue_at}"
        );
        assert!(
            cue_at.contains("thumbs.epoch"),
            "cue lookup ignores the epoch the index declares: {cue_at}"
        );
        // And the wall clock must come from the playlist's own absolute time,
        // not from anything the player invented.
        let wall = js_fn(html, "wallOn");
        assert!(
            wall.contains("programDateTime"),
            "wall clock is not taken from #EXT-X-PROGRAM-DATE-TIME: {wall}"
        );
        assert!(
            js_fn(html, "wallClockAt").contains("wallOn(main"),
            "main's wall clock no longer reads the playlist dates"
        );
    }

    /// A half-understood index must be refused outright.
    ///
    /// The failure mode of accepting one is a preview that shows confidently
    /// wrong pictures rather than no picture, which is worse: an operator
    /// trusts what they see on the way to a cue point.
    #[test]
    fn a_thumbnail_index_that_is_not_understood_yields_no_preview() {
        let f = js_fn(include_str!("dvr.html"), "parseThumbIndex");
        assert!(f.contains("return null"), "{f}");
        assert!(
            f.contains("epoch === null") || f.contains("isNaN(epoch)"),
            "an index with no usable epoch is still accepted: {f}"
        );
        assert!(
            f.contains("!cues.length"),
            "an index with no cues is still accepted: {f}"
        );
    }

    /// A mark is stored against wall clock, never against `currentTime`.
    ///
    /// hls.js zeroes its timeline at whichever fragment it happened to load
    /// first, so a mark recorded against the media clock points somewhere else
    /// after a reload and somewhere else again for a second viewer. Wall clock
    /// is the only thing two sessions agree on, and the only thing that
    /// survives the window rolling underneath it.
    #[test]
    fn a_mark_is_stored_against_wall_clock() {
        let html = include_str!("dvr.html");
        let add = js_fn(html, "addMark");
        assert!(
            add.contains("wallClockAt(t)"),
            "a mark is not recorded against the clock: {add}"
        );
        assert!(
            add.contains("if (wall === null)"),
            "a feed with no clock would store a mark that points nowhere: {add}"
        );
        // And going back to one converts the other way.
        let inv = js_fn(html, "mediaOn");
        assert!(
            inv.contains("f.programDateTime"),
            "the inverse does not go through the playlist clock: {inv}"
        );
        assert!(
            js_fn(html, "mainTimeAtWall").contains("mediaOn(main"),
            "the inverse no longer reads the playlist dates"
        );
        assert!(
            js_fn(html, "goToMark").contains("mainTimeAtWall(m.at)"),
            "going to a mark does not convert from wall clock"
        );
    }

    /// Everything drawn on the bar is inset to the thumb's travel.
    ///
    /// A range thumb's **centre** moves between half a thumb from each end,
    /// not across the full width. A layer drawn edge to edge therefore
    /// disagrees with the playhead by up to half a thumb — worst at the ends,
    /// zero in the middle — and a mark clicked or skipped to did not line up
    /// under the dot. Reported by AJ, and the geometry was already written
    /// down in the shading's own comment when it was built.
    #[test]
    fn the_bar_layers_are_inset_to_the_thumbs_travel() {
        let html = include_str!("dvr.html");
        assert!(html.contains("--thumb: 18px;"), "the thumb size is not named once");

        // Every layer that must agree with the playhead, and the thumb itself,
        // take their geometry from that one value.
        assert_eq!(
            html.matches("left: calc(var(--thumb) / 2); right: calc(var(--thumb) / 2);")
                .count(),
            3,
            "a layer on the bar is still drawn edge to edge"
        );
        assert!(
            html.contains("width: var(--thumb); height: var(--thumb);"),
            "the thumb no longer takes its size from the value the insets assume"
        );

        // And anything measured in script uses the same correction.
        let g = js_fn(html, "barGeom");
        assert!(
            g.contains("r.left + THUMB_PX / 2") && g.contains("r.width - THUMB_PX"),
            "pointer positions are measured against the full width: {g}"
        );
        assert!(
            js_fn(html, "barPct").contains("THUMB_PX / 2 + frac * (w - THUMB_PX)"),
            "the floating labels are placed against the full width"
        );
        // The hover hit-test and the press must both go through it, or a mark
        // is named at one position and acted on at another.
        assert_eq!(
            html.matches("var g = barGeom();").count(),
            2,
            "the hover and the press do not share the same geometry"
        );
    }

    /// Pressing a mark on the bar goes to it exactly, and stops.
    ///
    /// You have hovered it and read its name; a drag that lands *near* it is
    /// not what was asked for. So a press within the hover radius seeks to the
    /// mark and pauses there instead of starting a scrub.
    ///
    /// The subtlety is that a range input sets its value and fires `input`
    /// from that press even when the default is prevented — which would seek
    /// to the mark and then immediately seek again to wherever the pointer
    /// actually was. Close, but not the mark.
    #[test]
    fn pressing_a_mark_on_the_bar_goes_to_it_exactly() {
        let html = include_str!("dvr.html");
        let down = html
            .split(r#"scrub.addEventListener("pointerdown", function (e) {"#)
            .nth(1)
            .expect("no pointerdown handler")
            .split("
  });")
            .next()
            .expect("unterminated pointerdown handler");
        assert!(down.contains("markNear("), "the press does not look for a mark: {down}");
        assert!(down.contains("goToMark(m)"), "a press on a mark does not go to it: {down}");
        assert!(
            down.contains("e.preventDefault()") && down.contains("suppressNextInput = true"),
            "the input the press fires would seek away from the mark again: {down}"
        );
        assert!(
            down.contains("beginScrub();"),
            "a press away from a mark no longer starts a scrub: {down}"
        );
        // The suppression must be cleared two ways. Consuming an `input`
        // clears it — but preventing the default means the press may fire no
        // `input` at all, and the flag then survives to swallow the first
        // event of the next drag. Found by pressing a mark and then dragging
        // elsewhere: the drag did nothing.
        assert!(
            js_fn(html, "applyScrubPosition")
                .contains("if (suppressNextInput) { suppressNextInput = false; return; }"),
            "a consumed input does not clear the suppression"
        );
        assert!(
            down.starts_with("
    // Clear it here")
                || down.contains("suppressNextInput = false;
    // Pressing a mark"),
            "the press does not clear a suppression left over from the last one: {down}"
        );
    }

    /// Skipping to the next mark must not find the one you are sitting on.
    ///
    /// Land exactly on a mark — which is what the previous press just did —
    /// and a naive "first mark after now" finds that same mark, seeks nowhere,
    /// and the button reads as dead. Hence the margin.
    ///
    /// Skips are also bounded by reachability: a mark the window has rolled
    /// past is not a place the transport can go, so it must not be a skip
    /// target either.
    #[test]
    fn skipping_between_marks_steps_off_the_current_one() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "markRelative");
        assert!(
            f.contains("MARK_SKIP_EPS_MS"),
            "no margin, so `next` finds the mark already under the playhead: {f}"
        );
        assert!(
            f.contains("markIsReachable(m)"),
            "a skip could target a mark outside the window: {f}"
        );
        // Both directions come from the same search rather than two copies.
        assert!(
            f.contains("dir > 0 ? m.at > now") && f.contains("dir > 0 ? m.at < best.at"),
            "the two directions are not symmetric: {f}"
        );
        // A skip with nowhere to go is disabled, not inert: nothing happens
        // either way, but only one of them looks broken.
        assert!(
            js_fn(html, "refreshMarkStates").contains("btnNextMark.disabled = !markRelative(1)"),
            "a skip button with no target stays live and appears broken"
        );
    }

    /// Hovering a mark names it, without taking anything from the bar.
    ///
    /// The obvious implementation — pointer events on the flags plus a
    /// `title` — is wrong twice over. The flags sit inside the slider's own
    /// hit box, so a 2 px element that swallows a press costs a drag right
    /// where the operator is aiming; and a native `title` waits a second and
    /// never appears on a touch screen at all, which is the target device.
    #[test]
    fn hovering_a_mark_names_it_without_stealing_the_drag() {
        let html = include_str!("dvr.html");
        assert!(
            html.contains("#markbar { position: absolute")
                && html.contains("pointer-events: none; z-index: 1; }"),
            "the flag layer takes pointer events, so it can swallow a drag"
        );
        // Hit-tested from the slider's own pointer position instead.
        assert!(
            html.contains(r#"scrub.addEventListener("pointermove""#),
            "nothing detects the pointer over a mark"
        );
        let near = js_fn(html, "markNear");
        assert!(
            near.contains("MARK_HOVER_FRAC"),
            "no proximity bound, so the tip would show for any position: {near}"
        );
        // The scrub preview owns this space during a drag.
        assert!(
            html.contains("if (scrubbing) { hideMarkTip(); return; }"),
            "the mark tip fights the scrub preview during a drag"
        );
    }

    /// A mark the window has rolled past must be visibly unreachable.
    ///
    /// Marks outlive the DVR window — they are kept for the session, the
    /// window is minutes or hours. One that can no longer be seeked to has to
    /// say so rather than sit there looking like a button that does nothing.
    #[test]
    fn a_mark_outside_the_window_is_shown_as_unreachable() {
        let html = include_str!("dvr.html");
        assert!(
            js_fn(html, "markIsReachable").contains("t >= r.start && t <= r.end"),
            "nothing decides whether a mark can still be reached"
        );
        let render = js_fn(html, "renderMarks");
        assert!(
            render.contains("at.disabled = !reachable"),
            "an unreachable mark still offers a control that cannot work: {render}"
        );
        assert!(render.contains(r#"li.className = "gone""#), "no visible sign: {render}");

        // And it must be re-decided, not latched. The list is first drawn
        // before hls.js has a playlist, so every mark looks unreachable at
        // that moment; computed once, a freshly reloaded player had every mark
        // disabled until something else redrew the list. It also changes on
        // its own as the window rolls past a mark.
        assert!(
            js_fn(html, "render()").contains("refreshMarkStates()"),
            "reachability is decided once, when it cannot yet be known"
        );
        assert!(
            js_fn(html, "refreshMarkStates").contains("markIsReachable(marks[i])"),
            "the refresh does not actually re-decide"
        );
        assert!(
            js_fn(html, "goToMark").contains("t < r.start || t > r.end"),
            "goToMark would seek outside the window"
        );
    }

    /// Enter in a mark's name closes the drawer.
    ///
    /// The name is saved on every keystroke, so Enter is not a commit — it is
    /// "done, give me the picture back". Without it the drawer covers a third
    /// of the screen until the operator finds the close button, right after
    /// they have marked something they wanted to watch.
    #[test]
    fn enter_in_a_mark_name_closes_the_drawer() {
        let render = js_fn(include_str!("dvr.html"), "renderMarks");
        assert!(
            render.contains(r#"if (e.key !== "Enter") return;"#),
            "Enter is not handled in the name field: {render}"
        );
        assert!(
            render.contains("closeDrawer();"),
            "Enter does not close the drawer: {render}"
        );
        assert!(
            render.contains("e.preventDefault();"),
            "Enter would submit or scroll as well as close: {render}"
        );
    }

    /// The preview is prefetched, without racing the media.
    ///
    /// Fetched only on demand, a sheet lands after the thumb has passed it, so
    /// the first drag across any stretch of bar shows nothing. Pulling them in
    /// the background fixes that everywhere.
    ///
    /// The constraint is that this helps most on exactly the connections it
    /// could hurt. So: one at a time, with a gap, never while the operator is
    /// dragging (their fetches have a deadline), and not until playback has
    /// started so it never competes with the buffering that decides whether
    /// there is a picture at all.
    #[test]
    fn the_preview_is_prefetched_without_racing_the_media() {
        let html = include_str!("dvr.html");
        let step = js_fn(html, "prefetchStep");
        assert!(
            step.contains("if (!scrubbing)"),
            "prefetching competes with the drag it exists to serve: {step}"
        );
        assert!(
            step.contains("setTimeout(prefetchStep, PREFETCH_GAP_MS)"),
            "prefetching is not paced: {step}"
        );
        let start = js_fn(html, "startPrefetch");
        assert!(
            start.contains("PREFETCH_START_DELAY_MS"),
            "prefetching starts against the initial buffering: {start}"
        );
        assert!(
            html.contains(r#"main.addEventListener("playing", startPrefetch)"#),
            "prefetching does not wait for a picture"
        );
        // Nearest-first, so the ordering pays off before the sweep finishes.
        assert!(
            js_fn(html, "nextSheetToPrefetch").contains("Math.abs(at - here)"),
            "sheets are not fetched nearest-first"
        );
    }

    /// The sheet cache is bounded by bytes and evicts least-recently-used.
    ///
    /// A count is a guess about sheet size, and the twenty-slot version could
    /// be evicted end to end by a single drag — which is worse than useless
    /// once anything is prefetched into it. Bytes degrade sensibly instead:
    /// the whole window for a 2h30m event fits, and a longer one keeps what
    /// was used most recently.
    #[test]
    fn the_sheet_cache_is_bounded_by_bytes_and_evicts_lru() {
        let html = include_str!("dvr.html");
        assert!(html.contains("SHEET_CACHE_BYTES"), "the cache is still bounded by count");
        assert!(!html.contains("SHEET_CACHE = 20"), "the old count bound is still there");
        let trim = js_fn(html, "trimSheets");
        assert!(
            trim.contains("sheetBytes > SHEET_CACHE_BYTES") && trim.contains("sheetOrder.shift()"),
            "the trim does not drop the oldest by byte budget: {trim}"
        );
        assert!(
            trim.contains("URL.revokeObjectURL"),
            "evicted sheets leak their object URLs: {trim}"
        );
        // Used means recently used, or the LRU is really a FIFO.
        assert!(
            js_fn(html, "sheetUrl").contains("touchSheet(uri)"),
            "a cache hit does not count as use, so the LRU is a FIFO"
        );
    }

    /// The picture ladder is three distinct points, not three sizes.
    ///
    /// `balanced` is the one worth having: the moving picture comes from the
    /// proxy and the *stopped* picture from the main rendition, fetched on
    /// demand. Resolution matters most when someone has stopped to look, and
    /// that is exactly when a fetch is affordable — one segment when you stop
    /// instead of a megabyte a second forever.
    ///
    /// The default stays `full`. A quieter default would silently soften the
    /// picture for viewers who never asked; the ladder exists for links that
    /// need it.
    #[test]
    fn the_picture_ladder_has_three_distinct_modes() {
        let html = include_str!("dvr.html");
        assert!(html.contains(r#"var quality = "full";"#), "the default is no longer full");
        assert!(
            html.contains(r#"var lowRes = quality !== "full";"#),
            "balanced does not take its moving picture from the proxy"
        );
        assert!(
            html.contains(r#"var wantHiresStills = quality === "balanced";"#),
            "balanced does not fetch a full-resolution still"
        );
        // The boolean this replaced must still be honoured for anyone who set it.
        assert!(
            html.contains(r#"window.localStorage.getItem(LOWRES_KEY) === "1"#),
            "an existing low-res preference is dropped on upgrade"
        );
    }

    /// The still never blanks the picture to fetch a better one.
    ///
    /// On the links `balanced` is for, that fetch takes seconds. Swapping the
    /// element before it holds the frame would replace a soft picture with no
    /// picture, which is a worse answer than the one it replaced.
    #[test]
    fn a_full_resolution_still_never_blanks_the_picture() {
        let html = include_str!("dvr.html");
        let ready = js_fn(html, "stillReady");
        assert!(
            ready.contains("proxy.readyState < 2 || proxy.seeking"),
            "the still is shown before it has decoded anything: {ready}"
        );
        assert!(
            ready.contains("Math.abs(at - stillWantAt) > 0.5"),
            "a seek that landed elsewhere would be shown as this frame: {ready}"
        );
        // And it settles first: frame-stepping must not fetch a segment a step.
        let upd = js_fn(html, "updateStill");
        assert!(
            upd.contains("STILL_SETTLE_MS"),
            "every frame step would fetch a full-resolution segment"
        );
        // A settle timer that is restarted faster than it can expire never
        // fires. `render` calls this at 5 Hz and the settle is 220 ms, so
        // clearing unconditionally meant the still was never once requested —
        // which is what the rig showed, with no error anywhere.
        //
        // The property, not the comparison. This named the 50 ms tolerance the
        // guard happened to use, and that tolerance turned out to be wider
        // than a frame — so it also pinned the bug where only every second
        // frame step reached the still.
        assert!(
            upd.contains("sameFrame(t, stillPendingAt)) return;"),
            "the settle timer is restarted on every tick and can never fire: {upd}"
        );
        // Moving again drops it.
        assert!(
            js_fn(html, "stillWanted").contains("!scrubbing && mode !== \"shuttle\" && main.paused"),
            "the still would persist over a moving picture"
        );
    }

    /// The still is not positioned until the two clocks have been related.
    ///
    /// The elements hold two different streams and hls.js zeroes each
    /// timeline at whichever fragment it loaded first, so the offset between
    /// them is arbitrary and must be measured. Positioned on an unmeasured
    /// offset, the hi-res still lands somewhere else entirely — the same
    /// handover bug the scrub path was already guarded against, repeated in
    /// the new path and reported by AJ.
    ///
    /// Nothing downstream can catch it. The seek and the check that verifies
    /// it both convert through the same offset, so they agree with each other
    /// while both are wrong. The guard has to be before the seek.
    #[test]
    fn the_still_waits_for_the_two_clocks_to_be_related() {
        let html = include_str!("dvr.html");
        let upd = js_fn(html, "updateStill");
        assert!(
            upd.contains("offsetSamples.length < STILL_MIN_OFFSET_SAMPLES"),
            "the still is positioned on an unmeasured offset: {upd}"
        );
        // Enough samples for a median, not the single one a moving handover
        // can live with.
        assert!(
            html.contains("var STILL_MIN_OFFSET_SAMPLES = 5;"),
            "one sample of a sawtoothing signal is treated as a measurement"
        );
        // And the sampling has to actually run in this mode. It was gated on
        // `proxyAttached`, which balanced never sets, so the offset stayed 0.
        assert!(
            html.contains("if (proxyAttached || stillAttached) measureTimelineOffset();"),
            "the offset is not sampled while a still is attached"
        );
        // A median that improves after the fact must move the still with it.
        assert!(
            upd.contains("Math.abs(timelineOffset - stillOffsetUsed) > 0.08"),
            "a still placed on an early estimate is left there: {upd}"
        );
        // But it must stop chasing once the conversion is exact. The offset
        // now tracks the playlists, and those move ~50 ms every refresh
        // (edge#139) — a still that follows that re-seeks several times a
        // minute and refetches 2 MB each time, which on the links Balanced
        // exists for is a still that never settles.
        assert!(
            upd.contains("var nowExact = pdtLinked();")
                && upd.contains("stillOffsetUsed = nowExact ? null : timelineOffset;"),
            "the still keeps chasing an offset that is no longer an estimate: {upd}"
        );
        // That whole apparatus is the fallback. Where the playlists carry
        // dates the conversion is exact and there is no estimate to revise,
        // so the wait and the correction must be skipped rather than left to
        // chase a number the still no longer depends on.
        assert!(
            upd.contains("var exact = pdtLinked();") && upd.contains("if (!exact) {"),
            "an exactly-placed still is still made to wait for the median: {upd}"
        );
        assert!(
            upd.contains("stillOffsetUsed = exact ? null : timelineOffset;"),
            "an exactly-placed still records an offset it did not use: {upd}"
        );
    }

    /// Nothing asks "has a sample been taken" when it means "are the clocks
    /// related".
    ///
    /// The sampler stands down while the playlists relate the two renditions
    /// exactly, so `offsetSamples` stays empty for the whole session on a
    /// dated feed. `handPictureToProxy` gated on `offsetSamples.length` and
    /// therefore never handed the picture over at all: a held scrub ran on the
    /// 1920p main rendition, which this player measures at 6-8 fps on the
    /// target tablet against 18-19 on the proxy. That is what AJ reported as
    /// full-mode scrubbing being badly skewed "when working at all", and as
    /// the proxy not being used.
    ///
    /// It is the same mistake as the still chasing the offset, in the same
    /// change: altering what a variable means without auditing its readers.
    #[test]
    fn the_handover_asks_whether_the_clocks_are_related() {
        let html = include_str!("dvr.html");
        let hand = js_fn(html, "handPictureToProxy");
        assert!(
            hand.contains("if (!clocksRelated()) return;"),
            "the handover still gates on a sample count: {hand}"
        );
        assert!(
            !hand.contains("offsetSamples"),
            "the handover reads the sampler directly: {hand}"
        );
        // And the helper must admit both routes, or it is the old gate under
        // a better name.
        let rel = js_fn(html, "clocksRelated");
        assert!(
            rel.contains("pdtLinked()") && rel.contains("offsetSamples.length"),
            "clocksRelated does not cover both routes: {rel}"
        );
        // Priming has to work from whichever direction converts first: the
        // handover converts main->proxy, and if only the other direction
        // primed, the fallback would still be sitting at its initial zero.
        assert!(
            js_fn(html, "fromMainTime").contains("timelineOffset = p - t;"),
            "the main-to-proxy direction never primes the fallback"
        );
    }

    /// The two conversions never disagree with each other.
    ///
    /// `toMainTime` prefers the playlists' dates and falls back to
    /// `timelineOffset`. Those are different measurements — one relates the
    /// renditions by content, the other by the distance between two live
    /// edges — and on the demo rig they differed by 26 s. They are used
    /// interchangeably, because `fragsFor` goes null for a beat whenever
    /// hls.js swaps a level's details, which it does on every playlist
    /// refresh. Left independent, the picture is thrown 26 s and back again
    /// several times a minute: a skew that comes and goes, which is what AJ
    /// reported of full-mode scrubbing.
    ///
    /// So the fallback is *derived* from the exact answer rather than
    /// measured alongside it, and the sampler stands down while the exact
    /// link holds — otherwise it would overwrite the derived value with the
    /// live-edge difference every 200 ms and put the disagreement straight
    /// back.
    #[test]
    fn the_fallback_offset_tracks_the_exact_conversion() {
        let html = include_str!("dvr.html");
        let to = js_fn(html, "toMainTime");
        assert!(
            to.contains("timelineOffset = t - m;"),
            "the fallback is left as an independent estimate: {to}"
        );
        let measure = js_fn(html, "measureTimelineOffset");
        assert!(
            measure.contains("if (pdtLinked()) return;"),
            "the sampler still overwrites the derived offset: {measure}"
        );
        // And the derivation must be guarded, or one non-finite conversion
        // poisons the fallback for every later beat that needs it.
        assert!(
            to.contains("isFinite(m)"),
            "a non-finite conversion is written into the fallback: {to}"
        );
    }

    /// A frame step moves the still by a frame.
    ///
    /// "Already showing this frame" was a 50 ms window, and a frame at 25 fps
    /// is 40 ms — so a single step fell inside it and was discarded, and only
    /// every *second* step reached the still. Measured on the rig: the hi-res
    /// picture advanced 0.08 s at a time while the transport advanced 0.04 s,
    /// the steps in between timing out having changed nothing. AJ reported it
    /// as a one-to-two-second lag on stepping.
    ///
    /// A tolerance in seconds cannot express this question at all — any value
    /// wide enough to absorb conversion noise is wider than a frame. So ask
    /// the question directly, by frame index.
    #[test]
    fn a_frame_step_moves_the_still_by_a_frame() {
        let html = include_str!("dvr.html");
        let upd = js_fn(html, "updateStill");
        assert!(
            upd.contains("sameFrame(t, stillWantAt)") && upd.contains("sameFrame(t, stillPendingAt)"),
            "the still still decides sameness with a tolerance in seconds: {upd}"
        );
        assert!(
            !upd.contains("< 0.05"),
            "a seconds tolerance survives somewhere in the still path: {upd}"
        );
        assert!(
            js_fn(html, "sameFrame").contains("frameIndexAt(a) === frameIndexAt(b)"),
            "sameFrame is not asking about frames"
        );
    }

    /// A step to a frame already in hand does not wait out the settle.
    ///
    /// The settle exists so that a run of steps does not fetch a 2 MB segment
    /// each time. When the position is already buffered there is no fetch to
    /// avoid, and the wait is pure added latency on the common case —
    /// stepping within a segment, all of which is buffered as soon as the
    /// first still in it lands.
    #[test]
    fn a_buffered_step_skips_the_settle() {
        let html = include_str!("dvr.html");
        let upd = js_fn(html, "updateStill");
        assert!(
            upd.contains("var held = stillHolds(t);")
                && upd.contains("var settle = held ? 0 : STILL_SETTLE_MS;")
                && upd.contains("}, settle);"),
            "every step waits out the settle whether or not it needs to: {upd}"
        );
        // And the buffered test has to be about the *still* element, at the
        // converted position — asking main would answer a different question.
        let holds = js_fn(html, "stillHolds");
        assert!(
            holds.contains("fromMainTime(mainT, proxy)") && holds.contains("proxy.buffered"),
            "stillHolds does not ask the still element about its own clock: {holds}"
        );
        // A position on the very edge of a buffered range is not reliably
        // decodable from it, so the range is inset by a frame at each end.
        assert!(
            holds.contains("+ 1 / FPS") && holds.contains("- 1 / FPS"),
            "a boundary position counts as held: {holds}"
        );
        // And it must not ask `readyState`. That drops below 2 while a seek
        // settles — most of the time during a run of frame steps — so the
        // player concluded it did not hold data it did, woke the loader, and
        // paid ~1 s per step to re-establish while fetching zero bytes.
        // Match the expression, not the word: the comment above it in the
        // source explains the trap by name, and a bare `contains("readyState")`
        // fired on that instead of on any code.
        assert!(
            !holds.contains("proxy.readyState <"),
            "holding data is confused with being ready this instant: {holds}"
        );
    }

    /// The still lands on a frame, not between two.
    ///
    /// A position taken off one rendition is a frame boundary on that
    /// rendition and almost never one on the other, and a seek to a boundary
    /// may present either side of it — the ambiguity `frameCentre` already
    /// existed for on the jog path. Measured on the rig at full window depth:
    /// the still sat **+0.08 s, two frames, late** at every position tried,
    /// while the player's own clocks agreed to within 40 ms. So the seek was
    /// landing exactly where it was aimed and the *aim* was between frames.
    ///
    /// Only the still asks for the snap. On a moving picture it buys nothing,
    /// and a scrub handover that quantised every position would be doing
    /// arithmetic no one can see the benefit of.
    #[test]
    fn the_still_lands_on_a_frame_rather_than_between_two() {
        let html = include_str!("dvr.html");
        let seek = js_fn(html, "seekWhenReady");
        assert!(
            seek.contains("if (snap) t = frameCentre(frameIndexAt(t));"),
            "the seek does not snap to a frame at all: {seek}"
        );
        // A deferred seek has to carry the request, or the first still after
        // an attach — the one case the deferral exists for — skips it.
        assert!(
            seek.contains("snap: !!snapToFrame") && seek.contains("pendingSeek.snap"),
            "a deferred seek forgets whether it was asked to snap: {seek}"
        );
        let upd = js_fn(html, "updateStill");
        assert_eq!(
            upd.matches("seekWhenReady(proxy, ").count(),
            upd.matches(", true);").count(),
            "a still seek was left without the snap: {upd}"
        );
        // And the scrub handover must NOT snap.
        assert!(
            js_fn(html, "setMode").contains("seekWhenReady(to, toMainTime(t, from));"),
            "the moving handover quantises positions for no benefit"
        );
    }

    /// The two renditions are related by the clock they both publish, not by
    /// the difference between their live edges.
    ///
    /// `timelineOffset` is a median of `proxy.end - main.end`. Each end is
    /// quantised to its own segment grid, so the raw signal sawtooths and the
    /// median leaves a residual of a fair fraction of a segment. Behind a
    /// moving picture that residual is invisible — which is why scrub handover
    /// never showed it — but the balanced-mode still is *looked at*, and AJ
    /// reported exactly that: the hi-res frame arriving on a different moment
    /// than the low-res frame it replaced.
    ///
    /// Both playlists carry `#EXT-X-PROGRAM-DATE-TIME`, which relates them
    /// exactly and needs no measurement at all. The offset stays only for a
    /// feed that publishes no dates.
    #[test]
    fn the_two_renditions_are_related_by_their_published_clock() {
        let html = include_str!("dvr.html");
        for name in ["toMainTime", "fromMainTime"] {
            let f = js_fn(html, name);
            assert!(
                f.contains("wallOn(") && f.contains("mediaOn("),
                "{name} converts without consulting the playlist dates: {f}"
            );
            // The offset is the fallback, so it must come *after* the exact
            // path rather than instead of it.
            let exact = f.find("mediaOn(").expect("no exact path");
            let approx = f.find("timelineOffset").expect("no fallback");
            assert!(
                exact < approx,
                "{name} reaches for the median before the exact clock: {f}"
            );
        }
        // The date is read off the fragment that covers the position. Summing
        // `EXTINF` from the head of a three-hour window accumulates the
        // rounding in every one of several thousand durations.
        let w = js_fn(html, "wallOn");
        assert!(
            w.contains("fragAt(frags, t)"),
            "the clock is anchored on the head of the playlist: {w}"
        );
        // And a feed with no dates must fall through rather than convert
        // through a date that is not there.
        assert!(
            js_fn(html, "fragsFor")
                .contains(r#"typeof frags[0].programDateTime !== "number""#),
            "a dateless playlist is treated as having a clock"
        );
    }

    /// A softened picture says so.
    ///
    /// This player has produced "degraded but invisible" more than once — a
    /// preview box that painted black, buttons that did nothing, a ruler that
    /// stood still. A quieter picture with nothing to explain it is the same
    /// shape, and becomes a support call.
    #[test]
    fn a_reduced_picture_is_labelled() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "syncQualityBadge");
        assert!(
            f.contains(r#"if (quality === "full")"#),
            "the badge shows even when nothing is reduced: {f}"
        );
        assert!(
            f.contains(r#"hd ? "HD" : "LOW""#),
            "the badge does not distinguish a full-resolution still: {f}"
        );
        assert!(
            js_fn(html, "syncPicture").contains("syncQualityBadge()"),
            "the badge is not refreshed when the picture changes"
        );
    }

    /// Low-res mode replaces the main rendition rather than adding to it.
    ///
    /// The point is a link that cannot carry the main stream, so attaching
    /// both would defeat it. Playing the proxy *as* main also means one
    /// decoder instead of two, which is the other thing a struggling device
    /// does not have to spare — and costs nothing, because that rendition is
    /// already all-intra, so shuttle and scrub work on it directly.
    ///
    /// Everything downstream is expressed against whatever `main` is loading,
    /// which is why this is a URL swap and not a rewrite.
    #[test]
    fn low_res_mode_replaces_the_main_rendition() {
        let html = include_str!("dvr.html");
        assert!(
            html.contains("if (lowRes) MAIN = PROXY;"),
            "low-res mode does not swap the stream, so it saves no bandwidth"
        );
        assert!(
            js_fn(html, "ensureProxy").contains("if (lowRes) return;"),
            "the second element still attaches, fetching the same stream twice"
        );
        assert!(
            js_fn(html, "activeVideo").contains("if (lowRes) return main;"),
            "shuttle would hand over to an element that was never attached"
        );
    }

    /// A mark's colour comes from a closed palette, and is validated.
    ///
    /// The colour is written into an inline `style`, and marks are read from
    /// `localStorage`, which anything on the device can write. Accepting the
    /// stored string would let it carry a declaration of its own choosing
    /// into the page. Membership of the list is the whole check.
    #[test]
    fn a_mark_colour_must_be_one_of_the_palette() {
        let html = include_str!("dvr.html");
        let load = js_fn(html, "loadMarks");
        assert!(
            load.contains("if (!isMarkColour(m.colour)) m.colour = MARK_COLOUR_DEFAULT;"),
            "a stored colour is trusted as read: {load}"
        );
        let set = js_fn(html, "recolourMark");
        assert!(
            set.contains("if (!isMarkColour(css)) return;"),
            "a colour can be set to something off the palette: {set}"
        );
        // Red by default, as the flags have always been.
        assert!(
            html.contains(r#"var MARK_COLOUR_DEFAULT = MARK_COLOURS[0].css;"#)
                && html.contains(r##"{ name: "Red",    css: "#ff4d4f" }"##),
            "the default is no longer the red the bar used"
        );
        assert!(
            js_fn(html, "addMark").contains("colour: MARK_COLOUR_DEFAULT"),
            "a new mark has no colour"
        );
        // The flag carries it through a custom property: a pseudo-element
        // draws the pennant and cannot take an inline style.
        assert!(
            js_fn(html, "renderFlags").contains(r#"el.style.setProperty("--c""#),
            "the flag does not take the mark's colour"
        );
        assert!(
            html.contains("border-top: 5px solid var(--c, var(--live));"),
            "the pennant ignores the colour the flag was given"
        );
    }

    /// A stored list that does not parse must not take the player down.
    ///
    /// It is `localStorage` — a previous version, another tab, or someone with
    /// devtools open can have left anything there.
    #[test]
    fn a_corrupt_marks_store_is_survived() {
        let f = js_fn(include_str!("dvr.html"), "loadMarks");
        assert!(f.contains("try {") && f.contains("catch"), "no guard on the read: {f}");
        assert!(
            f.contains("Array.isArray(marks)"),
            "a stored value that is not a list would be iterated: {f}"
        );
        assert!(
            f.contains("typeof m.at === \"number\"") && f.contains("isFinite(m.at)"),
            "an entry with no usable time survives and renders at NaN%: {f}"
        );
    }

    /// Play means forward at full speed, whatever the transport was doing.
    ///
    /// It used to preserve the rate, so pressing play during a 4x fast-forward
    /// gave 4x *playback* and during a 33% review gave 33%. The operator asks
    /// for normal speed and gets something else, with no obvious way back
    /// except finding the 100% button.
    #[test]
    fn play_restores_forward_full_speed() {
        let html = include_str!("dvr.html");
        let handler = html
            .split(r#"btnPlay.addEventListener("click", function () {"#)
            .nth(1)
            .expect("no play handler")
            .split("
  });")
            .next()
            .expect("unterminated play handler");
        assert!(
            handler.contains("setRate(1);"),
            "play does not restore full speed: {handler}"
        );
        assert!(
            !handler.contains("rate > 0 ? rate"),
            "play still carries the previous rate forward: {handler}"
        );
        assert!(
            handler.contains("stopShuttle()"),
            "play does not stop a shuttle, so the loop would fight it: {handler}"
        );
    }

    /// The full-screen button is removed where it could not work.
    ///
    /// iOS Safari fullscreens a `<video>` and nothing else, which would take
    /// the transport with it — the one control an operator needs most. A
    /// button that does nothing when pressed is worse than no button.
    #[test]
    fn the_fullscreen_button_is_removed_where_it_cannot_work() {
        let html = include_str!("dvr.html");
        assert!(html.contains(r#"id="btnFull""#), "no full-screen control");
        assert!(
            html.contains("btnFull.remove()"),
            "an unsupported browser is left with a dead button"
        );
        // Prefixed calls for Safari, on both the enter and exit paths.
        let t = js_fn(html, "toggleFullscreen");
        assert!(
            t.contains("webkitRequestFullscreen") && t.contains("webkitExitFullscreen"),
            "only the unprefixed API is used: {t}"
        );
    }

    /// MARK is one corner with two jobs, and the tap must survive the hold.
    ///
    /// An operator presses MARK expecting to mark; finding the list is
    /// something they do deliberately. So a press that becomes a hold must
    /// spend the tap rather than doing both, a press that wanders off the
    /// button must do neither, and the hold has to show something before it
    /// fires or it reads as nothing having happened.
    #[test]
    fn mark_taps_and_holds_are_told_apart() {
        let html = include_str!("dvr.html");
        assert!(html.contains("MARK_HOLD_MS"), "no hold threshold");
        // A tap marks and nothing else. Throwing the drawer over a third of
        // the picture to ask for a name is the wrong moment — the operator is
        // usually still watching the thing they just marked.
        let add = js_fn(html, "addMark");
        assert!(
            !add.contains("openDrawer()"),
            "marking still opens the list, so a tap covers the picture: {add}"
        );
        assert!(
            js_fn(html, "openDrawer").contains("lastMarkId"),
            "opening the list after a mark does not offer it for naming"
        );
        assert!(
            html.contains("markHeld = true;      // the tap is now spent"),
            "a hold would also mark when the finger lifts"
        );
        assert!(
            html.contains(r#"btnMark.classList.add("holding")"#),
            "the hold gives no feedback before it fires"
        );
        // Leaving or cancelling must not mark.
        assert!(
            html.contains(r#"btnMark.addEventListener("pointercancel""#)
                && html.contains(r#"btnMark.addEventListener("pointerleave""#),
            "a press dragged off the button still marks"
        );
        // Keyboard activation has no pointer events at all.
        assert!(
            html.contains("if (e.detail === 0) addMark();"),
            "MARK cannot be operated from the keyboard"
        );
    }

    /// The zoom slider is geometric, and its top means "the whole window".
    ///
    /// A linear scale spends most of its travel between an hour and half an
    /// hour — the same picture — and crams everything an operator hunts at
    /// into the last few millimetres. And the top position must mean "whatever
    /// the window becomes", not the number it happened to be when released, or
    /// the view stops keeping up as the window grows.
    #[test]
    fn the_zoom_slider_is_geometric_and_its_top_is_the_whole_window() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "zoomFromSlider");
        assert!(
            f.contains("if (pos <= 0) return 0;"),
            "the top of the slider pins a number instead of tracking the window: {f}"
        );
        assert!(
            f.contains("Math.pow(ZOOM_MIN_SECS / span, frac)"),
            "the scale is not geometric: {f}"
        );
        assert!(
            js_fn(html, "applyZoom").contains("viewAnchor = null;"),
            "changing zoom leaves the view pinned where it was"
        );
        // The old preset buttons are gone, not merely hidden.
        assert!(!html.contains("data-zoom="), "the VIEW preset buttons are still present");
    }

    /// The bar spans the view; live is still measured against the whole window.
    ///
    /// Zooming trades reach for granularity — at 30 s across a 1000-step bar a
    /// step is ~30 ms, under a frame, where a 2h30m window is 9 s a step and a
    /// cue point cannot be found by dragging at all.
    ///
    /// The distinction that must not blur: `viewRange()` is what the bar
    /// covers, `range(main)` is what exists. Everything about live — how far
    /// behind, whether to snap, the badge — reads the whole window. Measure
    /// "behind live" against the view instead and zooming in would report the
    /// viewer as closer to live than they are, which is exactly the number an
    /// operator would act on.
    #[test]
    fn the_bar_spans_the_view_but_live_is_measured_against_the_whole_window() {
        let html = include_str!("dvr.html");
        let render = js_fn(html, "render()");
        assert!(
            render.contains("viewRange()"),
            "the bar does not follow the view: {render}"
        );
        // Assert on the specific readouts, not merely that the phrase occurs
        // somewhere in `render` — the first version of this test passed with
        // `tDur` broken because `updateLiveState` on another line satisfied it.
        assert!(
            render.contains(r#"tDur.textContent = "-" + fmt(Math.max(0, r.end - pos))"#),
            "`behind live` no longer measures against the whole window: {render}"
        );
        assert!(
            render.contains("updateLiveState(r.end - pos)"),
            "the live badge is being decided from the visible span"
        );

        // The drag maps the bar onto the view.
        let apply = js_fn(html, "applyScrubPosition");
        assert!(
            apply.contains("var r = viewRange();"),
            "a drag still maps onto the whole window while the bar shows a slice: {apply}"
        );
        assert!(
            html.contains(r#"scrub.addEventListener("input", applyScrubPosition)"#),
            "the bar is no longer wired to the shared position handler"
        );
    }

    /// The view must hold still while the thumb is held.
    ///
    /// A view that re-centres on the playhead mid-drag slides the bar under
    /// the finger: the operator drags right, the window follows, and the thumb
    /// snaps back to the middle having apparently moved nowhere. Pin it on
    /// pointerdown, release it on pointerup.
    #[test]
    fn the_view_is_pinned_for_the_duration_of_a_drag() {
        let html = include_str!("dvr.html");
        assert!(
            js_fn(html, "beginScrub").contains("viewAnchor ="),
            "the view is not pinned when the drag starts"
        );
        assert!(
            js_fn(html, "endScrub").contains("viewAnchor = null"),
            "the view stays pinned after the drag, so it stops following the playhead"
        );
    }

    /// The ruler is pinned to absolute time, which is what makes it move.
    ///
    /// Marks at round clock times drift left on their own as the view follows
    /// the playhead — the motion *is* the passage of time, and it stops when
    /// the transport does. Spacing them evenly across the visible span
    /// instead would produce marks that never move, which is decoration
    /// pretending to be information.
    ///
    /// It needs its own frame loop: `render` runs at 5 Hz, fine for a readout
    /// and visibly steppy for something in motion.
    #[test]
    fn the_ruler_is_pinned_to_absolute_time_and_runs_at_frame_rate() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "renderTicks");
        // Assert the value is *derived* from the clock, not merely that the
        // call appears: the first version of this test passed with `base`
        // hard-wired to 0, because the line above it still read the clock.
        assert!(
            f.contains("w0 === null ? view.start : w0 / 1000"),
            "marks are not anchored to the clock, so they would never move: {f}"
        );
        assert!(
            f.contains("Math.ceil(base / step) * step"),
            "marks do not land on round times: {f}"
        );

        // At least three labelled marks at every zoom: a ruler showing one
        // time is a caption, not a ruler. Check the rule that guarantees it,
        // and that every label/minor pairing it can pick divides cleanly so a
        // minor mark never lands just beside a labelled one.
        let steps = js_fn(html, "rulerSteps");
        assert!(
            steps.contains("span / TICK_STEPS[i] >= 3"),
            "nothing guarantees three labels across the bar: {steps}"
        );
        for (span, want_min_labels) in [(30.0, 3), (120.0, 3), (600.0, 3), (9000.0, 3)] {
            // Mirror the rule the page applies.
            let ladder = [
                1.0, 2.0, 5.0, 10.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0, 1800.0, 3600.0,
            ];
            let label = ladder
                .iter()
                .filter(|s| span / **s >= 3.0)
                .cloned()
                .fold(ladder[0], f64::max);
            let minor = ladder
                .iter()
                .filter(|s| **s <= label / 3.0)
                .cloned()
                .fold(ladder[0], f64::max);
            assert!(
                (span / label) as i32 >= want_min_labels,
                "a {span}s span yields only {} labels", (span / label) as i32
            );
            assert!(
                (label / minor).fract().abs() < 1e-9,
                "a {span}s span divides {label} by {minor}, which does not go evenly"
            );
        }
        // And that the loop is *started*. `tickLoop` re-arms itself, so the
        // call appears inside its own body and proves nothing on its own.
        assert!(
            html.contains("setInterval(render, 200);
  requestAnimationFrame(tickLoop);"),
            "the ruler loop is never started, so it only moves at render's 5 Hz"
        );
        // Redrawing every frame regardless would write to the DOM 60 times a
        // second for a picture that has not changed.
        assert!(
            f.contains("lastTickKey"),
            "the ruler redraws even when nothing has moved: {f}"
        );
    }

    /// The view is clamped to a live edge that moves continuously.
    ///
    /// The playlist end only advances when a segment lands, so clamping the
    /// view to it made the ruler stand still and then leap. Measured while
    /// following a single label: still for 77 of 79 frames, then a 6.649 %
    /// jump — the 2 s segment duration on a 30 s span, exactly.
    ///
    /// The smoothed value is for the *view* only. "How far behind live" must
    /// keep reading the real end, or the figure would lag by a segment.
    #[test]
    fn the_view_is_clamped_to_a_live_edge_that_moves_continuously() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "smoothWindowEnd");
        assert!(
            f.contains("liveSmooth += Math.max(0, now - liveSmoothAt)"),
            "the edge does not advance with real time: {f}"
        );
        assert!(
            f.contains("if (liveSmooth > full.end) liveSmooth = full.end"),
            "the smoothed edge can run past media that does not exist: {f}"
        );
        assert!(
            f.contains("lag > 10"),
            "a seek or restart would be crawled across at 1x: {f}"
        );

        // The view uses it — on *both* paths. The whole-window branch returns
        // early, and that early return is how ALL/30m/10m went on jumping
        // after the zoomed cases were smoothed.
        let vr = js_fn(html, "viewRange");
        assert_eq!(
            vr.matches("smoothWindowEnd(full)").count(),
            2,
            "only one of the two view paths uses the smoothed edge: {vr}"
        );
        let render = js_fn(html, "render()");
        assert!(
            render.contains(r#"tDur.textContent = "-" + fmt(Math.max(0, r.end - pos))"#),
            "`behind live` is reading the smoothed edge and would lag a segment"
        );
    }

    /// A zoomed view scrolls when the thumb is held near an end.
    ///
    /// Zoomed in, the bar reaches only as far as the visible span. Without
    /// this, holding the thumb at the end simply stops, and the operator has
    /// to release and drag again — clumsy with a thumb, and exactly the moment
    /// they are hunting for a cue point. Reported by AJ against the first
    /// version, which had this limitation.
    ///
    /// It must be driven by its own loop, not by `input`: a thumb held still
    /// at the edge fires no further events, so an implementation that panned
    /// only on movement would scroll one step and stall.
    #[test]
    fn a_zoomed_view_scrolls_when_the_thumb_is_held_near_an_end() {
        let html = include_str!("dvr.html");
        let pan = js_fn(html, "panStep");
        assert!(pan.contains("PAN_EDGE"), "nothing defines an edge zone: {pan}");
        assert!(
            pan.contains("requestAnimationFrame(panStep)"),
            "panning is not self-driving, so a stationary thumb stalls it: {pan}"
        );
        assert!(
            pan.contains("applyScrubPosition()"),
            "the view scrolls without moving the transport under the thumb: {pan}"
        );
        // Clamped, or the far ends stop being reachable.
        assert!(
            pan.contains("full.start + half") && pan.contains("full.end - half"),
            "the pan is not clamped to the window: {pan}"
        );
        // And it must stop when the drag does.
        assert!(
            js_fn(html, "endScrub").contains("cancelAnimationFrame(panRAF)"),
            "the pan loop outlives the drag"
        );
    }

    /// The left readout is a time of day, and it comes from the playlist.
    ///
    /// "What time was that?" is the question an operator asks of a DVR, and
    /// elapsed-since-the-window-started does not answer it. The only clock
    /// available is `#EXT-X-PROGRAM-DATE-TIME`; hls.js zeroes its own timeline
    /// at whichever fragment it loaded first, so `currentTime` means a
    /// different moment to two viewers who joined minutes apart.
    ///
    /// It must fall back rather than invent one. Native HLS exposes no
    /// playlist, and a stream published without the tag has no wall clock at
    /// all — showing a confident but wrong time of day would be worse than
    /// showing elapsed.
    #[test]
    fn the_left_readout_is_a_time_of_day_taken_from_the_playlist_clock() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "fmtTimeOfDay");
        assert!(
            f.contains("getHours") && f.contains("getMinutes"),
            "the readout is not a time of day: {f}"
        );
        // Frames, not milliseconds: this is a timecode an operator reads out.
        assert!(f.contains("FPS"), "no frame field on the timecode: {f}");
        // A rounding artefact must never print frame == FPS.
        assert!(
            f.contains("ff >= FPS"),
            "the frame field can overflow to :{{FPS}}: {f}"
        );

        // Every place the position is shown must go through the same clock,
        // and every one must fall back rather than invent a time.
        let render = js_fn(html, "render()");
        assert!(
            render.contains("wallClockAt(pos)") && render.contains("fmtTimeOfDay"),
            "the main readout does not show a time of day: {render}"
        );
        assert_eq!(
            html.matches("=== null ? fmt").count()
                + html.matches("=== null ? (r ? fmt").count(),
            3,
            "not every time-of-day readout falls back when there is no playlist clock"
        );
    }

    /// The player renews its own token before it runs out.
    ///
    /// Three hours does not cover a match plus its build-up, and the failure
    /// lands mid-second-half as "your viewing access has expired" — true, and
    /// useless. It bit twice during testing on 2026-08-25, once invalidating a
    /// whole measurement run before it was noticed.
    ///
    /// The deadline is read out of the token itself (`{exp}.{streams}.{hmac}`)
    /// rather than asked for: a second source for the same fact is a second
    /// thing that can disagree with the first.
    #[test]
    fn the_player_renews_its_token_before_it_expires() {
        let html = include_str!("dvr.html");
        let sched = js_fn(html, "scheduleRenewal");
        assert!(
            sched.contains("RENEW_LEAD_SECS"),
            "nothing renews ahead of the expiry: {sched}"
        );
        assert!(
            js_fn(html, "tokenExpiry").contains("parseInt"),
            "the deadline is not read from the token"
        );
        // A 32-bit setTimeout delay silently fires immediately when overflowed,
        // which would hammer the portal from every idle tab.
        assert!(
            sched.contains("0x7fffffff"),
            "an over-long delay would overflow setTimeout and fire at once: {sched}"
        );

        let now = js_fn(html, "renewNow");
        assert!(
            now.contains(r#"credentials: "include""#),
            "the renewal cannot authenticate: {now}"
        );
        assert!(
            now.contains("rememberToken(TOKEN)"),
            "a renewed token is not kept, so a reload loses it"
        );
    }

    /// Renewal must stop at the expiry rather than retry forever.
    ///
    /// Past it the existing expired-access path is the honest answer and it
    /// offers a way back that works. A tab retrying a dead credential every
    /// few seconds is a tab hammering the portal to no purpose.
    #[test]
    fn renewal_gives_up_at_the_expiry_and_backs_off_before_it() {
        let f = js_fn(include_str!("dvr.html"), "renewNow");
        assert!(f.contains("renewFailures"), "no backoff: {f}");
        assert!(
            f.contains("left > backoff"),
            "retries are not bounded by the token's own expiry: {f}"
        );
    }

    /// The self-test must be inert unless asked for.
    ///
    /// It seeks both elements dozens of times and drives the preview by hand.
    /// Running any of that for an ordinary viewer would be a player that
    /// jumps around on load, so the whole thing hangs off one query flag and
    /// a deliberate tap.
    #[test]
    fn the_self_test_runs_only_when_asked_for() {
        let html = include_str!("dvr.html");
        assert!(
            html.contains(r#"qs.get("selftest") === "1""#),
            "the self-test is not behind a flag"
        );
        // The only thing that starts it is the button, inside that guard.
        assert_eq!(
            html.matches("stRunAll").count(),
            2,
            "stRunAll is referenced somewhere other than its definition and its one listener"
        );
        // And it must not be wired to anything that fires on load.
        for on_load in ["loadedmetadata\", stRunAll", "DOMContentLoaded\", stRunAll"] {
            assert!(!html.contains(on_load), "self-test runs on load: {on_load}");
        }
    }

    /// What the page tells the operator about the bar must match what the
    /// bar now does.
    ///
    /// The shading was added when dragging outside the buffer showed nothing
    /// until you stopped, and the hint said so. The thumbnail track changed
    /// that and the sentence outlived it — which is worse than no hint,
    /// because an operator who reads "the picture waits until you stop" will
    /// stop, and never discover the preview. Caught by AJ asking what the
    /// green section meant.
    #[test]
    fn the_hint_describes_the_bar_as_it_behaves_now() {
        let html = include_str!("dvr.html");
        assert!(
            !html.contains("the picture waits until you stop"),
            "the hint still describes the player as it was before the preview"
        );
        assert!(
            html.contains("preview thumbnail while you drag"),
            "nothing tells the operator a preview exists outside the lit part"
        );
        // It moved into Settings when the picture went full-bleed. Wherever it
        // lives, it has to be reachable: an explanation of the green bar that
        // nothing links to is an explanation nobody reads.
        assert!(
            html.contains(r#"id="btnSettings""#) && html.contains(r#"class="note bar""#),
            "the explanation of the bar has no home in the UI"
        );
    }

    /// The scrub bar must span the playlist window, not `video.seekable`.
    ///
    /// They are different and the gap grows: measured against a live 300 s
    /// window, the playlist summed to exactly 300 s of `EXTINF` while
    /// `main.seekable` read `0.0-504.0`. MSE keeps extending its seekable
    /// range as segments are appended; the server-side window slides.
    ///
    /// Calibrated on `seekable`, the bar offers positions before the oldest
    /// segment and after the live edge — 40 % of the bar was footage the
    /// origin had evicted and 30 % was footage that had not happened. Both
    /// simply show nothing, with no error anywhere.
    #[test]
    fn the_scrub_bar_spans_the_playlist_window_not_the_media_source() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "range");
        assert!(
            f.contains("playlistWindow("),
            "the bar is calibrated on the media source again: {f}"
        );
        let w = js_fn(html, "playlistWindow");
        assert!(
            w.contains("totalduration") && w.contains("fragments"),
            "the window is not derived from the playlist: {w}"
        );
        // The fallback must stay for native HLS, which exposes no playlist.
        assert!(
            f.contains("v.seekable"),
            "no fallback for a player without hls.js: {f}"
        );
    }

    /// The thumbnail index is a rolling window and must be refetched.
    ///
    /// Sheets age out, new ones appear, and the declared epoch moves with the
    /// oldest — exactly like the media playlist. Fetched once and kept, it
    /// drifts out from under the bar: measured on a session fifteen minutes
    /// old, every position resolved outside the index's span and the preview
    /// was simply gone, with nothing on screen to say why.
    ///
    /// A refetch that fails to parse must also leave the working index alone,
    /// or a truncated read mid-publish takes the preview away.
    #[test]
    fn the_thumbnail_index_is_refetched_as_it_rolls() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "loadThumbs");
        assert!(
            f.contains("THUMBS_MAX_AGE_MS"),
            "the index is fetched once and kept forever: {f}"
        );
        assert!(
            f.contains("if (next) thumbs = next"),
            "a failed reparse drops the working index: {f}"
        );
    }

    /// A sprite sheet must be fetched with the viewer's credential.
    ///
    /// The origin refuses an unauthenticated GET, and a CSS
    /// `background-image` cannot carry an `Authorization` header — so a style
    /// pointed straight at the sheet URL gets a 401 and paints the box's own
    /// background colour. The element still has its size, its position and a
    /// `background-image`, so every assertion about the DOM passes while the
    /// operator sees a black rectangle where a frame should be. It shipped
    /// that way once and was caught by looking at a screenshot, not by a test.
    ///
    /// So the sheet goes through `fetch`, which can carry the header, and the
    /// style gets a blob URL.
    #[test]
    fn a_sprite_sheet_is_fetched_with_the_viewers_credential() {
        let html = include_str!("dvr.html");
        let f = js_fn(html, "sheetUrl");
        assert!(
            f.contains("Authorization") && f.contains("Bearer"),
            "the sheet is requested without a credential: {f}"
        );
        assert!(
            f.contains("createObjectURL"),
            "the style is not given a blob URL: {f}"
        );

        // And nothing may point a style straight at the origin URL again.
        let show = js_fn(html, "showPreview");
        assert!(
            !show.contains("url(STREAM, cue.uri)"),
            "backgroundImage points at the origin URL, which will 401: {show}"
        );
        assert!(
            show.contains("sheetUrl("),
            "the preview does not go through the authenticated fetch: {show}"
        );
    }

    /// A sheet arriving mid-drag must repaint the preview.
    ///
    /// `sheetUrl` answers null while its fetch is in flight, and nothing else
    /// redraws — so the first position on every sheet stayed blank until the
    /// thumb moved again. Measured along the bar that is a blank at perfectly
    /// regular intervals, one per sheet, which reads as a broken preview
    /// rather than a slow one.
    ///
    /// A failed fetch must also be forgotten, or one transient error means no
    /// preview from that sheet for the life of the tab.
    #[test]
    fn a_sheet_arriving_mid_drag_repaints_the_preview() {
        let f = js_fn(include_str!("dvr.html"), "sheetUrl");
        assert!(
            f.contains("showPreview(lastPreviewAt.t"),
            "nothing repaints when the sheet lands: {f}"
        );
        assert!(
            f.contains("delete sheetUrls[uri]"),
            "a failed fetch is remembered for the life of the tab: {f}"
        );
    }

    /// The preview must be taken down when the drag ends.
    ///
    /// It floats over the transport. Left up, it covers the controls and
    /// shows a frame the playhead has since left — and nothing else in the
    /// player would ever hide it.
    #[test]
    fn the_scrub_preview_is_taken_down_when_the_drag_ends() {
        assert!(
            js_fn(include_str!("dvr.html"), "endScrub").contains("hidePreview()"),
            "the preview outlives the drag that opened it"
        );
    }

    /// A held scrub shows the proxy; releasing hands the still back.
    ///
    /// Measured on the target tablet, 50 seeks over 2 s inside the buffer:
    /// main 1920p presented **13/50** at 6.1 fps, the proxy **39-41/50** at
    /// 18-19 fps. A drag on the main rendition there shows about one frame in
    /// four. The same test on a desktop showed no difference whatsoever
    /// (23.5 vs 23.5), which is exactly why this was nearly deleted as a
    /// no-op — the hardware was the hidden variable.
    ///
    /// It hands back on release because a stopped scrub is someone examining
    /// the frame they landed on, and 640x360 is not what they stopped to look
    /// at.
    #[test]
    fn a_held_scrub_shows_the_proxy_and_releases_back_to_main() {
        let html = include_str!("dvr.html");
        assert!(
            js_fn(html, "activeVideo").contains("scrubOnProxy"),
            "a held scrub still drives the main rendition"
        );
        let begin = js_fn(html, "beginScrub");
        assert!(begin.contains("ensureProxy()"), "the drag never asks for the rendition it needs");
        assert!(begin.contains("handPictureToProxy()"), "nothing hands the picture over");
        assert!(
            js_fn(html, "endScrub").contains("seekWhenReady(main"),
            "the picture is left on the proxy after the drag ends"
        );
    }

    /// The handover refuses until the proxy can show that position.
    ///
    /// Two ways to turn a choppy scrub into a broken one: promote to an
    /// element with no frames yet (black), or promote before the two
    /// timelines have been related — `timelineOffset` starts at 0, which is
    /// not a measurement, and the drag would land seconds from the thumb.
    #[test]
    fn the_scrub_handover_waits_for_a_picture_and_a_measured_offset() {
        let f = js_fn(include_str!("dvr.html"), "handPictureToProxy");
        assert!(f.contains("proxy.readyState"), "hands over to an element that may show nothing: {f}");
        // The property, not one particular way of establishing it. This
        // asserted `offsetSamples.length` — the sampler's own counter — and so
        // held the bug in place: once the sampler stood down in favour of the
        // playlists' dates, that counter stayed at zero for the session and
        // the handover never fired, with the test still green.
        assert!(
            f.contains("if (!clocksRelated()) return;"),
            "hands over before the two clocks are related: {f}"
        );
        // And never in the reduced modes: there the moving picture is already
        // the low-resolution one, and the second element is the hi-res still
        // sitting on an old frame rather than a scrub proxy. Handing over to
        // it made `endScrub` seek the transport back to that frame on every
        // release — the drag moved, then snapped back.
        assert!(
            f.contains("if (lowRes) return;"),
            "the scrub handover runs in a mode where the second element is the still: {f}"
        );
    }

    /// The stylesheet and `activeVideo` must not decide the picture separately.
    ///
    /// They used to: the CSS showed the proxy for `data-mode="shuttle"` and
    /// `activeVideo` returned it for the same test, so a second reason to show
    /// the proxy meant remembering to edit both. When they disagree the
    /// operator watches one element while the transport drives the other, and
    /// nothing reports it — the picture simply stops responding.
    #[test]
    fn the_stylesheet_shows_whatever_active_video_returns() {
        let html = include_str!("dvr.html");
        assert!(
            !html.contains(r#"body[data-mode="shuttle"] #proxy"#),
            "the stylesheet is picking the picture from the mode again"
        );
        assert!(html.contains(r#"body[data-picture="proxy"] #proxy"#), "no rule shows the proxy");
        assert_eq!(
            html.matches("dataset.picture =").count(),
            1,
            "`data-picture` has more than one writer, so they can disagree"
        );
        assert!(
            js_fn(html, "syncPicture").contains("onProxy()"),
            "the one writer does not ask `activeVideo` what is on screen"
        );
    }

    /// The shading has to be recomputed as fragments land, or it freezes at
    /// whatever was buffered on the first frame and then quietly misleads.
    #[test]
    fn the_shading_is_refreshed_by_the_render_loop() {
        assert!(
            // `render()` with the parens: bare "render" also prefix-matches
            // `renderCached` itself, which trivially contains its own name.
            js_fn(include_str!("dvr.html"), "render()").contains("renderCached("),
            "nothing updates the shading after the first paint"
        );
    }

    /// Both placeholders must be substituted, and the page must offer the
    /// portal only when there is one.
    ///
    /// A stray `__PORTAL_URL__` would become a link to a literally-named page,
    /// which is worse than the no-portal case it replaced: the viewer clicks
    /// it and lands nowhere, having been told that was the way back.
    #[test]
    fn dvr_page_offers_the_portal_only_when_one_is_configured() {
        let with = include_str!("dvr.html")
            .replace("__STREAM_ID__", "bigshow")
            .replace("__PORTAL_URL__", "https://portal.example");
        assert!(!with.contains("__PORTAL_URL__"), "placeholder left in page");
        assert!(with.contains("https://portal.example"));

        // With no portal, the page must not tell a viewer to reload: someone
        // who came from a portal has a dead token in their URL, so reloading
        // re-presents it and changes nothing.
        let without = include_str!("dvr.html")
            .replace("__STREAM_ID__", "bigshow")
            .replace("__PORTAL_URL__", "");
        assert!(!without.contains("__PORTAL_URL__"));
        assert!(
            without.contains("Open the feed again"),
            "no instruction for a viewer with no portal to return to"
        );
        assert!(
            !without.contains("reload the page to continue"),
            "page still promises a reload that cannot help a portal viewer"
        );
    }

    /// The link the page offers comes from the relay's config, never from the
    /// request. A page that would render a URL supplied by whoever asked for
    /// it is a phishing hop with extra steps, so the page must not read one
    /// out of its own query string.
    #[test]
    fn the_portal_link_is_not_taken_from_the_url() {
        let html = include_str!("dvr.html");
        let after = html
            .split("var PORTAL_URL")
            .nth(1)
            .expect("PORTAL_URL not found");
        let decl = after.lines().next().unwrap();
        assert!(
            decl.contains("__PORTAL_URL__"),
            "PORTAL_URL is not the server-substituted placeholder: {decl}"
        );
        assert!(
            !decl.contains("location") && !decl.contains("param"),
            "PORTAL_URL reads from the request: {decl}"
        );
    }

    /// The player must survive a reload.
    ///
    /// It strips the token from the URL on load, which is right — a viewer
    /// copying the address bar should not hand out their credential. On its
    /// own that made the page a one-shot: reload, press back, or let the
    /// browser restore the tab, and the URL that came back was the stripped
    /// one. The page then had no credential and told the viewer their access
    /// had EXPIRED, which was false and pointed them at the wrong fix.
    /// Measured in Chrome: first load 200 throughout, reload 401 on the first
    /// manifest.
    #[test]
    fn the_token_outlives_the_url_it_arrived_in() {
        let html = include_str!("dvr.html");
        assert!(
            html.contains("sessionStorage"),
            "the token is dropped from the URL and kept nowhere — a reload loses it"
        );
        // Per tab, not per browser: a viewing credential has no business
        // outliving the tab it was opened in.
        //
        // Asserted against the token's own helpers rather than by banning the
        // string `localStorage` from the file, which is what this used to do.
        // Marks are kept in `localStorage` deliberately — they are notes, not
        // a credential — and a file-wide ban would have to be deleted to let
        // them in, taking the real guarantee with it.
        for f in ["rememberToken", "recallToken", "forgetToken"] {
            let body = js_fn(html, f);
            assert!(
                body.contains("sessionStorage"),
                "{f} does not use sessionStorage: {body}"
            );
            assert!(
                !body.contains("localStorage"),
                "{f} would outlive the tab: {body}"
            );
        }
        // And nothing else may put a credential there either. The allow-list
        // is by *key*, and deliberately explicit: the property being defended
        // is "no credential outlives the tab", not "only marks are stored", so
        // a new preference is welcome and a new secret is not. Comments are
        // skipped — this section explains itself in prose, and prose stores
        // nothing.
        const NON_SECRET_KEYS: [&str; 3] = ["MARKS_KEY", "LOWRES_KEY", "QUALITY_KEY"];
        for line in html.lines().filter(|l| {
            let t = l.trim_start();
            l.contains("localStorage") && !t.starts_with("//") && !t.starts_with("*")
        }) {
            assert!(
                NON_SECRET_KEYS.iter().any(|k| line.contains(k)),
                "localStorage used for a key that is not on the non-secret list: {line}"
            );
        }
        // Every access wrapped: a browser with site data blocked throws on
        // read rather than returning null, and that must not take the player
        // down with it.
        let uses = html.matches("sessionStorage").count();
        let guarded = html.matches("try {").count();
        assert!(guarded >= uses, "an unguarded storage access will throw where site data is blocked");
    }

    /// Having no credential and having one refused need different words.
    ///
    /// Both used to produce "your viewing access has expired". For a page that
    /// was simply opened without a token nothing had expired, and the message
    /// sent the viewer to renew something they never had.
    #[test]
    fn a_missing_token_is_not_reported_as_an_expired_one() {
        let html = include_str!("dvr.html");
        assert!(html.contains("failNoToken"), "no distinct path for a missing credential");
        assert!(html.contains("failExpired"), "no path for a refused credential");
        assert!(
            html.contains("if (TOKEN) { failExpired(); } else { failNoToken(); }"),
            "the two failures are not actually told apart at the branch"
        );
        // A refused token must be forgotten, or the stored copy turns one
        // refusal into a loop that survives every reload.
        let expired = html.split("function failExpired()").nth(1).unwrap_or("");
        assert!(
            expired[..expired.len().min(300)].contains("forgetToken"),
            "a refused token is kept, so the failure repeats on every reload"
        );
    }

    /// hls.js is vendored, not fetched. Android Chrome has no native HLS, so a
    /// CDN reference would make the player fail exactly on the primary target
    /// whenever the relay is deployed without public internet.
    #[test]
    fn dvr_page_has_no_external_script_references() {
        let html = include_str!("dvr.html");
        for host in ["cdn.jsdelivr.net", "unpkg.com", "cdnjs", "//cdn."] {
            assert!(!html.contains(host), "external reference to {host}");
        }
        assert!(html.contains("/dvr/hls.js"), "page does not load the vendored hls.js");
    }

    /// The vendored bundle must actually be hls.js, not a stub or an error
    /// page saved by mistake.
    #[test]
    fn vendored_hls_js_is_present_and_plausible() {
        let js = include_str!("vendor/hls.min.js");
        assert!(js.len() > 100_000, "hls.js suspiciously small: {} bytes", js.len());
        assert!(js.contains("Hls"), "bundle does not mention Hls");
    }

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

    /// Helper-level shapes only. The wiring — that `whep_offer` actually
    /// reaches the query string — is asserted in `tests/distribution.rs`
    /// (`runtime_control_flips_viewer_gate`), because these two assertions
    /// pass with the extractor deleted from the handler.
    #[test]
    fn token_is_read_from_the_query_string() {
        assert_eq!(token_from_query(Some("token=abc")).as_deref(), Some("abc"));
        assert_eq!(
            token_from_query(Some("stream=x&token=1770000000.deadbeef&v=2")).as_deref(),
            Some("1770000000.deadbeef")
        );
    }

    /// axum's `RawQuery` yields the query with `?` already stripped, so a
    /// leading `?` is not a production shape. Assert what production sends.
    #[test]
    fn leading_question_mark_is_not_a_production_shape() {
        assert!(
            token_from_query(Some("?token=abc")).is_none(),
            "RawQuery never supplies the '?'; treating it as a key is correct"
        );
    }

    /// A blank `Authorization` header must read as *no* credential, not as the
    /// empty one. Header-first lookup means `Some("")` would swallow the
    /// fallthrough and 403 a client whose `?token=` is perfectly good.
    #[test]
    fn empty_bearer_header_is_not_a_credential() {
        use axum::http::HeaderValue;
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(bearer(&h).is_none(), "'Bearer ' must fall through to ?token=");
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer    "));
        assert!(bearer(&h).is_none(), "whitespace-only must fall through too");
        // A NON-empty junk header still wins and must NOT fall through: an
        // explicit credential outranks a URL, and is then rejected on merit.
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer junk"));
        assert_eq!(bearer(&h).as_deref(), Some("junk"));
        // A non-Bearer scheme is not ours to read.
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(bearer(&h).is_none());
    }

    #[test]
    fn token_from_query_rejects_nothing_useful() {
        assert!(token_from_query(None).is_none());
        assert!(token_from_query(Some("")).is_none());
        assert!(token_from_query(Some("other=abc")).is_none());
        // A bare `token` flag with no value is not a credential.
        assert!(token_from_query(Some("token")).is_none());
        assert!(token_from_query(Some("token=")).is_none());
        // Must not match a different key that merely ends in "token".
        assert!(token_from_query(Some("ingest_token=abc")).is_none());
    }
}
