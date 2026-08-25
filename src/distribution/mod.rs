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
        idle_grace: std::time::Duration::from_secs(60),
    };
    tracing::info!(
        root = %origin_cfg.root.display(),
        retention_secs = config.origin_retention_secs,
        max_bytes_per_stream = config.origin_max_bytes_per_stream,
        min_segments = config.origin_window_segments,
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
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
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
        let wall = js_fn(html, "wallClockAt");
        assert!(
            wall.contains("programDateTime"),
            "wall clock is not taken from #EXT-X-PROGRAM-DATE-TIME: {wall}"
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
        assert!(f.contains("offsetSamples.length"), "hands over on an unmeasured offset: {f}");
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
        assert!(!html.contains("localStorage"), "a viewer token must not persist beyond the tab");
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
