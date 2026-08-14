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
    let origin = Arc::new(OriginStore::new(config.origin_window_segments));

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
/// **Scope.** This gates the WHEP tier only. `GET /origin/{stream}/{file}`
/// (the CMAF/LL-HLS tier) is unauthenticated in every mode — see the note on
/// `origin::origin_get` and `docs/distribution.md`.
fn check_viewer_token(
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
