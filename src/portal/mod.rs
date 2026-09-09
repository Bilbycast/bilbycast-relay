// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! The viewer portal: sign in, see your feeds, get a token.
//!
//! Runs on the relay's VPS as its own process, behind **Authelia**. Authelia
//! authenticates and forwards the request with the username in a header; the
//! portal asks the manager what that username may watch and hands back links.
//!
//! # Why it is a separate binary
//!
//! It is public-facing and it is not the data plane. The relay terminates
//! media for every viewer on the box; a portal bug must not be able to take
//! that with it, and a portal exploit must not land inside the process holding
//! the media. Nothing here links str0m or the distribution feature.
//!
//! # What it deliberately does not hold
//!
//! **The token secret.** The portal never signs a viewer token — it asks the
//! manager to, and the manager re-checks the entitlement before it does. A
//! public-facing VPS holding the key that signs every viewer credential would
//! make a compromise here a compromise of every feed on every relay.
//!
//! **The entitlements.** They are read from the manager on each page load
//! rather than synced. Withdrawing someone's access then takes effect on their
//! next click, instead of on the next successful push to a box that might be
//! unreachable.
//!
//! # The header is only as good as what is in front of it
//!
//! `Remote-User` is a claim, not a proof. Anyone who can reach this service
//! directly can set it and become anyone. Two things stop that, and both are
//! fail-closed:
//!
//! * the default listen address is **loopback**, so the only way in is through
//!   the proxy on the same host, and
//! * the peer address is checked against `trusted_proxies` before the header is
//!   read at all — an untrusted peer is refused without the header being looked
//!   at, so a misconfiguration cannot silently downgrade to "trust everyone".

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

pub mod config;

pub use config::PortalConfig;

/// What the portal sends the browser for one watchable feed.
///
/// A subset of what the manager returns, on purpose: the manager knows which
/// relay a session lives on and which group owns it, and neither is the
/// viewer's business.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub session_id: String,
    pub name: String,
}

/// The manager's answer to "what may this username watch".
#[derive(Debug, Deserialize)]
struct StreamsResponse {
    #[serde(default)]
    streams: Vec<ManagerStream>,
}

#[derive(Debug, Deserialize)]
struct ManagerStream {
    session_id: String,
    name: String,
    /// Not forwarded to the browser — a viewer has no business knowing which
    /// relay stream backs a feed — but the portal matches the player's
    /// `?stream=` against it.
    #[serde(default)]
    stream_id: String,
}

/// The manager's answer to "mint a token for this feed".
#[derive(Debug, Deserialize)]
struct TokenResponse {
    watch_url: String,
    /// The opaque id of the device that now holds this login, when the mint
    /// claimed or renewed one. Absent for a mint that was only a permission
    /// check.
    #[serde(default)]
    holder: Option<String>,
    #[serde(default)]
    expires_in_secs: u64,
}

#[derive(Clone)]
pub struct PortalState {
    pub cfg: Arc<PortalConfig>,
    pub http: reqwest::Client,
}

pub fn router(state: PortalState) -> Router {
    Router::new()
        // Public and unauthenticated on purpose: a health check that needed a
        // signed-in user would report the proxy's health, not the portal's.
        .route("/healthz", get(healthz))
        .route("/", get(page))
        .route("/portal.js", get(portal_js))
        // One tap back to a feed whose credential ran out. The player links
        // here rather than to the front page: the portal already knows who
        // they are, so "find your feed again" is a step nobody needs.
        .route("/watch", get(watch_redirect))
        .route("/api/feeds", get(feeds))
        .route("/api/clips", get(clips).delete(delete_clip))
        .route("/api/clips/download", get(download_clip))
        .route("/api/watch", post(watch))
        .route("/api/renew", get(renew))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok\n"
}

/// Serve the page itself.
///
/// Static — the feed list is fetched by the script rather than rendered in, so
/// there is no path by which a feed name reaches the HTML through string
/// concatenation. The names come from an operator, not a viewer, but "only
/// trusted input reaches this" is exactly the assumption that stops being true
/// later.
async fn page() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // `script-src 'self'` is why the script is its own route rather
            // than an inline block.
            (header::CONTENT_SECURITY_POLICY, PAGE_CSP),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(include_str!("portal.html")),
    )
}

async fn portal_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("portal.js"),
    )
}

/// Who is asking?
///
/// Returns `None` unless the request came from a trusted proxy **and** carries
/// a usable username. The peer check comes first and is not skippable: the
/// header is a claim that only means anything because something in front of us
/// set it, so reading it from an untrusted peer is reading an assertion the
/// client made about itself.
pub fn identify(
    cfg: &PortalConfig,
    peer: IpAddr,
    headers: &HeaderMap,
) -> Option<String> {
    if !cfg.is_trusted_proxy(peer) {
        return None;
    }
    let raw = headers.get(&cfg.username_header)?.to_str().ok()?.trim();
    // Same rule as the manager's `valid_username`: reject only what cannot be
    // a username at all. A name with a space or a control character could not
    // have survived a header round-trip intact, so matching it against an
    // entitlement would be guesswork.
    if raw.is_empty()
        || raw.len() > 256
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    Some(raw.to_string())
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": "Not signed in. Reload the page to sign in again."
        })),
    )
        .into_response()
}

fn upstream_unavailable() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({
            "error": "Cannot reach the manager right now. Try again in a moment."
        })),
    )
        .into_response()
}

/// Ask the manager what this username may watch.
///
/// Shared by the JSON route the page calls and the redirect the player links
/// to, so the two cannot drift about which streams a viewer has.
async fn fetch_streams(st: &PortalState, username: &str) -> Result<Vec<ManagerStream>, Response> {
    fetch_streams_for(st, username, None).await
}

/// The feeds this viewer may act on, for a given purpose.
///
/// `for=clips` asks the wider question: a finished game cannot be watched, and
/// the clips exported from it are still wanted for a day afterwards. Watching
/// asks the narrower one, so a stopped session never offers a link to a black
/// screen.
async fn fetch_streams_for(
    st: &PortalState,
    username: &str,
    purpose: Option<&str>,
) -> Result<Vec<ManagerStream>, Response> {
    let url = format!("{}/api/v1/dvr/portal/streams", st.cfg.manager_url);
    let mut query = vec![("username", username)];
    if let Some(p) = purpose {
        query.push(("for", p));
    }
    let resp = st
        .http
        .get(&url)
        .query(&query)
        .bearer_auth(&st.cfg.manager_token)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "portal: manager stream list failed");
            upstream_unavailable()
        })?;
    if !resp.status().is_success() {
        // A 401 here is the PORTAL's credential being wrong, not the viewer's.
        // Saying "not signed in" would send them to log in again forever.
        tracing::warn!(status = %resp.status(), "portal: manager refused the stream list");
        return Err(upstream_unavailable());
    }
    let body: StreamsResponse = resp.json().await.map_err(|e| {
        tracing::warn!(error = %e, "portal: unreadable stream list");
        upstream_unavailable()
    })?;
    Ok(body.streams)
}

/// Ask the manager to mint, returning the URL to send the viewer to.
/// Mint purely as a permission check — listing clips, downloading one,
/// deleting one. Claims nothing, so it cannot displace the viewer's own
/// player, which matters because the clip list is polled while a cut runs.
async fn mint(st: &PortalState, username: &str, session_id: &str) -> Result<String, Response> {
    mint_inner(st, username, session_id, None, None, false).await
}

/// Mint, saying whether this is a renewal and where the viewer is.
///
/// `holder` is the opaque id the player was given when it took the login. Its
/// presence is what tells the manager this is a renewal rather than a fresh
/// watch — a fresh watch *claims* the login and displaces whatever held it,
/// where a renewal has to still hold it. Sending it on both would let two
/// devices take the feed back off each other indefinitely, each succeeding.
///
/// An id rather than the token, because two tokens minted in the same second
/// for the same streams are byte-identical and so cannot tell two devices
/// apart — which is exactly the case this exists to catch.
async fn mint_inner(
    st: &PortalState,
    username: &str,
    session_id: &str,
    holder: Option<&str>,
    viewer_ip: Option<String>,
    claim: bool,
) -> Result<String, Response> {
    let url = format!("{}/api/v1/dvr/portal/token", st.cfg.manager_url);
    let resp = st
        .http
        .post(&url)
        .bearer_auth(&st.cfg.manager_token)
        .json(&serde_json::json!({
            "username": username,
            "session_id": session_id,
            "holder": holder,
            "viewer_ip": viewer_ip,
            "claim": claim,
        }))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "portal: manager token mint failed");
            upstream_unavailable()
        })?;

    // Someone else took the login. Its own answer, and its own words: nothing
    // expired, so telling a viewer their access ran out would send them
    // looking for the wrong fix.
    if resp.status() == StatusCode::CONFLICT {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "This login is being used on another device.                           Only one at a time — sign in again here to take it back."
            })),
        )
            .into_response());
    }

    // The manager answers one uniform refusal whether the user is not
    // entitled, the session does not exist, or it is not running — so this
    // endpoint cannot be used to discover which feeds exist. Passing it
    // through as one message keeps that property.
    if resp.status() == StatusCode::FORBIDDEN {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "That feed is not available to you. It may have finished, \
                          or your access may have been changed."
            })),
        )
            .into_response());
    }
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "portal: manager refused to mint");
        return Err(upstream_unavailable());
    }
    let body: TokenResponse = resp.json().await.map_err(|e| {
        tracing::warn!(error = %e, "portal: unreadable mint response");
        upstream_unavailable()
    })?;
    // The holder id rides on the URL, so it reaches the player by the same
    // route the token does and needs no second channel. The player keeps it
    // and presents it on renewal; it is not a credential and grants nothing.
    Ok(match body.holder {
        Some(h) if !h.is_empty() => {
            let sep = if body.watch_url.contains('?') { '&' } else { '?' };
            format!("{}{sep}hold={h}", body.watch_url)
        }
        _ => body.watch_url,
    })
}

/// `GET /api/feeds` — what the signed-in user may watch.
async fn feeds(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        return unauthenticated();
    };
    let streams = match fetch_streams(&st, &username).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let feeds: Vec<Feed> = streams
        .into_iter()
        .map(|s| Feed { session_id: s.session_id, name: s.name })
        .collect();
    Json(serde_json::json!({
        "username": username,
        "feeds": feeds,
        // Rendered as a "Sign out" link when configured. The portal cannot end
        // the session itself — Authelia holds the cookie — so an absent value
        // means no button, rather than one that appears to work.
        "logout_url": st.cfg.logout_url,
    }))
    .into_response()
}

/// One exported clip, as the relay's origin describes it.
///
/// Declared here rather than reusing `distribution::origin::ClipRecord`: the
/// portal builds independently of `viewer-distribution` on purpose — it hands
/// out links to a relay, which need not be this one — and borrowing that type
/// would tie the two features together for the sake of four fields.
#[derive(Debug, Deserialize)]
struct OriginClip {
    name: String,
    #[serde(default)]
    at: String,
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    bytes: u64,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    error: Option<String>,
}

/// Split a minted watch URL into the origin root and the token it carries.
///
/// The manager mints a player URL — `https://relay/dvr/<stream>?token=…` — and
/// the clips live on the same relay under `/origin/…`. Deriving one from the
/// other keeps the portal from needing a second piece of manager plumbing just
/// to learn an address it has already been handed.
fn origin_root_and_token(watch_url: &str) -> Option<(String, String)> {
    let (before_query, query) = watch_url.split_once('?')?;
    let token = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("token="))?
        .to_string();
    // Everything up to `/dvr/` is the relay's root.
    let root = before_query.split("/dvr/").next()?.to_string();
    if root.is_empty() || token.is_empty() {
        return None;
    }
    Some((root, token))
}

/// Percent-encode a query-string value.
///
/// Clip names carry spaces and an operator's punctuation, and they travel as
/// query parameters on this page's own download link.
fn urlencode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The page's content policy.
///
/// A named constant so a test can assert against the policy actually served
/// rather than a copy of it. `connect-src 'self'` in particular is load-bearing
/// for `portal.js`: every fetch it makes has to be same-origin, and one that is
/// not fails inside the browser with nothing reaching any server.
const PAGE_CSP: &str = "default-src 'self'; script-src 'self'; \
                        style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
                        connect-src 'self'; frame-ancestors 'none'";

/// `GET /api/clips` — finished clips for the feeds this viewer may watch.
///
/// Clips belong to the **session**, not to whoever exported them: anyone
/// entitled to the feed sees them. That is what their retention already says —
/// kept as long as the session, cleaned up with it — and it means a reviewer
/// can hand a colleague a clip without re-exporting it.
///
/// Ones still being cut are listed too, marked not ready, so an operator who
/// has just pressed Export sees that something is happening rather than an
/// empty page.
async fn clips(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        return unauthenticated();
    };
    // Clips outlive their game by a day, so this asks for feeds whose clips
    // are still reachable rather than only those on air.
    let streams = match fetch_streams_for(&st, &username, Some("clips")).await {
        Ok(s) => s,
        Err(r) => return r,
    };

    // One feed at a time was two sequential round-trips per feed — a mint to
    // the manager, then a listing from the relay. At three feeds that is
    // invisible; at thirty it is the page's load time, and the browser now
    // polls this route while anything is being cut, so it is paid repeatedly.
    //
    // Concurrent, not cached. Minting per feed is what proves entitlement —
    // the manager re-checks it on every mint, so a feed the viewer has lost
    // access to yields nothing here without the portal reasoning about
    // permissions itself. Holding a mint would trade that away for latency,
    // which is the wrong side of the trade for a credential.
    let per_feed = streams.iter().map(|s| {
        let st = &st;
        let username = &username;
        async move {
            let watch_url = mint(st, username, &s.session_id).await.ok()?;
            let (root, token) = origin_root_and_token(&watch_url)?;
            let list_url = format!("{root}/origin/{}/clips?token={token}", s.stream_id);
            let listed: Vec<OriginClip> = match st.http.get(&list_url).send().await {
                Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
                // A relay too old to know about clips answers 404. That is not
                // an error worth showing a viewer.
                _ => return None,
            };
            Some((s, listed))
        }
    });
    let results = futures_util::future::join_all(per_feed).await;

    let mut out: Vec<serde_json::Value> = Vec::new();
    for (s, listed) in results.into_iter().flatten() {
        for c in listed {
            out.push(serde_json::json!({
                "feed": s.name,
                "name": c.name,
                "at": c.at,
                "ready": c.ready,
                "bytes": c.bytes,
                "failed": c.failed,
                // Passed through as the edge worded it. These are operator
                // facts — the window aged out, the clip was too large — and
                // rewording them here would only put distance between what
                // happened and what the viewer is told.
                "error": c.error,
                // The session the clip belongs to, so a delete can name it
                // without the page holding a URL on another origin.
                "session_id": s.session_id,
                // Downloaded through this page, not straight from the origin.
                //
                // A viewer token in the href is a credential in the browser's
                // history, in the referrer, and in the access log of anything
                // between here and the relay — for a link a viewer is meant to
                // right-click and save. Proxying costs the portal the bytes of
                // a clip somebody actually downloads, which is a few tens of
                // megabytes now and then, and hands out nothing.
                "url": if c.ready {
                    Some(format!(
                        "/api/clips/download?session={}&name={}",
                        urlencode(&s.session_id),
                        urlencode(&c.name),
                    ))
                } else {
                    None
                },
            }));
        }
    }

    // Newest first: an operator exporting during an event wants what they just
    // asked for at the top, not the first clip of the morning.
    out.sort_by(|a, b| b["at"].as_str().cmp(&a["at"].as_str()));
    Json(serde_json::json!({ "clips": out })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct WatchQuery {
    /// The relay's stream id, not the session id — the player knows which
    /// stream it is showing and nothing else about the session behind it.
    pub stream: String,
    /// On a renewal, the holder id the player was given.
    ///
    /// Its presence is what distinguishes "I am still watching" from "I am
    /// starting to watch": the first must still hold the login, the second
    /// takes it. A player that omits it is treated as starting.
    #[serde(default)]
    pub held: Option<String>,
}

/// The address to record for a viewer.
///
/// Every request arrives from the authenticating proxy on loopback, so the
/// peer address says nothing about the viewer. `X-Forwarded-For`'s first hop is
/// the client as the proxy saw it — trustworthy here for the same reason the
/// username is: the peer has already been checked against `trusted_proxies`,
/// and an untrusted peer never reaches this code.
///
/// Recorded for the access log, never for a decision.
fn viewer_address(peer: IpAddr, headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| Some(peer.to_string()))
}

/// `GET /watch?stream=…` — mint for the signed-in viewer and send them back.
///
/// The player's "sign in again" link. It resolves the stream against what this
/// user may watch, so an unentitled stream is indistinguishable from one that
/// does not exist: both land back on the portal with no explanation of which,
/// exactly as the mint endpoint refuses.
async fn watch_redirect(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<WatchQuery>,
) -> Response {
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        // Not signed in, or not through the proxy. Send them to the front
        // page, which is behind the same forward-auth and will bounce them
        // into a login.
        return Redirect::to("/").into_response();
    };

    let streams = match fetch_streams(&st, &username).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(hit) = streams.iter().find(|s| s.stream_id == q.stream) else {
        return Redirect::to("/").into_response();
    };

    match mint_inner(
        &st,
        &username,
        &hit.session_id,
        None,
        viewer_address(peer.ip(), &headers),
        true,
    )
    .await
    {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => Redirect::to("/").into_response(),
    }
}

/// `GET /api/renew?stream=…` — a fresh token for a player already watching.
///
/// A viewing token lasts three hours; an event plus its build-up does not fit
/// in that, and the failure lands mid-match as "your viewing access has
/// expired". So the player renews itself before it runs out.
///
/// **Renewal goes through the manager, exactly as the first mint did.** The
/// manager re-checks the entitlement before it signs, which is what keeps the
/// short expiry meaningful: it is revocation latency, not a countdown. A
/// renewal that skipped that check would turn "access lasts three hours" into
/// "access lasts as long as the tab is open", and withdrawing someone's access
/// would stop working entirely.
///
/// Cross-origin and credentialed, because the player is served by the relay
/// and this is the portal. Only origins named in `player_origins` are
/// answered, and an unlisted one gets the data without the CORS headers that
/// would let script read it — which is what the browser enforces anyway.
async fn renew(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<WatchQuery>,
) -> Response {
    // The origin is checked before anything is done, not before the answer is
    // returned: an un-allowed origin must not be able to cause a mint.
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !st.cfg.allows_player_origin(&origin) {
        return (StatusCode::FORBIDDEN, "origin not permitted to renew").into_response();
    }

    // Every exit past the origin check gets the CORS headers. The origin is
    // already allow-listed by this point, so withholding them tells the caller
    // nothing it may not have — it only makes the browser render a 401 or a
    // failed upstream as an opaque CORS error, which is the least useful
    // possible form of "your session ended, sign in again".
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        return with_cors(&origin, unauthenticated());
    };
    let streams = match fetch_streams(&st, &username).await {
        Ok(s) => s,
        Err(r) => return with_cors(&origin, r),
    };
    // Unentitled and non-existent are the same answer, as everywhere else
    // here: a renewal must not become a way to enumerate feeds.
    let Some(hit) = streams.iter().find(|s| s.stream_id == q.stream) else {
        return with_cors(&origin, (StatusCode::FORBIDDEN, "no such feed").into_response());
    };

    match mint_inner(
        &st,
        &username,
        &hit.session_id,
        // Absent when an older player renews without saying what it holds. It
        // is then treated as a fresh watch, which is the forgiving reading:
        // the viewer keeps their feed and simply retakes the login.
        q.held.as_deref(),
        viewer_address(peer.ip(), &headers),
        // A renewal that arrives without saying what it holds is treated as a
        // fresh watch, so an older player keeps its feed by retaking the login.
        q.held.is_none(),
    )
    .await
    {
        Ok(url) => {
            let field = |k: &str| {
                url.split_once(&format!("{k}="))
                    .map(|(_, t)| t.split('&').next().unwrap_or("").to_string())
                    .unwrap_or_default()
            };
            let token = field("token");
            if token.is_empty() {
                return with_cors(&origin, upstream_unavailable());
            }
            // The holder can change on a renewal only when the player had none
            // to present and was therefore treated as starting to watch — so
            // it is handed back either way and the player keeps the latest.
            with_cors(
                &origin,
                Json(serde_json::json!({ "token": token, "holder": field("hold") }))
                    .into_response(),
            )
        }
        Err(r) => with_cors(&origin, r),
    }
}

/// Let the named origin's script read the answer.
///
/// `Vary: Origin` because the response differs by origin and a cache that
/// missed that would hand one player another's answer.
fn with_cors(origin: &str, mut resp: Response) -> Response {
    let h = resp.headers_mut();
    // The body carries a viewing token. `Vary: Origin` already stops a shared
    // cache handing one origin another's answer, but nothing should be storing
    // a credential at all — the portal's own pages already say `no-store`.
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(origin) {
        h.insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        axum::http::HeaderValue::from_static("true"),
    );
    h.insert(
        axum::http::header::VARY,
        axum::http::HeaderValue::from_static("Origin"),
    );
    resp
}

#[derive(Debug, Deserialize)]
pub struct WatchRequest {
    pub session_id: String,
}

/// What a download names.
#[derive(Deserialize)]
pub struct DownloadClipQuery {
    pub session: String,
    pub name: String,
}

/// `GET /api/clips/download` — hand a finished clip to the viewer.
///
/// **Why this proxies rather than redirecting.** The obvious cheaper answer is
/// to mint a token and 302 to the origin, and it puts the credential straight
/// back in the URL — in the browser's history, in the referrer, and in the
/// access log of everything between here and the relay. For a link a viewer is
/// meant to right-click and save, that is the wrong place for it.
///
/// The cost is the bytes of a clip somebody actually downloads, tens of
/// megabytes now and then, and it is streamed rather than buffered so the
/// portal's memory does not grow with the clip.
///
/// Entitlement is re-checked by the same mint the listing uses.
async fn download_clip(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<DownloadClipQuery>,
) -> Response {
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        return unauthenticated();
    };
    let Ok(watch_url) = mint(&st, &username, &q.session).await else {
        return (StatusCode::FORBIDDEN, "That feed is not yours.").into_response();
    };
    let (Some((root, token)), Some(stream)) = (
        origin_root_and_token(&watch_url),
        stream_id_from(&watch_url),
    ) else {
        return (StatusCode::BAD_GATEWAY, "Could not reach the feed's relay.").into_response();
    };

    let url = format!(
        "{root}/origin/{stream}/clips/{}.mp4?token={token}",
        q.name.replace(' ', "%20"),
    );
    let upstream = match st.http.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(%username, clip = %q.name, status = r.status().as_u16(),
                "portal: the relay would not serve the clip");
            return (StatusCode::NOT_FOUND, "That clip is no longer available.").into_response();
        }
        Err(e) => {
            tracing::warn!(%username, clip = %q.name, error = %e,
                "portal: could not reach the relay for the clip");
            return (StatusCode::BAD_GATEWAY, "Could not reach the feed's relay.").into_response();
        }
    };

    let len = upstream.content_length();
    // Streamed, not collected: a clip is tens of megabytes and the portal
    // should not hold one per concurrent download.
    let body = axum::body::Body::from_stream(upstream.bytes_stream());
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "video/mp4")
        // The name the operator was promised. Quoted, because it carries
        // spaces and their own punctuation.
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}.mp4\"", q.name.replace('"', "")),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    if let Some(n) = len {
        resp.headers_mut()
            .insert(header::CONTENT_LENGTH, n.into());
    }
    resp
}

/// What a delete names: the feed, and the clip within it.
#[derive(serde::Deserialize)]
pub struct DeleteClipRequest {
    pub session_id: String,
    pub name: String,
}

/// `DELETE /api/clips` — remove one clip, on the viewer's behalf.
///
/// **Why the portal does this rather than the browser.** This page carries
/// `connect-src 'self'`, so a `fetch` to the origin — a different host and
/// port — never leaves the browser. The delete button therefore failed every
/// time, before any request was made, with the relay perfectly willing and no
/// sign of it in any log. Downloads were unaffected because a link is a
/// navigation, not a fetch.
///
/// Widening the policy to name the origin would have worked and is the worse
/// trade: it opens the page to a whole host for one button, and hands the
/// browser a credential it only needs because it is doing the relay's talking.
/// Going through here keeps the policy tight and the token server-side.
///
/// Entitlement is re-checked the same way a listing is — by minting against
/// the manager, which refuses a session this viewer may not see.
async fn delete_clip(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<DeleteClipRequest>,
) -> Response {
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        return unauthenticated();
    };

    // The mint is the permission check. A session the viewer has lost access
    // to yields nothing here, so there is no separate rule to keep in step.
    let Ok(watch_url) = mint(&st, &username, &req.session_id).await else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "That feed is not yours to change." })),
        )
            .into_response();
    };
    let Some((root, token)) = origin_root_and_token(&watch_url) else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "Could not reach the feed's relay." })),
        )
            .into_response();
    };
    let Some(stream) = stream_id_from(&watch_url) else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "Could not reach the feed's relay." })),
        )
            .into_response();
    };

    let url = format!(
        "{root}/origin/{stream}/clips/{}.mp4?token={token}",
        req.name.replace(' ', "%20"),
    );
    match st.http.delete(&url).send().await {
        // 404 is success from where the viewer stands: the clip is gone, which
        // is what they asked for. Anything else is reported.
        Ok(r) if r.status().is_success() || r.status() == StatusCode::NOT_FOUND => {
            tracing::info!(%username, clip = %req.name, "portal: clip deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(r) => {
            tracing::warn!(%username, clip = %req.name, status = r.status().as_u16(),
                "portal: the relay would not delete the clip");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "The relay would not delete that clip." })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(%username, clip = %req.name, error = %e,
                "portal: could not reach the relay to delete the clip");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "Could not reach the feed's relay." })),
            )
                .into_response()
        }
    }
}

/// The stream a watch URL points at — `…/dvr/{stream}?token=…`.
fn stream_id_from(watch_url: &str) -> Option<String> {
    let before_query = watch_url.split('?').next()?;
    let last = before_query.rsplit('/').next()?;
    (!last.is_empty()).then(|| last.to_string())
}

/// `POST /api/watch` — mint a viewing link for one feed.
///
/// The portal does not decide whether this is allowed; the manager re-checks
/// the entitlement before it signs anything. That is deliberate — the list the
/// browser is looking at was fetched some seconds ago, and access can be
/// withdrawn in between.
async fn watch(
    State(st): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<WatchRequest>,
) -> Response {
    let Some(username) = identify(&st.cfg, peer.ip(), &headers) else {
        return unauthenticated();
    };

    let url = format!("{}/api/v1/dvr/portal/token", st.cfg.manager_url);
    let resp = st
        .http
        .post(&url)
        .bearer_auth(&st.cfg.manager_token)
        .json(&serde_json::json!({
            "username": username,
            "session_id": req.session_id,
            // Pressing Watch is starting to watch, so this takes the login —
            // displacing whatever held it. The routes that mint only to check
            // a permission deliberately do not.
            "claim": true,
            "viewer_ip": viewer_address(peer.ip(), &headers),
        }))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "portal: manager token mint failed");
            return upstream_unavailable();
        }
    };

    // The manager answers one uniform refusal whether the user is not
    // entitled, the session does not exist, or it is not running — so that
    // this endpoint cannot be used to discover which feeds exist. Passing it
    // through as one message keeps that property.
    if resp.status() == StatusCode::FORBIDDEN {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "That feed is not available to you. It may have finished, \
                          or your access may have been changed."
            })),
        )
            .into_response();
    }
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "portal: manager refused to mint");
        return upstream_unavailable();
    }

    let body: TokenResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "portal: unreadable mint response");
            return upstream_unavailable();
        }
    };
    Json(serde_json::json!({
        // The holder id rides on the URL beside the token, so the player picks
        // both up the same way and can prove on renewal that it is still the
        // device holding this login.
        "watch_url": match body.holder.as_deref() {
            Some(h) if !h.is_empty() => {
                let sep = if body.watch_url.contains('?') { '&' } else { '?' };
                format!("{}{sep}hold={h}", body.watch_url)
            }
            _ => body.watch_url.clone(),
        },
        "expires_in_secs": body.expires_in_secs,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A viewer's credential does not travel in a link they are told to save.
    ///
    /// Downloads used to point straight at the origin with `?token=` on the
    /// end, which puts the credential in the browser's history, in the
    /// referrer, and in the access log of everything between the portal and
    /// the relay — for a URL a viewer is meant to right-click and keep. The
    /// portal proxies instead, so the link it hands out is its own.
    #[test]
    fn a_download_link_carries_no_credential() {
        let js = include_str!("portal.js");
        // The href comes from the API, so this is really a check on the
        // shape the API is expected to return — asserted here because it is
        // the page that puts it in front of a viewer.
        assert!(
            js.contains("a.href = c.url"),
            "the download link is built some other way now; re-check this"
        );

        // And the value the API builds is same-origin and token-free.
        let src = include_str!("mod.rs");
        let built = src
            .split("\"url\": if c.ready {")
            .nth(1)
            .expect("the download url is no longer built here");
        let built = &built[..built.len().min(400)];
        assert!(
            built.contains("/api/clips/download"),
            "downloads no longer go through the portal: {built}"
        );
        assert!(
            !built.contains("token="),
            "a viewer token is back in the download link: {built}"
        );
    }

    /// The page's own script may only talk to the page's own origin.
    ///
    /// `connect-src 'self'` is deliberate, and it means every `fetch` in
    /// `portal.js` must be same-origin. The Delete button reached for the
    /// relay directly and was blocked by the browser before a request was
    /// made: it failed every time, no log anywhere recorded an attempt, and
    /// the relay was perfectly willing all along. Downloads were unaffected
    /// because a link is a navigation, not a fetch.
    ///
    /// So this pins both halves — the policy, and the script honouring it.
    #[test]
    fn the_portal_script_only_fetches_its_own_origin() {
        let html = include_str!("portal.html");
        let js = include_str!("portal.js");

        assert!(
            PAGE_CSP.contains("connect-src 'self'"),
            "the policy this test defends has been relaxed; if that was deliberate,              this test should be reconsidered rather than deleted"
        );
        let _ = html;

        // Every fetch target must be a same-origin path. An absolute URL is
        // the failure mode: it looks reasonable in review and cannot work.
        let mut rest = js;
        let mut checked = 0;
        while let Some(i) = rest.find("fetch(") {
            rest = &rest[i + "fetch(".len()..];
            let arg = rest.trim_start();
            assert!(
                arg.starts_with('\'') || arg.starts_with('"'),
                "a fetch target that is not a literal cannot be checked here: {}",
                &arg[..arg.len().min(80)]
            );
            let quote = arg.as_bytes()[0] as char;
            let end = arg[1..].find(quote).expect("unterminated fetch target") + 1;
            let target = &arg[1..end];
            assert!(
                target.starts_with('/') && !target.starts_with("//"),
                "portal.js fetches '{target}', which the page's own CSP forbids —                  route it through the portal instead"
            );
            checked += 1;
        }
        assert!(checked >= 3, "only {checked} fetches found; the scan is not working");
    }
    use std::collections::HashSet;

    fn cfg(trusted: &[&str]) -> PortalConfig {
        PortalConfig {
            listen_addr: "127.0.0.1:8088".into(),
            manager_url: "https://manager.example".into(),
            manager_token: "t".into(),
            username_header: "remote-user".into(),
            trusted_proxies: trusted.iter().map(|s| s.parse().unwrap()).collect::<HashSet<_>>(),
            player_origins: Vec::new(),
            logout_url: None,
        }
    }

    fn hdrs(user: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(u) = user {
            h.insert("remote-user", u.parse().unwrap());
        }
        h
    }

    #[test]
    fn a_trusted_proxy_carrying_a_username_identifies_it() {
        let c = cfg(&["127.0.0.1"]);
        assert_eq!(
            identify(&c, "127.0.0.1".parse().unwrap(), &hdrs(Some("a.smith"))),
            Some("a.smith".into())
        );
        // Trimmed, but not otherwise altered — case is significant because
        // Authelia's is.
        assert_eq!(
            identify(&c, "127.0.0.1".parse().unwrap(), &hdrs(Some("  A.Smith  "))),
            Some("A.Smith".into())
        );
    }

    /// The header is a claim. From anywhere but the proxy it is the client
    /// asserting who it is, so it must not even be read.
    #[test]
    fn an_untrusted_peer_is_nobody_however_convincing_the_header() {
        let c = cfg(&["127.0.0.1"]);
        for peer in ["10.0.0.7", "203.0.113.9", "::1"] {
            assert_eq!(
                identify(&c, peer.parse().unwrap(), &hdrs(Some("admin"))),
                None,
                "trusted {peer}"
            );
        }
    }

    /// With no proxy configured the portal identifies nobody at all, rather
    /// than falling back to trusting everyone.
    #[test]
    fn no_configured_proxy_means_no_users() {
        let c = cfg(&[]);
        assert_eq!(
            identify(&c, "127.0.0.1".parse().unwrap(), &hdrs(Some("a.smith"))),
            None
        );
    }

    #[test]
    fn a_missing_or_unusable_username_is_nobody() {
        let c = cfg(&["127.0.0.1"]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(identify(&c, peer, &hdrs(None)), None);
        for bad in ["", "   ", "has space", &"x".repeat(257)] {
            assert_eq!(identify(&c, peer, &hdrs(Some(bad))), None, "accepted {bad:?}");
        }
    }

    /// The header name is configurable, and only the configured one counts —
    /// otherwise a deployment that renamed it would still admit the default.
    #[test]
    fn only_the_configured_header_is_read() {
        let mut c = cfg(&["127.0.0.1"]);
        c.username_header = "x-authelia-user".into();
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(identify(&c, peer, &hdrs(Some("a.smith"))), None);

        let mut h = HeaderMap::new();
        h.insert("x-authelia-user", "a.smith".parse().unwrap());
        assert_eq!(identify(&c, peer, &h), Some("a.smith".into()));
    }
}
