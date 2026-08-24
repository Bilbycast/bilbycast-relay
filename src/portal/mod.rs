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
        .route("/api/watch", post(watch))
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
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            ),
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
    let url = format!("{}/api/v1/dvr/portal/streams", st.cfg.manager_url);
    let resp = st
        .http
        .get(&url)
        .query(&[("username", username)])
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
async fn mint(st: &PortalState, username: &str, session_id: &str) -> Result<String, Response> {
    let url = format!("{}/api/v1/dvr/portal/token", st.cfg.manager_url);
    let resp = st
        .http
        .post(&url)
        .bearer_auth(&st.cfg.manager_token)
        .json(&serde_json::json!({ "username": username, "session_id": session_id }))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "portal: manager token mint failed");
            upstream_unavailable()
        })?;

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
    Ok(body.watch_url)
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

#[derive(Debug, Deserialize)]
pub struct WatchQuery {
    /// The relay's stream id, not the session id — the player knows which
    /// stream it is showing and nothing else about the session behind it.
    pub stream: String,
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

    match mint(&st, &username, &hit.session_id).await {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => Redirect::to("/").into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct WatchRequest {
    pub session_id: String,
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
        "watch_url": body.watch_url,
        "expires_in_secs": body.expires_in_secs,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn cfg(trusted: &[&str]) -> PortalConfig {
        PortalConfig {
            listen_addr: "127.0.0.1:8088".into(),
            manager_url: "https://manager.example".into(),
            manager_token: "t".into(),
            username_header: "remote-user".into(),
            trusted_proxies: trusted.iter().map(|s| s.parse().unwrap()).collect::<HashSet<_>>(),
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
