// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The portal over real HTTP, against a stub manager.
//!
//! The unit tests in `portal::tests` pin the identification decision. These
//! pin the things only a real request can be wrong about: whether the peer
//! address reaches the handler at all (it does not, without
//! `into_make_service_with_connect_info`), which URL the manager is called on,
//! whether the service token is actually attached, and which of the manager's
//! answers reach the viewer unchanged.
//!
//! The stub records what it was asked, so a call that goes to the wrong path or
//! arrives without a bearer fails here rather than at deployment.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use bilbycast_relay::portal::{self, PortalConfig, PortalState};
use serde::Deserialize;

const SERVICE_TOKEN: &str = "portal-service-token";

#[derive(Default)]
struct Seen {
    /// Every (path, authorization, query-or-body) the manager was asked.
    calls: Vec<(String, String, String)>,
    /// What the next mint should answer with.
    mint_status: u16,
    /// What the next heartbeat should answer with, and whether it lands.
    beat_status: u16,
    beat_held: bool,
}

type Recorder = Arc<Mutex<Seen>>;

#[derive(Deserialize)]
struct StreamsQuery {
    username: String,
}

async fn stub_streams(
    State(rec): State<Recorder>,
    headers: HeaderMap,
    Query(q): Query<StreamsQuery>,
) -> Json<serde_json::Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    rec.lock().unwrap().calls.push((
        "/api/v1/dvr/portal/streams".into(),
        auth,
        q.username.clone(),
    ));

    // The field set here is not invented: it is what
    // `manager-core`'s `dump_portal_contract` test prints, which is the
    // manager's own serialiser rather than a transcription of it. The portal
    // lives in a different repo and cannot import that type, so this is the
    // seam where a fixture would otherwise drift in silence.
    //
    // Only `a.smith` has anything; anyone else gets an empty list, which is
    // what the real manager does for an unknown username.
    let streams = if q.username == "a.smith" {
        serde_json::json!([
            { "session_id": "s1", "name": "Match feed",
              "stream_id": "match-feed", "state": "active", "relay_node_id": "n1" }
        ])
    } else {
        serde_json::json!([])
    };
    Json(serde_json::json!({ "streams": streams }))
}

async fn stub_token(
    State(rec): State<Recorder>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let status = {
        let mut g = rec.lock().unwrap();
        g.calls
            .push(("/api/v1/dvr/portal/token".into(), auth, body.clone()));
        g.mint_status
    };
    if status == 403 {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "not available to this user" })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "watch_url": "https://relay.example/dvr/match-feed?token=1800000000.match-feed,match-feed-proxy.abc",
        "expires_in_secs": 10_800,
        "stream_id": "match-feed",
        "name": "Match feed",
    }))
    .into_response()
}

async fn stub_heartbeat(
    State(rec): State<Recorder>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let (status, held) = {
        let mut g = rec.lock().unwrap();
        g.calls
            .push(("/api/v1/dvr/portal/heartbeat".into(), auth, body.clone()));
        (g.beat_status, g.beat_held)
    };
    if status != 200 {
        return (
            axum::http::StatusCode::from_u16(status).unwrap(),
            Json(serde_json::json!({ "error": "refused" })),
        )
            .into_response();
    }
    // The manager's real reply is `{held, next_beat_secs}`. The extra fields
    // are not something it sends today; they stand in for whatever it might
    // add later, to pin that the portal projects rather than forwards.
    Json(serde_json::json!({
        "held": held,
        "next_beat_secs": 60,
        "session_id": "s1",
        "displaced_ip": "203.0.113.9",
    }))
    .into_response()
}

/// Bring up a stub manager and a portal pointed at it. Returns the portal's
/// base URL and the recorder.
async fn harness() -> (String, Recorder) {
    harness_trusting(&["127.0.0.1"]).await
}

/// The same, with a player origin allow-listed, so `/api/renew` is reachable.
async fn harness_with_player_origin(origin: &str) -> (String, Recorder) {
    harness_cfg(&["127.0.0.1"], &[origin]).await
}

/// The same, with the trusted-proxy list under the test's control — the one
/// thing that decides whether a username header means anything.
async fn harness_trusting(trusted: &[&str]) -> (String, Recorder) {
    harness_cfg(trusted, &[]).await
}

async fn harness_cfg(trusted: &[&str], player_origins: &[&str]) -> (String, Recorder) {
    let rec: Recorder = Arc::new(Mutex::new(Seen {
        calls: Vec::new(),
        mint_status: 200,
        beat_status: 200,
        beat_held: true,
    }));

    let manager = Router::new()
        .route("/api/v1/dvr/portal/streams", get(stub_streams))
        .route("/api/v1/dvr/portal/token", post(stub_token))
        .route("/api/v1/dvr/portal/heartbeat", post(stub_heartbeat))
        .with_state(rec.clone());
    let ml = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let maddr = ml.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(ml, manager).await;
    });

    let mut cfg = PortalConfig {
        listen_addr: "127.0.0.1:0".into(),
        manager_url: format!("http://{maddr}"),
        manager_token: SERVICE_TOKEN.into(),
        username_header: "remote-user".into(),
        trusted_proxies: trusted.iter().map(|s| s.parse().unwrap()).collect(),
        player_origins: player_origins.iter().map(|s| (*s).to_string()).collect(),
        accounts: None,
        mail: None,
        logout_url: Some("https://auth.example/logout".into()),
    };
    cfg.normalise();

    let state = portal_state(cfg);
    let pl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let paddr = pl.local_addr().unwrap();
    let app = portal::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(pl, app).await;
    });

    (format!("http://{paddr}"), rec)
}

/// The portal as the binary builds it, clients included, so every test here
/// runs through the same client policy production does — no redirect
/// followed, the same deadlines.
fn portal_state(cfg: PortalConfig) -> PortalState {
    let clients = portal::clients::Clients::build().unwrap();
    PortalState {
        cfg: Arc::new(cfg),
        http: clients.http,
        media: clients.media,
        last_beat_answer: Default::default(),
        links: Default::default(),
    }
}

/// `reqwest` is built with `rustls-no-provider`, so a client built without an
/// installed provider panics at the first request rather than failing to
/// compile. The portal's own clients carry a finished TLS config and need
/// none; the bare client below, which stands in for a browser, does.
fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn client() -> reqwest::Client {
    install_provider();
    reqwest::Client::new()
}

#[tokio::test]
async fn a_signed_in_user_sees_their_feeds_and_the_manager_is_asked_correctly() {
    let (base, rec) = harness().await;

    let r = client()
        .get(format!("{base}/api/feeds"))
        .header("Remote-User", "a.smith")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();

    assert_eq!(body["username"], "a.smith");
    assert_eq!(body["feeds"].as_array().unwrap().len(), 1);
    assert_eq!(body["feeds"][0]["name"], "Match feed");
    assert_eq!(body["feeds"][0]["session_id"], "s1");

    // The relay a session lives on is the manager's business, not the
    // viewer's, and must not be forwarded.
    assert!(body["feeds"][0].get("relay_node_id").is_none());
    assert!(body["feeds"][0].get("stream_id").is_none());

    let calls = &rec.lock().unwrap().calls;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "/api/v1/dvr/portal/streams");
    assert_eq!(calls[0].1, format!("Bearer {SERVICE_TOKEN}"));
    assert_eq!(calls[0].2, "a.smith", "the manager was asked about the wrong user");
}

/// The header is a claim, and from an untrusted peer it is the client
/// asserting who it is. The same request that succeeds above must fail here
/// purely because of where it came from — and the manager must not be asked at
/// all, which is what would break if `ConnectInfo` ever stopped reaching the
/// handler and the peer silently read as something trusted.
#[tokio::test]
async fn an_untrusted_peer_is_refused_however_convincing_the_header() {
    let (base, rec) = harness_trusting(&["10.9.9.9"]).await;

    for (path, method) in [("/api/feeds", "GET"), ("/api/watch", "POST")] {
        let req = if method == "GET" {
            client().get(format!("{base}{path}"))
        } else {
            client()
                .post(format!("{base}{path}"))
                .json(&serde_json::json!({ "session_id": "s1" }))
        };
        let r = req.header("Remote-User", "a.smith").send().await.unwrap();
        assert_eq!(r.status(), 401, "{path} admitted an untrusted peer");
    }
    assert!(
        rec.lock().unwrap().calls.is_empty(),
        "the manager was asked on behalf of a username nothing vouched for"
    );
}

/// A trusted peer that carries no username is nobody either — the proxy is
/// what puts the header on, so its absence means the request did not come
/// through sign-in.
#[tokio::test]
async fn a_trusted_peer_with_no_username_is_refused() {
    let (base, rec) = harness().await;
    let r = client().get(format!("{base}/api/feeds")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(rec.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn watching_mints_through_the_manager_and_returns_the_link() {
    let (base, rec) = harness().await;

    let r = client()
        .post(format!("{base}/api/watch"))
        .header("Remote-User", "a.smith")
        .json(&serde_json::json!({ "session_id": "s1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(body["watch_url"].as_str().unwrap().starts_with("https://relay.example/dvr/"));
    assert_eq!(body["expires_in_secs"], 10_800, "the three-hour TTL did not survive");

    let calls = &rec.lock().unwrap().calls;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "/api/v1/dvr/portal/token");
    assert_eq!(calls[0].1, format!("Bearer {SERVICE_TOKEN}"));

    // The username the manager re-checks against must be the one the PROXY
    // asserted, never one the browser could put in the body.
    let sent: serde_json::Value = serde_json::from_str(&calls[0].2).unwrap();
    assert_eq!(sent["username"], "a.smith");
    assert_eq!(sent["session_id"], "s1");
}

/// A viewer cannot name themselves. If the body could carry a username, the
/// entitlement check would be against whatever the browser typed.
#[tokio::test]
async fn a_username_in_the_body_is_ignored() {
    let (base, rec) = harness().await;

    let r = client()
        .post(format!("{base}/api/watch"))
        .header("Remote-User", "a.smith")
        .json(&serde_json::json!({ "session_id": "s1", "username": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let calls = &rec.lock().unwrap().calls;
    let sent: serde_json::Value = serde_json::from_str(&calls[0].2).unwrap();
    assert_eq!(sent["username"], "a.smith", "the browser chose who it was");
}

/// The manager answers one uniform refusal whether the user is not entitled,
/// the session is gone, or it is not running — so this endpoint cannot be used
/// to discover which feeds exist. The portal must pass that through as one
/// message rather than elaborating.
#[tokio::test]
async fn a_refusal_reaches_the_viewer_as_one_message() {
    let (base, rec) = harness().await;
    rec.lock().unwrap().mint_status = 403;

    for session in ["s1", "does-not-exist", "s-someone-elses"] {
        let r = client()
            .post(format!("{base}/api/watch"))
            .header("Remote-User", "a.smith")
            .json(&serde_json::json!({ "session_id": session }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let body: serde_json::Value = r.json().await.unwrap();
        let msg = body["error"].as_str().unwrap();
        assert!(
            msg.contains("not available to you"),
            "refusal for {session} said something else: {msg}"
        );
        // Nothing that distinguishes the three cases may leak.
        assert!(!msg.contains(session), "the refusal named the session");
    }
}

/// A user with no entitlements gets an empty list, not an error — the portal
/// has a sentence for that, and an error would send them to support.
#[tokio::test]
async fn an_unentitled_user_gets_an_empty_list() {
    let (base, _rec) = harness().await;
    let r = client()
        .get(format!("{base}/api/feeds"))
        .header("Remote-User", "nobody.special")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["feeds"].as_array().unwrap().len(), 0);
}

/// The page must be servable and must load its script from a route that
/// exists, or the portal is a blank screen with a CSP violation in the console.
#[tokio::test]
async fn the_page_and_its_script_are_both_served() {
    let (base, _rec) = harness().await;

    let r = client().get(format!("{base}/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let csp = r
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let html = r.text().await.unwrap();
    assert!(csp.contains("script-src 'self'"), "page shipped without a script CSP");
    assert!(
        html.contains("src=\"/portal.js\""),
        "the page does not load the script from the route that serves it"
    );
    // An inline <script> block would be blocked by the CSP the page sets on
    // itself, so it must not appear.
    assert!(!html.contains("<script>"), "page carries an inline script the CSP forbids");

    let js = client().get(format!("{base}/portal.js")).send().await.unwrap();
    assert_eq!(js.status(), 200);
    assert!(js.text().await.unwrap().contains("/api/feeds"));
}

/// A portal whose manager is not there. Returns the portal's base URL.
async fn harness_unreachable(player_origins: &[&str]) -> String {
    let mut cfg = PortalConfig {
        listen_addr: "127.0.0.1:0".into(),
        // Port 1 on loopback: nothing listens, and the connection refusal is
        // immediate rather than a timeout.
        manager_url: "http://127.0.0.1:1".into(),
        manager_token: SERVICE_TOKEN.into(),
        username_header: "remote-user".into(),
        trusted_proxies: ["127.0.0.1".parse().unwrap()].into_iter().collect(),
        player_origins: player_origins.iter().map(|s| (*s).to_string()).collect(),
        accounts: None,
        mail: None,
        logout_url: None,
    };
    cfg.normalise();
    let state = portal_state(cfg);
    let pl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let paddr = pl.local_addr().unwrap();
    let app = portal::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(pl, app).await;
    });
    format!("http://{paddr}")
}

/// A portal that cannot reach the manager must say so as a gateway problem —
/// not as the viewer not being signed in, which would send them round a login
/// loop that cannot fix it.
#[tokio::test]
async fn an_unreachable_manager_is_not_reported_as_a_login_problem() {
    let base = harness_unreachable(&[]).await;

    let r = client()
        .get(format!("{base}/api/feeds"))
        .header("Remote-User", "a.smith")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502);
    assert_ne!(r.status(), 401);
}

/// Health must answer without a username: a check that needed one would be
/// reporting on the proxy rather than on the portal.
#[tokio::test]
async fn health_needs_no_user() {
    let (base, _rec) = harness().await;
    let r = client().get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
}

/// Renewal answers only an allow-listed origin, and must not mint for others.
///
/// The request carries the viewer's session cookie cross-origin, which is
/// exactly the shape a CSRF wants. The origin is therefore checked **before
/// anything is done**, not before the answer is returned: an un-allowed origin
/// must not be able to cause a mint at all, and asserting the recorder saw no
/// manager call is the only way to tell "refused" from "refused after doing
/// the work".
#[tokio::test]
async fn renewal_answers_only_an_allow_listed_origin() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;

    let r = client()
        .get(format!("{base}/api/renew?stream=match-feed"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "an unlisted origin was answered");
    assert!(
        rec.lock().unwrap().calls.is_empty(),
        "an unlisted origin still caused the manager to be called"
    );
}

/// The allow-listed player gets a fresh token, and the browser may read it.
///
/// Renewal goes through the manager exactly as the first mint did — that
/// re-check is what keeps the three-hour expiry meaningful as revocation
/// latency rather than a countdown, so the manager call is asserted, not just
/// the answer. The CORS headers are asserted too: without them the browser
/// discards a 200 the portal went to the trouble of producing.
#[tokio::test]
async fn an_allow_listed_player_is_given_a_fresh_token() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;

    let r = client()
        .get(format!("{base}/api/renew?stream=match-feed"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    assert_eq!(
        h.get("access-control-allow-origin").unwrap(),
        "https://player.example"
    );
    assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
    assert_eq!(h.get("vary").unwrap(), "Origin");
    // The body is a credential; nothing should be storing it.
    assert_eq!(h.get("cache-control").unwrap(), "no-store");

    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body["token"].as_str().is_some_and(|t| !t.is_empty()),
        "no token in the renewal answer: {body}"
    );

    let calls = rec.lock().unwrap().calls.clone();
    assert!(
        calls.iter().any(|(p, a, _)| p == "/api/v1/dvr/portal/token"
            && a == &format!("Bearer {SERVICE_TOKEN}")),
        "renewal did not re-check entitlement through the manager: {calls:?}"
    );
}

/// A feed the viewer is not entitled to is refused, and refused as CORS.
///
/// "Unentitled" and "no such feed" are deliberately the same answer, so a
/// renewal cannot be used to enumerate feeds. The refusal still carries the
/// CORS headers — the origin is already allow-listed by that point, so
/// withholding them only turns a clear 403 into an opaque browser error.
#[tokio::test]
async fn a_feed_the_viewer_does_not_have_is_refused_without_leaking_that_it_exists() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;

    let r = client()
        .get(format!("{base}/api/renew?stream=someone-elses-feed"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(
        r.headers().get("access-control-allow-origin").unwrap(),
        "https://player.example",
        "the refusal reaches the browser as an opaque CORS error"
    );
    let calls = rec.lock().unwrap().calls.clone();
    assert!(
        !calls.iter().any(|(p, _, _)| p == "/api/v1/dvr/portal/token"),
        "a feed the viewer does not have was still minted: {calls:?}"
    );
}

/// Renewal is off entirely when no player origin is configured.
///
/// Empty means nobody, on purpose: a portal that has not been told which
/// player to trust does not offer renewal at all, rather than trusting
/// whatever asks.
#[tokio::test]
async fn renewal_is_refused_when_no_player_origin_is_configured() {
    let (base, rec) = harness().await;

    let r = client()
        .get(format!("{base}/api/renew?stream=match-feed"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(
        rec.lock().unwrap().calls.is_empty(),
        "renewal reached the manager with no player origin configured"
    );
}

/// The beat has the renewal's origin gate, and for the same reason.
///
/// It is a credentialed cross-origin POST — the shape a CSRF wants — so an
/// unlisted origin is refused **before anything is done**, and a portal that
/// has not been told which player to trust answers nobody. Asserting the
/// recorder saw no manager call is what tells "refused" from "refused after
/// writing the timestamp".
#[tokio::test]
async fn a_beat_answers_only_an_allow_listed_origin() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    let r = client()
        .post(format!("{base}/api/beat?stream=match-feed&held=dev-1"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "an unlisted origin was answered");
    assert!(
        rec.lock().unwrap().calls.is_empty(),
        "an unlisted origin still caused the manager to be called"
    );

    let (base, rec) = harness().await;
    let r = client()
        .post(format!("{base}/api/beat?stream=match-feed&held=dev-1"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        403,
        "a beat was answered with no player origin configured"
    );
    assert!(rec.lock().unwrap().calls.is_empty());
}

/// Nobody signed in is nobody to count. The refusal still carries the CORS
/// headers — the origin is allow-listed by then — so the player sees a 401
/// rather than an opaque browser error.
#[tokio::test]
async fn a_beat_without_a_session_is_refused_before_the_manager_is_asked() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    let r = client()
        .post(format!("{base}/api/beat?stream=match-feed&held=dev-1"))
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(
        r.headers().get("access-control-allow-origin").unwrap(),
        "https://player.example"
    );
    assert!(rec.lock().unwrap().calls.is_empty());
}

/// A beat that names no holder is malformed, not a fresh watch.
///
/// This is the opposite of the renewal's forgiving reading, on purpose: a
/// renewal that guesses keeps somebody watching, while a beat that guessed
/// would let any signed-in tab keep any row warm. So it must not reach the
/// manager at all — and an empty holder is no holder.
#[tokio::test]
async fn a_beat_without_a_holder_is_malformed() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    for q in ["stream=match-feed", "stream=match-feed&held="] {
        let r = client()
            .post(format!("{base}/api/beat?{q}"))
            .header("Remote-User", "a.smith")
            .header("Origin", "https://player.example")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "{q} was not refused as malformed");
    }
    assert!(
        rec.lock().unwrap().calls.is_empty(),
        "a beat with no holder reached the manager"
    );
}

/// Junk is refused here, where it is free, not paid for with a manager round
/// trip and a Postgres comparison once a minute. The holder is held to the
/// cap the manager holds a mint's to, and the stream to the relay's own id
/// rule — the same one the player checks before it builds a link.
#[tokio::test]
async fn an_oversized_beat_is_refused_before_the_manager_is_asked() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    let long_holder = "h".repeat(65);
    let long_stream = "s".repeat(129);
    for q in [
        format!("stream=match-feed&held={long_holder}"),
        format!("stream={long_stream}&held=dev-1"),
        "stream=match%2Ffeed&held=dev-1".to_string(),
        "stream=...&held=dev-1".to_string(),
    ] {
        let r = client()
            .post(format!("{base}/api/beat?{q}"))
            .header("Remote-User", "a.smith")
            .header("Origin", "https://player.example")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "{q} was forwarded");
    }
    assert!(
        rec.lock().unwrap().calls.is_empty(),
        "an unbounded beat reached the manager"
    );
    // And the edge of the rule is inside it, or a real holder is refused.
    let r = client()
        .post(format!(
            "{base}/api/beat?stream=match-feed&held={}",
            "h".repeat(64)
        ))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// A beat reaches the manager on the route it serves, under the service
/// token, naming the viewer the PROXY vouched for — never one the browser put
/// in the query — and the player may read the answer.
#[tokio::test]
async fn a_beat_reaches_the_manager_under_the_proxys_username() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    let r = client()
        .post(format!(
            "{base}/api/beat?stream=match-feed&held=dev-1&username=admin"
        ))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    assert_eq!(
        h.get("access-control-allow-origin").unwrap(),
        "https://player.example"
    );
    assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
    assert_eq!(h.get("vary").unwrap(), "Origin");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["held"], true);
    assert_eq!(
        body["next_beat_secs"], 60,
        "the manager's cadence did not reach the player"
    );
    // Projected, not forwarded: what the player reads and nothing else. The
    // stub answers with two extra fields standing in for whatever the manager
    // may add to this reply later.
    assert_eq!(
        body.as_object().unwrap().len(),
        2,
        "the manager's reply reached the browser unprojected: {body}"
    );

    let calls = rec.lock().unwrap().calls.clone();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].0, "/api/v1/dvr/portal/heartbeat");
    assert_eq!(calls[0].1, format!("Bearer {SERVICE_TOKEN}"));
    let sent: serde_json::Value = serde_json::from_str(&calls[0].2).unwrap();
    assert_eq!(sent["username"], "a.smith", "the browser chose who it was");
    assert_eq!(sent["stream_id"], "match-feed");
    assert_eq!(sent["holder"], "dev-1");
}

/// `held: false` is the one answer that must reach the player unchanged: it
/// is what tells a displaced tab to stop beating rather than retry.
#[tokio::test]
async fn a_displaced_players_beat_is_answered_held_false() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    rec.lock().unwrap().beat_held = false;
    let r = client()
        .post(format!("{base}/api/beat?stream=match-feed&held=dev-1"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["held"], false, "{body}");
}

/// A lost beat is not worth an error to the viewer. The picture is playing;
/// the only casualty is a number on an operator's screen, and the next beat
/// is a minute away — so a manager that refuses, or is not there, is answered
/// as `held: true` and the player keeps going.
#[tokio::test]
async fn a_lost_beat_is_not_reported_to_the_viewer() {
    let (base, rec) = harness_with_player_origin("https://player.example").await;
    for status in [404u16, 401, 500] {
        rec.lock().unwrap().beat_status = status;
        let r = client()
            .post(format!("{base}/api/beat?stream=match-feed&held=dev-1"))
            .header("Remote-User", "a.smith")
            .header("Origin", "https://player.example")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "a manager {status} reached the viewer");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body["held"], true,
            "a manager {status} stopped the player: {body}"
        );
    }

    let base = harness_unreachable(&["https://player.example"]).await;
    let r = client()
        .post(format!("{base}/api/beat?stream=match-feed&held=dev-1"))
        .header("Remote-User", "a.smith")
        .header("Origin", "https://player.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "an unreachable manager reached the viewer");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["held"], true,
        "an unreachable manager stopped the player: {body}"
    );
}
