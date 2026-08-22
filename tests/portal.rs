// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

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

/// Bring up a stub manager and a portal pointed at it. Returns the portal's
/// base URL and the recorder.
async fn harness() -> (String, Recorder) {
    harness_trusting(&["127.0.0.1"]).await
}

/// The same, with the trusted-proxy list under the test's control — the one
/// thing that decides whether a username header means anything.
async fn harness_trusting(trusted: &[&str]) -> (String, Recorder) {
    let rec: Recorder = Arc::new(Mutex::new(Seen {
        calls: Vec::new(),
        mint_status: 200,
    }));

    let manager = Router::new()
        .route("/api/v1/dvr/portal/streams", get(stub_streams))
        .route("/api/v1/dvr/portal/token", post(stub_token))
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
    };
    cfg.normalise();

    let state = PortalState {
        cfg: Arc::new(cfg),
        http: reqwest::Client::new(),
    };
    let pl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let paddr = pl.local_addr().unwrap();
    let app = portal::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(pl, app).await;
    });

    (format!("http://{paddr}"), rec)
}

fn client() -> reqwest::Client {
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

/// A portal that cannot reach the manager must say so as a gateway problem —
/// not as the viewer not being signed in, which would send them round a login
/// loop that cannot fix it.
#[tokio::test]
async fn an_unreachable_manager_is_not_reported_as_a_login_problem() {
    let mut cfg = PortalConfig {
        listen_addr: "127.0.0.1:0".into(),
        // Port 1 on loopback: nothing listens, and the connection refusal is
        // immediate rather than a timeout.
        manager_url: "http://127.0.0.1:1".into(),
        manager_token: SERVICE_TOKEN.into(),
        username_header: "remote-user".into(),
        trusted_proxies: ["127.0.0.1".parse().unwrap()].into_iter().collect(),
    };
    cfg.normalise();
    let state = PortalState {
        cfg: Arc::new(cfg),
        http: reqwest::Client::new(),
    };
    let pl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let paddr = pl.local_addr().unwrap();
    let app = portal::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(pl, app).await;
    });

    let r = client()
        .get(format!("http://{paddr}/api/feeds"))
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
