// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The portal's outbound HTTP clients, built the one way the binary uses.
//!
//! Here rather than in `portal_bin.rs` so the policy they carry can be tested:
//! a builder that lives only in `main` is one no test can reach.

use std::sync::Arc;

/// The two clients [`super::PortalState`] holds. See its fields for why there
/// are two.
pub struct Clients {
    pub http: reqwest::Client,
    pub media: reqwest::Client,
}

impl Clients {
    /// Build both clients.
    ///
    /// **Neither follows a redirect.** Nothing the portal calls answers with
    /// one — not the manager's API, not Authelia's `/api/health` or
    /// `/api/reset-password/identity/start`, not the relay's origin — so a 3xx
    /// is reported through the callers' existing "did not answer 2xx"
    /// branches, as the refusal it is. Followed, it would do harm: a 307 or
    /// 308 re-sends a POST body (usernames, a viewer's IP, a session id) to
    /// wherever `Location` points, another host or plain `http://` included.
    /// That would quietly undo the rules `validate()` enforces, among them
    /// that Authelia is spoken to in plaintext only on loopback. reqwest
    /// strips `Authorization` on a cross-host hop, but not the body, the
    /// query or the headers it does not consider sensitive.
    ///
    /// Not `https_only`, on either. Both reach URLs that may validly be
    /// `http://`: `http` talks to a loopback Authelia and, under
    /// `BILBYCAST_ALLOW_INSECURE=1`, to a plaintext `manager_url`; both talk
    /// to the relay origin the manager's watch URL names, and a relay's
    /// `public_base_url` may be `http://`. Which scheme each URL may use is
    /// decided by config validation, per URL.
    pub fn build() -> reqwest::Result<Self> {
        let tls = tls_config();
        Ok(Self {
            http: reqwest::Client::builder()
                .use_preconfigured_tls(tls.clone())
                .redirect(reqwest::redirect::Policy::none())
                // The manager is one hop away and answers from a database. A
                // request that has not come back in ten seconds is not going to.
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
            // A clip, though, is up to 256 MiB proxied to a viewer at the
            // viewer's own rate, and reqwest's `timeout` covers the body too —
            // so the manager's deadline truncated every download that took
            // longer than ten seconds, which on a 10 Mbit/s line is anything
            // over about 12 MB. Connect and read deadlines instead: a stalled
            // origin is still caught, a slow viewer is not mistaken for one.
            media: reqwest::Client::builder()
                .use_preconfigured_tls(tls)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(10))
                .read_timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}

/// Hand reqwest a finished rustls config rather than letting it assemble one.
///
/// Under `rustls-no-provider` it has neither: it calls the strict
/// `CryptoProvider::get_default()`, which reads a process-installed provider
/// and never crate features, and panics when nothing is installed. Supplying
/// the config installs ring inline and keeps the portal on the bundled webpki
/// roots — the same roots the relay's own manager link uses — so a host with
/// an empty /etc/ssl/certs, which is every static-musl deployment, still
/// reaches the manager.
fn tls_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // `use_preconfigured_tls` takes the config verbatim, so reqwest sets no
    // ALPN of its own and the `http2` feature would never negotiate h2.
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{
        Router,
        http::{StatusCode, header},
        routing::any,
    };

    /// Two stubs on loopback: one that answers everything with `status` and
    /// `Location` pointing at the other, and the other, which counts how often
    /// anything arrives. Different ports, so to reqwest the hop is to another
    /// host, the case that matters.
    async fn redirect_to_elsewhere(status: StatusCode) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let elsewhere = Router::new().fallback(any(move || {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                "you should not be here"
            }
        }));
        let el = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("http://{}/collect", el.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(el, elsewhere).await;
        });

        let redirector = Router::new().fallback(any(move || {
            let target = target.clone();
            async move { (status, [(header::LOCATION, target)]) }
        }));
        let rl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let from = format!(
            "http://{}/api/v1/dvr/portal/token",
            rl.local_addr().unwrap()
        );
        tokio::spawn(async move {
            let _ = axum::serve(rl, redirector).await;
        });
        (from, hits)
    }

    /// The shape of the leak: a POST carrying a username, answered with a
    /// redirect to somewhere else.
    async fn post_username(
        client: &reqwest::Client,
        url: &str,
    ) -> reqwest::Result<reqwest::Response> {
        client
            .post(url)
            .bearer_auth("service-token")
            .json(&serde_json::json!({ "username": "alice", "viewer_ip": "203.0.113.7" }))
            .send()
            .await
    }

    /// Neither production client follows a redirect of any kind: the 3xx comes
    /// back to the caller as the answer, and the other host never hears a
    /// thing. 307 and 308 are the ones that re-send the body; the rest are
    /// here so a policy that stops only some of them still fails.
    #[tokio::test]
    async fn neither_client_follows_a_redirect() {
        let clients = Clients::build().unwrap();
        for status in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::SEE_OTHER,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            for (name, client) in [("http", &clients.http), ("media", &clients.media)] {
                let (url, hits) = redirect_to_elsewhere(status).await;
                let resp = post_username(client, &url).await.unwrap_or_else(|e| {
                    panic!("{name}: a {status} is an answer, not an error: {e}")
                });
                assert_eq!(
                    resp.status(),
                    status,
                    "{name} did not hand back the {status}"
                );
                assert_eq!(
                    hits.load(Ordering::SeqCst),
                    0,
                    "the {name} client followed a {status} and re-sent the request elsewhere"
                );
            }
        }
    }

    /// What the test above would miss if the rig were broken: a client on
    /// reqwest's default policy, with the same TLS, does follow the 308 and
    /// lands on the other stub. Without this, "zero hits" could just mean the
    /// redirect never pointed anywhere reachable.
    #[tokio::test]
    async fn the_rig_catches_a_client_that_follows() {
        let following = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config())
            .build()
            .unwrap();
        let (url, hits) = redirect_to_elsewhere(StatusCode::PERMANENT_REDIRECT).await;
        let resp = post_username(&following, &url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
