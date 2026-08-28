// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Portal configuration.
//!
//! Every default here is the safe one, because the unsafe settings are not
//! obviously unsafe: a portal on `0.0.0.0` with an empty `trusted_proxies` is
//! an open door that looks exactly like a working install until someone sets
//! a header.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The environment variable the service token is normally supplied through.
///
/// Preferred over the config file so the secret can live in a systemd
/// `EnvironmentFile` with its own permissions, rather than in a JSON file that
/// gets copied around while someone is debugging.
pub const TOKEN_ENV: &str = "BILBYCAST_PORTAL_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalConfig {
    /// Where to listen. **Loopback by default**: the only supported way in is
    /// through the authenticating proxy on the same host, and a portal reachable
    /// from anywhere else is one where `Remote-User` means nothing.
    #[serde(default = "default_listen")]
    pub listen_addr: String,

    /// The manager's base URL, e.g. `https://manager.example.com`. No trailing
    /// slash — `normalise` strips one if it is there.
    pub manager_url: String,

    /// The shared service token, matching the manager's `dvr_portal_service_token`
    /// setting. Normally supplied through [`TOKEN_ENV`] instead of this field.
    #[serde(default)]
    pub manager_token: String,

    /// The header the authenticating proxy puts the username in. Authelia's
    /// forward-auth default is `Remote-User`.
    #[serde(default = "default_header")]
    pub username_header: String,

    /// Where "sign out" sends someone — normally the identity provider's own
    /// logout, e.g. `https://auth.example.com/logout`.
    ///
    /// The portal cannot end the session itself: it never authenticated
    /// anyone. Authelia holds the cookie and only Authelia can clear it, so
    /// the most this can do is send the viewer to the right place. Unset means
    /// no button is offered, which is better than one that appears to work and
    /// leaves them signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logout_url: Option<String>,

    /// Peers whose `username_header` is believed. **Empty means nobody**, which
    /// is why the default is populated rather than left to mean "any": an empty
    /// list that meant "trust all" would turn a typo into an open portal.
    #[serde(default = "default_proxies")]
    pub trusted_proxies: HashSet<IpAddr>,

    /// Player origins allowed to renew a token in the background, e.g.
    /// `https://relay.example.com`.
    ///
    /// The player is served by the relay and the portal by this service, so a
    /// renewal is a cross-origin request carrying the viewer's Authelia
    /// cookie. That is exactly the shape a CSRF wants, so the list is explicit
    /// and **empty means nobody** — a portal that has not been told which
    /// player to trust simply does not offer renewal, and viewers fall back to
    /// signing in again when their three hours are up.
    ///
    /// Wildcards are not accepted, and could not be: a response carrying
    /// `Access-Control-Allow-Credentials` may not answer `*`.
    #[serde(default)]
    pub player_origins: Vec<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8088".to_string()
}

fn default_header() -> String {
    "Remote-User".to_string()
}

/// Loopback, both families. The proxy is on the same host in every supported
/// deployment; anything else has to be named explicitly.
fn default_proxies() -> HashSet<IpAddr> {
    ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()]
        .into_iter()
        .collect()
}

impl PortalConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        let mut cfg: PortalConfig = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", path.display()))?;
        cfg.normalise();
        Ok(cfg)
    }

    /// Fold in the environment and tidy the URL.
    ///
    /// The env var wins over the file: the file is the thing that gets copied
    /// between hosts, so a stale token in it must not override the one the
    /// service was actually started with.
    pub fn normalise(&mut self) {
        if let Ok(t) = std::env::var(TOKEN_ENV) {
            let t = t.trim();
            if !t.is_empty() {
                self.manager_token = t.to_string();
            }
        }
        while self.manager_url.ends_with('/') {
            self.manager_url.pop();
        }
        // Header lookup is case-insensitive in `http`, but the stored name is
        // used to build a `HeaderName`, which must be lowercase.
        self.username_header = self.username_header.trim().to_ascii_lowercase();
        // An origin is scheme://host[:port] and nothing else. A trailing slash
        // is the obvious thing to write and would never match the `Origin`
        // header, so fix it here rather than failing silently at renewal time.
        for o in &mut self.player_origins {
            *o = o.trim().trim_end_matches('/').to_string();
        }
    }

    /// Everything that must be true before the service will start.
    ///
    /// Checked at startup rather than per request so a misconfigured portal
    /// refuses to run instead of refusing every viewer with a message that
    /// reads like their account being wrong.
    pub fn validate(&self) -> Result<(), String> {
        if self.manager_url.is_empty() {
            return Err("manager_url is required".into());
        }
        if !self.manager_url.starts_with("https://") && !self.manager_url.starts_with("http://") {
            return Err("manager_url must start with https:// or http://".into());
        }
        // `manager_token` rides on every request to this URL as a bearer
        // credential, so plaintext hands the portal's service identity to
        // anyone on the path. Gated the way every other credential-bearing
        // escape hatch in the fleet is: an explicit env var, so it cannot be
        // reached by editing a config file alone.
        if self.manager_url.starts_with("http://")
            && std::env::var("BILBYCAST_ALLOW_INSECURE").unwrap_or_default() != "1"
        {
            return Err(format!(
                "manager_url {} is plaintext, and the portal sends its manager token on \
                 every request to it. Use https://, or set BILBYCAST_ALLOW_INSECURE=1 if \
                 this is a development host.",
                self.manager_url
            ));
        }
        // The token authenticates the portal to the manager. Without it every
        // request is refused, so failing here is the difference between one
        // clear startup error and a portal that loads and lists nothing.
        if self.manager_token.trim().is_empty() {
            return Err(format!(
                "no manager token: set {TOKEN_ENV} or `manager_token` in the config file"
            ));
        }
        if self.username_header.is_empty() {
            return Err("username_header cannot be empty".into());
        }
        if axum::http::HeaderName::try_from(self.username_header.as_str()).is_err() {
            return Err(format!("username_header `{}` is not a header name", self.username_header));
        }
        if let Some(ref url) = self.logout_url
            && !url.starts_with("http://") && !url.starts_with("https://") {
                return Err("logout_url must start with http:// or https://".into());
            }
        if self.trusted_proxies.is_empty() {
            return Err(
                "trusted_proxies is empty, so no request could ever be trusted to carry a \
                 username. List the authenticating proxy's address."
                    .into(),
            );
        }
        for o in &self.player_origins {
            // `*` cannot be answered alongside `Allow-Credentials`, and a
            // renewal without credentials is not a renewal. Refusing at
            // startup beats a portal that looks configured and never renews.
            if o == "*" {
                return Err(
                    "player_origins cannot contain `*`: a credentialed response may not                      answer a wildcard origin. List each player origin."
                        .into(),
                );
            }
            if !o.starts_with("http://") && !o.starts_with("https://") {
                return Err(format!("player_origins entry `{o}` must start with http:// or https://"));
            }
            // An `Origin` header is scheme://host[:port] — never a path. One
            // written with a path could not match, and would look like a
            // configured renewal that silently never fires.
            if o.split_once("://").is_some_and(|(_, rest)| rest.contains('/')) {
                return Err(format!(
                    "player_origins entry `{o}` has a path; an origin is scheme://host[:port]"
                ));
            }
        }
        self.listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("listen_addr `{}`: {e}", self.listen_addr))?;
        Ok(())
    }

    /// Is `origin` allowed to renew? Exact match, never a prefix.
    pub fn allows_player_origin(&self, origin: &str) -> bool {
        self.player_origins.iter().any(|o| o == origin)
    }

    pub fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        if self.trusted_proxies.contains(&peer) {
            return true;
        }
        // A v4 proxy reached over a dual-stack v6 socket arrives as
        // `::ffff:127.0.0.1`. Without this, the loopback default silently
        // fails on exactly the deployment it was written for.
        match peer {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .is_some_and(|v4| self.trusted_proxies.contains(&IpAddr::V4(v4))),
            IpAddr::V4(_) => false,
        }
    }

    /// Is this portal exposed beyond the host it runs on?
    ///
    /// Not an error — a deployment may legitimately put the proxy on another
    /// box — but it is the configuration where `Remote-User` stops being safe
    /// by construction, so it is said out loud at startup.
    pub fn binds_publicly(&self) -> bool {
        match self.listen_addr.parse::<std::net::SocketAddr>() {
            Ok(a) => !a.ip().is_loopback(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {

    /// The portal sends its manager token on every request, so a plaintext
    /// manager URL must not be reachable by editing a config file alone.
    #[test]
    fn a_plaintext_manager_url_needs_the_explicit_env_opt_in() {
        // SAFETY: single-threaded test, and the variable is read only here.
        unsafe { std::env::remove_var("BILBYCAST_ALLOW_INSECURE") };
        let mut cfg = PortalConfig {
            listen_addr: default_listen(),
            manager_url: "http://manager.internal".into(),
            manager_token: "t".repeat(32),
            username_header: default_header(),
            logout_url: None,
            trusted_proxies: default_proxies(),
        };
        let err = cfg.validate().expect_err("plaintext must be refused by default");
        assert!(err.contains("BILBYCAST_ALLOW_INSECURE"), "{err}");

        unsafe { std::env::set_var("BILBYCAST_ALLOW_INSECURE", "1") };
        assert!(cfg.validate().is_ok(), "the opt-in must actually allow it");
        unsafe { std::env::remove_var("BILBYCAST_ALLOW_INSECURE") };

        // https needs no opt-in.
        cfg.manager_url = "https://manager.internal".into();
        assert!(cfg.validate().is_ok());
    }
    use super::*;

    fn ok() -> PortalConfig {
        PortalConfig {
            listen_addr: default_listen(),
            manager_url: "https://manager.example".into(),
            manager_token: "tok".into(),
            username_header: default_header().to_ascii_lowercase(),
            trusted_proxies: default_proxies(),
            player_origins: Vec::new(),
            logout_url: None,
        }
    }

    /// Renewal is off unless a player origin is named, and `*` is refused.
    ///
    /// A credentialed response may not answer a wildcard origin — the browser
    /// rejects it — so `*` here would be a portal that looks configured for
    /// renewal and silently never renews, surfacing months later as "access
    /// expired mid-match". Refuse it at startup instead.
    #[test]
    fn renewal_is_off_by_default_and_refuses_a_wildcard() {
        let mut c = ok();
        assert!(c.player_origins.is_empty(), "renewal must not be on by default");
        assert!(!c.allows_player_origin("https://relay.example"));

        c.player_origins = vec!["*".into()];
        let err = c.validate().expect_err("a wildcard origin was accepted");
        // `*` is refused twice over — explicitly, and again by the scheme
        // check — so assert on the *message*, which is the only thing the
        // explicit check adds. Told "must start with https://", an operator
        // reaches for `https://*`; told why a wildcard cannot work with
        // credentials, they list the origin.
        assert!(
            err.contains("credential") || err.contains("wildcard"),
            "the wildcard refusal does not explain itself: {err}"
        );

        c.player_origins = vec!["https://relay.example/watch".into()];
        assert!(
            c.validate().is_err(),
            "an origin with a path was accepted; it could never match an Origin header"
        );

        c.player_origins = vec!["relay.example".into()];
        assert!(c.validate().is_err(), "a schemeless origin was accepted");
    }

    /// An origin must match exactly — never as a prefix.
    ///
    /// `https://relay.example.evil.com` starts with `https://relay.example`,
    /// and a prefix check would hand that site a viewing token belonging to
    /// whoever was signed in.
    #[test]
    fn a_player_origin_matches_exactly_and_not_by_prefix() {
        let mut c = ok();
        c.player_origins = vec!["https://relay.example".into()];
        assert!(c.allows_player_origin("https://relay.example"));
        assert!(!c.allows_player_origin("https://relay.example.evil.com"));
        assert!(!c.allows_player_origin("https://relay.example:8443"));
        assert!(!c.allows_player_origin("http://relay.example"));
        assert!(!c.allows_player_origin(""));
    }

    /// A trailing slash is the obvious thing to write and would never match.
    #[test]
    fn a_trailing_slash_on_a_player_origin_is_tidied_away() {
        let mut c = ok();
        c.player_origins = vec!["https://relay.example/".into()];
        c.normalise();
        assert!(c.allows_player_origin("https://relay.example"));
    }

    #[test]
    fn a_complete_config_validates() {
        assert_eq!(ok().validate(), Ok(()));
    }

    /// The whole point of the default: out of the box the portal listens where
    /// only the local proxy can reach it, and believes only the local proxy.
    #[test]
    fn the_defaults_are_the_closed_ones() {
        let c = ok();
        assert!(!c.binds_publicly());
        assert!(c.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        assert!(c.is_trusted_proxy("::1".parse().unwrap()));
        assert!(!c.is_trusted_proxy("10.0.0.1".parse().unwrap()));
    }

    /// A v4 proxy arriving over a dual-stack v6 listener presents as
    /// `::ffff:127.0.0.1`. Matching it is what stops the loopback default
    /// failing on the exact deployment it exists for.
    #[test]
    fn a_v4_mapped_loopback_peer_is_the_same_proxy() {
        assert!(ok().is_trusted_proxy("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!ok().is_trusted_proxy("::ffff:10.0.0.1".parse().unwrap()));
    }

    /// Each of these would produce a portal that starts and then fails every
    /// viewer in a way that looks like the viewer's fault.
    #[test]
    fn each_missing_piece_refuses_to_start() {
        fn refuses(what: &str, break_it: impl FnOnce(&mut PortalConfig)) {
            let mut c = ok();
            break_it(&mut c);
            assert!(c.validate().is_err(), "started with a broken {what}");
        }
        refuses("manager_url", |c| c.manager_url = String::new());
        refuses("scheme", |c| c.manager_url = "manager.example".into());
        refuses("token", |c| c.manager_token = "  ".into());
        refuses("header", |c| c.username_header = String::new());
        refuses("header name", |c| c.username_header = "bad header".into());
        refuses("trusted_proxies", |c| c.trusted_proxies.clear());
        refuses("listen_addr", |c| c.listen_addr = "not-an-address".into());
    }

    /// A config file that names only the manager must still come up closed.
    #[test]
    fn the_minimal_file_inherits_the_safe_defaults() {
        let c: PortalConfig =
            serde_json::from_str(r#"{"manager_url":"https://m.example"}"#).unwrap();
        assert_eq!(c.listen_addr, "127.0.0.1:8088");
        assert_eq!(c.username_header, "Remote-User");
        assert_eq!(c.trusted_proxies.len(), 2);
        // ...and refuses to start, because it has no token to authenticate with.
        assert!(c.validate().is_err());
    }

    /// The shipped example must actually be a starting point: it parses, and
    /// the only thing standing between it and a running portal is the token.
    /// An example that no longer matches the struct is worse than none, since
    /// the operator edits it before finding out.
    #[test]
    fn the_shipped_example_parses_and_only_wants_a_token() {
        let text = include_str!("../../portal-config.example.json");
        let mut c: PortalConfig = serde_json::from_str(text).expect("example does not parse");
        // Deliberately not `normalise()` — that would pick up a token from the
        // environment and hide the one thing this asserts.
        c.username_header = c.username_header.to_ascii_lowercase();
        assert!(!c.binds_publicly(), "the example binds off loopback");
        assert!(c.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        assert!(c.validate().unwrap_err().contains(TOKEN_ENV));

        c.manager_token = "supplied-by-the-environment".into();
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn normalise_trims_the_url_and_lowercases_the_header() {
        let mut c = ok();
        c.manager_url = "https://m.example///".into();
        c.username_header = "  Remote-User  ".into();
        c.normalise();
        assert_eq!(c.manager_url, "https://m.example");
        assert_eq!(c.username_header, "remote-user");
    }

    /// A logout URL that is not a URL would be rendered as a link the viewer
    /// is invited to click, so it is checked like the others.
    #[test]
    fn a_logout_url_must_be_a_url() {
        let mut c = ok();
        c.logout_url = Some("javascript:alert(1)".into());
        assert!(c.validate().is_err());
        c.logout_url = Some("auth.example.com".into());
        assert!(c.validate().is_err());
        c.logout_url = Some("https://auth.example.com/logout".into());
        assert_eq!(c.validate(), Ok(()));
        c.logout_url = None;
        assert_eq!(c.validate(), Ok(()), "no button is a valid choice");
    }

    #[test]
    fn a_bound_public_address_is_reported_as_such() {
        let mut c = ok();
        c.listen_addr = "0.0.0.0:8088".into();
        assert!(c.binds_publicly());
        c.listen_addr = "[::1]:8088".into();
        assert!(!c.binds_publicly());
    }
}
