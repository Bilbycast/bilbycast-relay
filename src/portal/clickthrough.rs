// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A page between the email and Authelia, so a link scanner cannot spend the
//! link.
//!
//! Authelia's set-password link is **one-time**, and its page submits the token
//! the moment it loads. Mail security that opens links to check them therefore
//! *uses the link up*: measured on 2026-10-02, an invitation to a Microsoft 365
//! mailbox was consumed by `172.186.9.0` (AS8075, Microsoft) seconds after
//! delivery, and the person who had been sent it was told the token "may have
//! expired" two minutes later. Every M365 recipient would hit this.
//!
//! So the email points here instead. This page:
//!
//! * **does nothing on `GET`** beyond rendering HTML — a scanner that fetches
//!   it, follows it, or renders it with JavaScript spends nothing, because
//!   there is nothing here to spend;
//! * carries **no link to Authelia** in its markup, so there is nothing for a
//!   crawler to follow; and
//! * moves on only when somebody **presses the button**, which is a form
//!   `POST` — the one thing automated link-checking does not do.
//!
//! The honest limits: a scanner that submitted forms would still spend the
//! link, and so would one that decoded the `u` parameter of the emailed URL
//! and fetched what it found. None of the ones that cause this behave either
//! way. The alternative — holding link state on disk so the token never leaves
//! this process — buys little against a scanner that renders *and* clicks, at
//! the cost of state to keep, expire and lose on a restart.
//!
//! It covers the links the portal asks for, which are the only ones
//! [`super::mail`] rewrites. A viewer who uses "Reset password" on Authelia's
//! sign-in page gets Authelia's own email, relayed unchanged.
//!
//! # Why the whole URL travels in the query
//!
//! Authelia mints the link; the portal only forwards it. Carrying the URL
//! rather than the token alone means this module needs to know nothing about
//! the path Authelia is served under — but it also means the value is
//! attacker-controlled, so [`permitted`] parses it and refuses anything that is
//! not Authelia's reset page on the host Authelia names in its links:
//! `accounts.public_host`, which is the portal's own host when Authelia sits
//! under a path there and Authelia's login host otherwise. Without that check
//! this would be an open redirect: a link on your own domain that bounces to
//! anywhere.

use super::PortalState;
use super::mail::{MailConfig, html_escape};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use reqwest::Url;
use serde::Deserialize;

/// Where the email sends people, under `click_through_base`.
pub const PATH: &str = "/set-password";

/// The page Authelia serves the real step at, at the end of whatever path
/// prefix it is served under.
const AUTHELIA_RESET_PATH: &str = "/reset-password/step2";

/// Every answer from this route. The page carries a one-time credential in its
/// own address, so nothing may cache it, frame it or pass that address on, and
/// it runs nothing: no script, nothing loaded from anywhere. `form-action` is
/// left out on purpose — browsers apply it to the redirect a form submission
/// is answered with, and that redirect goes to Authelia's host, which need not
/// be this one.
fn guarded() -> [(HeaderName, &'static str); 4] {
    [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; \
             base-uri 'none'",
        ),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
    ]
}

/// `u`: on the page's query, the Authelia URL as [`wrap`] encoded it; in the
/// form, the same URL as the page's hidden field holds it.
#[derive(Debug, Deserialize)]
pub(super) struct Link {
    #[serde(default)]
    u: String,
}

/// The URL to put in an email, for a link that should survive scanning.
///
/// `base` is where this portal answers, e.g. `https://watch.example.com`.
pub fn wrap(base: &str, authelia_link: &str) -> String {
    format!(
        "{}{PATH}?u={}",
        base.trim_end_matches('/'),
        percent_encode(authelia_link)
    )
}

/// The link an email should carry: this page's, when the page would take the
/// person on to `link` — and Authelia's own otherwise.
///
/// Checked here rather than trusted, because an email pointing at a page that
/// cannot work is worse than the problem this module exists for: a scanner
/// spends only *some* links, and that would spend every one. So a link this
/// page would refuse, a base it cannot be served at, or a base that is
/// Authelia's own goes out as Authelia wrote it, with a warning naming why.
pub fn email_link(cfg: &MailConfig, link: String) -> String {
    if !cfg.click_through {
        return link;
    }
    match through_the_page(cfg, &link) {
        Ok(wrapped) => wrapped,
        Err(why) => {
            tracing::warn!(reason = %why, "emailing Authelia's own link, not the set-password page");
            link
        }
    }
}

fn through_the_page(cfg: &MailConfig, link: &str) -> Result<String, String> {
    let base = cfg.click_through_base();
    let page = origin(base).ok_or_else(|| {
        format!(
            "`{base}` is not an https address of a host alone for the page to be served at; \
             set mail.click_through_base"
        )
    })?;
    let host = cfg
        .authelia_host
        .as_deref()
        .ok_or("no accounts block names the host Authelia's links are on")?;
    let url = permitted(host, link).ok_or_else(|| {
        let named = Url::parse(link)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| "no host".into());
        format!(
            "the link names {named}, and the page follows links only to accounts.public_host {host}"
        )
    })?;
    if served_by_authelia(&page, &url) {
        return Err(format!(
            "{base}{PATH} would be Authelia's: it is served at the root of that host. Set \
             mail.click_through_base (or sign_in_url) to the portal's own address"
        ));
    }
    Ok(wrap(base, link))
}

/// Would `{page}/set-password` reach Authelia rather than this portal? Only
/// when they share a host and Authelia is served at its root — under a path
/// prefix (`/auth`), the rest of the host is the portal's.
fn served_by_authelia(page: &Url, link: &Url) -> bool {
    let prefix = link
        .path()
        .strip_suffix(AUTHELIA_RESET_PATH)
        .unwrap_or_default();
    page.host_str() == link.host_str()
        && page.port() == link.port()
        && (prefix.is_empty() || PATH.starts_with(&format!("{prefix}/")))
}

/// Can the page be served at `base`? An `https` address of a host alone: the
/// page's form posts to `/set-password` at the root, and Authelia's bypass rule
/// names that path — and the address carries a one-time credential, so not
/// in clear.
pub fn usable_base(base: &str) -> bool {
    origin(base).is_some()
}

fn origin(base: &str) -> Option<Url> {
    Url::parse(base).ok().filter(|u| {
        u.scheme() == "https"
            && u.host_str().is_some_and(|h| !h.is_empty())
            && u.username().is_empty()
            && u.password().is_none()
            && u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none()
    })
}

/// The monorepo's cap on a URL. Authelia's reset links are a few hundred
/// bytes; anything this long was not minted by it, and would otherwise be
/// echoed back whole in a page or a `Location`.
const MAX_LINK_LEN: usize = 2048;

/// Is this a URL this portal is willing to send somebody to?
///
/// Only Authelia's reset page, over `https`, on `authelia_host`
/// (`accounts.public_host`, the host Authelia names in every link the portal
/// asks for), carrying a token — and nothing else that could change where it
/// leads: no credentials, no fragment. The value arrives in a query string
/// anybody can write, so it is parsed the way the browser will parse it, and
/// the parsed URL is what the redirect names: there is no second reading of
/// the string for the two to disagree about.
pub fn permitted(authelia_host: &str, url: &str) -> Option<Url> {
    if url.len() > MAX_LINK_LEN {
        return None;
    }
    // Parsed through a URL so both sides are compared normalised: case, IDNA
    // and a default port spelled out in the config.
    let want = Url::parse(&format!("https://{authelia_host}/")).ok()?;
    let u = Url::parse(url).ok()?;
    let ok = u.scheme() == "https"
        && u.host_str().is_some()
        && u.host_str() == want.host_str()
        && u.port() == want.port()
        && u.username().is_empty()
        && u.password().is_none()
        && u.fragment().is_none()
        && u.path().ends_with(AUTHELIA_RESET_PATH)
        && u.query_pairs().any(|(k, v)| k == "token" && !v.is_empty());
    ok.then_some(u)
}

fn percent_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 0x0f)] as char);
            }
        }
    }
    out
}

/// The inverse of [`percent_encode`], for the value the page hands back.
///
/// A `%` not followed by two hex digits is left alone rather than dropped: the
/// result is checked by [`permitted`] either way, and a mangled URL should
/// fail that check rather than quietly become a different one.
fn percent_decode(s: &str) -> String {
    fn hex(c: u8) -> Option<u8> {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let escape = if b[i] == b'%' && i + 2 < b.len() {
            hex(b[i + 1]).zip(hex(b[i + 2]))
        } else {
            None
        };
        match escape {
            Some((hi, lo)) => {
                out.push((hi << 4) | lo);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The page is for links the portal asked for, so it exists only where the
/// portal asks for them: with `mail`, and with `accounts` naming the host
/// Authelia's links are on.
fn configured(state: &PortalState) -> Result<(&MailConfig, &str), Response> {
    state
        .cfg
        .mail
        .as_ref()
        .and_then(|m| Some((m, m.authelia_host.as_deref()?)))
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                guarded(),
                "this portal does not send password links",
            )
                .into_response()
        })
}

/// `GET /set-password?u=…` — the page with the button.
///
/// Renders for anybody. It has to: the person it is for has no password yet,
/// so there is nobody to authenticate. Nothing here reaches Authelia.
pub(super) async fn page(State(state): State<PortalState>, Query(q): Query<Link>) -> Response {
    let (mail, host) = match configured(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let brand = html_escape(&mail.brand);
    let Some(url) = permitted(host, &q.u) else {
        // Deliberately not "that link is wrong": a page that explains how the
        // check works is a page that helps somebody probe it.
        return (
            StatusCode::BAD_REQUEST,
            guarded(),
            Html(shell(&brand, &format!(
                "<p style=\"margin:0 0 14px;\">This link is not one {brand} issued, or it has been \
                 altered on its way here.</p><p style=\"margin:0;color:#52606d;font-size:14px;\">\
                 Ask whoever invited you to send another.</p>"
            ))),
        )
            .into_response();
    };
    let action = html_escape(PATH);
    // Encoded, not plain: a hidden field holding `https://…/step2?token=…`
    // puts the one-time link back into the markup, where a scanner that
    // scrapes URL-shaped strings — rather than following `<a>` — would find
    // and open it. Encoded, it is not a URL to anything that reads HTML, and
    // `go` decodes it on the way back.
    let u = html_escape(&percent_encode(url.as_str()));
    (
        guarded(),
        Html(shell(
            &brand,
            &format!(
                "<p style=\"margin:0 0 20px;\">You are one step from setting your {brand} password.</p>\
                 <form method=\"post\" action=\"{action}\">\
                 <input type=\"hidden\" name=\"u\" value=\"{u}\">\
                 <button type=\"submit\" style=\"display:inline-block;background:#2563eb;color:#ffffff;\
                 border:0;border-radius:8px;padding:13px 24px;font-size:16px;font-weight:600;\
                 cursor:pointer;\">Set your password</button></form>\
                 <p style=\"margin:20px 0 0;color:#52606d;font-size:14px;\">The link works once, so \
                 this page waits for you rather than opening it by itself.</p>"
            ),
        )),
    )
        .into_response()
}

/// `POST /set-password` — the button. Only now does Authelia see the token.
pub(super) async fn go(State(state): State<PortalState>, Form(f): Form<Link>) -> Response {
    let (_, host) = match configured(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match permitted(host, &percent_decode(&f.u)) {
        // 303: the browser must GET what comes next, whatever this was. The
        // parsed URL, not the string: it is what `permitted` judged.
        Some(url) => (guarded(), Redirect::to(url.as_str())).into_response(),
        None => (
            StatusCode::BAD_REQUEST,
            guarded(),
            "that is not a link this portal issued",
        )
            .into_response(),
    }
}

/// The page around either message. No link, no script, no auto-submit — the
/// three things that would hand the token to a scanner.
fn shell(brand: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{brand}</title></head>
<body style="margin:0;background:#f4f6f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2933;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:48px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border:1px solid #e1e6eb;border-radius:10px;overflow:hidden;">
<tr><td style="background:#0f172a;padding:18px 24px;color:#ffffff;font-size:16px;font-weight:600;">{brand}</td></tr>
<tr><td style="padding:28px 24px;font-size:16px;line-height:1.6;">{body}</td></tr>
</table></td></tr></table></body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://watch.example.com";
    /// `accounts.public_host` for a portal with Authelia under `/auth` on its
    /// own host.
    const HOST: &str = "watch.example.com";
    const LINK: &str =
        "https://watch.example.com/auth/reset-password/step2?token=eyJhbGciOiJIUzI1NiJ9.abc.def";

    #[test]
    fn the_email_carries_our_page_and_not_authelias() {
        let wrapped = wrap(BASE, LINK);
        assert!(wrapped.starts_with("https://watch.example.com/set-password?u="));
        // The Authelia URL survives only as an encoded parameter: there is no
        // second clickable link in the message for a crawler to follow.
        assert!(!wrapped.contains("/auth/reset-password/step2?token="));
        assert!(wrapped.contains("%2Fauth%2Freset-password%2Fstep2%3Ftoken%3D"));
    }

    #[test]
    fn a_trailing_slash_on_the_base_does_not_double_up() {
        assert_eq!(wrap(BASE, LINK), wrap("https://watch.example.com/", LINK));
    }

    #[test]
    fn only_authelias_reset_page_on_authelias_host_is_followed() {
        assert_eq!(permitted(HOST, LINK).unwrap().as_str(), LINK);
        for bad in [
            // Somewhere else entirely.
            "https://evil.test/auth/reset-password/step2?token=x",
            // The host as a prefix of a longer one.
            "https://watch.example.com.evil.test/auth/reset-password/step2?token=x",
            // Credentials in front of the host, either way round.
            "https://watch.example.com@evil.test/auth/reset-password/step2?token=x",
            "https://evil.test@watch.example.com/auth/reset-password/step2?token=x",
            // Our host, but not the page this exists for — including one that
            // only mentions it in the query.
            "https://watch.example.com/api/clips?token=x",
            "https://watch.example.com/api/clips?next=/reset-password/step2&token=x",
            // A fragment, which the page this exists for never carries.
            "https://watch.example.com/auth/reset-password/step2?token=x#/elsewhere",
            // No token to carry, or an empty one.
            "https://watch.example.com/auth/reset-password/step2",
            "https://watch.example.com/auth/reset-password/step2?token=",
            // Another port on our host.
            "https://watch.example.com:8443/auth/reset-password/step2?token=x",
            // Plain HTTP, a scheme-relative try, and not a URL at all.
            "http://watch.example.com/auth/reset-password/step2?token=x",
            "//watch.example.com/auth/reset-password/step2?token=x",
            "javascript:alert(1)//watch.example.com/reset-password/step2?token=x",
            "",
            // Longer than any link Authelia mints.
            &format!("{LINK}{}", "A".repeat(MAX_LINK_LEN)),
        ] {
            assert!(
                permitted(HOST, bad).is_none(),
                "{bad} would have been followed"
            );
        }
    }

    /// The layout docs/portal.md describes besides Authelia-under-a-path:
    /// Authelia on its own login host, which is then `public_host` and the host
    /// of every link — while the page itself stays on the portal's host.
    #[test]
    fn authelia_on_its_own_host_is_followed_there_and_only_there() {
        let link = "https://auth.example.com/reset-password/step2?token=abc";
        assert!(permitted("auth.example.com", link).is_some());
        assert!(permitted(HOST, link).is_none());
        assert!(permitted("auth.example.com", LINK).is_none());
        assert!(wrap(BASE, link).starts_with("https://watch.example.com/set-password?u="));
    }

    /// Authelia at the root of the host the page would be on owns
    /// `/set-password` there too; under a path prefix it does not.
    #[test]
    fn a_page_on_authelias_own_host_is_noticed() {
        let at_root = Url::parse("https://auth.example.com/reset-password/step2?token=x").unwrap();
        let under_auth = Url::parse(LINK).unwrap();
        let portal = origin(BASE).unwrap();
        let authelias = origin("https://auth.example.com").unwrap();
        assert!(served_by_authelia(&authelias, &at_root));
        assert!(!served_by_authelia(&portal, &at_root));
        assert!(!served_by_authelia(&portal, &under_auth));
        let elsewhere = origin("https://auth.example.com:8443").unwrap();
        assert!(!served_by_authelia(&elsewhere, &at_root));
    }

    #[test]
    fn the_host_is_compared_as_a_browser_reads_it() {
        let shouted = "https://WATCH.Example.COM/auth/reset-password/step2?token=x";
        assert!(permitted("watch.example.com", shouted).is_some());
        assert!(permitted("Watch.Example.Com", LINK).is_some());
        assert!(permitted("watch.example.com:443", LINK).is_some());
        let ported = "https://watch.example.com:8443/auth/reset-password/step2?token=x";
        assert!(permitted("watch.example.com:8443", ported).is_some());
    }

    /// What the redirect names is the parsed URL, which never carries a byte a
    /// `Location` header cannot — so a hostile value is a `400` or a harmless
    /// `303`, never a `500` or a second header.
    #[test]
    fn nothing_permitted_can_break_the_location_header() {
        for nasty in [
            "https://watch.example.com/auth/reset-password/step2?token=a\r\nSet-Cookie: x=1",
            "https://watch.example.com/auth/reset-password/step2?token=a\0b",
            "https://watch.example.com/auth/reset-password/step2?token=a\u{7f}b\u{1}c",
            "https://watch.example.com/auth/reset-password/step2?token=a b\"<c>",
        ] {
            if let Some(url) = permitted(HOST, nasty) {
                assert!(
                    url.as_str().bytes().all(|b| b.is_ascii_graphic()),
                    "{nasty:?} became {:?}",
                    url.as_str()
                );
                assert!(axum::http::HeaderValue::from_str(url.as_str()).is_ok());
            }
        }
    }

    #[test]
    fn the_value_the_page_hands_back_survives_the_round_trip() {
        for url in [
            LINK,
            "https://watch.example.com/auth/reset-password/step2?token=a.b-c_d~e",
            "https://watch.example.com/auth/reset-password/step2?token=a+b/c==&x=%2B",
        ] {
            assert_eq!(percent_decode(&percent_encode(url)), url);
        }
        // Anything that is not `%` and two hex digits stays as it was, so a
        // mangled escape fails `permitted` rather than turning into something
        // else that might pass it. `u8::from_str_radix` alone would read `+A`
        // as ten.
        for kept in ["abc%4", "abc%", "%zz", "%+A", "%-1", "% 1"] {
            assert_eq!(percent_decode(kept), kept);
        }
        assert_eq!(percent_decode("%2b%2B"), "++");
    }

    #[test]
    fn the_page_is_served_only_at_an_https_address() {
        for ok in [
            "https://watch.example.com",
            "https://watch.example.com/",
            "https://watch.example.com:8443",
        ] {
            assert!(usable_base(ok), "{ok} refused");
        }
        for bad in [
            "",
            "/",
            "https:",
            "https:/",
            "https://",
            "watch.example.com",
            "http://watch.example.com",
            // The form posts to `/set-password` at the root, and the bypass
            // rule names that path: a prefix would serve a page that cannot
            // work.
            "https://watch.example.com/portal",
            "https://u:p@watch.example.com",
            "https://watch.example.com/?from=email",
            "https://watch.example.com/#top",
            "javascript:alert(1)//",
        ] {
            assert!(!usable_base(bad), "{bad:?} accepted");
        }
    }
}
