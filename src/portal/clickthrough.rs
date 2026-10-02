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
//! * carries **no link to Authelia** at all, so there is nothing for a crawler
//!   to follow; and
//! * moves on only when somebody **presses the button**, which is a form
//!   `POST` — the one thing automated link-checking does not do.
//!
//! The honest limit: a scanner that submitted forms would still spend the
//! link. None of the ones that cause this behave that way, and the alternative
//! — holding link state on disk so the token never leaves this process — buys
//! little against a scanner that renders *and* clicks, at the cost of state to
//! keep, expire and lose on a restart.
//!
//! # Why the whole URL travels in the query
//!
//! Authelia mints the link; the portal only forwards it. Carrying the URL
//! rather than the token alone means this module needs to know nothing about
//! Authelia's paths — but it also means the value is attacker-controlled, so
//! [`permitted`] refuses anything that is not the configured base plus
//! Authelia's own reset path. Without that check this would be an open
//! redirect: a link on your own domain that bounces to anywhere.

use super::PortalState;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

/// Where the email sends people, under the configured base.
pub const PATH: &str = "/set-password";

/// The path Authelia serves the real page at. A permitted URL is the
/// configured base followed by this.
const AUTHELIA_RESET_PATH: &str = "/reset-password/step2";

#[derive(Debug, Deserialize)]
pub struct LinkQuery {
    /// The Authelia URL, percent-encoded by [`wrap`].
    #[serde(default)]
    pub u: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkForm {
    #[serde(default)]
    pub u: String,
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

/// Is this a URL this portal is willing to send somebody to?
///
/// Only the configured base, and only Authelia's reset page under it. Anything
/// else — another host, another path, a scheme that is not https — is refused,
/// because the value arrives in a query string anybody can write.
pub fn permitted(base: &str, url: &str) -> bool {
    let base = base.trim_end_matches('/');
    let Some(rest) = url.strip_prefix(base) else {
        return false;
    };
    // `rest` must begin with a path segment, or `base` matched a longer host:
    // `https://watch.example.com.evil.test/...` starts with the base too.
    if !rest.starts_with('/') {
        return false;
    }
    rest.contains(AUTHELIA_RESET_PATH) && rest.contains("token=") && !url.contains('"')
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The inverse of [`percent_encode`], for the value the page hands back.
///
/// A stray `%` that is not an escape is left alone rather than dropped: the
/// result is checked by [`permitted`] either way, and a mangled URL should
/// fail that check rather than quietly become a different one.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `GET /set-password?u=…` — the page with the button.
///
/// Renders for anybody. It has to: the person it is for has no password yet,
/// so there is nobody to authenticate. Nothing here reaches Authelia.
pub async fn page(State(state): State<PortalState>, Query(q): Query<LinkQuery>) -> Response {
    let Some(mail) = state.cfg.mail.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "this portal does not send password links",
        )
            .into_response();
    };
    let base = mail.click_through_base();
    let brand = html_escape(&mail.brand);
    if !permitted(base, &q.u) {
        // Deliberately not "that link is wrong": a page that explains how the
        // check works is a page that helps somebody probe it.
        return (
            StatusCode::BAD_REQUEST,
            Html(shell(&brand, &format!(
                "<p style=\"margin:0 0 14px;\">This link is not one {brand} issued, or it has been \
                 altered on its way here.</p><p style=\"margin:0;color:#52606d;font-size:14px;\">\
                 Ask whoever invited you to send another.</p>"
            ))),
        )
            .into_response();
    }
    let action = html_escape(PATH);
    // Encoded, not plain: a hidden field holding `https://…/step2?token=…`
    // puts the one-time link back into the markup, where a scanner that
    // scrapes URL-shaped strings — rather than following `<a>` — would find
    // and open it. Encoded, it is not a URL to anything that reads HTML, and
    // `go` decodes it on the way back.
    let u = html_escape(&percent_encode(&q.u));
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
    ))
    .into_response()
}

/// `POST /set-password` — the button. Only now does Authelia see the token.
pub async fn go(State(state): State<PortalState>, Form(f): Form<LinkForm>) -> Response {
    let Some(mail) = state.cfg.mail.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "this portal does not send password links",
        )
            .into_response();
    };
    let url = percent_decode(&f.u);
    if !permitted(mail.click_through_base(), &url) {
        return (
            StatusCode::BAD_REQUEST,
            "that is not a link this portal issued",
        )
            .into_response();
    }
    // 303: the browser must GET what comes next, whatever this was.
    Redirect::to(&url).into_response()
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
    fn only_authelias_reset_page_on_our_own_host_is_followed() {
        assert!(permitted(BASE, LINK));
        for bad in [
            // Somewhere else entirely.
            "https://evil.test/auth/reset-password/step2?token=x",
            // The base as a prefix of a longer host — the reason the check
            // demands a path separator next.
            "https://watch.example.com.evil.test/auth/reset-password/step2?token=x",
            // Our host, but not the page this exists for.
            "https://watch.example.com/api/clips?token=x",
            // No token to carry.
            "https://watch.example.com/auth/reset-password/step2",
            // Plain HTTP, and a scheme-relative try.
            "http://watch.example.com/auth/reset-password/step2?token=x",
            "//watch.example.com/auth/reset-password/step2?token=x",
            "",
        ] {
            assert!(!permitted(BASE, bad), "{bad} would have been followed");
        }
    }

    #[test]
    fn a_url_that_could_break_out_of_the_hidden_field_is_refused() {
        // Belt and braces: the value is escaped into the form anyway, but a
        // quote has no business in a URL we minted.
        assert!(!permitted(
            BASE,
            "https://watch.example.com/auth/reset-password/step2?token=a\"><script>x</script>"
        ));
    }

    #[test]
    fn the_value_the_page_hands_back_survives_the_round_trip() {
        for url in [
            LINK,
            "https://watch.example.com/auth/reset-password/step2?token=a.b-c_d~e",
        ] {
            assert_eq!(percent_decode(&percent_encode(url)), url);
        }
        // A mangled escape fails `permitted` rather than turning into something
        // else that might pass it.
        assert!(!permitted(
            BASE,
            &percent_decode("https://watch.example.com/%zz")
        ));
    }

    #[test]
    fn the_page_offers_a_form_and_no_link() {
        let body = shell(
            "GRS",
            "<form method=\"post\" action=\"/set-password\"></form>",
        );
        assert!(
            !body.contains("<a "),
            "a crawler would follow a link: {body}"
        );
        assert!(
            !body.contains("<script"),
            "a scanner that runs JS must find nothing to run"
        );
        assert!(body.contains("noindex"));
    }
}
