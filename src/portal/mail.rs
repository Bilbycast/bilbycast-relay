// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The portal writes the emails, Authelia mints the links.
//!
//! Authelia sends one email for "set your first password" and "I forgot my
//! password", with one subject, one body and one link lifetime, because it
//! cannot tell them apart. The manager can: it knows whether this is the first
//! link an account has ever been sent. So Authelia is pointed at an SMTP
//! listener **inside this process** instead of at the relay, and what it hands
//! over is rewritten before it goes out.
//!
//! ```text
//! manager ──asks──▶ portal ──start reset──▶ Authelia
//!                     ▲                         │ mints the link, mails it
//!                     └──── 127.0.0.1:2525 ◀────┘
//!                     │ rewrite: invite or reset
//!                     └──────▶ Brevo ──▶ the viewer
//! ```
//!
//! # Why intercept rather than send our own
//!
//! The link is a JWT Authelia signs *and* records: a token minted anywhere else
//! is refused, because the identity-verification row behind it would not exist.
//! So the only way to put our own words around Authelia's link is to take the
//! message it produced.
//!
//! # Who may deliver here
//!
//! Only Authelia. Loopback alone would not make it so: every other process on
//! this host — and anything that can steer one of them into opening a socket —
//! could hand the listener a message and have it relayed under our domain and
//! its reputation. So the listener takes no sender until the client has
//! authenticated (`AUTH PLAIN` or `AUTH LOGIN`) with the secret in
//! `mail.listen_password_file`, which Authelia's notifier is given too. After
//! that the envelope sender must still be `mail.from`'s address. A different
//! one is refused at `MAIL FROM` with a `550`, so an Authelia configured with
//! another sender fails loudly — at its own startup check, and on every send —
//! instead of having its mail accepted and then dropped.
//!
//! # What is rewritten, and what is not
//!
//! Only a message to somebody the portal has just asked for a link for, matched
//! by recipient within [`PENDING_TTL`]. Everything else Authelia sends — a
//! viewer using the "reset password" link on the sign-in page itself, or one of
//! Authelia's own event notices — is relayed byte for byte. So is a message the
//! portal asked for but could not rewrite: the person still gets their link, in
//! Authelia's wording rather than ours.
//!
//! # What "sent" means
//!
//! Authelia believes a message is sent the moment this listener answers `250`,
//! and it will not send it again. For a link the portal asked for, the relay's
//! answer is what the manager is told: the Portal logins list says "sent" once
//! the relay has accepted the message for delivery — not once it has reached
//! an inbox — and names the error when it has not. Mail nobody here asked for
//! has nobody to report to, so a relay failure on it is logged at ERROR and
//! that is all.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lettre::address::Envelope;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, oneshot};

/// How long a requested link stays matchable.
///
/// No longer than the account sync waits for the email (its `RELAY_WAIT`,
/// 30 s): an expectation that outlived its waiter would claim — and reword —
/// the next email Authelia sends that address, a viewer's own reset from the
/// sign-in page among them, with nobody left to report the outcome to.
/// Authelia mails during the request that asks it to, so this is still ample.
pub const PENDING_TTL: Duration = Duration::from_secs(30);

/// The longest one relay attempt may take, end to end.
///
/// Below the account sync's 30 s wait, so the manager is told the relay's real
/// answer rather than a timeout. Enforced around the whole send: on tokio,
/// lettre's own timeout covers only the connect.
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(20);

/// Caps on what the listener will read. Authelia's message is a few kilobytes,
/// and no line is read further than [`MAX_LINE_BYTES`], however long it is.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
/// A conversation that stalls is dropped rather than held open...
const SMTP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// ...and so is one that keeps talking. Authelia is done in well under a
/// second; this is what stops a client sending `NOOP` forever from holding a
/// connection slot, and with it Authelia's mail, hostage.
const SESSION_DEADLINE: Duration = Duration::from_secs(60);
/// Connections served at once. Past this a new one is told `421` and closed.
const MAX_CONNECTIONS: usize = 16;
/// Messages accepted and not yet relayed. Past this `DATA` is answered `451`.
const MAX_IN_FLIGHT: usize = 8;
/// Failed `AUTH` attempts, and unrecognised commands, before a connection is
/// closed. Authelia needs neither more than once.
const MAX_AUTH_FAILURES: u8 = 3;
const MAX_UNKNOWN_COMMANDS: u8 = 3;
/// The shortest listener secret accepted. It is a machine secret two services
/// read from a file; nobody types it.
const MIN_LISTEN_PASSWORD: usize = 32;

const AUTH_FIRST: &[u8] = b"530 5.7.0 Authentication required\r\n";
const AUTH_INVALID: &[u8] = b"535 5.7.8 authentication credentials invalid\r\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailConfig {
    /// Where Authelia delivers. Loopback only: the listener speaks no TLS, so
    /// the secret Authelia authenticates with must not cross a network.
    #[serde(default = "default_listen")]
    pub listen_addr: String,

    /// A file holding the secret Authelia authenticates to the listener with —
    /// the same file Authelia's `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE` names.
    /// Required. Defaulted only so a config written before it existed is
    /// refused by [`validate`](Self::validate), with a message saying what to
    /// add, rather than by the JSON parser.
    #[serde(default)]
    pub listen_password_file: PathBuf,

    /// The relay that actually delivers, e.g. `smtp-relay.brevo.com`.
    pub relay_host: String,
    /// 587 unless set, or 465 with `implicit_tls`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_port: Option<u16>,
    pub relay_username: String,
    /// A file holding the relay's password (Brevo calls it an SMTP key), so it
    /// is not in this config.
    pub relay_password_file: PathBuf,

    /// The From on everything that leaves here, e.g.
    /// `Example Notifications <noreply@example.com>`. Its domain has to be
    /// authenticated at the relay, and Authelia's `notifier.smtp.sender` must
    /// carry the same address.
    pub from: String,

    /// Where a viewer signs in, named in the emails.
    pub sign_in_url: String,

    /// Who the emails say they come from, in their wording and in the default
    /// subjects.
    #[serde(default = "default_brand")]
    pub brand: String,

    /// How long the link lasts, in words — `three days` — as the emails should
    /// state it. It has to agree with Authelia's
    /// `identity_validation.reset_password.jwt_lifespan`, which the portal
    /// cannot read; unset, the emails make no claim about it at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_lifetime: Option<String>,

    /// Unset means `Your <brand> account`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_subject: Option<String>,
    /// Unset means `<brand> password reset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_subject: Option<String>,

    /// STARTTLS on the way out, which is what unset means unless
    /// `implicit_tls` is on. Off with neither is for a local test sink only —
    /// it sends the relay password in clear, so [`validate`](Self::validate)
    /// refuses it for any relay not on this host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starttls: Option<bool>,
    /// TLS from the first byte (`submissions`, port 465) instead of STARTTLS.
    #[serde(default)]
    pub implicit_tls: bool,
}

fn default_listen() -> String {
    "127.0.0.1:2525".to_string()
}
fn default_brand() -> String {
    "Bilbycast".to_string()
}

/// How the connection to the relay is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outbound {
    StartTls,
    Implicit,
    Clear,
}

impl MailConfig {
    pub fn normalise(&mut self) {
        self.relay_host = self.relay_host.trim().to_string();
        self.from = self.from.trim().to_string();
        self.sign_in_url = self.sign_in_url.trim().trim_end_matches('/').to_string();
        self.brand = self.brand.trim().to_string();
        for text in [
            &mut self.link_lifetime,
            &mut self.invite_subject,
            &mut self.reset_subject,
        ] {
            *text = text
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string);
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let addr: SocketAddr = self
            .listen_addr
            .parse()
            .map_err(|_| "mail.listen_addr must be host:port".to_string())?;
        if !addr.ip().is_loopback() {
            return Err(
                "mail.listen_addr must be a loopback address: the listener speaks no TLS, so \
                 the secret Authelia authenticates with would cross the network in clear"
                    .into(),
            );
        }
        if self.listen_password_file.as_os_str().is_empty() {
            return Err(format!(
                "mail.listen_password_file is required: the listener takes mail only from a \
                 client that authenticates. Put a random secret of at least \
                 {MIN_LISTEN_PASSWORD} characters in a file, name it here, and give Authelia the \
                 same secret (notifier.smtp.username, and AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE \
                 pointing at that file)"
            ));
        }
        if self.relay_host.is_empty() {
            return Err("mail.relay_host is required".into());
        }
        if self.relay_port == Some(0) {
            return Err("mail.relay_port cannot be 0".into());
        }
        if self.relay_username.is_empty() {
            return Err("mail.relay_username is required".into());
        }
        if self.relay_password_file.as_os_str().is_empty() {
            return Err("mail.relay_password_file is required".into());
        }
        // Parsed as the rewritten email will parse it, so a From that cannot be
        // sent is found now rather than on the first invitation.
        if self.from.parse::<Mailbox>().is_err() {
            return Err(format!(
                "mail.from `{}` is not an address to send from: write `Name <noreply@example.com>`, \
                 with the name in double quotes if it contains any of , ( ) : ; @ [ ] \\ \"",
                self.from
            ));
        }
        if !self.sign_in_url.starts_with("https://") && !self.sign_in_url.starts_with("http://") {
            return Err("mail.sign_in_url must be an http(s) URL".into());
        }
        one_line("mail.brand", &self.brand, 64)?;
        if let Some(l) = &self.link_lifetime {
            one_line("mail.link_lifetime", l, 64)?;
        }
        if let Some(s) = &self.invite_subject {
            one_line("mail.invite_subject", s, 200)?;
        }
        if let Some(s) = &self.reset_subject {
            one_line("mail.reset_subject", s, 200)?;
        }
        if self.implicit_tls && self.starttls == Some(true) {
            return Err(
                "mail.implicit_tls and mail.starttls are two ways of encrypting the same \
                 connection; for implicit TLS (port 465) remove starttls or set it to false"
                    .into(),
            );
        }
        if self.outbound() == Outbound::Clear && !on_this_host(&self.relay_host) {
            return Err(
                "mail.starttls may only be off for a relay on this host (127.0.0.1, ::1 or \
                 localhost): it sends the relay password in clear"
                    .into(),
            );
        }
        Ok(())
    }

    fn outbound(&self) -> Outbound {
        if self.implicit_tls {
            Outbound::Implicit
        } else if self.starttls.unwrap_or(true) {
            Outbound::StartTls
        } else {
            Outbound::Clear
        }
    }

    fn port(&self) -> u16 {
        self.relay_port
            .unwrap_or(if self.implicit_tls { 465 } else { 587 })
    }

    fn subject(&self, kind: LinkKind) -> String {
        match kind {
            LinkKind::Invite => self
                .invite_subject
                .clone()
                .unwrap_or_else(|| format!("Your {} account", self.brand)),
            LinkKind::Reset => self
                .reset_subject
                .clone()
                .unwrap_or_else(|| format!("{} password reset", self.brand)),
        }
    }

    fn password(&self) -> anyhow::Result<String> {
        let raw = std::fs::read_to_string(&self.relay_password_file).map_err(|e| {
            anyhow::anyhow!("cannot read {}: {e}", self.relay_password_file.display())
        })?;
        Ok(raw.trim().to_string())
    }

    /// The secret Authelia must present to the listener, read once at startup.
    pub fn listen_password(&self) -> anyhow::Result<String> {
        let path = self.listen_password_file.display();
        let raw = std::fs::read_to_string(&self.listen_password_file)
            .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let secret = raw.trim();
        if secret.chars().any(char::is_control) {
            anyhow::bail!("{path} must hold the listener secret on one line");
        }
        if secret.len() < MIN_LISTEN_PASSWORD {
            anyhow::bail!(
                "the listener secret in {path} is shorter than {MIN_LISTEN_PASSWORD} characters; \
                 generate one with `openssl rand -hex 32`"
            );
        }
        Ok(secret.to_string())
    }
}

/// Plain text to a relay is allowed only here: an address that is loopback,
/// not a name that merely starts like one.
fn on_this_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        || host.eq_ignore_ascii_case("localhost")
}

/// A value that goes into a header or a sentence: present, short, one line.
fn one_line(what: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{what} cannot be empty"));
    }
    if value.chars().count() > max {
        return Err(format!("{what} is longer than {max} characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{what} cannot contain control characters"));
    }
    Ok(())
}

/// Which email this is, which decides what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// The account's first link: nobody has ever set a password on it.
    Invite,
    Reset,
}

struct Pending {
    kind: LinkKind,
    display_name: String,
    /// Told when the message has been relayed, or could not be.
    done: Option<oneshot::Sender<Result<(), String>>>,
    at: Instant,
}

/// Links the portal has asked Authelia for and not yet seen come back.
#[derive(Default)]
pub struct PendingLinks(Mutex<HashMap<String, Pending>>);

fn key(email: &str) -> String {
    email
        .trim()
        .trim_matches(|c| c == '<' || c == '>')
        .to_ascii_lowercase()
}

impl PendingLinks {
    /// Expect a message to `email`, and hand back the channel that reports how
    /// it went.
    pub async fn expect(
        &self,
        email: &str,
        kind: LinkKind,
        display_name: &str,
    ) -> oneshot::Receiver<Result<(), String>> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.0.lock().await;
        map.retain(|_, p| p.at.elapsed() < PENDING_TTL);
        map.insert(
            key(email),
            Pending {
                kind,
                display_name: display_name.to_string(),
                done: Some(tx),
                at: Instant::now(),
            },
        );
        rx
    }

    /// Stop expecting a message to `email`: Authelia was asked and refused, so
    /// nothing is coming — and a stale expectation would otherwise rewrite the
    /// viewer's own reset from the sign-in page as ours.
    pub async fn forget(&self, email: &str) {
        self.0.lock().await.remove(&key(email));
    }

    async fn take(&self, recipients: &[String]) -> Option<(String, Pending)> {
        let mut map = self.0.lock().await;
        map.retain(|_, p| p.at.elapsed() < PENDING_TTL);
        let found = recipients.iter().find_map(|r| {
            let k = key(r);
            map.contains_key(&k).then_some(k)
        })?;
        let pending = map.remove(&found)?;
        Some((found, pending))
    }
}

/// One message as it arrived from Authelia.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Incoming {
    pub from: String,
    pub recipients: Vec<String>,
    pub data: Vec<u8>,
}

/// The set-your-password link Authelia put in the message.
///
/// Taken out of the raw bytes rather than by parsing MIME: the link is the one
/// thing needed, it appears in both the text and HTML parts, and a
/// quoted-printable soft break can split it across lines — which is undone
/// first.
pub fn extract_link(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data)
        .replace("=\r\n", "")
        .replace("=\n", "");
    let at = text.find("/reset-password/step2?token=")?;
    let start = text[..at]
        .rfind("https://")
        .or_else(|| text[..at].rfind("http://"))?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '>' || c == ')')
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches(['.', ',', ';']);
    // A quoted-printable `=3D` survives the soft-break undo above.
    Some(url.replace("=3D", "="))
}

/// A display name fit for a header and a page. It is whatever an operator
/// typed: control characters become spaces — a CR or LF above all, which
/// lettre cannot encode and panics on when it writes the header — and runs of
/// whitespace collapse.
fn clean_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// For everything interpolated into the HTML part, which goes out under our
/// own domain.
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

/// What either email is made of.
struct Letter<'a> {
    brand: &'a str,
    /// Already through [`clean_name`].
    name: &'a str,
    link: &'a str,
    sign_in: &'a str,
    lifetime: Option<&'a str>,
}

/// The sentences that differ between an invitation and a reset.
struct Wording {
    lead: String,
    ask: &'static str,
    action: &'static str,
    /// Either side of the sign-in address.
    then: (&'static str, &'static str),
    footer: &'static str,
}

fn wording(kind: LinkKind, brand: &str) -> Wording {
    match kind {
        LinkKind::Invite => Wording {
            lead: format!("You have been given access to {brand} live and recorded video."),
            ask: "To get started, choose a password for your account:",
            action: "Set your password",
            then: (
                "Once your password is set, sign in at",
                "with your email address or your username, and the feeds you have been given \
                 will be listed there.",
            ),
            footer: "If you were not expecting this, you can ignore this email — no password is \
                     set and no access is granted until somebody uses the link.",
        },
        LinkKind::Reset => Wording {
            lead: format!("Somebody asked to reset the password on your {brand} account."),
            ask: "To choose a new one:",
            action: "Choose a new password",
            then: (
                "Once your new password is set, sign in at",
                "with your email address or your username.",
            ),
            footer: "If you did not ask for this, you can ignore this email — your current \
                     password still works and nothing changes until somebody uses the link.",
        },
    }
}

fn greeting(name: &str) -> String {
    if name.is_empty() {
        "Hello,".to_string()
    } else {
        format!("Hello {name},")
    }
}

/// "This link lasts three days. " — or nothing, when nobody has said how long
/// Authelia makes it last.
fn lifetime_sentence(lifetime: Option<&str>) -> String {
    lifetime
        .map(|l| format!("This link lasts {l}. "))
        .unwrap_or_default()
}

fn text_body(l: &Letter, kind: LinkKind) -> String {
    let w = wording(kind, l.brand);
    format!(
        "{greeting}\n\n{lead}\n\n{ask}\n\n{link}\n\n{lasts}{before} {sign_in} {after}\n\n\
         {footer}\n\n{brand} Notifications\n",
        greeting = greeting(l.name),
        lead = w.lead,
        ask = w.ask,
        link = l.link,
        lasts = lifetime_sentence(l.lifetime),
        before = w.then.0,
        sign_in = l.sign_in,
        after = w.then.1,
        footer = w.footer,
        brand = l.brand,
    )
}

fn html_body(l: &Letter, kind: LinkKind) -> String {
    let w = wording(kind, l.brand);
    let greeting = html_escape(&greeting(l.name));
    let lead = html_escape(&w.lead);
    let action = html_escape(w.action);
    let lasts = html_escape(&lifetime_sentence(l.lifetime));
    let before = html_escape(w.then.0);
    let after = html_escape(w.then.1);
    let footer = html_escape(w.footer);
    let brand = html_escape(l.brand);
    let link = html_escape(l.link);
    let sign_in = html_escape(l.sign_in);
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f6f8;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:10px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2933;border:1px solid #e1e6eb;">
<tr><td style="background:#0f172a;padding:18px 24px;color:#ffffff;font-size:16px;font-weight:600;">{brand} Notifications</td></tr>
<tr><td style="padding:24px;font-size:15px;line-height:1.6;">
<p style="margin:0 0 14px;">{greeting}</p>
<p style="margin:0 0 20px;">{lead}</p>
<p style="margin:0 0 22px;"><a href="{link}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;">{action}</a></p>
<p style="margin:0 0 14px;color:#52606d;font-size:13px;">{lasts}{before} <a href="{sign_in}" style="color:#2563eb;">{sign_in}</a> {after}</p>
<p style="margin:0 0 14px;color:#52606d;font-size:13px;">{footer}</p>
<p style="margin:18px 0 0;color:#7b8794;font-size:12px;word-break:break-all;">If the button does not work, paste this into your browser:<br>{link}</p>
</td></tr></table></td></tr></table></body></html>"#
    )
}

/// What to send instead of what Authelia wrote.
pub fn rewrite(
    cfg: &MailConfig,
    kind: LinkKind,
    display_name: &str,
    to: &str,
    link: &str,
) -> anyhow::Result<Message> {
    let name = clean_name(display_name);
    let letter = Letter {
        brand: &cfg.brand,
        name: &name,
        link,
        sign_in: &cfg.sign_in_url,
        lifetime: cfg.link_lifetime.as_deref(),
    };
    // Built, never parsed out of `Name <address>`: lettre's parser takes only a
    // bare phrase, so `Jones, Bea`, `Bea (Producer)` or a username that is an
    // email address could not be written that way. Built, the name is quoted
    // as it needs to be on the way out.
    let to_mailbox = Mailbox::new(
        (!name.is_empty()).then(|| name.clone()),
        to.parse::<Address>()?,
    );
    Ok(Message::builder()
        .from(cfg.from.parse()?)
        .to(to_mailbox)
        .subject(cfg.subject(kind))
        .multipart(MultiPart::alternative_plain_html(
            text_body(&letter, kind),
            html_body(&letter, kind),
        ))?)
}

/// Where rewritten and passed-through mail goes. A trait so a test can watch
/// what would have been sent without a relay to send it to.
#[async_trait::async_trait]
pub trait Relay: Send + Sync {
    async fn send(&self, envelope: Envelope, body: Vec<u8>) -> Result<(), String>;
}

pub struct SmtpRelay {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    /// [`RELAY_TIMEOUT`]; a field so a test need not wait that long.
    deadline: Duration,
}

impl SmtpRelay {
    pub fn new(cfg: &MailConfig) -> anyhow::Result<Self> {
        let creds = Credentials::new(cfg.relay_username.clone(), cfg.password()?);
        let builder = match cfg.outbound() {
            Outbound::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.relay_host)?
            }
            Outbound::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.relay_host)?,
            // This host only — `validate` refuses it anywhere else.
            Outbound::Clear => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.relay_host)
            }
        };
        Ok(Self {
            transport: builder
                .port(cfg.port())
                .credentials(creds)
                .timeout(Some(RELAY_TIMEOUT))
                .build(),
            deadline: RELAY_TIMEOUT,
        })
    }
}

#[async_trait::async_trait]
impl Relay for SmtpRelay {
    async fn send(&self, envelope: Envelope, body: Vec<u8>) -> Result<(), String> {
        match tokio::time::timeout(self.deadline, self.transport.send_raw(&envelope, &body)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("the mail relay refused it: {e}")),
            Err(_) => Err(format!(
                "the mail relay did not answer within {:?}",
                self.deadline
            )),
        }
    }
}

/// Decide what leaves, given what arrived.
///
/// Split from the network so both paths are testable: a message the portal
/// asked for becomes our own, anything else is passed through untouched.
pub async fn handle(
    cfg: &MailConfig,
    pending: &PendingLinks,
    relay: &dyn Relay,
    msg: Incoming,
) -> Result<(), String> {
    // Refused at `MAIL FROM` already. Checked again so that nothing reaching
    // here by some other road is relayed under our domain.
    if !sender_is_ours(cfg, &msg.from) {
        tracing::error!(
            from = %msg.from,
            mail_from = %cfg.from,
            "refusing to relay a message that did not come from this portal's sender address"
        );
        return Err("the message was not from this portal's sender address".into());
    }
    let Some((to, mut pending_entry)) = pending.take(&msg.recipients).await else {
        // Not ours: a viewer resetting their own password from the sign-in
        // page, or one of Authelia's notices. Relayed exactly as written — and
        // if that fails, the log is all there is to tell: Authelia already
        // has its 250.
        let out = pass_through(relay, msg).await;
        if let Err(ref e) = out {
            tracing::error!(
                error = %e,
                "could not relay an email Authelia sent; Authelia was told it was accepted and \
                 will not send it again"
            );
        }
        return out;
    };

    let result = match extract_link(&msg.data) {
        Some(link) => match rewrite(
            cfg,
            pending_entry.kind,
            &pending_entry.display_name,
            &to,
            &link,
        ) {
            Ok(message) => {
                let envelope = message.envelope().clone();
                relay.send(envelope, message.formatted()).await
            }
            Err(e) => {
                // Still the person's link, in Authelia's words rather than ours.
                tracing::warn!(
                    to = %to, error = %e,
                    "could not compose the rewritten email; relaying Authelia's unchanged"
                );
                pass_through(relay, msg).await
            }
        },
        None => {
            // Authelia changed its message, or this was not the mail we
            // expected. Send what it wrote rather than nothing at all.
            tracing::warn!(
                to = %to,
                "no set-password link found in Authelia's email; relaying it unchanged"
            );
            pass_through(relay, msg).await
        }
    };
    if let Err(ref e) = result {
        tracing::warn!(to = %to, error = %e, "a requested password link was not relayed");
    }
    if let Some(done) = pending_entry.done.take() {
        let _ = done.send(result.clone());
    }
    result
}

/// Relay what Authelia wrote, untouched.
async fn pass_through(relay: &dyn Relay, msg: Incoming) -> Result<(), String> {
    let envelope = envelope_for(&msg)?;
    relay.send(envelope, msg.data).await
}

fn envelope_for(msg: &Incoming) -> Result<Envelope, String> {
    let from = msg.from.parse().ok();
    let to: Vec<_> = msg
        .recipients
        .iter()
        .filter_map(|r| r.parse().ok())
        .collect();
    if to.is_empty() {
        return Err("the message named no recipient this relay could parse".into());
    }
    Envelope::new(from, to).map_err(|e| format!("bad envelope: {e}"))
}

/// Does this message claim to come from the address this portal sends as?
///
/// Compared on the address alone: `from` carries a display name, the envelope
/// never does.
fn sender_is_ours(cfg: &MailConfig, envelope_from: &str) -> bool {
    let ours = cfg
        .from
        .rsplit_once('<')
        .map(|(_, rest)| rest.trim_end_matches('>'))
        .unwrap_or(&cfg.from)
        .trim()
        .to_ascii_lowercase();
    key(envelope_from) == ours
}

/// `MAIL FROM:<a@b>` / `RCPT TO:<a@b> SIZE=…` → `a@b`.
fn address_in(cmd: &str) -> String {
    let rest = cmd.split_once(':').map(|(_, r)| r).unwrap_or("");
    match (rest.find('<'), rest.find('>')) {
        (Some(a), Some(b)) if b > a => rest[a + 1..b].trim().to_string(),
        _ => rest.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// Is this (upper-cased) line the start of an HTTP request rather than an
/// SMTP command? A browser, or a server-side request somebody steered at this
/// port, says this first; nothing that speaks SMTP ever does.
fn speaks_http(upper: &str) -> bool {
    [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
        "HOST:",
    ]
    .iter()
    .any(|m| upper.starts_with(m))
}

/// Standard base64, as SASL carries it. `None` for anything else.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A SASL response line, decoded — or the reply that refuses it.
fn decode_response(response: &str) -> Result<Vec<u8>, &'static [u8]> {
    if response == "*" {
        return Err(b"501 5.7.0 authentication cancelled\r\n");
    }
    base64_decode(response).ok_or(b"501 5.5.2 cannot decode the response\r\n")
}

/// What one bounded read produced. The line itself is left in the buffer.
enum Line {
    Read,
    TooLong,
    /// End of stream (mid-line included), the idle timeout, or an I/O error.
    Closed,
}

/// Read one line into `buf`, never more than [`MAX_LINE_BYTES`] of it.
///
/// `read_line` alone buffers until a newline comes, so a client that never
/// sends one would grow the buffer without limit — gigabytes inside the idle
/// timeout, over loopback — in the process that is also the viewers' front
/// door.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> Line {
    buf.clear();
    let mut bounded = (&mut *reader).take(MAX_LINE_BYTES as u64 + 1);
    match tokio::time::timeout(SMTP_IDLE_TIMEOUT, bounded.read_until(b'\n', buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => Line::Closed,
        Ok(Ok(_)) if buf.len() > MAX_LINE_BYTES => Line::TooLong,
        Ok(Ok(_)) if !buf.ends_with(b"\n") => Line::Closed,
        Ok(Ok(_)) => Line::Read,
    }
}

/// Send a `334` challenge and read the answer, or `None` once the client has
/// gone.
async fn prompt<R, W>(
    challenge: &[u8],
    reader: &mut R,
    write: &mut W,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write.write_all(challenge).await?;
    Ok(match read_line(reader, buf).await {
        Line::Read => Some(String::from_utf8_lossy(buf).trim().to_string()),
        Line::TooLong | Line::Closed => None,
    })
}

/// How an `AUTH` exchange ended.
enum Auth {
    Accepted,
    /// Refused, with the reply that says why.
    Refused(&'static [u8]),
    Closed,
}

/// The listener Authelia delivers to, and what its connections share.
pub struct Interceptor {
    cfg: MailConfig,
    /// What a client must present in `AUTH`. Never logged.
    secret: String,
    pending: Arc<PendingLinks>,
    relay: Arc<dyn Relay>,
    connections: Arc<Semaphore>,
    in_flight: Arc<Semaphore>,
    /// [`SESSION_DEADLINE`]; a field so a test need not wait that long.
    session_deadline: Duration,
}

impl Interceptor {
    pub fn new(
        cfg: MailConfig,
        secret: String,
        pending: Arc<PendingLinks>,
        relay: Arc<dyn Relay>,
    ) -> Self {
        Self {
            cfg,
            secret,
            pending,
            relay,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            session_deadline: SESSION_DEADLINE,
        }
    }

    /// Take Authelia's mail on `listener` for as long as the process runs.
    ///
    /// The caller binds it, so a port somebody else already holds stops the
    /// portal at startup, instead of leaving it serving viewers while
    /// Authelia's mail — reset links included — goes to whoever holds it.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let mut full = false;
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        // Cannot happen while bound to loopback; cheap to keep true.
                        continue;
                    }
                    let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                        if !full {
                            tracing::warn!(
                                limit = MAX_CONNECTIONS,
                                "the notification mail listener is full; turning connections \
                                 away until one closes"
                            );
                            full = true;
                        }
                        // Written without waiting, on the non-blocking std
                        // socket: a client that never reads must not stall
                        // the accept loop. (tokio's `try_write` would not do:
                        // a socket the reactor has not yet seen writable
                        // answers WouldBlock.)
                        if let Ok(mut s) = stream.into_std() {
                            let _ = std::io::Write::write(
                                &mut s,
                                b"421 4.3.2 too many connections, try again later\r\n",
                            );
                        }
                        continue;
                    };
                    full = false;
                    let this = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        this.serve_conn(stream).await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "notification mail listener: accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// One connection, cut off at the session deadline however it is going.
    async fn serve_conn<S>(self: Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _ = tokio::time::timeout(self.session_deadline, self.converse(stream)).await;
    }

    /// Does `presented` match the listener secret? Constant time, and without
    /// the trailing newline a password file read as-is may carry — ours was
    /// trimmed when it was read.
    fn is_secret(&self, presented: &[u8]) -> bool {
        crate::util::constant_time_eq(presented.trim_ascii(), self.secret.as_bytes())
    }

    /// One `AUTH` exchange: PLAIN or LOGIN, with or without an initial
    /// response. Only the password is checked — it is the secret, and the name
    /// Authelia gives for itself is not.
    async fn authenticate<R, W>(
        &self,
        cmd: &str,
        reader: &mut R,
        write: &mut W,
        buf: &mut Vec<u8>,
    ) -> std::io::Result<Auth>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut words = cmd.split_whitespace().skip(1);
        let mechanism = words.next().unwrap_or_default().to_ascii_uppercase();
        let initial = words.next().map(str::to_string);
        let password = match mechanism.as_str() {
            "PLAIN" => {
                let response = match initial {
                    Some(r) => r,
                    // `AUTH PLAIN` alone: an empty challenge, then the response.
                    None => match prompt(b"334 \r\n", reader, write, buf).await? {
                        Some(r) => r,
                        None => return Ok(Auth::Closed),
                    },
                };
                let decoded = match decode_response(&response) {
                    Ok(d) => d,
                    Err(reply) => return Ok(Auth::Refused(reply)),
                };
                // authzid NUL authcid NUL password
                let mut parts = decoded.splitn(3, |&b| b == 0);
                match (parts.next(), parts.next(), parts.next()) {
                    (Some(_), Some(_), Some(p)) => p.to_vec(),
                    _ => return Ok(Auth::Refused(AUTH_INVALID)),
                }
            }
            "LOGIN" => {
                // A username given with the command needs no prompt for it.
                if initial.is_none() {
                    // "Username:"
                    match prompt(b"334 VXNlcm5hbWU6\r\n", reader, write, buf).await? {
                        Some(r) => {
                            if let Err(reply) = decode_response(&r) {
                                return Ok(Auth::Refused(reply));
                            }
                        }
                        None => return Ok(Auth::Closed),
                    }
                }
                // "Password:"
                match prompt(b"334 UGFzc3dvcmQ6\r\n", reader, write, buf).await? {
                    Some(r) => match decode_response(&r) {
                        Ok(p) => p,
                        Err(reply) => return Ok(Auth::Refused(reply)),
                    },
                    None => return Ok(Auth::Closed),
                }
            }
            _ => {
                return Ok(Auth::Refused(
                    b"504 5.5.4 only AUTH PLAIN and AUTH LOGIN are offered\r\n",
                ));
            }
        };
        Ok(if self.is_secret(&password) {
            Auth::Accepted
        } else {
            Auth::Refused(AUTH_INVALID)
        })
    }

    /// The SMTP conversation. Enough of RFC 5321 and RFC 4954 for Authelia,
    /// and nothing more.
    async fn converse<S>(self: &Arc<Self>, stream: S) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read, mut write) = tokio::io::split(stream);
        let mut reader = BufReader::new(read);
        let mut buf = Vec::new();
        let mut msg = Incoming::default();
        let mut authenticated = false;
        let (mut auth_failures, mut unknown) = (0u8, 0u8);

        write.write_all(b"220 bilbycast-portal ESMTP\r\n").await?;
        loop {
            match read_line(&mut reader, &mut buf).await {
                Line::Read => {}
                Line::TooLong => {
                    write.write_all(b"500 5.5.2 line too long\r\n").await?;
                    return Ok(());
                }
                Line::Closed => return Ok(()),
            }
            let line = String::from_utf8_lossy(&buf).trim_end().to_string();
            let upper = line.to_ascii_uppercase();
            if speaks_http(&upper) {
                tracing::warn!("closed a notification mail connection that spoke HTTP");
                return Ok(());
            }
            if upper.starts_with("EHLO") {
                msg = Incoming::default();
                write
                    .write_all(
                        b"250-bilbycast-portal\r\n250-8BITMIME\r\n250-SIZE 1048576\r\n\
                          250 AUTH PLAIN LOGIN\r\n",
                    )
                    .await?;
            } else if upper.starts_with("HELO") {
                msg = Incoming::default();
                write.write_all(b"250 bilbycast-portal\r\n").await?;
            } else if upper == "AUTH" || upper.starts_with("AUTH ") {
                if authenticated {
                    write
                        .write_all(b"503 5.5.1 already authenticated\r\n")
                        .await?;
                    continue;
                }
                match self
                    .authenticate(&line, &mut reader, &mut write, &mut buf)
                    .await?
                {
                    Auth::Accepted => {
                        authenticated = true;
                        write.write_all(b"235 2.7.0 authenticated\r\n").await?;
                    }
                    Auth::Refused(reply) => {
                        auth_failures += 1;
                        tracing::warn!(
                            "a client failed to authenticate to the notification mail listener; \
                             if it was Authelia, its notifier.smtp password is not the secret in \
                             mail.listen_password_file"
                        );
                        write.write_all(reply).await?;
                        if auth_failures >= MAX_AUTH_FAILURES {
                            return Ok(());
                        }
                    }
                    Auth::Closed => return Ok(()),
                }
            } else if upper.starts_with("MAIL FROM:") {
                if !authenticated {
                    write.write_all(AUTH_FIRST).await?;
                } else if !msg.from.is_empty() {
                    write
                        .write_all(b"503 5.5.1 sender already given\r\n")
                        .await?;
                } else {
                    let from = address_in(&line);
                    if sender_is_ours(&self.cfg, &from) {
                        msg = Incoming {
                            from,
                            ..Default::default()
                        };
                        write.write_all(b"250 2.1.0 ok\r\n").await?;
                    } else {
                        tracing::error!(
                            from = %from,
                            mail_from = %self.cfg.from,
                            "refused mail from a sender other than mail.from; Authelia's \
                             notifier.smtp.sender must carry the same address"
                        );
                        write
                            .write_all(
                                b"550 5.7.1 sender is not this portal's mail.from address\r\n",
                            )
                            .await?;
                    }
                }
            } else if upper.starts_with("RCPT TO:") {
                if !authenticated {
                    write.write_all(AUTH_FIRST).await?;
                } else if msg.from.is_empty() {
                    write.write_all(b"503 5.5.1 need MAIL first\r\n").await?;
                } else if !msg.recipients.is_empty() {
                    // Authelia addresses every message to one person.
                    write
                        .write_all(b"452 4.5.3 one recipient per message\r\n")
                        .await?;
                } else {
                    let to = address_in(&line);
                    if to.is_empty() {
                        write
                            .write_all(b"501 5.1.3 no recipient address\r\n")
                            .await?;
                    } else {
                        msg.recipients.push(to);
                        write.write_all(b"250 2.1.5 ok\r\n").await?;
                    }
                }
            } else if upper.starts_with("DATA") {
                if !authenticated {
                    write.write_all(AUTH_FIRST).await?;
                    continue;
                }
                if msg.from.is_empty() {
                    write.write_all(b"503 5.5.1 need MAIL first\r\n").await?;
                    continue;
                }
                if msg.recipients.is_empty() {
                    write.write_all(b"503 5.5.1 need RCPT first\r\n").await?;
                    continue;
                }
                write.write_all(b"354 go ahead\r\n").await?;
                loop {
                    match read_line(&mut reader, &mut buf).await {
                        Line::Read => {}
                        Line::TooLong => {
                            write.write_all(b"500 5.5.2 line too long\r\n").await?;
                            return Ok(());
                        }
                        Line::Closed => return Ok(()),
                    }
                    if buf == b".\r\n" || buf == b".\n" {
                        break;
                    }
                    // Dot-stuffing undone: the sender doubled every leading dot.
                    let body = buf.strip_prefix(b".").unwrap_or(&buf);
                    if msg.data.len() + body.len() > MAX_MESSAGE_BYTES {
                        write.write_all(b"552 5.3.4 message too large\r\n").await?;
                        return Ok(());
                    }
                    msg.data.extend_from_slice(body);
                }
                let taken = std::mem::take(&mut msg);
                // Accepted here, delivered after: Authelia will not send it
                // again, so whatever happens next is reported to the manager
                // instead. Bounded, so no client can queue relay work faster
                // than the relay drains it.
                let Ok(permit) = self.in_flight.clone().try_acquire_owned() else {
                    tracing::warn!(
                        limit = MAX_IN_FLIGHT,
                        "too many notification emails waiting on the relay; refused one with 451"
                    );
                    write
                        .write_all(b"451 4.3.2 too many messages in flight, try again later\r\n")
                        .await?;
                    continue;
                };
                write.write_all(b"250 2.0.0 accepted\r\n").await?;
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let _permit = permit;
                    // Every outcome is logged, or reported to the manager, inside.
                    let _ = handle(&this.cfg, &this.pending, this.relay.as_ref(), taken).await;
                });
            } else if upper.starts_with("RSET") {
                msg = Incoming::default();
                write.write_all(b"250 2.0.0 ok\r\n").await?;
            } else if upper.starts_with("NOOP") {
                write.write_all(b"250 2.0.0 ok\r\n").await?;
            } else if upper.starts_with("QUIT") {
                write.write_all(b"221 2.0.0 bye\r\n").await?;
                return Ok(());
            } else {
                unknown += 1;
                if unknown >= MAX_UNKNOWN_COMMANDS {
                    write
                        .write_all(b"421 4.7.0 too many unrecognised commands\r\n")
                        .await?;
                    return Ok(());
                }
                write.write_all(b"502 5.5.2 not implemented\r\n").await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
    use tokio::net::TcpStream;

    const SECRET: &str = "a-listener-secret-that-is-well-over-thirty-two-characters";

    fn cfg() -> MailConfig {
        MailConfig {
            listen_addr: default_listen(),
            listen_password_file: "/etc/bilbycast/portal-mail-listener".into(),
            relay_host: "smtp-relay.example.com".into(),
            relay_port: None,
            relay_username: "u".into(),
            relay_password_file: "/dev/null".into(),
            from: "Example Notifications <noreply@portal.example>".into(),
            sign_in_url: "https://watch.portal.example".into(),
            brand: default_brand(),
            link_lifetime: None,
            invite_subject: None,
            reset_subject: None,
            starttls: None,
            implicit_tls: false,
        }
    }

    /// A message shaped like Authelia's: multipart, quoted-printable, with the
    /// link split across lines by a soft break.
    fn authelia_message(to: &str) -> Incoming {
        let data = format!(
            "From: Example <noreply@portal.example>\r\n\
             To: {to}\r\n\
             Subject: Reset your password\r\n\
             Content-Type: multipart/alternative; boundary=b1\r\n\r\n\
             --b1\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\r\n\
             Use this link:\r\n\
             https://watch.portal.example/auth/reset-password/step2?token=3DeyJhbGciOiJIUzI1NiJ9.=\r\n\
             abc-def_123\r\n\r\n\
             --b1--\r\n"
        );
        Incoming {
            from: "noreply@portal.example".into(),
            recipients: vec![to.into()],
            data: data.into_bytes(),
        }
    }

    const LINK: &str =
        "https://watch.portal.example/auth/reset-password/step2?token=eyJhbGciOiJIUzI1NiJ9.abc";

    /// The words of a message, with quoted-printable's soft breaks and `=3D`
    /// undone so an assertion reads what the recipient would.
    fn readable(body: &str) -> String {
        body.replace("=\r\n", "").replace("=3D", "=")
    }

    #[derive(Default)]
    struct Captured {
        sent: Mutex<Vec<(Envelope, String)>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl Relay for Captured {
        async fn send(&self, envelope: Envelope, body: Vec<u8>) -> Result<(), String> {
            if self.fail {
                return Err("relay said no".into());
            }
            self.sent
                .lock()
                .await
                .push((envelope, String::from_utf8_lossy(&body).into_owned()));
            Ok(())
        }
    }

    fn interceptor(pending: Arc<PendingLinks>, relay: Arc<Captured>) -> Interceptor {
        Interceptor::new(cfg(), SECRET.into(), pending, relay)
    }

    /// Standard base64, for writing credentials the way a client does.
    fn b64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// The client end of one SMTP conversation.
    struct Client<S> {
        r: BufReader<ReadHalf<S>>,
        w: WriteHalf<S>,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
        fn over(stream: S) -> Self {
            let (r, w) = tokio::io::split(stream);
            Self {
                r: BufReader::new(r),
                w,
            }
        }

        async fn send(&mut self, line: &str) {
            // The server may already have hung up; the reply says what it did.
            let _ = self.w.write_all(format!("{line}\r\n").as_bytes()).await;
        }

        /// The next reply, continuation lines included, or `None` once the
        /// server has closed the connection.
        async fn reply(&mut self) -> Option<String> {
            let mut all = String::new();
            loop {
                let mut line = String::new();
                let read =
                    tokio::time::timeout(Duration::from_secs(5), self.r.read_line(&mut line))
                        .await
                        .expect("no reply within five seconds");
                match read {
                    Ok(0) | Err(_) => return (!all.is_empty()).then_some(all),
                    Ok(_) => {}
                }
                all.push_str(&line);
                if line.as_bytes().get(3) != Some(&b'-') {
                    return Some(all);
                }
            }
        }

        async fn say(&mut self, line: &str) -> String {
            self.send(line).await;
            self.reply()
                .await
                .unwrap_or_else(|| panic!("the connection closed after {line:?}"))
        }

        async fn authenticate(&mut self) {
            let r = self
                .say(&format!(
                    "AUTH PLAIN {}",
                    b64(format!("\0authelia\0{SECRET}").as_bytes())
                ))
                .await;
            assert!(r.starts_with("235"), "{r}");
        }

        /// MAIL, RCPT and DATA for `msg`; the reply to the closing dot.
        async fn deliver(&mut self, msg: &Incoming) -> String {
            let r = self.say(&format!("MAIL FROM:<{}>", msg.from)).await;
            assert!(r.starts_with("250"), "{r}");
            let r = self.say(&format!("RCPT TO:<{}>", msg.recipients[0])).await;
            assert!(r.starts_with("250"), "{r}");
            let r = self.say("DATA").await;
            assert!(r.starts_with("354"), "{r}");
            self.w.write_all(&msg.data).await.unwrap();
            self.say(".").await
        }
    }

    /// A conversation with `interceptor`, past its greeting.
    async fn connect(interceptor: Arc<Interceptor>) -> Client<DuplexStream> {
        let (ours, theirs) = tokio::io::duplex(1 << 20);
        tokio::spawn(interceptor.serve_conn(theirs));
        let mut c = Client::over(ours);
        let greeting = c.reply().await.unwrap();
        assert!(greeting.starts_with("220"), "{greeting}");
        c
    }

    /// Give a spawned relay the moment it would need to send anything.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[test]
    fn the_link_survives_a_soft_line_break() {
        let msg = authelia_message("bea@example.com");
        let link = extract_link(&msg.data).expect("no link found");
        assert_eq!(
            link,
            "https://watch.portal.example/auth/reset-password/step2?token=eyJhbGciOiJIUzI1NiJ9.abc-def_123",
            "the token was truncated or the soft break left in"
        );
    }

    #[test]
    fn a_message_with_no_link_reports_none() {
        assert!(extract_link(b"Subject: hello\r\n\r\nnothing to see").is_none());
    }

    #[tokio::test]
    async fn the_first_link_is_an_invite_and_a_later_one_is_a_reset() {
        for (kind, subject, phrase) in [
            (
                LinkKind::Invite,
                "Your Bilbycast account",
                "You have been given access",
            ),
            (
                LinkKind::Reset,
                "Bilbycast password reset",
                "asked to reset the password",
            ),
        ] {
            let pending = PendingLinks::default();
            let rx = pending.expect("Bea@Example.com", kind, "Bea Jones").await;
            let relay = Captured::default();
            handle(
                &cfg(),
                &pending,
                &relay,
                authelia_message("bea@example.com"),
            )
            .await
            .unwrap();
            let sent = relay.sent.lock().await;
            let (envelope, body) = sent.first().expect("nothing was relayed");
            let body = readable(body);
            assert!(body.contains(subject), "wrong subject for {kind:?}: {body}");
            assert!(body.contains(phrase), "wrong wording for {kind:?}");
            assert!(
                body.contains("reset-password/step2?token="),
                "the link did not travel"
            );
            assert!(
                body.contains("Bea Jones"),
                "the recipient is not addressed by name"
            );
            assert_eq!(envelope.to().len(), 1);
            assert_eq!(envelope.to()[0].to_string(), "bea@example.com");
            // And the manager hears that it went.
            assert_eq!(rx.await.unwrap(), Ok(()));
        }
    }

    /// Names an operator will type, and the one a username falls back to.
    /// lettre's parser refuses every one of these as `Name <address>`; built
    /// rather than parsed, each is written as a header that reads back as
    /// itself — and a CR/LF cannot start a header of its own.
    #[tokio::test]
    async fn any_display_name_composes_and_cannot_add_a_header() {
        for name in [
            "Jones, Bea",
            "Bea (Producer)",
            "a<b",
            "Bea\r\nBcc: someone@attacker.example",
            "Bea\u{1b}[31m\u{7}",
            "bea@example.com",
        ] {
            let message = rewrite(&cfg(), LinkKind::Invite, name, "bea@example.com", LINK)
                .unwrap_or_else(|e| panic!("{name:?} did not compose: {e}"));
            let to: Mailbox = message
                .headers()
                .get_raw("To")
                .expect("no To header")
                .parse()
                .unwrap_or_else(|e| panic!("the To header for {name:?} does not parse: {e:?}"));
            assert_eq!(to.email.to_string(), "bea@example.com");
            assert_eq!(to.name.as_deref(), Some(clean_name(name).as_str()));
            assert!(
                !to.name.unwrap().contains(char::is_control),
                "{name:?} kept a control character"
            );
            let formatted = String::from_utf8(message.formatted()).unwrap();
            assert!(
                !formatted.contains("\nBcc:"),
                "a name added a header: {formatted}"
            );
        }

        // And through the whole path: the person is invited, by name.
        let pending = PendingLinks::default();
        let rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Jones, Bea")
            .await;
        let relay = Captured::default();
        let msg = authelia_message("bea@example.com");
        handle(&cfg(), &pending, &relay, msg.clone()).await.unwrap();
        assert_eq!(rx.await.unwrap(), Ok(()));
        let sent = relay.sent.lock().await;
        assert_ne!(
            sent[0].1.as_bytes(),
            msg.data.as_slice(),
            "it was not rewritten"
        );
        assert!(
            readable(&sent[0].1).contains("Hello Jones, Bea,"),
            "{}",
            sent[0].1
        );
    }

    /// The name is whatever a group administrator typed, and the email goes
    /// out under our domain: nothing typed may become markup.
    #[test]
    fn the_html_part_escapes_everything_it_interpolates() {
        let name = clean_name(r#"Bea</p><a href="https://evil.example">Sign in again</a>"#);
        let letter = Letter {
            brand: "Tom & Jerry's",
            name: &name,
            link: "https://watch.portal.example/r?token=a&b=\"c\"",
            sign_in: "https://watch.portal.example",
            lifetime: Some("3 <b>days</b>"),
        };
        for kind in [LinkKind::Invite, LinkKind::Reset] {
            let html = html_body(&letter, kind);
            assert!(
                !html.contains("<a href=\"https://evil.example\">"),
                "{html}"
            );
            assert!(html.contains(
                "Hello Bea&lt;/p&gt;&lt;a href=&quot;https://evil.example&quot;&gt;Sign in \
                 again&lt;/a&gt;,"
            ));
            assert!(html.contains("Tom &amp; Jerry&#39;s Notifications"));
            assert!(html.contains("This link lasts 3 &lt;b&gt;days&lt;/b&gt;."));
            assert!(
                html.contains(
                    "href=\"https://watch.portal.example/r?token=a&amp;b=&quot;c&quot;\""
                )
            );
        }
    }

    /// Whatever stops the rewrite, the person still gets Authelia's email and
    /// its link, and the manager hears how the relay answered.
    #[tokio::test]
    async fn a_compose_failure_relays_authelias_own_email() {
        let mut c = cfg();
        // `validate` refuses this From at startup; a rewrite that fails for
        // any reason must still not cost anyone their link.
        c.from = "Example, Inc <noreply@portal.example>".into();
        assert!(rewrite(&c, LinkKind::Invite, "Bea", "bea@example.com", LINK).is_err());
        let pending = PendingLinks::default();
        let rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Bea")
            .await;
        let relay = Captured::default();
        let msg = authelia_message("bea@example.com");
        handle(&c, &pending, &relay, msg.clone()).await.unwrap();
        let sent = relay.sent.lock().await;
        let (_, body) = sent.first().expect("the link was dropped");
        assert_eq!(body.as_bytes(), msg.data.as_slice());
        assert_eq!(rx.await.unwrap(), Ok(()));
    }

    /// No customer's name in the code: the brand is configured, and so is how
    /// long the link lasts — which the emails do not guess at.
    #[test]
    fn the_emails_carry_the_configured_brand_and_claim_no_lifetime_unless_told() {
        let message = rewrite(&cfg(), LinkKind::Reset, "Bea", "bea@example.com", LINK).unwrap();
        let body = readable(&String::from_utf8(message.formatted()).unwrap());
        assert!(body.contains("Subject: Bilbycast password reset"), "{body}");
        assert!(body.contains("your Bilbycast account"));
        assert!(
            !body.contains("lasts"),
            "a lifetime nobody configured: {body}"
        );

        let mut c = cfg();
        c.brand = "Acme Sport".into();
        c.link_lifetime = Some("three days".into());
        let message = rewrite(&c, LinkKind::Invite, "Bea", "bea@example.com", LINK).unwrap();
        let body = readable(&String::from_utf8(message.formatted()).unwrap());
        assert!(body.contains("Subject: Your Acme Sport account"), "{body}");
        assert!(body.contains("access to Acme Sport live"));
        assert!(body.contains("This link lasts three days."));
        assert!(!body.contains("Bilbycast"));

        c.invite_subject = Some("Welcome aboard".into());
        let message = rewrite(&c, LinkKind::Invite, "Bea", "bea@example.com", LINK).unwrap();
        assert_eq!(message.headers().get_raw("Subject"), Some("Welcome aboard"));
    }

    #[tokio::test]
    async fn a_message_from_anything_but_us_is_dropped() {
        let pending = PendingLinks::default();
        let relay = Captured::default();
        let mut msg = authelia_message("bea@example.com");
        msg.from = "spammer@elsewhere.example".into();
        let out = handle(&cfg(), &pending, &relay, msg).await;
        assert!(out.is_err(), "the listener relayed mail for a stranger");
        assert!(relay.sent.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_message_nobody_asked_for_is_relayed_untouched() {
        let pending = PendingLinks::default();
        let relay = Captured::default();
        let msg = authelia_message("someone.else@example.com");
        handle(&cfg(), &pending, &relay, msg.clone()).await.unwrap();
        let sent = relay.sent.lock().await;
        let (_, body) = sent.first().expect("nothing was relayed");
        assert_eq!(
            body.as_bytes(),
            msg.data.as_slice(),
            "an unexpected email was rewritten"
        );
        assert!(body.contains("Subject: Reset your password"));
    }

    #[tokio::test]
    async fn a_relay_failure_reaches_the_manager() {
        let pending = PendingLinks::default();
        let rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Bea")
            .await;
        let relay = Captured {
            fail: true,
            ..Default::default()
        };
        let out = handle(
            &cfg(),
            &pending,
            &relay,
            authelia_message("bea@example.com"),
        )
        .await;
        assert!(out.is_err());
        assert_eq!(rx.await.unwrap(), Err("relay said no".into()));
    }

    async fn aged(age: Duration) -> PendingLinks {
        let pending = PendingLinks::default();
        let _rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Bea")
            .await;
        if let Some(p) = pending.0.lock().await.get_mut("bea@example.com") {
            p.at = Instant::now() - age;
        }
        pending
    }

    #[tokio::test]
    async fn a_stale_expectation_does_not_claim_a_later_email() {
        let pending = aged(PENDING_TTL + Duration::from_secs(1)).await;
        let relay = Captured::default();
        let msg = authelia_message("bea@example.com");
        handle(&cfg(), &pending, &relay, msg.clone()).await.unwrap();
        let sent = relay.sent.lock().await;
        assert_eq!(
            sent[0].1.as_bytes(),
            msg.data.as_slice(),
            "a stale expectation rewrote it"
        );
    }

    /// The account sync gives up on an email after 30 s. An expectation that
    /// lived on past that would reword the viewer's own reset, minutes later,
    /// as an invitation nobody is waiting to hear about.
    #[tokio::test]
    async fn an_expectation_does_not_outlive_the_account_syncs_wait() {
        let pending = aged(Duration::from_secs(31)).await;
        let relay = Captured::default();
        let msg = authelia_message("bea@example.com");
        handle(&cfg(), &pending, &relay, msg.clone()).await.unwrap();
        assert_eq!(relay.sent.lock().await[0].1.as_bytes(), msg.data.as_slice());
    }

    #[test]
    fn addresses_are_read_out_of_the_commands() {
        assert_eq!(address_in("MAIL FROM:<a@b.c>"), "a@b.c");
        assert_eq!(address_in("RCPT TO:<a@b.c> SIZE=42"), "a@b.c");
        assert_eq!(address_in("MAIL FROM: a@b.c"), "a@b.c");
    }

    #[test]
    fn base64_decodes_what_sasl_clients_send_and_nothing_else() {
        for sample in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"\0authelia\0pass",
            &[0xff, 0x00, 0x80],
        ] {
            assert_eq!(base64_decode(&b64(sample)).as_deref(), Some(sample));
        }
        assert_eq!(
            base64_decode("VXNlcm5hbWU6").as_deref(),
            Some(&b"Username:"[..])
        );
        // RFC 4954's zero-length response.
        assert_eq!(base64_decode("=").as_deref(), Some(&b""[..]));
        assert_eq!(base64_decode("A"), None);
        assert_eq!(base64_decode("not base64!"), None);
        assert_eq!(base64_decode("QQ==="), None);
    }

    #[test]
    fn the_listener_must_be_loopback_and_clear_text_relaying_is_this_host_only() {
        let mut c = cfg();
        assert_eq!(c.validate(), Ok(()));
        c.listen_addr = "0.0.0.0:2525".into();
        assert!(
            c.validate().is_err(),
            "a public listener would put its secret on the network"
        );

        let mut c = cfg();
        c.starttls = Some(false);
        assert!(
            c.validate().is_err(),
            "the relay password would go out in clear"
        );
        for local in ["127.0.0.1", "127.0.0.2", "::1", "localhost", "LocalHost"] {
            c.relay_host = local.into();
            assert_eq!(c.validate(), Ok(()), "{local} is this host");
        }
        for remote in [
            "127.0.0.1.mailsink.example",
            "localhost.example",
            "10.0.0.1",
        ] {
            c.relay_host = remote.into();
            assert!(c.validate().is_err(), "{remote} was taken for this host");
        }
    }

    #[test]
    fn implicit_tls_is_its_own_setting_with_its_own_port() {
        let mut c = cfg();
        assert_eq!((c.outbound(), c.port()), (Outbound::StartTls, 587));
        c.implicit_tls = true;
        assert_eq!(c.validate(), Ok(()));
        assert_eq!((c.outbound(), c.port()), (Outbound::Implicit, 465));
        // Encrypted from the first byte, so not "starttls off" in clear.
        c.starttls = Some(false);
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.outbound(), Outbound::Implicit);
        c.starttls = Some(true);
        let err = c.validate().unwrap_err();
        assert!(err.contains("starttls"), "{err}");

        let mut c = cfg();
        c.relay_port = Some(2587);
        assert_eq!(c.port(), 2587);
        c.relay_port = Some(0);
        assert!(c.validate().is_err());
    }

    /// The config in production before the listener demanded a password must
    /// be refused by name, not by a parse error or not at all.
    #[test]
    fn a_config_from_before_the_listener_secret_says_what_to_add() {
        let mut c: MailConfig = serde_json::from_str(
            r#"{
                "relay_host": "smtp-relay.brevo.com",
                "relay_port": 587,
                "relay_username": "xxxx@smtp-brevo.com",
                "relay_password_file": "/etc/bilbycast/brevo-smtp-key",
                "from": "Example Notifications <noreply@example.com>",
                "sign_in_url": "https://watch.example.com/",
                "invite_subject": "Welcome",
                "reset_subject": "Password reset",
                "starttls": true
            }"#,
        )
        .expect("the existing keys no longer parse");
        c.normalise();
        let err = c.validate().unwrap_err();
        assert!(err.contains("mail.listen_password_file"), "{err}");
        c.listen_password_file = "/etc/bilbycast/portal-mail-listener".into();
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.subject(LinkKind::Invite), "Welcome");
    }

    #[test]
    fn what_goes_into_a_header_or_a_sentence_is_one_short_line() {
        fn refuses(what: &str, break_it: impl FnOnce(&mut MailConfig)) {
            let mut c = cfg();
            break_it(&mut c);
            assert!(c.validate().is_err(), "accepted a bad {what}");
        }
        refuses("brand", |c| c.brand = String::new());
        refuses("brand", |c| c.brand = "Acme\r\nBcc: x@y.z".into());
        refuses("brand", |c| c.brand = "A".repeat(65));
        refuses("link_lifetime", |c| {
            c.link_lifetime = Some("three\ndays".into())
        });
        refuses("invite_subject", |c| {
            c.invite_subject = Some("Hi\r\nBcc: x@y.z".into())
        });
        refuses("reset_subject", |c| c.reset_subject = Some(String::new()));
        refuses("from", |c| {
            c.from = "Example, Inc <noreply@example.com>".into()
        });
        refuses("from", |c| c.from = "not an address".into());

        let mut c = cfg();
        c.from = "\"Example, Inc\" <noreply@example.com>".into();
        assert_eq!(c.validate(), Ok(()), "a quoted name is an address");
        c.link_lifetime = Some("   ".into());
        c.invite_subject = Some(String::new());
        c.normalise();
        assert_eq!((c.link_lifetime, c.invite_subject), (None, None));
    }

    #[test]
    fn the_listener_secret_is_one_long_line_from_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("listener");
        let mut c = cfg();
        c.listen_password_file = path.clone();
        assert!(c.listen_password().is_err(), "a missing file");
        std::fs::write(&path, "short\n").unwrap();
        assert!(c.listen_password().is_err(), "a guessable secret");
        std::fs::write(&path, format!("{SECRET}\nsecond line\n")).unwrap();
        assert!(c.listen_password().is_err(), "two lines");
        std::fs::write(&path, format!("{SECRET}\n")).unwrap();
        assert_eq!(c.listen_password().unwrap(), SECRET);
    }

    #[test]
    fn the_secret_is_compared_whole() {
        let i = interceptor(Default::default(), Default::default());
        assert!(i.is_secret(SECRET.as_bytes()));
        assert!(
            i.is_secret(format!("{SECRET}\n").as_bytes()),
            "Authelia may send its file's newline"
        );
        assert!(!i.is_secret(&SECRET.as_bytes()[..SECRET.len() - 1]));
        assert!(!i.is_secret(format!("{SECRET}x").as_bytes()));
        assert!(!i.is_secret(b""));
    }

    /// The configured sender's address is public — it is the From of every
    /// email the portal sends — so claiming it proves nothing. Without the
    /// listener secret, nothing is taken.
    #[tokio::test]
    async fn mail_is_refused_until_the_client_authenticates() {
        let relay = Arc::new(Captured::default());
        let mut c = connect(Arc::new(interceptor(Default::default(), relay.clone()))).await;
        let ehlo = c.say("EHLO somebody").await;
        assert!(ehlo.contains("AUTH PLAIN LOGIN"), "{ehlo}");
        for cmd in [
            "MAIL FROM:<noreply@portal.example>",
            "RCPT TO:<victim@example.com>",
            "DATA",
        ] {
            let r = c.say(cmd).await;
            assert!(r.starts_with("530"), "{cmd}: {r}");
        }
        settle().await;
        assert!(relay.sent.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_the_third_ends_the_conversation() {
        let mut c = connect(Arc::new(interceptor(
            Default::default(),
            Default::default(),
        )))
        .await;
        let wrong = format!("AUTH PLAIN {}", b64(b"\0authelia\0not-the-secret"));
        for _ in 0..MAX_AUTH_FAILURES {
            let r = c.say(&wrong).await;
            assert!(r.starts_with("535"), "{r}");
        }
        assert_eq!(c.reply().await, None, "a fourth guess was allowed");
    }

    /// Every way Authelia's SMTP client might present the secret.
    #[tokio::test]
    async fn each_form_of_auth_a_client_uses_is_accepted() {
        let plain = b64(format!("\0authelia\0{SECRET}").as_bytes());
        let (user, pass) = (b64(b"authelia"), b64(SECRET.as_bytes()));
        let forms: [&[(&str, &str)]; 4] = [
            &[(&format!("AUTH PLAIN {plain}"), "235")],
            &[("AUTH PLAIN", "334"), (&plain, "235")],
            &[
                ("AUTH LOGIN", "334 VXNlcm5hbWU6"),
                (&user, "334 UGFzc3dvcmQ6"),
                (&pass, "235"),
            ],
            &[
                (&format!("AUTH LOGIN {user}"), "334 UGFzc3dvcmQ6"),
                (&pass, "235"),
            ],
        ];
        for steps in forms {
            let relay = Arc::new(Captured::default());
            let mut c = connect(Arc::new(interceptor(Default::default(), relay.clone()))).await;
            c.say("EHLO authelia").await;
            for (send, expect) in steps {
                let r = c.say(send).await;
                assert!(r.starts_with(expect), "{send}: {r}");
            }
            let r = c.deliver(&authelia_message("bea@example.com")).await;
            assert!(r.starts_with("250"), "{r}");
            settle().await;
            assert_eq!(relay.sent.lock().await.len(), 1, "{steps:?}");
        }
    }

    /// Refused while Authelia is still talking, so a mismatched sender fails
    /// Authelia's own startup check instead of being accepted and dropped.
    #[tokio::test]
    async fn a_sender_other_than_ours_is_refused_at_mail_from() {
        let relay = Arc::new(Captured::default());
        let mut c = connect(Arc::new(interceptor(Default::default(), relay.clone()))).await;
        c.authenticate().await;
        let r = c.say("MAIL FROM:<noreply@somewhere-else.example>").await;
        assert!(r.starts_with("550"), "{r}");
        let r = c.say("RCPT TO:<bea@example.com>").await;
        assert!(
            r.starts_with("503"),
            "a recipient without an accepted sender: {r}"
        );
        let r = c.say("DATA").await;
        assert!(r.starts_with("503"), "{r}");
        settle().await;
        assert!(relay.sent.lock().await.is_empty());
    }

    #[tokio::test]
    async fn one_message_goes_to_one_recipient() {
        let relay = Arc::new(Captured::default());
        let mut c = connect(Arc::new(interceptor(Default::default(), relay.clone()))).await;
        c.authenticate().await;
        c.say("MAIL FROM:<noreply@portal.example>").await;
        assert!(c.say("RCPT TO:<bea@example.com>").await.starts_with("250"));
        let r = c.say("RCPT TO:<second@example.com>").await;
        assert!(r.starts_with("452"), "{r}");
        assert!(c.say("DATA").await.starts_with("354"));
        c.w.write_all(&authelia_message("bea@example.com").data)
            .await
            .unwrap();
        assert!(c.say(".").await.starts_with("250"));
        settle().await;
        let sent = relay.sent.lock().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.to().len(), 1);
    }

    /// A line with no end is cut off at the cap and answered, rather than
    /// buffered until a newline that never comes.
    #[tokio::test]
    async fn an_endless_line_is_cut_off_not_buffered() {
        let endless = vec![b'A'; MAX_LINE_BYTES + 1];

        let mut c = connect(Arc::new(interceptor(
            Default::default(),
            Default::default(),
        )))
        .await;
        c.say("EHLO somebody").await;
        c.w.write_all(&endless).await.unwrap();
        let r = c.reply().await.expect("closed without an answer");
        assert!(r.starts_with("500"), "{r}");
        assert_eq!(c.reply().await, None);

        // And inside a message, where no line was checked at all.
        let relay = Arc::new(Captured::default());
        let mut c = connect(Arc::new(interceptor(Default::default(), relay.clone()))).await;
        c.authenticate().await;
        c.say("MAIL FROM:<noreply@portal.example>").await;
        c.say("RCPT TO:<bea@example.com>").await;
        assert!(c.say("DATA").await.starts_with("354"));
        c.w.write_all(&endless).await.unwrap();
        let r = c.reply().await.expect("closed without an answer");
        assert!(r.starts_with("500"), "{r}");
        assert_eq!(c.reply().await, None);
        settle().await;
        assert!(relay.sent.lock().await.is_empty());
    }

    /// An HTTP request smuggling SMTP in its body never reaches the body.
    #[tokio::test]
    async fn http_is_hung_up_on() {
        for first in [
            "POST /send HTTP/1.1",
            "GET / HTTP/1.0",
            "Host: 127.0.0.1:2525",
        ] {
            let mut c = connect(Arc::new(interceptor(
                Default::default(),
                Default::default(),
            )))
            .await;
            c.send(first).await;
            assert_eq!(c.reply().await, None, "{first} was answered");
        }
    }

    #[tokio::test]
    async fn three_unrecognised_commands_end_the_conversation() {
        let mut c = connect(Arc::new(interceptor(
            Default::default(),
            Default::default(),
        )))
        .await;
        assert!(c.say("VRFY bea").await.starts_with("502"));
        assert!(c.say("HELP").await.starts_with("502"));
        assert!(c.say("EXPN staff").await.starts_with("421"));
        assert_eq!(c.reply().await, None);
    }

    #[tokio::test]
    async fn a_full_relay_queue_refuses_the_message_rather_than_growing() {
        let relay = Arc::new(Captured::default());
        let i = Arc::new(interceptor(Default::default(), relay.clone()));
        let _busy = i
            .in_flight
            .clone()
            .try_acquire_many_owned(MAX_IN_FLIGHT as u32)
            .unwrap();
        let mut c = connect(i).await;
        c.authenticate().await;
        let r = c.deliver(&authelia_message("bea@example.com")).await;
        assert!(r.starts_with("451"), "{r}");
        settle().await;
        assert!(relay.sent.lock().await.is_empty());
    }

    /// Resetting the idle timer with a NOOP does not buy a connection forever.
    #[tokio::test]
    async fn a_conversation_that_never_ends_is_cut_off() {
        let mut i = interceptor(Default::default(), Default::default());
        i.session_deadline = Duration::from_millis(300);
        let mut c = connect(Arc::new(i)).await;
        let started = Instant::now();
        loop {
            c.send("NOOP").await;
            let Some(r) = c.reply().await else { break };
            assert!(r.starts_with("250"), "{r}");
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "a NOOP every 100 ms held the session open"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The whole conversation, over a real socket, the way Authelia holds it.
    #[tokio::test]
    async fn authelia_can_deliver_over_smtp() {
        let pending = Arc::new(PendingLinks::default());
        let rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Bea Jones")
            .await;
        let relay = Arc::new(Captured::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Arc::new(interceptor(pending, relay.clone())).serve(listener));

        let mut c = Client::over(TcpStream::connect(addr).await.unwrap());
        assert!(c.reply().await.unwrap().starts_with("220"));
        c.say("EHLO authelia").await;
        assert!(c.say("AUTH LOGIN").await.starts_with("334"));
        assert!(c.say(&b64(b"authelia")).await.starts_with("334"));
        assert!(c.say(&b64(SECRET.as_bytes())).await.starts_with("235"));
        let r = c.deliver(&authelia_message("bea@example.com")).await;
        assert!(r.starts_with("250"), "{r}");
        c.send("QUIT").await;

        // The relay result is what the manager is told.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
        let sent = relay.sent.lock().await;
        assert!(
            sent[0].1.contains("Your Bilbycast account"),
            "the invite was not rewritten"
        );
    }

    #[tokio::test]
    async fn a_full_listener_turns_the_next_connection_away() {
        let i = Arc::new(interceptor(Default::default(), Default::default()));
        let busy = i
            .connections
            .clone()
            .try_acquire_many_owned(MAX_CONNECTIONS as u32)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(i.serve(listener));

        let mut c = Client::over(TcpStream::connect(addr).await.unwrap());
        let r = c.reply().await.expect("closed without an answer");
        assert!(r.starts_with("421"), "{r}");
        drop(busy);
        let mut c = Client::over(TcpStream::connect(addr).await.unwrap());
        assert!(c.reply().await.unwrap().starts_with("220"));
    }

    /// lettre bounds only the connect. A relay that accepts the connection and
    /// then says nothing must still be given up on before the account sync
    /// stops waiting, or the manager hears "timed out" about a send that may
    /// yet succeed — and the operator sends it again.
    #[tokio::test]
    async fn a_relay_that_never_answers_is_given_up_on() {
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = silent.accept().await;
            std::future::pending::<()>().await;
        });
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("relay-key");
        std::fs::write(&key, "key\n").unwrap();
        let mut c = cfg();
        c.relay_host = "127.0.0.1".into();
        c.relay_port = Some(port);
        c.starttls = Some(false);
        c.relay_password_file = key;
        let mut relay = SmtpRelay::new(&c).unwrap();
        relay.deadline = Duration::from_millis(300);
        let envelope = Envelope::new(
            Some("noreply@portal.example".parse().unwrap()),
            vec!["bea@example.com".parse().unwrap()],
        )
        .unwrap();
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            relay.send(envelope, b"Subject: x\r\n\r\nx\r\n".to_vec()),
        )
        .await
        .expect("the send outlived every deadline");
        let err = out.unwrap_err();
        assert!(err.contains("did not answer"), "{err}");
    }
}
