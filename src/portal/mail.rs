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
//! # What is rewritten, and what is not
//!
//! Only a message to somebody the portal has just asked for a link for, matched
//! by recipient within [`PENDING_TTL`]. Everything else Authelia sends — a
//! viewer using the "reset password" link on the sign-in page itself, or one of
//! Authelia's own event notices — is relayed **byte for byte**, so turning this
//! on cannot silently swallow mail nobody here anticipated.
//!
//! # Failure is reported, not swallowed
//!
//! Authelia believes the message is sent the moment this listener accepts it,
//! and it will not send it again. So the relay result is what the manager is
//! told: the Portal logins list says "sent" only once Brevo has taken it, and
//! names the error when it has not.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};

/// How long a requested link stays matchable. Authelia sends within a second of
/// being asked; this is generous so a slow box still matches, and short enough
/// that a viewer's own reset minutes later is not mistaken for our invite.
const PENDING_TTL: Duration = Duration::from_secs(300);

/// Caps on what the listener will read. Authelia's message is a few kilobytes.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
/// A conversation that stalls is dropped rather than held open.
const SMTP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailConfig {
    /// Where Authelia delivers. Loopback: it speaks no TLS and authenticates
    /// with nothing, so anything that can reach it can send mail as us.
    #[serde(default = "default_listen")]
    pub listen_addr: String,

    /// The relay that actually delivers, e.g. `smtp-relay.brevo.com`.
    pub relay_host: String,
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
    pub relay_username: String,
    /// A file holding the relay's password (Brevo calls it an SMTP key), so it
    /// is not in this config.
    pub relay_password_file: PathBuf,

    /// The From on everything that leaves here, e.g.
    /// `GRS Notifications <noreply@example.com>`. Its domain has to be
    /// authenticated at the relay.
    pub from: String,

    /// Where a viewer signs in, named in the emails.
    pub sign_in_url: String,

    #[serde(default = "default_invite_subject")]
    pub invite_subject: String,
    #[serde(default = "default_reset_subject")]
    pub reset_subject: String,

    /// STARTTLS on the way out. Off is for a local test sink only — it sends
    /// the relay password in clear, so [`validate`](Self::validate) refuses it
    /// against anything but loopback.
    #[serde(default = "default_true")]
    pub starttls: bool,
}

fn default_listen() -> String {
    "127.0.0.1:2525".to_string()
}
fn default_relay_port() -> u16 {
    587
}
fn default_invite_subject() -> String {
    "GRS New User".to_string()
}
fn default_reset_subject() -> String {
    "GRS password reset".to_string()
}
fn default_true() -> bool {
    true
}

impl MailConfig {
    pub fn normalise(&mut self) {
        self.relay_host = self.relay_host.trim().to_string();
        self.from = self.from.trim().to_string();
        self.sign_in_url = self.sign_in_url.trim().trim_end_matches('/').to_string();
    }

    pub fn validate(&self) -> Result<(), String> {
        let addr: SocketAddr = self
            .listen_addr
            .parse()
            .map_err(|_| "mail.listen_addr must be host:port".to_string())?;
        if !addr.ip().is_loopback() {
            return Err(
                "mail.listen_addr must be a loopback address: the listener has no \
                        authentication, so anything that can reach it can send mail as you"
                    .into(),
            );
        }
        if self.relay_host.is_empty() {
            return Err("mail.relay_host is required".into());
        }
        if self.relay_username.is_empty() {
            return Err("mail.relay_username is required".into());
        }
        if self.relay_password_file.as_os_str().is_empty() {
            return Err("mail.relay_password_file is required".into());
        }
        if self.from.is_empty() || !self.from.contains('@') {
            return Err("mail.from must be an email address".into());
        }
        if !self.sign_in_url.starts_with("https://") && !self.sign_in_url.starts_with("http://") {
            return Err("mail.sign_in_url must be an http(s) URL".into());
        }
        if !self.starttls
            && !self.relay_host.starts_with("127.0.0.1")
            && self.relay_host != "localhost"
        {
            return Err("mail.starttls may only be off for a relay on this host".into());
        }
        Ok(())
    }

    fn password(&self) -> anyhow::Result<String> {
        let raw = std::fs::read_to_string(&self.relay_password_file).map_err(|e| {
            anyhow::anyhow!("cannot read {}: {e}", self.relay_password_file.display())
        })?;
        Ok(raw.trim().to_string())
    }
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
#[derive(Debug, Clone, PartialEq)]
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

fn invite_text(name: &str, link: &str, sign_in: &str) -> String {
    format!(
        "Hello {name},\n\n\
         You have been given access to GRS live and recorded video.\n\n\
         To get started, choose a password for your account:\n\n\
         {link}\n\n\
         This link lasts three days. Once your password is set, sign in at\n\
         {sign_in} with your email address or your username, and the feeds you\n\
         have been given will be listed there.\n\n\
         If you were not expecting this, you can ignore this email — no password\n\
         is set and no access is granted until somebody uses the link.\n\n\
         GRS Notifications\n"
    )
}

fn reset_text(name: &str, link: &str, sign_in: &str) -> String {
    format!(
        "Hello {name},\n\n\
         Somebody asked to reset the password on your GRS account.\n\n\
         To choose a new one:\n\n\
         {link}\n\n\
         This link lasts three days. Afterwards, sign in at {sign_in} with your\n\
         email address or your username.\n\n\
         If you did not ask for this, you can ignore this email — your current\n\
         password still works and nothing changes until somebody uses the link.\n\n\
         GRS Notifications\n"
    )
}

fn html_body(name: &str, link: &str, sign_in: &str, kind: LinkKind) -> String {
    let (lead, action, footer) = match kind {
        LinkKind::Invite => (
            "You have been given access to GRS live and recorded video.",
            "Set your password",
            "If you were not expecting this you can ignore this email — no password is set \
             and no access is granted until somebody uses the link.",
        ),
        LinkKind::Reset => (
            "Somebody asked to reset the password on your GRS account.",
            "Choose a new password",
            "If you did not ask for this you can ignore this email — your current password \
             still works and nothing changes until somebody uses the link.",
        ),
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f6f8;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:10px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2933;border:1px solid #e1e6eb;">
<tr><td style="background:#0f172a;padding:18px 24px;color:#ffffff;font-size:16px;font-weight:600;">GRS Notifications</td></tr>
<tr><td style="padding:24px;font-size:15px;line-height:1.6;">
<p style="margin:0 0 14px;">Hello {name},</p>
<p style="margin:0 0 20px;">{lead}</p>
<p style="margin:0 0 22px;"><a href="{link}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;">{action}</a></p>
<p style="margin:0 0 14px;color:#52606d;font-size:13px;">This link lasts three days. Afterwards, sign in at <a href="{sign_in}" style="color:#2563eb;">{sign_in}</a> with your email address or your username.</p>
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
    let (subject, text) = match kind {
        LinkKind::Invite => (
            cfg.invite_subject.clone(),
            invite_text(display_name, link, &cfg.sign_in_url),
        ),
        LinkKind::Reset => (
            cfg.reset_subject.clone(),
            reset_text(display_name, link, &cfg.sign_in_url),
        ),
    };
    let to_mailbox = if display_name.is_empty() {
        to.parse()?
    } else {
        format!("{display_name} <{to}>").parse()?
    };
    Ok(Message::builder()
        .from(cfg.from.parse()?)
        .to(to_mailbox)
        .subject(subject)
        .multipart(lettre::message::MultiPart::alternative_plain_html(
            text,
            html_body(display_name, link, &cfg.sign_in_url, kind),
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
}

impl SmtpRelay {
    pub fn new(cfg: &MailConfig) -> anyhow::Result<Self> {
        let creds = Credentials::new(cfg.relay_username.clone(), cfg.password()?);
        let builder = if cfg.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.relay_host)?
        } else {
            // Loopback only — `validate` refuses this anywhere else.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.relay_host)
        };
        Ok(Self {
            transport: builder.port(cfg.relay_port).credentials(creds).build(),
        })
    }
}

#[async_trait::async_trait]
impl Relay for SmtpRelay {
    async fn send(&self, envelope: Envelope, body: Vec<u8>) -> Result<(), String> {
        self.transport
            .send_raw(&envelope, &body)
            .await
            .map(|_| ())
            .map_err(|e| format!("the mail relay refused it: {e}"))
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
    // Nothing but Authelia should be delivering here, but the listener has no
    // authentication — it cannot, Authelia has no credential to offer — so
    // anything else running on this host could hand it a message and have it
    // relayed under our own domain. The envelope sender is the one thing that
    // distinguishes them, so a message claiming to be from anyone else is
    // dropped rather than forwarded.
    if !sender_is_ours(cfg, &msg.from) {
        tracing::warn!(
            from = %msg.from,
            "refusing to relay a message that did not come from this portal's sender address"
        );
        return Err("the message was not from this portal's sender address".into());
    }
    let matched = pending.take(&msg.recipients).await;
    let Some((to, mut pending_entry)) = matched else {
        // Not ours: a viewer resetting their own password from the sign-in
        // page, or one of Authelia's notices. Relayed exactly as written.
        let envelope = envelope_for(&msg)?;
        let out = relay.send(envelope, msg.data).await;
        if let Err(ref e) = out {
            tracing::warn!(error = %e, "could not relay a message Authelia sent");
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
            Err(e) => Err(format!("could not compose the email: {e}")),
        },
        None => {
            // Authelia changed its message, or this was not the mail we
            // expected. Send what it wrote rather than nothing at all.
            tracing::warn!(
                to = %to,
                "no set-password link found in Authelia's email; relaying it unchanged"
            );
            let envelope = envelope_for(&msg)?;
            relay.send(envelope, msg.data).await
        }
    };
    if let Some(done) = pending_entry.done.take() {
        let _ = done.send(result.clone());
    }
    result
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

/// The SMTP conversation. Enough of RFC 5321 for Authelia, and nothing more.
async fn serve_conn(
    stream: TcpStream,
    cfg: Arc<MailConfig>,
    pending: Arc<PendingLinks>,
    relay: Arc<dyn Relay>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    let mut msg = Incoming {
        from: String::new(),
        recipients: Vec::new(),
        data: Vec::new(),
    };

    write.write_all(b"220 bilbycast-portal ESMTP\r\n").await?;
    loop {
        line.clear();
        let read = tokio::time::timeout(SMTP_IDLE_TIMEOUT, reader.read_line(&mut line)).await;
        let n = match read {
            Ok(Ok(n)) => n,
            _ => return Ok(()),
        };
        if n == 0 {
            return Ok(());
        }
        if line.len() > MAX_LINE_BYTES {
            write.write_all(b"500 line too long\r\n").await?;
            return Ok(());
        }
        let cmd = line.trim_end();
        let upper = cmd.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            write
                .write_all(b"250-bilbycast-portal\r\n250-8BITMIME\r\n250 SIZE 1048576\r\n")
                .await?;
        } else if upper.starts_with("HELO") {
            write.write_all(b"250 bilbycast-portal\r\n").await?;
        } else if upper.starts_with("MAIL FROM:") {
            msg.from = address_in(cmd);
            msg.recipients.clear();
            write.write_all(b"250 2.1.0 ok\r\n").await?;
        } else if upper.starts_with("RCPT TO:") {
            msg.recipients.push(address_in(cmd));
            write.write_all(b"250 2.1.5 ok\r\n").await?;
        } else if upper.starts_with("DATA") {
            if msg.recipients.is_empty() {
                write.write_all(b"503 5.5.1 need RCPT first\r\n").await?;
                continue;
            }
            write.write_all(b"354 go ahead\r\n").await?;
            msg.data.clear();
            loop {
                line.clear();
                let n = match tokio::time::timeout(SMTP_IDLE_TIMEOUT, reader.read_line(&mut line))
                    .await
                {
                    Ok(Ok(n)) => n,
                    _ => return Ok(()),
                };
                if n == 0 {
                    return Ok(());
                }
                if line == ".\r\n" || line == ".\n" {
                    break;
                }
                // Dot-stuffing, as the sender applied it.
                let body = line.strip_prefix("..").map(|r| format!(".{r}"));
                msg.data
                    .extend_from_slice(body.as_deref().unwrap_or(&line).as_bytes());
                if msg.data.len() > MAX_MESSAGE_BYTES {
                    write.write_all(b"552 5.3.4 message too large\r\n").await?;
                    return Ok(());
                }
            }
            // Accepted here, delivered after: Authelia will not send it again,
            // so whatever happens next is reported to the manager instead.
            write.write_all(b"250 2.0.0 accepted\r\n").await?;
            let taken = std::mem::replace(
                &mut msg,
                Incoming {
                    from: String::new(),
                    recipients: Vec::new(),
                    data: Vec::new(),
                },
            );
            let (cfg, pending, relay) = (cfg.clone(), pending.clone(), relay.clone());
            tokio::spawn(async move {
                if let Err(e) = handle(&cfg, &pending, relay.as_ref(), taken).await {
                    tracing::warn!(error = %e, "a notification email was not relayed");
                }
            });
        } else if upper.starts_with("RSET") {
            msg.recipients.clear();
            msg.data.clear();
            write.write_all(b"250 2.0.0 ok\r\n").await?;
        } else if upper.starts_with("NOOP") {
            write.write_all(b"250 2.0.0 ok\r\n").await?;
        } else if upper.starts_with("QUIT") {
            write.write_all(b"221 2.0.0 bye\r\n").await?;
            return Ok(());
        } else {
            write.write_all(b"502 5.5.2 not implemented\r\n").await?;
        }
    }
}

/// `MAIL FROM:<a@b>` / `RCPT TO:<a@b> SIZE=…` → `a@b`.
fn address_in(cmd: &str) -> String {
    let rest = cmd.split_once(':').map(|(_, r)| r).unwrap_or("");
    match (rest.find('<'), rest.find('>')) {
        (Some(a), Some(b)) if b > a => rest[a + 1..b].trim().to_string(),
        _ => rest.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// Listen for Authelia. Returns once the listener cannot be bound.
pub async fn run(cfg: Arc<MailConfig>, pending: Arc<PendingLinks>, relay: Arc<dyn Relay>) {
    let listener = match TcpListener::bind(&cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                addr = %cfg.listen_addr, error = %e,
                "cannot bind the notification mail listener; Authelia's emails will not be sent"
            );
            return;
        }
    };
    tracing::info!(addr = %cfg.listen_addr, relay = %cfg.relay_host,
                   "accepting notification mail from Authelia");
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    // Cannot happen while bound to loopback; cheap to keep true.
                    continue;
                }
                let (cfg, pending, relay) = (cfg.clone(), pending.clone(), relay.clone());
                tokio::spawn(async move {
                    let _ = serve_conn(stream, cfg, pending, relay).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "notification mail listener: accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MailConfig {
        MailConfig {
            listen_addr: default_listen(),
            relay_host: "smtp-relay.example.com".into(),
            relay_port: 587,
            relay_username: "u".into(),
            relay_password_file: "/dev/null".into(),
            from: "GRS Notifications <noreply@grs.example>".into(),
            sign_in_url: "https://watch.grs.example".into(),
            invite_subject: default_invite_subject(),
            reset_subject: default_reset_subject(),
            starttls: true,
        }
    }

    /// A message shaped like Authelia's: multipart, quoted-printable, with the
    /// link split across lines by a soft break.
    fn authelia_message(to: &str) -> Incoming {
        let data = format!(
            "From: GRS <noreply@grs.example>\r\n\
             To: {to}\r\n\
             Subject: Reset your password\r\n\
             Content-Type: multipart/alternative; boundary=b1\r\n\r\n\
             --b1\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\r\n\
             Use this link:\r\n\
             https://watch.grs.example/auth/reset-password/step2?token=3DeyJhbGciOiJIUzI1NiJ9.=\r\n\
             abc-def_123\r\n\r\n\
             --b1--\r\n"
        );
        Incoming {
            from: "noreply@grs.example".into(),
            recipients: vec![to.into()],
            data: data.into_bytes(),
        }
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

    #[test]
    fn the_link_survives_a_soft_line_break() {
        let msg = authelia_message("bea@example.com");
        let link = extract_link(&msg.data).expect("no link found");
        assert_eq!(
            link,
            "https://watch.grs.example/auth/reset-password/step2?token=eyJhbGciOiJIUzI1NiJ9.abc-def_123",
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
                "GRS New User",
                "You have been given access",
            ),
            (
                LinkKind::Reset,
                "GRS password reset",
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

    #[tokio::test]
    async fn a_message_from_anything_but_us_is_dropped() {
        let pending = PendingLinks::default();
        let relay = Captured::default();
        let mut msg = authelia_message("bea@example.com");
        // Some other process on the box, using our listener as a way out.
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

    #[tokio::test]
    async fn a_stale_expectation_does_not_claim_a_later_email() {
        let pending = PendingLinks::default();
        let _rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Bea")
            .await;
        // Age it past the window.
        {
            let mut map = pending.0.lock().await;
            if let Some(p) = map.get_mut("bea@example.com") {
                p.at = Instant::now() - PENDING_TTL - Duration::from_secs(1);
            }
        }
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

    #[test]
    fn addresses_are_read_out_of_the_commands() {
        assert_eq!(address_in("MAIL FROM:<a@b.c>"), "a@b.c");
        assert_eq!(address_in("RCPT TO:<a@b.c> SIZE=42"), "a@b.c");
        assert_eq!(address_in("MAIL FROM: a@b.c"), "a@b.c");
    }

    #[test]
    fn the_listener_must_be_loopback_and_clear_text_relaying_is_refused() {
        let mut c = cfg();
        assert!(c.validate().is_ok());
        c.listen_addr = "0.0.0.0:2525".into();
        assert!(
            c.validate().is_err(),
            "a public listener would let anyone send mail as us"
        );
        let mut c = cfg();
        c.starttls = false;
        assert!(
            c.validate().is_err(),
            "the relay password would go out in clear"
        );
        c.relay_host = "127.0.0.1".into();
        assert!(
            c.validate().is_ok(),
            "a local sink is the one case that may be plain"
        );
    }

    /// The whole conversation, over a real socket.
    #[tokio::test]
    async fn authelia_can_deliver_over_smtp() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let cfg = Arc::new(cfg());
        let pending = Arc::new(PendingLinks::default());
        let rx = pending
            .expect("bea@example.com", LinkKind::Invite, "Bea Jones")
            .await;
        let relay = Arc::new(Captured::default());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let (cfg, pending, relay) = (cfg.clone(), pending.clone(), relay.clone());
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let _ = serve_conn(stream, cfg, pending, relay).await;
            });
        }

        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut r = BufReader::new(r);
        let mut line = String::new();
        let expect = |line: &mut String, code: &str| assert!(line.starts_with(code), "{line}");
        r.read_line(&mut line).await.unwrap();
        expect(&mut line, "220");

        for (cmd, code) in [
            ("EHLO authelia\r\n", "250"),
            ("MAIL FROM:<noreply@grs.example>\r\n", "250"),
            ("RCPT TO:<bea@example.com>\r\n", "250"),
        ] {
            w.write_all(cmd.as_bytes()).await.unwrap();
            line.clear();
            r.read_line(&mut line).await.unwrap();
            // EHLO answers several lines; drain the continuations.
            while line.len() > 3 && line.as_bytes()[3] == b'-' {
                line.clear();
                r.read_line(&mut line).await.unwrap();
            }
            expect(&mut line, code);
        }
        w.write_all(b"DATA\r\n").await.unwrap();
        line.clear();
        r.read_line(&mut line).await.unwrap();
        expect(&mut line, "354");

        let body = String::from_utf8(authelia_message("bea@example.com").data).unwrap();
        w.write_all(body.as_bytes()).await.unwrap();
        w.write_all(b".\r\n").await.unwrap();
        line.clear();
        r.read_line(&mut line).await.unwrap();
        expect(&mut line, "250");
        w.write_all(b"QUIT\r\n").await.unwrap();

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
            sent[0].1.contains("GRS New User"),
            "the invite was not rewritten"
        );
    }
}
