// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bilbycast-portal` — the viewer portal, run beside the relay on its VPS.
//!
//! A thin shell, the same shape as `main.rs`: parse, validate, bind, serve.
//! Everything worth testing lives in [`bilbycast_relay::portal`].
//!
//! Built only with `--features portal`, so a plain relay build is byte-for-byte
//! what it was and does not pull an HTTP client in.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bilbycast_relay::portal::mail::{MailConfig, PendingLinks};
use bilbycast_relay::portal::{self, PortalConfig, PortalState};
use clap::Parser;
use tokio::task::JoinHandle;

#[derive(Parser, Debug)]
#[command(name = "bilbycast-portal", version, about = "bilbycast DVR viewer portal")]
struct Args {
    /// Config file (JSON).
    #[arg(short, long, default_value = "portal-config.json")]
    config: PathBuf,

    /// Override the listen address from the config file.
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bilbycast_relay=info,bilbycast_portal=info".into()),
        )
        .init();

    let args = Args::parse();
    let mut cfg = PortalConfig::load(&args.config)?;
    if let Some(l) = args.listen {
        cfg.listen_addr = l;
    }
    // Re-run after the CLI override so a `--listen` value is validated too.
    cfg.normalise();
    if let Err(e) = cfg.validate() {
        anyhow::bail!("portal config: {e}");
    }

    // Said once, loudly, at the one moment someone is watching the logs. A
    // portal off loopback is a portal where `Remote-User` is only as good as
    // whatever else can reach the port, and that is a deployment decision
    // rather than a mistake — so it warns and starts.
    if cfg.binds_publicly() {
        tracing::warn!(
            listen = %cfg.listen_addr,
            "portal is NOT on loopback: anything that can reach this port can present a \
             username header. Only the addresses in trusted_proxies are believed, so make \
             sure nothing else can route to it."
        );
    }

    let addr: SocketAddr = cfg.listen_addr.parse()?;
    let listener = bilbycast_relay::build_tcp_listener(addr)?;

    tracing::info!(
        listen = %addr,
        manager = %cfg.manager_url,
        header = %cfg.username_header,
        trusted = cfg.trusted_proxies.len(),
        "viewer portal listening"
    );

    // Built in the library so their policy is tested there: no redirects
    // followed, and why each has the deadlines it has.
    let clients = portal::clients::Clients::build()?;
    let state = PortalState {
        cfg: Arc::new(cfg),
        http: clients.http,
        media: clients.media,
        last_beat_answer: Default::default(),
        links: Default::default(),
    };

    // Authelia's notification emails, rewritten and relayed as ours. Started
    // before the account sync, which asks Authelia for links this listener has
    // to be there to receive.
    let mail_task = match state.cfg.mail.clone() {
        Some(mail) => Some(start_mail(mail, state.links.clone())?),
        None => None,
    };

    // Only when configured: a portal without an `accounts` block runs exactly
    // as it always did, and never touches Authelia's files.
    let accounts_task = state.cfg.accounts.clone().map(|acc| {
        tracing::info!(
            users_file = %acc.users_file.display(),
            authelia = %acc.authelia_url,
            every_secs = acc.interval_secs,
            "syncing portal logins to Authelia"
        );
        tokio::spawn(portal::accounts::run(state.clone(), acc))
    });

    // `into_make_service_with_connect_info` is load-bearing, not boilerplate:
    // the peer address is what decides whether the username header is believed
    // at all, and without this the extractor has nothing to read.
    let app = portal::router(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    });

    // Neither background job returns while the portal is healthy, so either
    // one ending — a panic included — ends the process with an error, and
    // systemd's `Restart=always` brings the whole portal back. Left running
    // without it, the portal would go on serving viewers while invitations and
    // resets quietly stopped.
    tokio::select! {
        served = server.into_future() => served?,
        failed = ended(mail_task, "notification mail listener") => return Err(failed),
        failed = ended(accounts_task, "account sync") => return Err(failed),
    }
    Ok(())
}

/// Take Authelia's notification email on `mail.listen_addr`.
///
/// Everything that can fail does so here, before the listener task exists: a
/// relay password or listener secret that cannot be read, and above all a port
/// somebody else already holds. That must stop the portal at startup, not
/// leave it serving viewers while Authelia's mail — reset links included —
/// goes to whoever holds the port.
fn start_mail(mail: MailConfig, links: Arc<PendingLinks>) -> anyhow::Result<JoinHandle<()>> {
    let relay = portal::mail::SmtpRelay::new(&mail)
        .map_err(|e| anyhow::anyhow!("portal mail relay: {e}"))?;
    let secret = mail
        .listen_password()
        .map_err(|e| anyhow::anyhow!("portal mail listener: {e}"))?;
    let addr: SocketAddr = mail.listen_addr.parse()?;
    let listener = bilbycast_relay::build_tcp_listener(addr)
        .map_err(|e| anyhow::anyhow!("portal mail listener {addr}: {e}"))?;
    tracing::info!(
        listen = %addr, relay = %mail.relay_host,
        "rewriting Authelia's notification email"
    );
    let interceptor = portal::mail::Interceptor::new(mail, secret, links, Arc::new(relay));
    Ok(tokio::spawn(Arc::new(interceptor).serve(listener)))
}

/// Wait for a background job to end, and say how it did. A job that is not
/// configured never ends.
async fn ended(task: Option<JoinHandle<()>>, what: &str) -> anyhow::Error {
    match task {
        Some(task) => match task.await {
            Ok(()) => anyhow::anyhow!("the portal's {what} stopped"),
            Err(e) => anyhow::anyhow!("the portal's {what} failed: {e}"),
        },
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A config whose secrets can be read, listening on `listen_addr`.
    fn mail(dir: &std::path::Path, listen_addr: String) -> MailConfig {
        let relay_key = dir.join("relay-key");
        let listener_secret = dir.join("listener-secret");
        std::fs::write(&relay_key, "key\n").unwrap();
        std::fs::write(&listener_secret, format!("{}\n", "s".repeat(40))).unwrap();
        serde_json::from_value(serde_json::json!({
            "listen_addr": listen_addr,
            "listen_password_file": listener_secret,
            "relay_host": "smtp-relay.example.com",
            "relay_username": "u",
            "relay_password_file": relay_key,
            "from": "Example <noreply@example.com>",
            "sign_in_url": "https://watch.example.com",
        }))
        .unwrap()
    }

    /// Somebody else on the port is a startup failure that names the port —
    /// not a log line from a task, with the portal serving on regardless.
    #[tokio::test]
    async fn a_mail_port_somebody_else_holds_stops_the_portal() {
        let dir = tempfile::tempdir().unwrap();
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = squatter.local_addr().unwrap();
        let err = start_mail(mail(dir.path(), addr.to_string()), Default::default())
            .expect_err("started with the port already taken");
        assert!(err.to_string().contains(&addr.to_string()), "{err}");

        // And a free port starts, and keeps running.
        let task = start_mail(mail(dir.path(), "127.0.0.1:0".into()), Default::default()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
    }

    #[tokio::test]
    async fn an_unreadable_listener_secret_stops_the_portal() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = mail(dir.path(), "127.0.0.1:0".into());
        m.listen_password_file = dir.path().join("missing");
        let err = start_mail(m, Default::default()).expect_err("started without a secret");
        assert!(err.to_string().contains("listener"), "{err}");
    }

    /// A background job that ends, however it ends, is an error for the
    /// process; one that is not configured never ends.
    #[tokio::test]
    async fn a_background_job_ending_is_fatal_and_an_absent_one_never_ends() {
        let panicked = ended(Some(tokio::spawn(async { panic!("boom") })), "account sync").await;
        assert!(
            panicked.to_string().contains("account sync failed"),
            "{panicked}"
        );
        let returned = ended(Some(tokio::spawn(async {})), "mail listener").await;
        assert!(
            returned.to_string().contains("mail listener stopped"),
            "{returned}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), ended(None, "nothing"))
                .await
                .is_err()
        );
    }
}
