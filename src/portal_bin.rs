// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

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

use bilbycast_relay::portal::{self, PortalConfig, PortalState};
use clap::Parser;

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

    let state = PortalState {
        cfg: Arc::new(cfg),
        http: reqwest::Client::builder()
            // The manager is one hop away and answers from a database. A
            // request that has not come back in ten seconds is not going to.
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
    };

    // `into_make_service_with_connect_info` is load-bearing, not boilerplate:
    // the peer address is what decides whether the username header is believed
    // at all, and without this the extractor has nothing to read.
    let app = portal::router(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}
