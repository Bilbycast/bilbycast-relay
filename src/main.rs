// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

mod api;
mod auth;
mod config;
mod manager;
mod protocol;
mod server;
mod session;
mod stats;
mod tunnel_router;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use crate::config::RelayConfig;
use crate::stats::RelayStats;

#[derive(Parser)]
#[command(name = "bilbycast-relay", about = "QUIC relay server for bilbycast IP tunneling")]
struct Cli {
    /// Path to config file (JSON).
    #[arg(short, long, default_value = "relay-config.json")]
    config: String,

    /// Override QUIC listen address.
    #[arg(long)]
    quic_addr: Option<String>,

    /// Override API listen address.
    #[arg(long)]
    api_addr: Option<String>,

    /// Generate a relay token for the given edge_id and exit.
    #[arg(long)]
    generate_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bilbycast_relay=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Load config
    let mut config = if std::path::Path::new(&cli.config).exists() {
        let data = std::fs::read_to_string(&cli.config)
            .with_context(|| format!("failed to read config: {}", cli.config))?;
        serde_json::from_str::<RelayConfig>(&data)
            .with_context(|| format!("failed to parse config: {}", cli.config))?
    } else {
        tracing::warn!("Config file '{}' not found, using defaults", cli.config);
        RelayConfig::default()
    };

    // CLI overrides
    if let Some(addr) = cli.quic_addr {
        config.quic_addr = addr;
    }
    if let Some(addr) = cli.api_addr {
        config.api_addr = addr;
    }

    // Check shared_secret from env or config
    if let Ok(secret) = std::env::var("RELAY_SHARED_SECRET") {
        config.shared_secret = secret;
    }
    if config.shared_secret.is_empty() {
        anyhow::bail!(
            "shared_secret is required. Set it in the config file or via RELAY_SHARED_SECRET env var."
        );
    }
    config.validate()?;

    // Token generation mode
    if let Some(edge_id) = cli.generate_token {
        let token = auth::generate_token(&edge_id, &config.shared_secret);
        println!("Token for edge '{edge_id}':\n{token}");
        return Ok(());
    }

    tracing::info!("bilbycast-relay v{}", env!("CARGO_PKG_VERSION"));

    // Create shared state
    let ctx = server::create_session_context(&config);
    let relay_stats = Arc::new(RelayStats::new());

    // Start REST API
    let api_state = Arc::new(api::ApiState {
        ctx: ctx.clone(),
        relay_stats: relay_stats.clone(),
    });
    let api_router = api::create_router(api_state);
    let api_addr: std::net::SocketAddr = config
        .api_addr
        .parse()
        .context("invalid api_addr")?;

    let api_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        tracing::info!("REST API listening on {api_addr}");
        axum::serve(listener, api_router).await.unwrap();
    });

    // Start manager client if configured
    let manager_handle = if let Some(ref mgr_config) = config.manager {
        if mgr_config.enabled {
            tracing::info!(
                "Manager client enabled, connecting to {}",
                mgr_config.url
            );
            Some(manager::client::start_manager_client(
                mgr_config.clone(),
                ctx.clone(),
                relay_stats.clone(),
                config.clone(),
                std::path::PathBuf::from(&cli.config),
            ))
        } else {
            None
        }
    } else {
        None
    };

    // Start QUIC server (blocks until shutdown)
    let quic_handle = tokio::spawn({
        let config = config.clone();
        let ctx = ctx.clone();
        async move {
            if let Err(e) = server::run_quic_server(&config, ctx).await {
                tracing::error!("QUIC server error: {e:#}");
            }
        }
    });

    // Wait for any to finish
    tokio::select! {
        _ = api_handle => tracing::info!("API server stopped"),
        _ = quic_handle => tracing::info!("QUIC server stopped"),
        _ = async {
            if let Some(h) = manager_handle {
                let _ = h.await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("Manager client stopped");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down");
        }
    }

    Ok(())
}
