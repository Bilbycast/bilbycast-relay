// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use bilbycast_relay::build_tcp_listener;
use bilbycast_relay::config::RelayConfig;
use bilbycast_relay::distribution_control::{DistributionControl, RuntimeDistConfig};
use bilbycast_relay::stats::RelayStats;
use bilbycast_relay::{api, manager, observability, server, udp_relay};
#[cfg(feature = "viewer-distribution")]
use bilbycast_relay::distribution;

#[derive(Parser)]
#[command(name = "bilbycast-relay", about = "QUIC relay server for bilbycast IP tunneling", version)]
struct Cli {
    /// Path to config file (JSON). Optional — relay can run with defaults.
    #[arg(short, long)]
    config: Option<String>,

    /// Override QUIC listen address (legacy single-address override).
    /// Use `--quic-addrs` for dual-stack / multi-listener overrides.
    #[arg(long)]
    quic_addr: Option<String>,

    /// Override API listen address (legacy single-address override).
    /// Use `--api-addrs` for dual-stack / multi-listener overrides.
    #[arg(long)]
    api_addr: Option<String>,

    /// Override QUIC dual-stack listener addresses (comma-separated, e.g.
    /// `0.0.0.0:4433,[::]:4433`). When set, takes precedence over
    /// `--quic-addr` and the config file. v6 entries get
    /// `IPV6_V6ONLY=1` so they coexist with v4 listeners on the same port.
    #[arg(long)]
    quic_addrs: Option<String>,

    /// Override REST API dual-stack listener addresses (comma-separated, e.g.
    /// `0.0.0.0:4480,[::]:4480`). When set, takes precedence over
    /// `--api-addr` and the config file.
    #[arg(long)]
    api_addrs: Option<String>,

    /// Override the publicly-reachable QUIC address advertised to remote
    /// edges via the manager (e.g. `54.1.2.3:4433` or
    /// `relay.example.com:4433`). This is what edges dial; distinct from
    /// the bind list above. Unspecified addresses (`0.0.0.0`, `[::]`)
    /// are rejected.
    #[arg(long)]
    public_quic_addr: Option<String>,

    /// Override the plain-UDP relay (native SRT/RIST, no QUIC) listener
    /// addresses (comma-separated, e.g. `0.0.0.0:4434,[::]:4434`).
    #[arg(long)]
    udp_relay_addrs: Option<String>,

    /// Override the publicly-reachable plain-UDP relay address advertised to
    /// remote edges for the native SRT/RIST path (e.g. `54.1.2.3:4434`).
    #[arg(long)]
    public_udp_addr: Option<String>,

    /// Disable the plain-UDP relay data plane (native SRT/RIST over relay).
    /// The relay then carries QUIC tunnels only.
    #[arg(long)]
    no_udp_relay: bool,
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

    // Load config (optional — defaults used if no config file)
    let mut config = if let Some(ref config_path) = cli.config {
        if std::path::Path::new(config_path).exists() {
            let data = std::fs::read_to_string(config_path)
                .with_context(|| format!("failed to read config: {config_path}"))?;
            serde_json::from_str::<RelayConfig>(&data)
                .with_context(|| format!("failed to parse config: {config_path}"))?
        } else {
            tracing::warn!("Config file '{config_path}' not found, using defaults");
            RelayConfig::default()
        }
    } else {
        RelayConfig::default()
    };

    // CLI overrides
    if let Some(addr) = cli.quic_addr {
        config.quic_addr = addr;
    }
    if let Some(addr) = cli.api_addr {
        config.api_addr = addr;
    }
    if let Some(raw) = cli.quic_addrs {
        let entries: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        config.quic_addrs = Some(entries);
    }
    if let Some(raw) = cli.api_addrs {
        let entries: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        config.api_addrs = Some(entries);
    }
    if let Some(addr) = cli.public_quic_addr {
        config.public_quic_addr = Some(addr);
    }
    if let Some(raw) = cli.udp_relay_addrs {
        let entries: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        config.udp_relay_addrs = Some(entries);
    }
    if let Some(addr) = cli.public_udp_addr {
        config.public_udp_addr = Some(addr);
    }
    if cli.no_udp_relay {
        config.udp_relay_enabled = false;
    }

    config.validate()?;

    tracing::info!("bilbycast-relay v{}", env!("CARGO_PKG_VERSION"));

    // Create shared state
    let relay_stats = Arc::new(RelayStats::new());
    let (mut event_sender, event_rx) = manager::event_channel();

    // Optional structured-JSON log shipper. Mirrors the edge: installed
    // before any clone, all clones inherit the value.
    if let Some(ref logging_cfg) = config.logging {
        let relay_id = config
            .manager
            .as_ref()
            .and_then(|m| m.node_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        match observability::JsonLogShipper::from_config(
            logging_cfg,
            relay_id,
            env!("CARGO_PKG_VERSION"),
        ) {
            Ok(Some(shipper)) => {
                tracing::info!("structured-JSON log shipper enabled");
                event_sender.set_log_shipper(shipper);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("failed to start structured-JSON log shipper: {e:#}");
            }
        }
    }

    let ctx = server::create_session_context(
        relay_stats.clone(),
        event_sender.clone(),
        config.require_bind_auth,
        config.max_connections_per_ip,
        config.max_tunnels_per_connection,
    );

    // Start REST API
    if config.api_token.is_none() {
        tracing::warn!("No api_token configured — REST API endpoints are open without authentication");
    }
    if !config.require_bind_auth {
        tracing::warn!(
            "require_bind_auth=false — tunnels without a pre-registered authorize_tunnel \
             entry accept unauthenticated binds (backwards-compatible mode). Set \
             require_bind_auth=true for fail-closed bind authentication."
        );
    }
    let api_state = Arc::new(api::ApiState {
        ctx: ctx.clone(),
        relay_stats: relay_stats.clone(),
        api_token: config.api_token.clone(),
    });
    let api_router = api::create_router(api_state);
    let api_entries = config.effective_api_addrs();
    if api_entries.is_empty() {
        anyhow::bail!("REST API address list resolved to empty");
    }
    let mut api_addrs: Vec<std::net::SocketAddr> = Vec::with_capacity(api_entries.len());
    for raw in &api_entries {
        let addr: std::net::SocketAddr = raw
            .parse()
            .with_context(|| format!("invalid REST API bind address '{raw}'"))?;
        api_addrs.push(addr);
    }

    let api_handle = tokio::spawn(async move {
        let mut listeners: Vec<(std::net::SocketAddr, tokio::net::TcpListener)> = Vec::new();
        for addr in &api_addrs {
            match build_tcp_listener(*addr) {
                Ok(listener) => {
                    tracing::info!("REST API listening on {addr}");
                    listeners.push((*addr, listener));
                }
                Err(e) => {
                    tracing::error!("Failed to bind REST API on {addr}: {e}");
                }
            }
        }
        if listeners.is_empty() {
            tracing::error!("No REST API listeners could be bound — aborting");
            return;
        }
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        for (addr, listener) in listeners {
            let router = api_router.clone();
            set.spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    tracing::error!("REST API on {addr}: {e}");
                }
            });
        }
        // First listener to exit collapses the whole REST API task;
        // dropping the JoinSet aborts the rest.
        let _ = set.join_next().await;
    });

    // Build the shared distribution runtime-config control up front, so the
    // manager client can apply `configure_distribution` pushes onto the same
    // cell the subsystem (below) reads live. Present only on a distribution
    // build (feature on) where the role isn't opted out (`enabled: false`).
    // `enabled` defaults true, so a `-distribution` binary comes up as a
    // distribution node with no config edits and the manager configures it.
    let distribution_control: Option<Arc<DistributionControl>> = {
        let dcfg = config.distribution.clone().unwrap_or_default();
        if cfg!(feature = "viewer-distribution") && dcfg.enabled {
            let public_ip = dcfg.public_ip_parsed();
            let rt = RuntimeDistConfig::from_config(&dcfg, public_ip);
            Some(DistributionControl::new(rt, dcfg.cascade_sources.clone()))
        } else {
            None
        }
    };

    // Start manager client if configured
    let config_path = cli.config.clone().unwrap_or_default();
    let manager_handle = if let Some(ref mgr_config) = config.manager {
        if mgr_config.enabled {
            tracing::info!(
                "Manager client enabled, connecting to {} URL(s): {}",
                mgr_config.urls.len(),
                mgr_config.urls.join(", ")
            );
            Some(manager::client::start_manager_client(
                mgr_config.clone(),
                ctx.clone(),
                relay_stats.clone(),
                config.clone(),
                std::path::PathBuf::from(&config_path),
                event_rx,
                event_sender.clone(),
                distribution_control.clone(),
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

    // Start the plain-UDP relay data plane (native SRT/RIST, no QUIC) unless
    // disabled. Bind failures inside are non-fatal (logged); if it can't bind
    // any listener the task exits and the relay continues QUIC-only.
    let udp_relay_handle = if config.udp_relay_enabled {
        let config = config.clone();
        let ctx = ctx.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = udp_relay::run_udp_relay(&config, ctx).await {
                tracing::warn!("native-UDP relay not started: {e:#}");
            }
        }))
    } else {
        tracing::info!("native-UDP relay disabled by config");
        None
    };

    // Start the viewer-distribution subsystem (WHEP SFU + LL-HLS origin) when
    // compiled in AND enabled in config. Isolated behind the feature so a
    // plain opaque-forwarder build carries none of it.
    #[cfg(feature = "viewer-distribution")]
    let distribution_handle = if let Some(control) = distribution_control.clone() {
        let dist_cfg = config.distribution.clone().unwrap_or_default();
        let hub = Arc::new(distribution::hub::DistributionHub::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let events = event_sender.clone();
        let dist_stats = relay_stats.clone();
        tracing::info!("viewer-distribution subsystem enabled");
        Some(tokio::spawn(async move {
            if let Err(e) =
                distribution::run_distribution(dist_cfg, control, hub, cancel, events, dist_stats)
                    .await
            {
                tracing::error!("viewer-distribution subsystem stopped: {e:#}");
            }
        }))
    } else {
        None
    };

    #[cfg(not(feature = "viewer-distribution"))]
    if config.distribution.as_ref().map(|d| d.enabled).unwrap_or(false) {
        tracing::warn!(
            "config has distribution.enabled=true but this binary was built WITHOUT the \
             `viewer-distribution` feature — the subsystem will NOT start. Rebuild with \
             `--features viewer-distribution` to enable it."
        );
    }

    // Wait for any to finish
    tokio::select! {
        _ = api_handle => tracing::info!("API server stopped"),
        _ = quic_handle => tracing::info!("QUIC server stopped"),
        _ = async {
            #[cfg(feature = "viewer-distribution")]
            if let Some(h) = distribution_handle {
                let _ = h.await;
            } else {
                std::future::pending::<()>().await;
            }
            #[cfg(not(feature = "viewer-distribution"))]
            std::future::pending::<()>().await;
        } => {
            tracing::info!("viewer-distribution subsystem stopped");
        }
        _ = async {
            if let Some(h) = udp_relay_handle {
                let _ = h.await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("native-UDP relay stopped");
        }
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
