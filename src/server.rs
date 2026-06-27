// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! QUIC server: accepts connections from edge nodes.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::ServerConfig;

use crate::config::RelayConfig;
use crate::manager::events::EventSender;
use crate::protocol::ALPN_RELAY;
use crate::session::{self, SessionContext};
use crate::stats::RelayStats;
use crate::tunnel_router::TunnelRouter;

/// Build the QUIC server and start accepting connections. Binds one
/// `quinn::Endpoint` per address in [`RelayConfig::effective_quic_addrs`]
/// — defaults to dual-stack on a fresh install. v6 entries are bound
/// with `IPV6_V6ONLY=1` so they coexist with v4 listeners on the same
/// port. All endpoints share one `ServerConfig` and one `SessionContext`.
pub async fn run_quic_server(
    config: &RelayConfig,
    ctx: Arc<SessionContext>,
) -> Result<()> {
    let server_config = build_server_config(config)?;
    let bind_entries = config.effective_quic_addrs();
    if bind_entries.is_empty() {
        anyhow::bail!("quic listener address list resolved to empty");
    }

    let mut endpoint_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    for raw in &bind_entries {
        let addr: std::net::SocketAddr = raw
            .parse()
            .with_context(|| format!("invalid QUIC bind address '{raw}'"))?;
        let udp_socket = build_udp_socket(addr)
            .with_context(|| format!("failed to bind QUIC socket on {addr}"))?;
        let runtime = quinn::default_runtime()
            .context("no compatible async runtime found for quinn")?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config.clone()),
            udp_socket,
            runtime,
        )
        .with_context(|| format!("failed to start QUIC endpoint on {addr}"))?;

        tracing::info!("QUIC server listening on {addr}");

        let ctx_clone = ctx.clone();
        endpoint_set.spawn(async move {
            run_quic_endpoint(endpoint, ctx_clone, addr).await;
        });
    }

    // First endpoint to exit (e.g. a fatal accept error) brings the
    // whole serve down; dropping the JoinSet aborts the others.
    let _ = endpoint_set.join_next().await;
    Ok(())
}

async fn run_quic_endpoint(
    endpoint: quinn::Endpoint,
    ctx: Arc<SessionContext>,
    bind_addr: std::net::SocketAddr,
) {
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                tracing::info!("QUIC endpoint on {bind_addr} closed");
                break;
            }
        };

        let ctx = ctx.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    session::handle_edge_connection(ctx, connection).await;
                }
                Err(e) => {
                    tracing::warn!("Failed to accept QUIC connection on {bind_addr}: {e}");
                    ctx.event_sender.emit_with_details(
                        crate::manager::events::EventSeverity::Warning,
                        crate::manager::events::category::EDGE,
                        format!("QUIC connection accept failed: {e}"),
                        serde_json::json!({ "error": e.to_string(), "bind_addr": bind_addr.to_string() }),
                    );
                }
            }
        });
    }
}

/// Build a `std::net::UdpSocket` with the dual-stack contract applied:
/// v6 sockets get `IPV6_V6ONLY=1` so they don't claim the v4 address
/// space, both families get `SO_REUSEADDR`, and the socket is set to
/// non-blocking for quinn.
fn build_udp_socket(addr: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match addr.ip() {
        std::net::IpAddr::V4(_) => Domain::IPV4,
        std::net::IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if matches!(addr.ip(), std::net::IpAddr::V6(_)) {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Create the SessionContext shared state.
///
/// `require_bind_auth` flips the router into fail-closed mode: binds for
/// tunnels without a pre-registered `authorize_tunnel` entry are rejected.
/// Pass `false` for the default backwards-compatible behaviour.
///
/// `max_connections_per_ip` and `max_tunnels_per_connection` are the
/// DoS-mitigation caps; pass the values from `RelayConfig`. Generous
/// defaults (64 / 100) accommodate any realistic legitimate workload.
pub fn create_session_context(
    relay_stats: Arc<RelayStats>,
    event_sender: EventSender,
    require_bind_auth: bool,
    max_connections_per_ip: u32,
    max_tunnels_per_connection: u32,
) -> Arc<SessionContext> {
    Arc::new(SessionContext {
        router: Arc::new(TunnelRouter::with_auth_policy(require_bind_auth)),
        // Reuse the per-IP cap for native-UDP session creation too.
        udp_sessions: Arc::new(crate::udp_relay::UdpSessionRouter::new(
            max_connections_per_ip,
        )),
        edge_connections: dashmap::DashMap::new(),
        connections_by_ip: dashmap::DashMap::new(),
        relay_stats,
        event_sender,
        max_connections_per_ip,
        max_tunnels_per_connection,
    })
}

fn build_server_config(config: &RelayConfig) -> Result<ServerConfig> {
    let (cert_chain, key) = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("failed to read TLS cert: {cert_path}"))?;
            let key_pem = std::fs::read(key_path)
                .with_context(|| format!("failed to read TLS key: {key_path}"))?;

            let certs = rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<Vec<_>, _>>()
                .context("failed to parse TLS certs")?;
            let key = rustls_pemfile::private_key(&mut &key_pem[..])
                .context("failed to parse TLS key")?
                .context("no private key found")?;

            (certs, key)
        }
        _ => {
            // Generate self-signed certificate for development
            tracing::info!("No TLS cert configured, generating self-signed certificate");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "bilbycast-relay".into()])
                .context("failed to generate self-signed cert")?;
            let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
            (vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(key_der))
        }
    };

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("failed to build TLS config")?;

    tls_config.alpn_protocols = vec![ALPN_RELAY.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("failed to create QUIC server config")?,
    ));

    // Configure transport
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(256u32.into());
    // Enable QUIC datagrams for UDP tunnel forwarding.
    // Buffer must be large enough for bursty traffic (e.g., SRT at 10 Mbps).
    // 2 MB accommodates ~1500 max-size datagrams in-flight.
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    // Failover tuning: 5 missed keep-alives before declaring dead (matches edge side).
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(25)
            .try_into()
            .context("max_idle_timeout conversion")?,
    ));

    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}
