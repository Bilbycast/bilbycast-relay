// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! QUIC server: accepts connections from edge nodes.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::ServerConfig;

use crate::config::RelayConfig;
use crate::protocol::ALPN_RELAY;
use crate::session::{self, SessionContext};
use crate::tunnel_router::TunnelRouter;

/// Build the QUIC server and start accepting connections.
pub async fn run_quic_server(
    config: &RelayConfig,
    ctx: Arc<SessionContext>,
) -> Result<()> {
    let server_config = build_server_config(config)?;
    let endpoint = quinn::Endpoint::server(
        server_config,
        config.quic_addr.parse().context("invalid quic_addr")?,
    )?;

    tracing::info!("QUIC server listening on {}", config.quic_addr);

    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                tracing::info!("QUIC endpoint closed");
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
                    tracing::warn!("Failed to accept QUIC connection: {e}");
                }
            }
        });
    }

    Ok(())
}

/// Create the SessionContext shared state.
pub fn create_session_context() -> Arc<SessionContext> {
    Arc::new(SessionContext {
        router: Arc::new(TunnelRouter::new()),
        edge_connections: dashmap::DashMap::new(),
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
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}
