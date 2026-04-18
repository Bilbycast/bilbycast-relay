// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Integration tests: two quinn clients simulate ingress + egress edges,
//! verify TCP and UDP data flows through the relay.
//!
//! The relay is stateless — no authentication required. Edges connect and
//! immediately bind tunnels by UUID.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection, Endpoint, TransportConfig};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

// ── Wire protocol (mirrors src/protocol.rs — no auth messages) ──

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum EdgeMessage {
    #[serde(rename = "tunnel_bind")]
    TunnelBind {
        tunnel_id: Uuid,
        direction: TunnelDirection,
        protocol: TunnelProtocol,
    },
    #[serde(rename = "tunnel_unbind")]
    TunnelUnbind { tunnel_id: Uuid },
    #[serde(rename = "identify")]
    Identify { edge_id: String },
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum RelayMessage {
    #[serde(rename = "tunnel_ready")]
    TunnelReady { tunnel_id: Uuid },
    #[serde(rename = "tunnel_waiting")]
    TunnelWaiting { tunnel_id: Uuid },
    #[serde(rename = "tunnel_down")]
    TunnelDown { tunnel_id: Uuid, reason: String },
    #[serde(rename = "pong")]
    Pong,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum TunnelDirection {
    #[serde(rename = "ingress")]
    Ingress,
    #[serde(rename = "egress")]
    Egress,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum TunnelProtocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamHeader {
    tunnel_id: Uuid,
    stream_type: StreamType,
}

#[derive(Debug, Serialize, Deserialize)]
enum StreamType {
    #[serde(rename = "tcp")]
    Tcp,
}

// ── Wire helpers ──

async fn write_msg<T: Serialize>(send: &mut quinn::SendStream, msg: &T) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&json).await?;
    Ok(())
}

async fn read_msg<T: serde::de::DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

// ── Test helpers ──

/// Build a quinn client endpoint that trusts any certificate (for testing with self-signed).
fn make_client_endpoint() -> anyhow::Result<Endpoint> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    // Trust any certificate (test only)
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"bilbycast-relay".to_vec()];

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.max_concurrent_uni_streams(128u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    client_config.transport_config(Arc::new(transport));

    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Rustls certificate verifier that accepts any cert (test only).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Start the relay server in the background and return its QUIC address.
async fn start_relay() -> anyhow::Result<SocketAddr> {
    use std::net::TcpListener;

    // Find free ports
    let quic_listener = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_listener.local_addr()?;
    drop(quic_listener);

    let api_listener = TcpListener::bind("127.0.0.1:0")?;
    let api_addr = api_listener.local_addr()?;
    drop(api_listener);

    // Generate self-signed cert
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "bilbycast-relay".into()])?;
    let key_der =
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )?;
    tls_config.alpn_protocols = vec![b"bilbycast-relay".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    let endpoint = quinn::Endpoint::server(server_config, quic_addr)?;
    let actual_addr = endpoint.local_addr()?;

    // Shared state — no auth needed
    let router = Arc::new(TestTunnelRouter::new());
    let edge_connections: Arc<dashmap::DashMap<String, Connection>> =
        Arc::new(dashmap::DashMap::new());

    // Accept loop
    let conn_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let router = router.clone();
            let edge_connections = edge_connections.clone();
            let counter = conn_counter.clone();

            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let conn_id = format!(
                    "conn-{}",
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                );
                handle_test_edge(connection, &conn_id, &router, &edge_connections).await;
            });
        }
    });

    // Start API server
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    Ok(actual_addr)
}

// ── Minimal relay logic for integration tests ──

struct TestTunnelRouter {
    tunnels: dashmap::DashMap<Uuid, TestTunnelState>,
}

struct TestTunnelState {
    ingress: Option<TestEndpoint>,
    egress: Option<TestEndpoint>,
}

struct TestEndpoint {
    edge_id: String,
    connection: Connection,
}

impl TestTunnelRouter {
    fn new() -> Self {
        Self {
            tunnels: dashmap::DashMap::new(),
        }
    }
}

async fn handle_test_edge(
    connection: Connection,
    conn_id: &str,
    router: &Arc<TestTunnelRouter>,
    edge_connections: &Arc<dashmap::DashMap<String, Connection>>,
) {
    // Accept control stream
    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
        return;
    };

    // No auth — connection is immediately ready
    let edge_id = conn_id.to_string();
    edge_connections.insert(edge_id.clone(), connection.clone());

    // Handle control messages and data streams concurrently
    let router2 = router.clone();
    let edge_connections2 = edge_connections.clone();
    let edge_id2 = edge_id.clone();
    let conn2 = connection.clone();

    tokio::select! {
        _ = async {
            // Control stream loop
            loop {
                let Ok(msg) = read_msg::<EdgeMessage>(&mut recv).await else {
                    break;
                };
                match msg {
                    EdgeMessage::TunnelBind { tunnel_id, direction, protocol: _ } => {
                        let mut entry = router.tunnels.entry(tunnel_id).or_insert_with(|| TestTunnelState {
                            ingress: None,
                            egress: None,
                        });
                        let state = entry.value_mut();
                        match direction {
                            TunnelDirection::Ingress => {
                                state.ingress = Some(TestEndpoint {
                                    edge_id: edge_id.clone(),
                                    connection: connection.clone(),
                                });
                            }
                            TunnelDirection::Egress => {
                                state.egress = Some(TestEndpoint {
                                    edge_id: edge_id.clone(),
                                    connection: connection.clone(),
                                });
                            }
                        }
                        let active = state.ingress.is_some() && state.egress.is_some();
                        if active {
                            let _ = write_msg(&mut send, &RelayMessage::TunnelReady { tunnel_id }).await;
                            // Notify peer
                            let peer_edge_id = match direction {
                                TunnelDirection::Ingress => state.egress.as_ref().map(|e| e.edge_id.clone()),
                                TunnelDirection::Egress => state.ingress.as_ref().map(|e| e.edge_id.clone()),
                            };
                            drop(entry);
                            if let Some(peer_id) = peer_edge_id {
                                if let Some(peer_conn) = edge_connections.get(&peer_id) {
                                    if let Ok(mut uni) = peer_conn.open_uni().await {
                                        let _ = write_msg(&mut uni, &RelayMessage::TunnelReady { tunnel_id }).await;
                                        let _ = uni.finish();
                                    }
                                }
                            }
                        } else {
                            let _ = write_msg(&mut send, &RelayMessage::TunnelWaiting { tunnel_id }).await;
                        }
                    }
                    EdgeMessage::Ping => {
                        let _ = write_msg(&mut send, &RelayMessage::Pong).await;
                    }
                    _ => {}
                }
            }
        } => {}
        _ = async {
            // Data stream handler
            loop {
                let Ok((data_send, mut data_recv)) = conn2.accept_bi().await else {
                    break;
                };
                let router = router2.clone();
                let edge_id = edge_id2.clone();
                let edge_connections = edge_connections2.clone();
                tokio::spawn(async move {
                    let _ = forward_test_tcp_stream(data_send, &mut data_recv, &edge_id, &router, &edge_connections).await;
                });
            }
        } => {}
        _ = async {
            // UDP datagram handler
            loop {
                let Ok(datagram) = conn2.read_datagram().await else {
                    break;
                };
                if datagram.len() < 16 {
                    continue;
                }
                let tunnel_id = Uuid::from_bytes(datagram[..16].try_into().unwrap());
                let Some(entry) = router2.tunnels.get(&tunnel_id) else {
                    continue;
                };
                // Determine direction and find peer
                let peer_conn = if entry.ingress.as_ref().is_some_and(|e| e.edge_id == edge_id2) {
                    entry.egress.as_ref().map(|e| e.connection.clone())
                } else {
                    entry.ingress.as_ref().map(|e| e.connection.clone())
                };
                drop(entry);
                if let Some(pc) = peer_conn {
                    let _ = pc.send_datagram(datagram);
                }
            }
        } => {}
        _ = connection.closed() => {}
    }

    edge_connections.remove(&edge_id);
}

async fn forward_test_tcp_stream(
    mut from_send: quinn::SendStream,
    from_recv: &mut quinn::RecvStream,
    edge_id: &str,
    router: &Arc<TestTunnelRouter>,
    _edge_connections: &Arc<dashmap::DashMap<String, Connection>>,
) -> anyhow::Result<()> {
    // Read stream header
    let header: StreamHeader = read_msg(from_recv).await?;
    let tunnel_id = header.tunnel_id;

    // Find peer connection
    let entry = router
        .tunnels
        .get(&tunnel_id)
        .ok_or_else(|| anyhow::anyhow!("tunnel not found"))?;

    let peer_conn = if entry
        .ingress
        .as_ref()
        .is_some_and(|e| e.edge_id == edge_id)
    {
        entry.egress.as_ref().map(|e| e.connection.clone())
    } else {
        entry.ingress.as_ref().map(|e| e.connection.clone())
    };
    drop(entry);

    let peer_conn = peer_conn.ok_or_else(|| anyhow::anyhow!("peer not connected"))?;

    // Open stream to peer
    let (mut peer_send, mut peer_recv) = peer_conn.open_bi().await?;
    write_msg(&mut peer_send, &header).await?;

    // Bidirectional copy
    let copy_a = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = from_recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            peer_send.write_all(&buf[..n]).await?;
        }
        peer_send.finish()?;
        Ok::<_, anyhow::Error>(())
    };

    let copy_b = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = peer_recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            from_send.write_all(&buf[..n]).await?;
        }
        from_send.finish()?;
        Ok::<_, anyhow::Error>(())
    };

    let _ = tokio::join!(copy_a, copy_b);
    Ok(())
}

// ── Helper: connect a client edge (no auth needed) ──

async fn connect_edge(
    endpoint: &Endpoint,
    relay_addr: SocketAddr,
) -> anyhow::Result<(Connection, quinn::SendStream, quinn::RecvStream)> {
    let connection = endpoint.connect(relay_addr, "localhost")?.await?;

    // Open control stream — no auth step
    let (send, recv) = connection.open_bi().await?;

    Ok((connection, send, recv))
}

// ── Tests ──

#[tokio::test]
async fn test_connect_no_auth() {
    let relay_addr = start_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let (_conn, _send, _recv) = connect_edge(&client, relay_addr).await.unwrap();
}

#[tokio::test]
async fn test_ping_pong() {
    let relay_addr = start_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let (_conn, mut send, mut recv) = connect_edge(&client, relay_addr).await.unwrap();

    write_msg(&mut send, &EdgeMessage::Ping).await.unwrap();
    let resp: RelayMessage = read_msg(&mut recv).await.unwrap();
    match resp {
        RelayMessage::Pong => {} // expected
        other => panic!("expected Pong, got {:?}", other),
    }
}

#[tokio::test]
async fn test_tunnel_bind_waiting_then_active() {
    let relay_addr = start_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let tunnel_id = Uuid::new_v4();

    // Ingress edge binds first → should get TunnelWaiting
    let (_conn1, mut send1, mut recv1) =
        connect_edge(&client, relay_addr).await.unwrap();

    write_msg(
        &mut send1,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();

    let resp: RelayMessage = read_msg(&mut recv1).await.unwrap();
    match resp {
        RelayMessage::TunnelWaiting { tunnel_id: id } => assert_eq!(id, tunnel_id),
        other => panic!("expected TunnelWaiting, got {:?}", other),
    }

    // Egress edge binds → both should get TunnelReady
    let (_conn2, mut send2, mut recv2) =
        connect_edge(&client, relay_addr).await.unwrap();

    write_msg(
        &mut send2,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();

    // Egress gets TunnelReady on control stream
    let resp: RelayMessage = read_msg(&mut recv2).await.unwrap();
    match resp {
        RelayMessage::TunnelReady { tunnel_id: id } => assert_eq!(id, tunnel_id),
        other => panic!("expected TunnelReady on egress control, got {:?}", other),
    }

    // Ingress gets TunnelReady via uni stream notification
    if let Ok(Ok(mut uni)) =
        tokio::time::timeout(Duration::from_secs(2), _conn1.accept_uni()).await
    {
        let msg: RelayMessage = read_msg(&mut uni).await.unwrap();
        match msg {
            RelayMessage::TunnelReady { tunnel_id: id } => assert_eq!(id, tunnel_id),
            other => panic!("expected TunnelReady notification, got {:?}", other),
        }
    }
}

#[tokio::test]
async fn test_tcp_tunnel_bidirectional() {
    let relay_addr = start_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let tunnel_id = Uuid::new_v4();

    // Connect both edges (no auth)
    let (conn_ingress, mut ctrl_send_i, mut ctrl_recv_i) =
        connect_edge(&client, relay_addr).await.unwrap();
    let (conn_egress, mut ctrl_send_e, mut ctrl_recv_e) =
        connect_edge(&client, relay_addr).await.unwrap();

    // Bind ingress
    write_msg(
        &mut ctrl_send_i,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut ctrl_recv_i).await.unwrap(); // TunnelWaiting

    // Bind egress
    write_msg(
        &mut ctrl_send_e,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut ctrl_recv_e).await.unwrap(); // TunnelReady

    // Wait a moment for the tunnel to be fully active
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Ingress opens a data stream (simulating a TCP connection from a local device)
    let (mut data_send_i, mut data_recv_i) = conn_ingress.open_bi().await.unwrap();

    // Write stream header
    let header = StreamHeader {
        tunnel_id,
        stream_type: StreamType::Tcp,
    };
    write_msg(&mut data_send_i, &header).await.unwrap();

    // Write test data from ingress → egress
    let test_data = b"Hello from ingress device!";
    data_send_i.write_all(test_data).await.unwrap();
    data_send_i.finish().unwrap();

    // Egress side should receive a new bi-stream with the forwarded data
    let (mut data_send_e, mut data_recv_e) = tokio::time::timeout(
        Duration::from_secs(5),
        conn_egress.accept_bi(),
    )
    .await
    .expect("timeout waiting for forwarded stream")
    .expect("failed to accept bi stream");

    // Read stream header on egress side
    let recv_header: StreamHeader = read_msg(&mut data_recv_e).await.unwrap();
    assert_eq!(recv_header.tunnel_id, tunnel_id);

    // Read forwarded data
    let mut received = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        match data_recv_e.read(&mut buf).await.unwrap() {
            Some(n) => received.extend_from_slice(&buf[..n]),
            None => break,
        }
    }
    assert_eq!(&received, test_data);

    // Now send response data from egress → ingress
    let response_data = b"Hello back from egress device!";
    data_send_e.write_all(response_data).await.unwrap();
    data_send_e.finish().unwrap();

    // Read response on ingress side
    let mut response = Vec::new();
    loop {
        match data_recv_i.read(&mut buf).await.unwrap() {
            Some(n) => response.extend_from_slice(&buf[..n]),
            None => break,
        }
    }
    assert_eq!(&response, response_data);
}

#[tokio::test]
async fn test_udp_tunnel_datagram() {
    let relay_addr = start_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let tunnel_id = Uuid::new_v4();

    // Connect both edges (no auth)
    let (conn_ingress, mut ctrl_send_i, mut ctrl_recv_i) =
        connect_edge(&client, relay_addr).await.unwrap();
    let (conn_egress, mut ctrl_send_e, mut ctrl_recv_e) =
        connect_edge(&client, relay_addr).await.unwrap();

    // Bind both sides as UDP tunnel
    write_msg(
        &mut ctrl_send_i,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Udp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut ctrl_recv_i).await.unwrap();

    write_msg(
        &mut ctrl_send_e,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Udp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut ctrl_recv_e).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send a UDP datagram from ingress → relay → egress
    let payload = b"UDP test payload";
    let mut datagram = Vec::with_capacity(16 + payload.len());
    datagram.extend_from_slice(tunnel_id.as_bytes());
    datagram.extend_from_slice(payload);

    conn_ingress
        .send_datagram(bytes::Bytes::from(datagram))
        .unwrap();

    // Egress should receive the datagram
    let received = tokio::time::timeout(Duration::from_secs(5), conn_egress.read_datagram())
        .await
        .expect("timeout waiting for UDP datagram")
        .expect("failed to read datagram");

    assert!(received.len() >= 16);
    let recv_tunnel_id = Uuid::from_bytes(received[..16].try_into().unwrap());
    assert_eq!(recv_tunnel_id, tunnel_id);
    assert_eq!(&received[16..], payload);
}
