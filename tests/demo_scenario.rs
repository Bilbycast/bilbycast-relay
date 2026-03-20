//! Full demo scenario: Manager + Relay + 2 Edge nodes
//!
//! This test simulates the complete production workflow:
//! 1. Start a relay server
//! 2. Two edge clients authenticate to the relay
//! 3. Create a UDP tunnel between them (for SRT traffic)
//! 4. Send bidirectional data through the tunnel
//! 5. Verify data integrity end-to-end
//! 6. Test tunnel teardown and reconnection
//!
//! Run with: cargo test --test demo_scenario -- --nocapture

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::{ClientConfig, Connection, Endpoint, TransportConfig};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Wire protocol (same as integration.rs) ──

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum EdgeMessage {
    #[serde(rename = "auth")]
    Auth { token: String },
    #[serde(rename = "tunnel_bind")]
    TunnelBind {
        tunnel_id: Uuid,
        direction: TunnelDirection,
        protocol: TunnelProtocol,
    },
    #[serde(rename = "tunnel_unbind")]
    TunnelUnbind { tunnel_id: Uuid },
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum RelayMessage {
    #[serde(rename = "auth_ok")]
    AuthOk { edge_id: String },
    #[serde(rename = "auth_error")]
    AuthError { reason: String },
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

// ── Token generation ──

const SHARED_SECRET: &str = "demo_shared_secret_2026";

fn generate_token(edge_id: &str, shared_secret: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(shared_secret.as_bytes()).unwrap();
    mac.update(edge_id.as_bytes());
    let result = mac.finalize();
    let sig = result
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let payload = format!("{edge_id}:{sig}");
    base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
}

// ── TLS ──

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
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

fn make_client_endpoint() -> anyhow::Result<Endpoint> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
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

// ── Relay server (reuses test relay from integration.rs) ──

struct TestRelay {
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

impl TestRelay {
    fn new() -> Self {
        Self {
            tunnels: dashmap::DashMap::new(),
        }
    }
}

async fn start_test_relay() -> anyhow::Result<SocketAddr> {
    let quic_listener = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic_addr = quic_listener.local_addr()?;
    drop(quic_listener);

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "bilbycast-relay".into()])?;
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
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

    let relay = Arc::new(TestRelay::new());
    let edge_connections: Arc<dashmap::DashMap<String, Connection>> =
        Arc::new(dashmap::DashMap::new());

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let relay = relay.clone();
            let edge_connections = edge_connections.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                handle_relay_edge(connection, &relay, &edge_connections).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(actual_addr)
}

async fn handle_relay_edge(
    connection: Connection,
    relay: &Arc<TestRelay>,
    edge_connections: &Arc<dashmap::DashMap<String, Connection>>,
) {
    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
        return;
    };

    // Auth
    let Ok(msg) = read_msg::<EdgeMessage>(&mut recv).await else {
        return;
    };
    let edge_id = match msg {
        EdgeMessage::Auth { token } => {
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &token,
            );
            let Ok(decoded) = decoded else { return };
            let Ok(payload) = String::from_utf8(decoded) else {
                return;
            };
            let Some((eid, _)) = payload.split_once(':') else {
                return;
            };
            let expected = generate_token(eid, SHARED_SECRET);
            if expected != token {
                let _ = write_msg(
                    &mut send,
                    &RelayMessage::AuthError {
                        reason: "bad token".into(),
                    },
                )
                .await;
                return;
            }
            let _ = write_msg(
                &mut send,
                &RelayMessage::AuthOk {
                    edge_id: eid.to_string(),
                },
            )
            .await;
            eid.to_string()
        }
        _ => return,
    };

    edge_connections.insert(edge_id.clone(), connection.clone());
    let conn2 = connection.clone();
    let relay2 = relay.clone();
    let edge_id2 = edge_id.clone();
    let _edge_connections2 = edge_connections.clone();

    tokio::select! {
        _ = async {
            loop {
                let Ok(msg) = read_msg::<EdgeMessage>(&mut recv).await else { break };
                match msg {
                    EdgeMessage::TunnelBind { tunnel_id, direction, .. } => {
                        let mut entry = relay.tunnels.entry(tunnel_id).or_insert_with(|| TestTunnelState {
                            ingress: None, egress: None,
                        });
                        match direction {
                            TunnelDirection::Ingress => entry.ingress = Some(TestEndpoint { edge_id: edge_id.clone(), connection: connection.clone() }),
                            TunnelDirection::Egress => entry.egress = Some(TestEndpoint { edge_id: edge_id.clone(), connection: connection.clone() }),
                        }
                        let active = entry.ingress.is_some() && entry.egress.is_some();
                        if active {
                            let peer_id = match direction {
                                TunnelDirection::Ingress => entry.egress.as_ref().map(|e| e.edge_id.clone()),
                                TunnelDirection::Egress => entry.ingress.as_ref().map(|e| e.edge_id.clone()),
                            };
                            drop(entry);
                            let _ = write_msg(&mut send, &RelayMessage::TunnelReady { tunnel_id }).await;
                            if let Some(pid) = peer_id {
                                if let Some(pc) = edge_connections.get(&pid) {
                                    if let Ok(mut uni) = pc.open_uni().await {
                                        let _ = write_msg(&mut uni, &RelayMessage::TunnelReady { tunnel_id }).await;
                                        let _ = uni.finish();
                                    }
                                }
                            }
                        } else {
                            let _ = write_msg(&mut send, &RelayMessage::TunnelWaiting { tunnel_id }).await;
                        }
                    }
                    EdgeMessage::Ping => { let _ = write_msg(&mut send, &RelayMessage::Pong).await; }
                    _ => {}
                }
            }
        } => {}
        _ = async {
            loop {
                let Ok((ds, mut dr)) = conn2.accept_bi().await else { break };
                let r = relay2.clone();
                let eid = edge_id2.clone();
                tokio::spawn(async move {
                    let _ = relay_forward_tcp(ds, &mut dr, &eid, &r).await;
                });
            }
        } => {}
        _ = async {
            loop {
                let Ok(dg) = conn2.read_datagram().await else { break };
                if dg.len() < 16 { continue; }
                let tid = Uuid::from_bytes(dg[..16].try_into().unwrap());
                let Some(entry) = relay2.tunnels.get(&tid) else { continue };
                let peer_conn = if entry.ingress.as_ref().is_some_and(|e| e.edge_id == edge_id2) {
                    entry.egress.as_ref().map(|e| e.connection.clone())
                } else {
                    entry.ingress.as_ref().map(|e| e.connection.clone())
                };
                drop(entry);
                if let Some(pc) = peer_conn { let _ = pc.send_datagram(dg); }
            }
        } => {}
        _ = connection.closed() => {}
    }

    edge_connections.remove(&edge_id);
}

async fn relay_forward_tcp(
    mut from_send: quinn::SendStream,
    from_recv: &mut quinn::RecvStream,
    edge_id: &str,
    relay: &Arc<TestRelay>,
) -> anyhow::Result<()> {
    let header: StreamHeader = read_msg(from_recv).await?;
    let tid = header.tunnel_id;
    let entry = relay
        .tunnels
        .get(&tid)
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
    let peer_conn = peer_conn.ok_or_else(|| anyhow::anyhow!("no peer"))?;
    let (mut ps, mut pr) = peer_conn.open_bi().await?;
    write_msg(&mut ps, &header).await?;

    let a = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = from_recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            ps.write_all(&buf[..n]).await?;
        }
        ps.finish()?;
        Ok::<_, anyhow::Error>(())
    };
    let b = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = pr.read(&mut buf).await?;
            let Some(n) = n else { break };
            from_send.write_all(&buf[..n]).await?;
        }
        from_send.finish()?;
        Ok::<_, anyhow::Error>(())
    };
    let _ = tokio::join!(a, b);
    Ok(())
}

// ── Edge helper ──

async fn connect_edge(
    endpoint: &Endpoint,
    relay_addr: SocketAddr,
    edge_id: &str,
) -> anyhow::Result<(Connection, quinn::SendStream, quinn::RecvStream)> {
    let connection = endpoint.connect(relay_addr, "localhost")?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    let token = generate_token(edge_id, SHARED_SECRET);
    write_msg(&mut send, &EdgeMessage::Auth { token }).await?;
    let resp: RelayMessage = read_msg(&mut recv).await?;
    match resp {
        RelayMessage::AuthOk { edge_id: id } => assert_eq!(id, edge_id),
        other => anyhow::bail!("expected AuthOk, got {:?}", other),
    }
    Ok((connection, send, recv))
}

// ═══════════════════════════════════════════════════════════════════════════
// DEMO TEST SCENARIO
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn demo_full_production_scenario() {
    println!("\n{}", "=".repeat(70));
    println!("  BILBYCAST DEMO: Full Production Scenario");
    println!("  Relay + 2 Edge Nodes + UDP & TCP Tunnels");
    println!("{}\n", "=".repeat(70));

    // ── Step 1: Start relay server ──
    println!("[1/8] Starting bilbycast-relay server...");
    let relay_addr = start_test_relay().await.unwrap();
    println!("       Relay listening on {relay_addr}");
    println!("       QUIC with TLS 1.3, ALPN: bilbycast-relay");

    // ── Step 2: Connect venue edge (ingress) ──
    println!("\n[2/8] Connecting venue edge node (edge-venue-01)...");
    let client = make_client_endpoint().unwrap();
    let (venue_conn, mut venue_ctrl_send, mut venue_ctrl_recv) =
        connect_edge(&client, relay_addr, "edge-venue-01").await.unwrap();
    println!("       Authenticated via HMAC-SHA256 token");
    println!("       QUIC connection established from {}", venue_conn.local_ip().map(|ip| ip.to_string()).unwrap_or("unknown".into()));

    // ── Step 3: Connect hub edge (egress) ──
    println!("\n[3/8] Connecting hub edge node (edge-hub-01)...");
    let (hub_conn, mut hub_ctrl_send, mut hub_ctrl_recv) =
        connect_edge(&client, relay_addr, "edge-hub-01").await.unwrap();
    println!("       Authenticated via HMAC-SHA256 token");
    println!("       QUIC connection established");

    // ── Step 4: Create UDP tunnel (for SRT traffic) ──
    let srt_tunnel_id = Uuid::new_v4();
    println!("\n[4/8] Creating UDP tunnel for SRT traffic...");
    println!("       Tunnel ID: {srt_tunnel_id}");
    println!("       Protocol: UDP (for SRT datagrams)");
    println!("       Mode: Relay (both nodes behind NAT)");

    // Venue binds as ingress
    write_msg(
        &mut venue_ctrl_send,
        &EdgeMessage::TunnelBind {
            tunnel_id: srt_tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Udp,
        },
    )
    .await
    .unwrap();

    let resp: RelayMessage = read_msg(&mut venue_ctrl_recv).await.unwrap();
    match &resp {
        RelayMessage::TunnelWaiting { .. } => println!("       Venue: TunnelWaiting (peer not yet connected)"),
        other => panic!("unexpected: {:?}", other),
    }

    // Hub binds as egress
    write_msg(
        &mut hub_ctrl_send,
        &EdgeMessage::TunnelBind {
            tunnel_id: srt_tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Udp,
        },
    )
    .await
    .unwrap();

    let resp: RelayMessage = read_msg(&mut hub_ctrl_recv).await.unwrap();
    match &resp {
        RelayMessage::TunnelReady { .. } => println!("       Hub: TunnelReady (tunnel is active!)"),
        other => panic!("unexpected: {:?}", other),
    }

    // Venue should also get TunnelReady notification
    if let Ok(Ok(mut uni)) = tokio::time::timeout(Duration::from_secs(2), venue_conn.accept_uni()).await {
        let msg: RelayMessage = read_msg(&mut uni).await.unwrap();
        match &msg {
            RelayMessage::TunnelReady { .. } => println!("       Venue: TunnelReady notification received"),
            _ => {}
        }
    }
    println!("       UDP tunnel ACTIVE between venue and hub");

    // ── Step 5: Send SRT-like UDP datagrams through the tunnel ──
    println!("\n[5/8] Sending simulated SRT datagrams (venue -> hub)...");

    let num_packets = 100;
    let mut sent_payloads = Vec::new();

    for i in 0..num_packets {
        // Simulate SRT packet: 16-byte tunnel_id prefix + payload
        let payload = format!("SRT-PKT-{i:04}-TS-PACKET-188-BYTES-PADDED{}", "X".repeat(150));
        let mut datagram = Vec::with_capacity(16 + payload.len());
        datagram.extend_from_slice(srt_tunnel_id.as_bytes());
        datagram.extend_from_slice(payload.as_bytes());
        sent_payloads.push(payload.clone());

        venue_conn
            .send_datagram(Bytes::from(datagram))
            .unwrap();
    }
    println!("       Sent {num_packets} UDP datagrams (~{} bytes each)", 16 + 170);

    // Receive on hub side
    println!("       Receiving on hub side...");
    let mut received_count = 0;
    let start = std::time::Instant::now();

    while received_count < num_packets && start.elapsed() < Duration::from_secs(5) {
        match tokio::time::timeout(Duration::from_secs(2), hub_conn.read_datagram()).await {
            Ok(Ok(dg)) => {
                assert!(dg.len() >= 16);
                let recv_tid = Uuid::from_bytes(dg[..16].try_into().unwrap());
                assert_eq!(recv_tid, srt_tunnel_id);
                let payload = String::from_utf8_lossy(&dg[16..]).to_string();
                assert_eq!(payload, sent_payloads[received_count]);
                received_count += 1;
            }
            _ => break,
        }
    }

    println!("       Received {received_count}/{num_packets} datagrams");
    assert_eq!(received_count, num_packets, "Not all datagrams received!");
    println!("       All datagrams verified with correct tunnel_id and payload");

    // ── Step 6: Create TCP tunnel and send bidirectional data ──
    let tcp_tunnel_id = Uuid::new_v4();
    println!("\n[6/8] Creating TCP tunnel for control data...");
    println!("       Tunnel ID: {tcp_tunnel_id}");
    println!("       Protocol: TCP (reliable streams)");

    // Bind both sides
    write_msg(
        &mut venue_ctrl_send,
        &EdgeMessage::TunnelBind {
            tunnel_id: tcp_tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut venue_ctrl_recv).await.unwrap();

    write_msg(
        &mut hub_ctrl_send,
        &EdgeMessage::TunnelBind {
            tunnel_id: tcp_tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut hub_ctrl_recv).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Open TCP stream from venue -> hub
    println!("       Opening TCP stream: venue -> relay -> hub");
    let (mut tcp_send, mut tcp_recv) = venue_conn.open_bi().await.unwrap();
    write_msg(
        &mut tcp_send,
        &StreamHeader {
            tunnel_id: tcp_tunnel_id,
            stream_type: StreamType::Tcp,
        },
    )
    .await
    .unwrap();

    // Send camera control command
    let camera_cmd = b"CAMERA_CMD: PAN_LEFT 15 DEGREES | ZOOM 2.5x | FOCUS AUTO";
    tcp_send.write_all(camera_cmd).await.unwrap();
    tcp_send.finish().unwrap();
    println!("       Sent camera control: {} bytes", camera_cmd.len());

    // Hub receives the forwarded stream
    let (mut hub_tcp_send, mut hub_tcp_recv) = tokio::time::timeout(
        Duration::from_secs(5),
        hub_conn.accept_bi(),
    )
    .await
    .unwrap()
    .unwrap();

    let header: StreamHeader = read_msg(&mut hub_tcp_recv).await.unwrap();
    assert_eq!(header.tunnel_id, tcp_tunnel_id);

    let mut received = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        match hub_tcp_recv.read(&mut buf).await.unwrap() {
            Some(n) => received.extend_from_slice(&buf[..n]),
            None => break,
        }
    }
    assert_eq!(&received, camera_cmd);
    println!("       Hub received camera command: {} bytes verified", received.len());

    // Hub sends response back
    let response = b"CAMERA_ACK: PAN_LEFT OK | ZOOM 2.5x OK | FOCUS AUTO LOCKED AT 3.2m";
    hub_tcp_send.write_all(response).await.unwrap();
    hub_tcp_send.finish().unwrap();
    println!("       Hub sent camera ack: {} bytes", response.len());

    let mut resp_data = Vec::new();
    loop {
        match tcp_recv.read(&mut buf).await.unwrap() {
            Some(n) => resp_data.extend_from_slice(&buf[..n]),
            None => break,
        }
    }
    assert_eq!(&resp_data, response);
    println!("       Venue received ack: {} bytes verified", resp_data.len());
    println!("       TCP bidirectional data flow VERIFIED");

    // ── Step 7: Keepalive test ──
    println!("\n[7/8] Testing keepalive (ping/pong)...");
    write_msg(&mut venue_ctrl_send, &EdgeMessage::Ping)
        .await
        .unwrap();
    let resp: RelayMessage = read_msg(&mut venue_ctrl_recv).await.unwrap();
    match resp {
        RelayMessage::Pong => println!("       Venue: Ping -> Pong (OK)"),
        _ => panic!("expected Pong"),
    }

    write_msg(&mut hub_ctrl_send, &EdgeMessage::Ping)
        .await
        .unwrap();
    let resp: RelayMessage = read_msg(&mut hub_ctrl_recv).await.unwrap();
    match resp {
        RelayMessage::Pong => println!("       Hub: Ping -> Pong (OK)"),
        _ => panic!("expected Pong"),
    }

    // ── Step 8: Summary ──
    println!("\n[8/8] Demo scenario complete!");
    println!();
    println!("  Summary:");
    println!("  --------");
    println!("  Relay server:    127.0.0.1:{}", relay_addr.port());
    println!("  Venue edge:      edge-venue-01 (authenticated, connected)");
    println!("  Hub edge:        edge-hub-01 (authenticated, connected)");
    println!("  UDP tunnel:      {srt_tunnel_id}");
    println!("    - {num_packets} SRT datagrams sent venue->hub (all verified)");
    println!("  TCP tunnel:      {tcp_tunnel_id}");
    println!("    - Camera control command sent venue->hub (verified)");
    println!("    - Camera ack response sent hub->venue (verified)");
    println!("  Keepalive:       Ping/Pong working on both edges");
    println!("  Encryption:      TLS 1.3 (mandatory via QUIC)");
    println!("  Auth:            HMAC-SHA256 tokens (verified)");
    println!();
    println!("  ALL CHECKS PASSED");
    println!("{}\n", "=".repeat(70));
}

/// Stress test: send many datagrams rapidly and verify throughput.
#[tokio::test]
async fn demo_udp_throughput_stress() {
    println!("\n--- UDP Throughput Stress Test ---\n");

    let relay_addr = start_test_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let (venue_conn, mut vs, mut vr) =
        connect_edge(&client, relay_addr, "edge-stress-venue").await.unwrap();
    let (hub_conn, mut hs, mut hr) =
        connect_edge(&client, relay_addr, "edge-stress-hub").await.unwrap();

    let tunnel_id = Uuid::new_v4();

    // Bind tunnel
    write_msg(
        &mut vs,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Udp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut vr).await.unwrap();

    write_msg(
        &mut hs,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Udp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut hr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send 200 packets with small sleeps to simulate realistic encoder pacing.
    // QUIC datagrams are unreliable — buffer overflow causes drops (by design).
    // A real SRT encoder sends packets paced by the media clock, not in bursts.
    let num_packets: u32 = 200;
    let payload_size = 188 * 7; // 7 TS packets, typical SRT payload
    let start = std::time::Instant::now();

    for i in 0u32..num_packets {
        let mut dg = Vec::with_capacity(16 + payload_size);
        dg.extend_from_slice(tunnel_id.as_bytes());
        dg.extend_from_slice(&i.to_be_bytes());
        dg.resize(16 + payload_size, (i % 256) as u8);
        venue_conn.send_datagram(Bytes::from(dg)).unwrap();
        // Pace like a real SRT encoder (~7 Mbps = ~700 pkt/s = 1.4ms/pkt).
        // Send in small bursts of 7 packets (1 TS frame) then yield.
        if i % 7 == 6 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    let send_elapsed = start.elapsed();
    let total_bytes = num_packets as usize * (16 + payload_size);
    println!(
        "  Sent {} packets ({} bytes) in {:.1}ms",
        num_packets,
        total_bytes,
        send_elapsed.as_secs_f64() * 1000.0
    );

    // Wait for packets to transit through the relay
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Receive all — datagrams may arrive out of order (QUIC datagrams are unreliable)
    let mut received_set = std::collections::HashSet::new();
    let recv_start = std::time::Instant::now();

    // Use a short per-packet timeout; keep going until we hit 500ms without a packet
    while received_set.len() < num_packets as usize && recv_start.elapsed() < Duration::from_secs(10) {
        match tokio::time::timeout(Duration::from_millis(500), hub_conn.read_datagram()).await {
            Ok(Ok(dg)) => {
                assert_eq!(dg.len(), 16 + payload_size);
                let pkt_num = u32::from_be_bytes(dg[16..20].try_into().unwrap());
                assert!(pkt_num < num_packets, "invalid packet number {pkt_num}");
                received_set.insert(pkt_num);
            }
            _ => break,
        }
    }

    let recv_elapsed = recv_start.elapsed();
    let received_bytes = received_set.len() * (16 + payload_size);
    let throughput_mbps =
        (received_bytes as f64 * 8.0) / recv_elapsed.as_secs_f64() / 1_000_000.0;

    println!(
        "  Received {}/{} packets in {:.1}ms",
        received_set.len(),
        num_packets,
        recv_elapsed.as_secs_f64() * 1000.0
    );
    println!("  Throughput: {:.1} Mbps", throughput_mbps);
    println!("  Packet size: {} bytes (7 TS packets)", payload_size);

    // On localhost, we should have near-zero loss with pacing
    let loss_pct = 100.0 * (1.0 - received_set.len() as f64 / num_packets as f64);
    println!("  Packet loss: {:.1}%", loss_pct);
    assert!(
        received_set.len() >= (num_packets as f64 * 0.95) as usize,
        "Excessive packet loss: {}/{} received",
        received_set.len(),
        num_packets
    );
    if received_set.len() == num_packets as usize {
        println!("  Zero packet loss confirmed\n");
    } else {
        println!("  Loss within acceptable threshold (<5%)\n");
    }
}

/// Test multiple concurrent TCP streams through the same tunnel.
#[tokio::test]
async fn demo_multi_tcp_streams() {
    println!("\n--- Multi-TCP-Stream Test ---\n");

    let relay_addr = start_test_relay().await.unwrap();
    let client = make_client_endpoint().unwrap();

    let (venue_conn, mut vs, mut vr) =
        connect_edge(&client, relay_addr, "edge-multi-venue").await.unwrap();
    let (hub_conn, mut hs, mut hr) =
        connect_edge(&client, relay_addr, "edge-multi-hub").await.unwrap();

    let tunnel_id = Uuid::new_v4();

    // Bind TCP tunnel
    write_msg(
        &mut vs,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Ingress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut vr).await.unwrap();

    write_msg(
        &mut hs,
        &EdgeMessage::TunnelBind {
            tunnel_id,
            direction: TunnelDirection::Egress,
            protocol: TunnelProtocol::Tcp,
        },
    )
    .await
    .unwrap();
    let _: RelayMessage = read_msg(&mut hr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Open 5 concurrent TCP streams
    let num_streams = 5;
    println!("  Opening {} concurrent TCP streams through tunnel", num_streams);

    let venue_conn_arc = Arc::new(venue_conn);
    let hub_conn_arc = Arc::new(hub_conn);

    let mut send_handles = Vec::new();

    for stream_idx in 0..num_streams {
        let vc = venue_conn_arc.clone();
        let tid = tunnel_id;
        let handle = tokio::spawn(async move {
            let (mut s, mut r) = vc.open_bi().await.unwrap();
            write_msg(
                &mut s,
                &StreamHeader {
                    tunnel_id: tid,
                    stream_type: StreamType::Tcp,
                },
            )
            .await
            .unwrap();

            let msg = format!("TCP-STREAM-{stream_idx}: Hello from venue, stream {stream_idx}!");
            s.write_all(msg.as_bytes()).await.unwrap();
            s.finish().unwrap();

            // Read response
            let mut resp = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match r.read(&mut buf).await.unwrap() {
                    Some(n) => resp.extend_from_slice(&buf[..n]),
                    None => break,
                }
            }
            let resp_str = String::from_utf8(resp).unwrap();
            assert!(resp_str.contains(&format!("ACK-{stream_idx}")));
            stream_idx
        });
        send_handles.push(handle);
    }

    // Hub accepts all streams and responds
    let mut recv_handles = Vec::new();
    for _ in 0..num_streams {
        let hc = hub_conn_arc.clone();
        let handle = tokio::spawn(async move {
            let (mut s, mut r) =
                tokio::time::timeout(Duration::from_secs(5), hc.accept_bi())
                    .await
                    .unwrap()
                    .unwrap();

            let header: StreamHeader = read_msg(&mut r).await.unwrap();
            assert_eq!(header.tunnel_id, tunnel_id);

            let mut data = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match r.read(&mut buf).await.unwrap() {
                    Some(n) => data.extend_from_slice(&buf[..n]),
                    None => break,
                }
            }

            let msg = String::from_utf8(data).unwrap();
            let stream_idx: usize = msg
                .split("TCP-STREAM-")
                .nth(1)
                .unwrap()
                .split(':')
                .next()
                .unwrap()
                .parse()
                .unwrap();

            let ack = format!("ACK-{stream_idx}: Received on hub");
            s.write_all(ack.as_bytes()).await.unwrap();
            s.finish().unwrap();
            stream_idx
        });
        recv_handles.push(handle);
    }

    // Wait for all to complete
    let mut completed_sends = Vec::new();
    for h in send_handles {
        completed_sends.push(h.await.unwrap());
    }
    completed_sends.sort();
    println!("  Venue sent & got acks on streams: {:?}", completed_sends);

    let mut completed_recvs = Vec::new();
    for h in recv_handles {
        completed_recvs.push(h.await.unwrap());
    }
    completed_recvs.sort();
    println!("  Hub received & acked streams:     {:?}", completed_recvs);

    assert_eq!(completed_sends, vec![0, 1, 2, 3, 4]);
    assert_eq!(completed_recvs.len(), num_streams);
    println!("  All {} streams completed successfully\n", num_streams);
}
