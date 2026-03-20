//! Integration tests for direct edge-to-edge tunnel mode.
//!
//! Two quinn endpoints connect directly (one as server, one as client).
//! Verifies PeerAuth handshake, TCP stream forwarding, and UDP datagram forwarding.

use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

// ── Wire protocol (mirrors src/protocol.rs) ──

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum PeerMessage {
    #[serde(rename = "peer_auth")]
    PeerAuth { tunnel_id: Uuid, token: String },
    #[serde(rename = "peer_auth_ok")]
    PeerAuthOk { tunnel_id: Uuid },
    #[serde(rename = "peer_auth_error")]
    PeerAuthError { reason: String },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
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

// ── HMAC token helpers (same as auth.rs) ──

const TEST_PSK: &str = "test_psk_for_direct_tunnel";

fn generate_token(identity: &str, secret: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(identity.as_bytes());
    let result = mac.finalize();
    let sig = result
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let payload = format!("{identity}:{sig}");
    base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
}

fn verify_token(token: &str, secret: &str) -> Option<String> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let payload = String::from_utf8(decoded).ok()?;
    let (identity, _sig) = payload.split_once(':')?;

    let expected = generate_token(identity, secret);
    if expected == token {
        Some(identity.to_string())
    } else {
        None
    }
}

// ── TLS helpers ──

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

// ── Endpoint helpers ──

fn make_direct_server() -> anyhow::Result<Endpoint> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "bilbycast-direct".into()])?;
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )?;
    tls_config.alpn_protocols = vec![b"bilbycast-direct".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.max_concurrent_uni_streams(128u32.into());
    transport.datagram_receive_buffer_size(Some(65536));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    server_config.transport_config(Arc::new(transport));

    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    Ok(endpoint)
}

fn make_direct_client() -> anyhow::Result<Endpoint> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"bilbycast-direct".to_vec()];

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.max_concurrent_uni_streams(128u32.into());
    transport.datagram_receive_buffer_size(Some(65536));

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    client_config.transport_config(Arc::new(transport));

    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Perform PeerAuth on a server-accepted connection. Returns the connection on success.
async fn server_authenticate(
    connection: &quinn::Connection,
    psk: &str,
) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let msg: PeerMessage = read_msg(&mut recv).await?;
    match msg {
        PeerMessage::PeerAuth { tunnel_id, token } => {
            if verify_token(&token, psk).is_some() {
                write_msg(&mut send, &PeerMessage::PeerAuthOk { tunnel_id }).await?;
                Ok((send, recv))
            } else {
                write_msg(
                    &mut send,
                    &PeerMessage::PeerAuthError {
                        reason: "invalid token".into(),
                    },
                )
                .await?;
                anyhow::bail!("invalid token")
            }
        }
        other => anyhow::bail!("expected PeerAuth, got {:?}", other),
    }
}

/// Perform PeerAuth as a client.
async fn client_authenticate(
    connection: &quinn::Connection,
    tunnel_id: Uuid,
    psk: &str,
) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = connection.open_bi().await?;
    let token = generate_token(&tunnel_id.to_string(), psk);
    write_msg(&mut send, &PeerMessage::PeerAuth { tunnel_id, token }).await?;
    let resp: PeerMessage = read_msg(&mut recv).await?;
    match resp {
        PeerMessage::PeerAuthOk { .. } => Ok((send, recv)),
        PeerMessage::PeerAuthError { reason } => anyhow::bail!("auth failed: {reason}"),
        other => anyhow::bail!("unexpected response: {:?}", other),
    }
}

// ── Tests ──

#[tokio::test]
async fn test_direct_peer_auth_success() {
    let tunnel_id = Uuid::new_v4();

    let server_ep = make_direct_server().unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let result = server_authenticate(&conn, TEST_PSK).await;
        assert!(result.is_ok());
        // Keep alive until client closes
        conn.closed().await;
    });

    let client_ep = make_direct_client().unwrap();
    let conn = client_ep
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let result = client_authenticate(&conn, tunnel_id, TEST_PSK).await;
    assert!(result.is_ok());

    conn.close(0u32.into(), b"done");
    server.await.unwrap();
}

#[tokio::test]
async fn test_direct_peer_auth_failure() {
    let tunnel_id = Uuid::new_v4();
    let wrong_psk = "wrong_psk_value";

    let server_ep = make_direct_server().unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // Server verifies with correct PSK — should fail since client used wrong PSK
        let result = server_authenticate(&conn, TEST_PSK).await;
        assert!(result.is_err());
    });

    let client_ep = make_direct_client().unwrap();
    let conn = client_ep
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Client uses wrong PSK
    let result = client_authenticate(&conn, tunnel_id, wrong_psk).await;
    assert!(result.is_err());

    conn.close(0u32.into(), b"done");
    server.await.unwrap();
}

#[tokio::test]
async fn test_direct_tcp_bidirectional() {
    let tunnel_id = Uuid::new_v4();

    let server_ep = make_direct_server().unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let _ctrl = server_authenticate(&conn, TEST_PSK).await.unwrap();

        // Accept data stream (TCP tunnel)
        let (mut data_send, mut data_recv) = conn.accept_bi().await.unwrap();

        // Read stream header
        let header: StreamHeader = read_msg(&mut data_recv).await.unwrap();
        assert_eq!(header.tunnel_id, tunnel_id);

        // Read all incoming data
        let mut received = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match data_recv.read(&mut buf).await.unwrap() {
                Some(n) => received.extend_from_slice(&buf[..n]),
                None => break,
            }
        }
        assert_eq!(&received, b"Hello from ingress edge!");

        // Send response back
        data_send
            .write_all(b"Hello back from egress edge!")
            .await
            .unwrap();
        data_send.finish().unwrap();

        // Keep alive until client closes
        conn.closed().await;
    });

    let client_ep = make_direct_client().unwrap();
    let conn = client_ep
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let _ctrl = client_authenticate(&conn, tunnel_id, TEST_PSK)
        .await
        .unwrap();

    // Open data stream with StreamHeader (same format as relay mode)
    let (mut data_send, mut data_recv) = conn.open_bi().await.unwrap();
    write_msg(
        &mut data_send,
        &StreamHeader {
            tunnel_id,
            stream_type: StreamType::Tcp,
        },
    )
    .await
    .unwrap();

    // Send data ingress → egress
    data_send
        .write_all(b"Hello from ingress edge!")
        .await
        .unwrap();
    data_send.finish().unwrap();

    // Read response egress → ingress
    let mut response = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        match data_recv.read(&mut buf).await.unwrap() {
            Some(n) => response.extend_from_slice(&buf[..n]),
            None => break,
        }
    }
    assert_eq!(&response, b"Hello back from egress edge!");

    conn.close(0u32.into(), b"done");
    server.await.unwrap();
}

#[tokio::test]
async fn test_direct_udp_datagram() {
    let tunnel_id = Uuid::new_v4();

    let server_ep = make_direct_server().unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let _ctrl = server_authenticate(&conn, TEST_PSK).await.unwrap();

        // Receive UDP datagram
        let datagram = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("timeout waiting for datagram")
            .expect("failed to read datagram");

        // Verify tunnel_id prefix + payload
        assert!(datagram.len() >= 16);
        let recv_tunnel_id = Uuid::from_bytes(datagram[..16].try_into().unwrap());
        assert_eq!(recv_tunnel_id, tunnel_id);
        assert_eq!(&datagram[16..], b"UDP payload from ingress");

        // Reply with a datagram (same format)
        let mut reply = Vec::with_capacity(16 + 21);
        reply.extend_from_slice(tunnel_id.as_bytes());
        reply.extend_from_slice(b"UDP reply from egress");
        conn.send_datagram(bytes::Bytes::from(reply)).unwrap();

        // Wait for client to signal done
        conn.closed().await;
    });

    let client_ep = make_direct_client().unwrap();
    let conn = client_ep
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let _ctrl = client_authenticate(&conn, tunnel_id, TEST_PSK)
        .await
        .unwrap();

    // Send UDP datagram with tunnel_id prefix (same format as relay mode)
    let mut datagram = Vec::with_capacity(16 + 24);
    datagram.extend_from_slice(tunnel_id.as_bytes());
    datagram.extend_from_slice(b"UDP payload from ingress");
    conn.send_datagram(bytes::Bytes::from(datagram)).unwrap();

    // Receive reply datagram
    let reply = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("timeout waiting for reply datagram")
        .expect("failed to read reply datagram");

    assert!(reply.len() >= 16);
    let reply_tunnel_id = Uuid::from_bytes(reply[..16].try_into().unwrap());
    assert_eq!(reply_tunnel_id, tunnel_id);
    assert_eq!(&reply[16..], b"UDP reply from egress");

    conn.close(0u32.into(), b"done");
    server.await.unwrap();
}
