// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Edge → relay distribution ingest (QUIC).
//!
//! An edge that has pre-demuxed + pre-transcoded its flow to browser-ready
//! H.264 + Opus opens a QUIC connection here and streams elementary frames
//! for a named stream. The relay validates the ingest token, registers the
//! stream in the [`DistributionHub`], and publishes each frame for the WHEP
//! fan-out.
//!
//! This is a **separate** listener from the opaque forwarder's QUIC endpoint
//! (different ALPN, different port), so the two never share a code path.
//!
//! ## Wire format (must match `bilbycast-edge`'s distribution output)
//!
//! ALPN: `bilbycast-distribution`. The edge opens **one unidirectional
//! stream** and writes:
//!
//! 1. **Hello**: `[u32 BE len][JSON]` where JSON = [`IngestHello`].
//! 2. **Frames** (repeated), each:
//!    `[u8 kind][u8 flags][u64 BE pts_90k][u32 BE len][payload]`
//!    - `kind`: 1 = H.264 video access unit, 2 = Opus audio frame,
//!      0xFF = end-of-stream (no more fields).
//!    - `flags`: bit0 = keyframe (video IDR).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use quinn::{RecvStream, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::config::DistributionConfig;
use crate::distribution_control::DistributionControl;
use crate::manager::events::{category, EventSender, EventSeverity};

use super::es::{EsFrame, EsKind};
use super::hub::DistributionHub;
use super::token;

/// ALPN for the distribution ingest QUIC endpoint.
pub const ALPN_DISTRIBUTION: &[u8] = b"bilbycast-distribution";

const KIND_VIDEO: u8 = 1;
const KIND_AUDIO: u8 = 2;
const KIND_EOS: u8 = 0xFF;
const FLAG_KEYFRAME: u8 = 0x01;

/// Max single ES frame the ingest will accept (a generous 4 MiB — a 4K IDR
/// access unit is well under this).
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_HELLO_BYTES: usize = 64 * 1024;

/// Ingest stream opener sent by the edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestHello {
    pub v: u32,
    pub stream: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub has_audio: bool,
}

/// Run the distribution ingest QUIC listener(s).
pub async fn run_ingest(
    config: DistributionConfig,
    control: Arc<DistributionControl>,
    hub: Arc<DistributionHub>,
    events: EventSender,
    cancel: CancellationToken,
) -> Result<()> {
    let server_config = build_ingest_server_config()?;
    let entries = config.effective_ingest_addrs();

    let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    for raw in &entries {
        let addr: SocketAddr = raw
            .parse()
            .with_context(|| format!("invalid distribution.ingest bind address '{raw}'"))?;
        let socket = match build_udp_socket(addr) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to bind distribution ingest on {addr}: {e}");
                continue;
            }
        };
        let runtime = quinn::default_runtime().context("no async runtime for quinn")?;
        let endpoint = match quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config.clone()),
            socket,
            runtime,
        ) {
            Ok(ep) => ep,
            Err(e) => {
                tracing::error!("failed to start distribution ingest endpoint on {addr}: {e}");
                continue;
            }
        };
        tracing::info!("distribution ingest (edge→relay ES) listening on {addr}");

        let hub = hub.clone();
        let control = control.clone();
        let events = events.clone();
        let cancel = cancel.clone();
        set.spawn(async move {
            accept_loop(endpoint, control, hub, events, cancel).await;
        });
    }

    if set.is_empty() {
        bail!("no distribution ingest listeners could be bound");
    }

    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = set.join_next() => {}
    }
    Ok(())
}

/// Accept + serve loop for one ingest QUIC endpoint. Exposed so tests can
/// bind an ephemeral endpoint and drive it directly.
pub async fn accept_loop(
    endpoint: quinn::Endpoint,
    control: Arc<DistributionControl>,
    hub: Arc<DistributionHub>,
    events: EventSender,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let hub = hub.clone();
                let control = control.clone();
                let events = events.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => handle_ingest_connection(conn, control, hub, events).await,
                        Err(e) => tracing::debug!("distribution ingest accept failed: {e}"),
                    }
                });
            }
        }
    }
}

async fn handle_ingest_connection(
    conn: quinn::Connection,
    control: Arc<DistributionControl>,
    hub: Arc<DistributionHub>,
    events: EventSender,
) {
    let peer = conn.remote_address();
    tracing::debug!("distribution ingest connection from {peer}");
    loop {
        match conn.accept_uni().await {
            Ok(recv) => {
                let hub = hub.clone();
                let control = control.clone();
                let events = events.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ingest_stream(recv, control, hub, events).await {
                        tracing::debug!("distribution ingest stream from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::debug!("distribution ingest connection {peer} closed: {e}");
                break;
            }
        }
    }
}

async fn handle_ingest_stream(
    mut recv: RecvStream,
    control: Arc<DistributionControl>,
    hub: Arc<DistributionHub>,
    events: EventSender,
) -> Result<()> {
    // 1. Read the Hello.
    let hello_len = read_u32(&mut recv).await? as usize;
    if hello_len > MAX_HELLO_BYTES {
        bail!("ingest hello too large: {hello_len}");
    }
    let mut hello_buf = vec![0u8; hello_len];
    recv.read_exact(&mut hello_buf).await.context("read hello")?;
    let hello: IngestHello =
        serde_json::from_slice(&hello_buf).context("parse ingest hello")?;

    let Some(stream_id) = super::sanitize_stream_id(&hello.stream) else {
        bail!("invalid stream id in ingest hello");
    };

    // 2. Token gate (runtime, manager-overridable).
    let rt = control.load();
    if rt.require_ingest_token {
        let Some(ref secret) = rt.token_secret else {
            bail!("ingest token required but no token_secret configured");
        };
        let Some(ref tok) = hello.token else {
            bail!("ingest token required but none supplied");
        };
        token::verify_ingest_token(secret, &stream_id, tok)
            .context("ingest token rejected")?;
    }

    tracing::info!("distribution ingest for stream '{stream_id}' opened (has_audio={})", hello.has_audio);
    events.emit_with_details(
        EventSeverity::Info,
        category::DISTRIBUTION,
        format!("distribution ingest opened for stream '{stream_id}'"),
        serde_json::json!({ "stream": stream_id, "has_audio": hello.has_audio }),
    );
    hub.register(&stream_id);

    // 3. Frame loop.
    let result = read_frames(&mut recv, &hub, &stream_id).await;

    tracing::info!("distribution ingest for stream '{stream_id}' closed");
    // Tear the stream down so live viewers see the broadcast close and exit.
    hub.remove(&stream_id);
    events.emit_with_details(
        EventSeverity::Info,
        category::DISTRIBUTION,
        format!("distribution ingest closed for stream '{stream_id}'"),
        serde_json::json!({ "stream": stream_id }),
    );
    result
}

async fn read_frames(recv: &mut RecvStream, hub: &DistributionHub, stream_id: &str) -> Result<()> {
    loop {
        let mut hdr = [0u8; 1];
        match recv.read_exact(&mut hdr).await {
            Ok(()) => {}
            Err(_) => return Ok(()), // clean EOF / stream finished
        }
        let kind_byte = hdr[0];
        if kind_byte == KIND_EOS {
            return Ok(());
        }

        let mut flags = [0u8; 1];
        recv.read_exact(&mut flags).await.context("read flags")?;
        let pts_90k = read_u64(recv).await.context("read pts")?;
        let len = read_u32(recv).await.context("read frame len")? as usize;
        if len > MAX_FRAME_BYTES {
            bail!("ingest frame too large: {len}");
        }
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await.context("read payload")?;
        let data = Bytes::from(payload);

        let frame = match kind_byte {
            KIND_VIDEO => {
                let keyframe = flags[0] & FLAG_KEYFRAME != 0;
                EsFrame { kind: EsKind::VideoH264, pts_90k, data, keyframe }
            }
            KIND_AUDIO => EsFrame::audio(pts_90k, data),
            other => bail!("unknown ingest frame kind {other}"),
        };
        hub.publish(stream_id, frame);
    }
}

async fn read_u32(recv: &mut RecvStream) -> Result<u32> {
    let mut b = [0u8; 4];
    recv.read_exact(&mut b).await?;
    Ok(u32::from_be_bytes(b))
}

async fn read_u64(recv: &mut RecvStream) -> Result<u64> {
    let mut b = [0u8; 8];
    recv.read_exact(&mut b).await?;
    Ok(u64::from_be_bytes(b))
}

/// Encode a frame for the wire (edge side / tests). Kept next to the decoder
/// so the two never drift.
pub fn encode_frame(frame: &EsFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + frame.data.len());
    let kind = match frame.kind {
        EsKind::VideoH264 => KIND_VIDEO,
        EsKind::AudioOpus => KIND_AUDIO,
    };
    out.push(kind);
    out.push(if frame.keyframe { FLAG_KEYFRAME } else { 0 });
    out.extend_from_slice(&frame.pts_90k.to_be_bytes());
    out.extend_from_slice(&(frame.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&frame.data);
    out
}

/// Encode the EOS marker.
pub fn encode_eos() -> [u8; 1] {
    [KIND_EOS]
}

/// Encode the Hello frame (4-byte len prefix + JSON).
pub fn encode_hello(hello: &IngestHello) -> Vec<u8> {
    let json = serde_json::to_vec(hello).expect("serialize IngestHello");
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    out
}

/// Build the QUIC server config for the ingest endpoint (self-signed;
/// the media itself never traverses this — only opaque ES the operator's
/// own edge produced, encrypted again by QUIC/TLS in transit).
pub fn build_ingest_server_config() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "bilbycast-distribution".into(),
    ])
    .context("failed to generate self-signed cert for ingest")?;
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(key_der))
        .context("failed to build ingest TLS config")?;
    tls_config.alpn_protocols = vec![ALPN_DISTRIBUTION.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("failed to create ingest QUIC server config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(64u32.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(25).try_into().context("idle timeout")?,
    ));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Bind a UDP socket for a QUIC endpoint with the dual-stack contract
/// (`IPV6_V6ONLY=1` on v6). Mirrors `server::build_udp_socket`.
fn build_udp_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encode_shape() {
        let f = EsFrame::video(90_000, Bytes::from_static(&[0, 0, 0, 1, 0x65, 0xaa]), true);
        let enc = encode_frame(&f);
        assert_eq!(enc[0], KIND_VIDEO);
        assert_eq!(enc[1], FLAG_KEYFRAME);
        assert_eq!(&enc[2..10], &90_000u64.to_be_bytes());
        assert_eq!(&enc[10..14], &6u32.to_be_bytes());
        assert_eq!(&enc[14..], &[0, 0, 0, 1, 0x65, 0xaa]);
    }

    #[test]
    fn hello_encode_roundtrips() {
        let h = IngestHello { v: 1, stream: "s".into(), token: Some("t".into()), has_audio: true };
        let enc = encode_hello(&h);
        let len = u32::from_be_bytes(enc[0..4].try_into().unwrap()) as usize;
        let parsed: IngestHello = serde_json::from_slice(&enc[4..4 + len]).unwrap();
        assert_eq!(parsed.stream, "s");
        assert!(parsed.has_audio);
    }
}
