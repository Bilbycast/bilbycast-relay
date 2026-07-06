// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Integration tests for the viewer-distribution subsystem.
//!
//! Unlike `integration.rs` (which reimplements a minimal relay), these
//! exercise the REAL `bilbycast_relay::distribution` code via the library
//! target. Requires `--features viewer-distribution`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use tokio_util::sync::CancellationToken;

use bilbycast_relay::config::DistributionConfig;
use bilbycast_relay::distribution::es::EsFrame;
use bilbycast_relay::distribution::hub::DistributionHub;
use bilbycast_relay::distribution::ingest::{
    self, encode_eos, encode_frame, encode_hello, IngestHello,
};
use bilbycast_relay::distribution::origin::OriginStore;
use bilbycast_relay::distribution::token;
use bilbycast_relay::manager::events::event_channel;

fn idr_au() -> Bytes {
    Bytes::from_static(&[
        0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, // SPS
        0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, // PPS
        0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, // IDR slice
    ])
}

#[tokio::test]
async fn hub_fans_out_to_multiple_viewers_with_keyframe_cache() {
    let hub = DistributionHub::new();

    // First IDR arrives before anyone is watching → cached.
    hub.publish("show", EsFrame::video(0, idr_au(), true));

    // Two late joiners both get the cached keyframe.
    let mut a = hub.subscribe("show");
    let mut b = hub.subscribe("show");
    assert!(a.keyframe.is_some());
    assert!(b.keyframe.is_some());
    assert_eq!(hub.get("show").unwrap().viewer_count(), 2);

    // A live P-frame reaches both.
    hub.publish("show", EsFrame::video(3600, Bytes::from_static(&[0, 0, 0, 1, 0x41, 0x9a]), false));
    let fa = a.rx.recv().await.unwrap();
    let fb = b.rx.recv().await.unwrap();
    assert_eq!(fa.pts_90k, 3600);
    assert_eq!(fb.pts_90k, 3600);

    drop(a);
    drop(b);
    assert_eq!(hub.get("show").unwrap().viewer_count(), 0);
}

#[test]
fn viewer_and_ingest_tokens_are_scoped_and_expiring() {
    let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;

    let vt = token::mint_viewer_token(secret, "show", exp).unwrap();
    assert!(token::verify_viewer_token(secret, "show", &vt).is_ok());
    assert!(token::verify_viewer_token(secret, "other", &vt).is_err());
    assert!(token::verify_ingest_token(secret, "show", &vt).is_err()); // wrong scope

    let it = token::mint_ingest_token(secret, "show", exp).unwrap();
    assert!(token::verify_ingest_token(secret, "show", &it).is_ok());
}

#[test]
fn origin_sliding_window_and_manifest_persistence() {
    let store = OriginStore::new(3);
    store.put("s", "index.m3u8", Bytes::from_static(b"#EXTM3U"));
    for i in 0..6 {
        store.put("s", &format!("seg{i}.m4s"), Bytes::from(vec![0u8; 100]));
    }
    // Manifest kept; only last 3 segments retained.
    assert!(store.get("s", "index.m3u8").is_some());
    assert!(store.get("s", "seg0.m4s").is_none());
    assert!(store.get("s", "seg5.m4s").is_some());
    assert_eq!(store.get("s", "seg5.m4s").unwrap().content_type, "video/mp4");
}

#[test]
fn ingest_wire_frame_and_hello_shapes() {
    let hello = IngestHello { v: 1, stream: "show".into(), token: None, has_audio: true };
    let henc = encode_hello(&hello);
    let len = u32::from_be_bytes(henc[0..4].try_into().unwrap()) as usize;
    let parsed: IngestHello = serde_json::from_slice(&henc[4..4 + len]).unwrap();
    assert_eq!(parsed.stream, "show");

    let frame = EsFrame::video(90_000, idr_au(), true);
    let enc = encode_frame(&frame);
    assert_eq!(enc[0], 1); // video kind
    assert_eq!(enc[1] & 0x01, 1); // keyframe flag
}

/// End-to-end over REAL QUIC: a client edge streams framed ES to the ingest
/// server, and the frames come out the other side of the hub for a viewer.
#[tokio::test]
async fn ingest_over_quic_delivers_frames_to_hub() {
    let hub = Arc::new(DistributionHub::new());
    let (events, _rx) = event_channel();
    let cancel = CancellationToken::new();
    let config = DistributionConfig { require_ingest_token: false, ..Default::default() };

    // Bind the ingest server on an ephemeral port.
    let server_cfg = ingest::build_ingest_server_config().unwrap();
    let server = Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    let accept_hub = hub.clone();
    let accept_cancel = cancel.clone();
    tokio::spawn(async move {
        ingest::accept_loop(server, accept_hub, config, events, accept_cancel).await;
    });

    // A viewer subscribes before ingest starts.
    let mut sub = hub.subscribe("show");

    // Client edge connects and streams: hello + IDR + P-frame + Opus + EOS.
    let client = make_ingest_client();
    let conn = client
        .connect(server_addr, "bilbycast-distribution")
        .unwrap()
        .await
        .unwrap();
    let mut uni = conn.open_uni().await.unwrap();
    uni.write_all(&encode_hello(&IngestHello {
        v: 1,
        stream: "show".into(),
        token: None,
        has_audio: true,
    }))
    .await
    .unwrap();
    uni.write_all(&encode_frame(&EsFrame::video(0, idr_au(), true))).await.unwrap();
    uni.write_all(&encode_frame(&EsFrame::video(
        3600,
        Bytes::from_static(&[0, 0, 0, 1, 0x41, 0x9a]),
        false,
    )))
    .await
    .unwrap();
    uni.write_all(&encode_frame(&EsFrame::audio(3600, Bytes::from_static(&[0xfc, 0x11, 0x22]))))
        .await
        .unwrap();
    uni.write_all(&encode_eos()).await.unwrap();
    uni.finish().unwrap();

    // The three frames arrive at the viewer in order.
    let f1 = recv_timeout(&mut sub.rx).await;
    assert_eq!(f1.pts_90k, 0);
    assert!(f1.keyframe);
    let f2 = recv_timeout(&mut sub.rx).await;
    assert_eq!(f2.pts_90k, 3600);
    let f3 = recv_timeout(&mut sub.rx).await;
    assert_eq!(f3.kind, bilbycast_relay::distribution::es::EsKind::AudioOpus);

    // The stream registered audio + primed its keyframe cache. Read through
    // the subscription's Arc — the ingest handler tears the stream out of the
    // hub registry on EOS (correct: live viewers see the broadcast close), but
    // the StreamState stays alive as long as a viewer holds it.
    assert!(sub.state.has_audio());
    assert!(sub.state.keyframe().is_some());

    cancel.cancel();
    drop(conn);
}

/// With `require_ingest_token`, an ingest attempt lacking a valid token is
/// rejected — the hub never sees the stream's frames.
#[tokio::test]
async fn ingest_rejects_missing_token_when_required() {
    let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let hub = Arc::new(DistributionHub::new());
    let (events, _rx) = event_channel();
    let cancel = CancellationToken::new();
    let config = DistributionConfig {
        require_ingest_token: true,
        token_secret: Some(secret.to_string()),
        ..Default::default()
    };

    let server_cfg = ingest::build_ingest_server_config().unwrap();
    let server = Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let accept_hub = hub.clone();
    let accept_cancel = cancel.clone();
    tokio::spawn(async move {
        ingest::accept_loop(server, accept_hub, config, events, accept_cancel).await;
    });

    let mut sub = hub.subscribe("gated");
    let client = make_ingest_client();
    let conn = client
        .connect(server_addr, "bilbycast-distribution")
        .unwrap()
        .await
        .unwrap();
    let mut uni = conn.open_uni().await.unwrap();
    // No token supplied → server drops the stream.
    let _ = uni
        .write_all(&encode_hello(&IngestHello {
            v: 1,
            stream: "gated".into(),
            token: None,
            has_audio: false,
        }))
        .await;
    let _ = uni.write_all(&encode_frame(&EsFrame::video(0, idr_au(), true))).await;
    let _ = uni.finish();

    // No frame should arrive within the window.
    let got = tokio::time::timeout(Duration::from_millis(400), sub.rx.recv()).await;
    assert!(got.is_err() || got.unwrap().is_err(), "gated ingest must not deliver frames");

    cancel.cancel();
    drop(conn);
}

/// The crown-jewel test: a full WHEP handshake (ICE + DTLS + SRTP over real
/// loopback UDP) between a str0m client (the "browser viewer") and the relay
/// SFU, verifying that media published to the hub is packetized, encrypted,
/// and actually received + decrypted on the far side.
#[tokio::test]
async fn whep_viewer_receives_encrypted_media_end_to_end() {
    use bilbycast_relay::distribution::webrtc::session::{
        SessionConfig, SessionEvent, WebrtcSession,
    };
    use bilbycast_relay::distribution::whep;

    let hub = Arc::new(DistributionHub::new());
    let cancel = CancellationToken::new();
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // Publisher: keep the stream alive with an IDR then P-frames + Opus so the
    // viewer loop always has something to fan out once DTLS completes.
    let pub_hub = hub.clone();
    let pub_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut pts: u64 = 0;
        // Prime with a keyframe immediately.
        pub_hub.publish("live", EsFrame::video(pts, idr_au(), true));
        let mut tick = tokio::time::interval(Duration::from_millis(30));
        loop {
            tokio::select! {
                _ = pub_cancel.cancelled() => break,
                _ = tick.tick() => {
                    pts += 2700; // ~30 fps at 90 kHz
                    // Periodic IDR so a late DTLS completion still decodes.
                    if pts % 27_000 == 0 {
                        pub_hub.publish("live", EsFrame::video(pts, idr_au(), true));
                    } else {
                        pub_hub.publish("live", EsFrame::video(
                            pts, Bytes::from_static(&[0, 0, 0, 1, 0x41, 0x9a, 0x33]), false));
                    }
                    pub_hub.publish("live", EsFrame::audio(pts, Bytes::from_static(&[0xfc, 0x55, 0x66])));
                }
            }
        }
    });

    // The "browser": a str0m client in recvonly mode. Video-only on the
    // client to sidestep a str0m client-role codec-config quirk (the vendored
    // add_h264 workaround reuses PT 111 as an RTX slot, which str0m's local
    // offer-generation collides with Opus's 111 — a client concern; the relay
    // SERVER uses accept_offer, which the shipping edge proves works with real
    // browsers offering Opus). Video-only exercises the identical SFU media
    // path: packetize → SRTP encrypt → loopback → SRTP decrypt → depacketize.
    let client_cfg = SessionConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), public_ip: Some(lo), ice_lite: false };
    let mut client = WebrtcSession::new(&client_cfg).await.unwrap();
    let (offer_sdp, pending) = client.create_offer(true, false, false).unwrap();

    // The relay SFU accepts the offer, answers, and starts fanning out.
    let handle = whep::create_and_spawn_viewer(
        hub.clone(),
        "live".to_string(),
        &offer_sdp,
        Some(lo),
        cancel.clone(),
    )
    .await
    .expect("WHEP setup");

    client.apply_answer(&handle.answer_sdp, pending).unwrap();

    // Drive the client until it decrypts a media packet (or time out).
    let client_cancel = CancellationToken::new();
    let got_media = tokio::time::timeout(Duration::from_secs(20), async {
        let mut connected = false;
        loop {
            match client.poll_event(&client_cancel).await {
                SessionEvent::Connected => { connected = true; }
                SessionEvent::MediaData { .. } => return connected,
                SessionEvent::Disconnected => return false,
                _ => {}
            }
        }
    })
    .await;

    cancel.cancel();
    assert!(
        matches!(got_media, Ok(true)),
        "viewer must complete DTLS and receive decrypted media, got {got_media:?}"
    );
}

/// WHIP ingest end-to-end: a str0m WHIP client (standing in for the edge's
/// shipped WHIP-client output) pushes H.264 into the relay's WHIP ingest over
/// real ICE + DTLS + SRTP; the relay depacketizes + reassembles access units
/// and the frames come out the hub for a viewer. Proves the zero-edge-code
/// ingest path.
#[tokio::test]
async fn whip_ingest_depacketizes_h264_into_hub() {
    use bilbycast_relay::distribution::webrtc::session::{
        SessionConfig, SessionEvent, WebrtcSession,
    };
    use bilbycast_relay::distribution::{whep, whip_ingest};

    let hub = Arc::new(DistributionHub::new());
    let cancel = CancellationToken::new();
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // A viewer-side subscriber to observe what lands in the hub.
    let mut sub = hub.subscribe("live2");

    // WHIP client (the "edge"): sendonly video.
    let whip_cfg = SessionConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), public_ip: Some(lo), ice_lite: false };
    let mut whip = WebrtcSession::new(&whip_cfg).await.unwrap();
    let (offer, pending) = whip.create_offer(true, false, true).unwrap();

    // Relay accepts the WHIP ingest.
    let handle = whip_ingest::create_and_spawn_ingest(
        hub.clone(),
        "live2".to_string(),
        &offer,
        Some(lo),
        cancel.clone(),
    )
    .await
    .expect("WHIP ingest setup");
    whip.apply_answer(&handle.answer_sdp, pending).unwrap();

    // Drive the WHIP client: reach Connected, then push IDR access units.
    let whip_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            match whip.poll_event(&whip_cancel).await {
                SessionEvent::Connected => break,
                SessionEvent::Disconnected => return,
                _ => {}
            }
        }
        let mut pts: u64 = 0;
        let mut tick = tokio::time::interval(Duration::from_millis(30));
        loop {
            tokio::select! {
                _ = whip_cancel.cancelled() => break,
                _ = tick.tick() => {
                    pts += 2700;
                    whep::write_video_au(&mut whip, pts, &idr_au()).await;
                    let _ = whip.drive_udp_io().await;
                }
            }
        }
    });

    // A reassembled keyframe access unit should reach the hub.
    let got = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match sub.rx.recv().await {
                Ok(f) if f.keyframe => {
                    // Reassembled AU carries all 3 NALs (SPS+PPS+IDR).
                    let starts = f.data.windows(4).filter(|w| *w == [0, 0, 0, 1]).count();
                    return starts >= 3;
                }
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await;

    cancel.cancel();
    assert!(matches!(got, Ok(true)), "WHIP ingest must deliver a reassembled keyframe AU, got {got:?}");
}

async fn recv_timeout(
    rx: &mut tokio::sync::broadcast::Receiver<Arc<EsFrame>>,
) -> Arc<EsFrame> {
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("frame did not arrive in time")
        .expect("broadcast closed")
}

/// A quinn client that trusts any cert, speaking the distribution ALPN.
fn make_ingest_client() -> Endpoint {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"bilbycast-distribution".to_vec()];
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(64u32.into());
    let mut client_config =
        ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap()));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);
    endpoint
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ED25519,
        ]
    }
}
