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
use bilbycast_relay::distribution_control::{DistributionControl, RuntimeDistConfig};
use bilbycast_relay::distribution::es::EsFrame;
use bilbycast_relay::distribution::hub::DistributionHub;
use bilbycast_relay::distribution::ingest::{
    self, encode_eos, encode_frame, encode_hello, IngestHello,
};
use bilbycast_relay::distribution::origin::{OriginConfig, OriginStore};
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

/// A store root that nothing else is using. `OriginStore::new` creates it, and
/// the nanosecond stamp keeps every call's root to itself, so the adoption pass
/// that runs at startup finds an empty directory and each test begins with the
/// window it wrote itself.
fn test_origin_config(min_segments: usize, max_bytes_per_stream: u64) -> OriginConfig {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    OriginConfig {
        root: std::env::temp_dir()
            .join(format!("bilbycast-relay-test-origin-{}-{unique}", std::process::id())),
        retention: std::time::Duration::from_secs(3600),
        max_bytes_per_stream,
        min_segments,
        // The free-space floor off: these tests are about the retention and
        // byte policies, and the floor is the one bound whose trigger is the
        // *host's* disk rather than anything the test wrote. Leaving it armed
        // would make them pass or fail on how full the runner's volume
        // happens to be. `0` is the disabled value the config layer defines.
        min_free_bytes: 0,
        idle_grace: std::time::Duration::from_secs(60),
    }
}

#[tokio::test]
async fn origin_sliding_window_and_manifest_persistence() {
    // Segment count is only a floor now, so drive eviction with the byte
    // bound: 350 bytes at 100 bytes a segment keeps roughly the last three.
    let store = OriginStore::new(test_origin_config(1, 350)).unwrap();
    store
        .put("s", "index.m3u8", Bytes::from_static(b"#EXTM3U"))
        .await
        .unwrap();
    for i in 0..6 {
        store
            .put("s", &format!("seg{i}.m4s"), Bytes::from(vec![0u8; 100]))
            .await
            .unwrap();
    }
    // Manifest kept; the oldest segments are gone.
    assert!(store.get("s", "index.m3u8").await.is_some());
    assert!(store.get("s", "seg0.m4s").await.is_none());
    assert!(store.get("s", "seg5.m4s").await.is_some());
    assert_eq!(
        store.get("s", "seg5.m4s").await.unwrap().content_type,
        "video/mp4"
    );
    store.remove_stream("s").await;
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

    let control = DistributionControl::new(RuntimeDistConfig::from_config(&config, None), config.cascade_sources.clone());
    let accept_hub = hub.clone();
    let accept_cancel = cancel.clone();
    tokio::spawn(async move {
        ingest::accept_loop(server, control, accept_hub, events, accept_cancel).await;
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
    let control = DistributionControl::new(RuntimeDistConfig::from_config(&config, None), config.cascade_sources.clone());
    let accept_hub = hub.clone();
    let accept_cancel = cancel.clone();
    tokio::spawn(async move {
        ingest::accept_loop(server, control, accept_hub, events, accept_cancel).await;
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

/// PT-111 regression: a client (ice_lite=false) building an offer WITH audio
/// must not panic. Before the fix, the vendored session applied the level-5.1
/// H.264 workaround unconditionally, reusing PT 111 as an RTX slot that
/// collides with Opus (also PT 111) — str0m panicked "Pt locked multiple
/// times: 111". The workaround is now server-role-only. This unblocks the
/// cascade WHEP-client (which pulls video+audio from an upstream relay).
#[tokio::test]
async fn client_offer_with_audio_does_not_panic() {
    use bilbycast_relay::distribution::webrtc::session::{SessionConfig, WebrtcSession};
    let cfg = SessionConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        public_ip: Some("127.0.0.1".parse().unwrap()),
        ice_lite: false,
    };
    let mut s = WebrtcSession::new(&cfg).await.unwrap();
    let (offer, _pending) = s.create_offer(true, true, false).unwrap();
    assert!(offer.contains("m=video"), "offer must carry video");
    assert!(offer.contains("m=audio"), "offer must carry audio");
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
                    if pts.is_multiple_of(27_000) {
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

    // The "browser": a str0m client in recvonly mode, negotiating BOTH video
    // and audio (the PT-111 RTX/Opus collision is fixed, so a client offer with
    // audio no longer panics). Exercises the full SFU media path end to end:
    // packetize → SRTP encrypt → loopback → SRTP decrypt → depacketize.
    let client_cfg = SessionConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), public_ip: Some(lo), ice_lite: false };
    let mut client = WebrtcSession::new(&client_cfg).await.unwrap();
    let (offer_sdp, pending) = client.create_offer(true, true, false).unwrap();

    // The relay SFU accepts the offer, answers, and starts fanning out.
    let (whep_events, _whep_rx) = bilbycast_relay::manager::events::event_channel();
    let handle = whep::create_and_spawn_viewer(
        hub.clone(),
        "live".to_string(),
        &offer_sdp,
        Some(lo),
        cancel.clone(),
        whep_events,
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

/// Runtime config: flipping `require_viewer_token` on the control cell (as the
/// manager's `configure_distribution` push does) changes the live WHEP gate —
/// proving the manager-owned runtime config reaches the request handlers.
#[tokio::test]
async fn runtime_control_flips_viewer_gate() {
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use bilbycast_relay::config::DistributionConfig;
    use bilbycast_relay::distribution::hub::DistributionHub as Hub;
    use bilbycast_relay::distribution::origin::OriginStore;
    use bilbycast_relay::distribution::{build_router, DistributionState};
    use bilbycast_relay::distribution_control::DistUpdate;
    use bilbycast_relay::manager::events::event_channel;

    let cancel = CancellationToken::new();
    let hub = Arc::new(Hub::new());
    let (events, _rx) = event_channel();
    // Start ungated (no viewer token required).
    let cfg = DistributionConfig { require_viewer_token: false, require_ingest_token: false, ..Default::default() };
    let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
    let state = DistributionState::new(hub, Arc::new(OriginStore::new(test_origin_config(8, 1 << 30)).unwrap()), cfg, control.clone(), cancel.clone(), events);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    async fn post(addr: SocketAddr, path: &str, body: &str) -> u16 {
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).lines().next().unwrap_or("").split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
    }

    // Gate OFF: a WHEP POST is NOT rejected for a missing token (it fails later
    // on the bogus SDP → 400, not 401).
    let before = post(addr, "/whep/teststream", "v=0\r\n").await;
    assert_ne!(before, 401, "gate should be off initially (got {before})");

    // Manager pushes require_viewer_token=true + a secret.
    control.apply(DistUpdate {
        token_secret: Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into()),
        require_viewer_token: Some(true),
        ..Default::default()
    });

    // Gate ON: the same tokenless request is now rejected with 401.
    let after = post(addr, "/whep/teststream", "v=0\r\n").await;
    assert_eq!(after, 401, "viewer gate must be enforced after the runtime push (got {after})");

    // ── The `?token=` form, through the REAL router ──
    //
    // This is the wiring test the helper-level unit tests cannot be. The bug
    // was never in a parser: `whep_offer` had no access to the query string at
    // all. Deleting `RawQuery(query): RawQuery` from the handler's extractor
    // list (and passing `None` at the call site) leaves `token_from_query`
    // fully intact and every unit test green — but turns this assertion red,
    // because the request then presents no credential and 401s.
    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;

    let tok = token::mint_viewer_token(SECRET, "teststream", exp).expect("mint");
    let admitted = post(addr, &format!("/whep/teststream?token={tok}"), "v=0\r\n").await;
    assert_ne!(admitted, 401, "?token= must be accepted by the WHEP gate (got {admitted})");

    // …and it must be checked on merit, not merely present: a token minted for
    // a DIFFERENT stream is rejected, so this is authentication and not a
    // "any token unlocks any stream" hole.
    let wrong_stream = token::mint_viewer_token(SECRET, "otherstream", exp).expect("mint");
    let rejected = post(addr, &format!("/whep/teststream?token={wrong_stream}"), "v=0\r\n").await;
    assert_eq!(rejected, 403, "a token for another stream must be refused (got {rejected})");

    cancel.cancel();
}

/// `require_origin_token` gates the CMAF/LL-HLS tier, through the real router.
///
/// This is the wiring test the helper-level unit tests cannot be. The whole
/// point of the flag is that `GET /origin/...` is otherwise reachable with no
/// credential, so a WHEP viewer gate is bypassable on any stream that also
/// runs the CMAF tier. Deleting the `HeaderMap` / `RawQuery` extractors from
/// `origin_get` leaves every token helper intact and every unit test green,
/// and turns this red.
#[tokio::test]
async fn origin_get_gate_is_off_by_default_and_enforced_when_pushed() {
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use bilbycast_relay::config::DistributionConfig;
    use bilbycast_relay::distribution::hub::DistributionHub as Hub;
    use bilbycast_relay::distribution::origin::OriginStore;
    use bilbycast_relay::distribution::{build_router, DistributionState};
    use bilbycast_relay::distribution_control::DistUpdate;
    use bilbycast_relay::manager::events::event_channel;

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    let cancel = CancellationToken::new();
    let hub = Arc::new(Hub::new());
    let (events, _rx) = event_channel();
    let cfg = DistributionConfig {
        require_viewer_token: false,
        require_ingest_token: false,
        ..Default::default()
    };
    let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
    let origin = Arc::new(OriginStore::new(test_origin_config(8, 1 << 30)).unwrap());
    // Seed BOTH renditions with a real object, so a 200 means "served" and not
    // "not found" -- the point of the test is which of them a token admits.
    for stream in ["teststream", "teststream-proxy"] {
        origin
            .put(stream, "seg-00000.m4s", axum::body::Bytes::from_static(b"abcd"))
            .await
            .expect("seed segment");
    }
    let state = DistributionState::new(
        hub,
        origin,
        cfg,
        control.clone(),
        cancel.clone(),
        events,
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });

    async fn get(addr: SocketAddr, path: &str, bearer: Option<&str>) -> u16 {
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf)
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    const OBJ: &str = "/origin/teststream/seg-00000.m4s";

    // Default OFF: the CDN case. No credential, served.
    assert_eq!(
        get(addr, OBJ, None).await,
        200,
        "the origin must be open by default -- a CDN pulls with no credential"
    );

    control.apply(DistUpdate {
        token_secret: Some(SECRET.into()),
        require_origin_token: Some(true),
        ..Default::default()
    });

    // ON: the same request is now refused.
    assert_eq!(
        get(addr, OBJ, None).await,
        401,
        "origin GET must be gated once the manager pushes require_origin_token"
    );

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;

    // Both credential forms, because a segment fetch from hls.js can carry a
    // header but the first manifest fetch on native HLS cannot.
    let tok = token::mint_viewer_token(SECRET, "teststream", exp).expect("mint");
    assert_eq!(
        get(addr, OBJ, Some(&tok)).await,
        200,
        "a valid bearer token must be admitted"
    );
    assert_eq!(
        get(addr, &format!("{OBJ}?token={tok}"), None).await,
        200,
        "?token= must be admitted too"
    );

    // Checked on merit: a token for an unrelated stream is refused, so this is
    // authentication and not "any token unlocks any stream".
    let wrong = token::mint_viewer_token(SECRET, "otherstream", exp).expect("mint");
    assert_eq!(
        get(addr, OBJ, Some(&wrong)).await,
        403,
        "a token for an unrelated stream must be refused"
    );

    // ONE token covers the pair. The DVR player fetches `{stream}` and
    // `{stream}-proxy`; requiring a token each made the main rendition play
    // while the first shuttle silently buffered nothing.
    assert_eq!(
        get(addr, "/origin/teststream-proxy/seg-00000.m4s", Some(&tok)).await,
        200,
        "the source's token must also admit its derived rendition"
    );

    // ...but only in that direction. Handing someone the low-resolution
    // rendition must not hand them the full-resolution one.
    let proxy_only = token::mint_viewer_token(SECRET, "teststream-proxy", exp).expect("mint");
    assert_eq!(
        get(addr, OBJ, Some(&proxy_only)).await,
        403,
        "a rendition token must not grant its source"
    );

    // The gate must run BEFORE the store is consulted, or a 404-vs-401 split
    // tells an unauthenticated caller which segments exist.
    assert_eq!(
        get(addr, "/origin/teststream/seg-99999.m4s", None).await,
        401,
        "a missing object must not leak its absence to an unauthenticated caller"
    );

    cancel.cancel();
}

/// Cascade end-to-end: an UPSTREAM relay serves a stream over WHEP; a
/// DOWNSTREAM relay pulls it as a WHEP client (real HTTP signalling + real
/// ICE/DTLS/SRTP) and republishes it into its own hub for its own viewers.
/// Proves the relay-to-relay scale path.
#[tokio::test]
async fn cascade_pulls_upstream_whep_and_republishes() {
    use std::net::SocketAddr;

    use bilbycast_relay::config::{CascadeSource, DistributionConfig};
    use bilbycast_relay::distribution::hub::DistributionHub as Hub;
    use bilbycast_relay::distribution::origin::OriginStore;
    use bilbycast_relay::distribution::{build_router, cascade, DistributionState};
    use bilbycast_relay::manager::events::event_channel;

    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let cancel = CancellationToken::new();

    // ── Upstream relay: a hub + a real WHEP HTTP server ──
    let up_hub = Arc::new(Hub::new());
    let (up_events, _up_rx) = event_channel();
    let up_cfg = DistributionConfig {
        require_viewer_token: false,
        require_ingest_token: false,
        ..Default::default()
    };
    let up_control = DistributionControl::new(
        RuntimeDistConfig::from_config(&up_cfg, Some(lo)),
        up_cfg.cascade_sources.clone(),
    );
    let up_state = DistributionState::new(
        up_hub.clone(),
        Arc::new(OriginStore::new(test_origin_config(8, 1 << 30)).unwrap()),
        up_cfg,
        up_control,
        cancel.clone(),
        up_events,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = listener.local_addr().unwrap();
    let router = build_router(up_state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    // Publisher feeding the upstream hub.
    let pub_hub = up_hub.clone();
    let pub_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut pts: u64 = 0;
        pub_hub.publish("big-game", EsFrame::video(pts, idr_au(), true));
        let mut tick = tokio::time::interval(Duration::from_millis(30));
        loop {
            tokio::select! {
                _ = pub_cancel.cancelled() => break,
                _ = tick.tick() => {
                    pts += 2700;
                    if pts.is_multiple_of(27_000) {
                        pub_hub.publish("big-game", EsFrame::video(pts, idr_au(), true));
                    } else {
                        pub_hub.publish("big-game", EsFrame::video(pts, Bytes::from_static(&[0,0,0,1,0x41,0x9a]), false));
                    }
                    pub_hub.publish("big-game", EsFrame::audio(pts, Bytes::from_static(&[0xfc,0x22])));
                }
            }
        }
    });

    // ── Downstream relay: cascade pull into a local hub ──
    let down_hub = Arc::new(Hub::new());
    let mut sub = down_hub.subscribe("regional-copy");
    let source = CascadeSource {
        upstream_whep_url: format!("http://{up_addr}/whep/big-game"),
        local_stream: "regional-copy".to_string(),
        token: None,
    };
    let casc_hub = down_hub.clone();
    let casc_cancel = cancel.clone();
    tokio::spawn(async move { cascade::run_cascade(casc_hub, source, Some(lo), casc_cancel).await; });

    // A keyframe access unit must reach the DOWNSTREAM hub, having traversed:
    // publisher -> upstream hub -> upstream WHEP viewer (SRTP) -> cascade client
    // -> downstream hub.
    let got = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            match sub.rx.recv().await {
                Ok(f) if f.keyframe => return true,
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return false,
            }
        }
    })
    .await;

    cancel.cancel();
    assert!(matches!(got, Ok(true)), "cascade must republish a keyframe downstream, got {got:?}");
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

/// The whole clip lifecycle, over HTTP, through the real router.
///
/// Every other clip test drives `OriginStore` directly, which cannot see the
/// two things most likely to break here. The first is route ordering:
/// `/origin/{stream}/clips` and `/origin/{stream}/{file}` both match that
/// path, and if the object route wins, asking for the clip list serves a 404
/// for a segment named "clips" — with the store perfectly correct underneath.
/// The second is that the clips live on their own router with their own body
/// limit, merged into the object router; a merge that drops them leaves every
/// helper green and every endpoint gone.
#[tokio::test]
async fn the_clip_lifecycle_works_over_http() {
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use bilbycast_relay::distribution::hub::DistributionHub as Hub;
    use bilbycast_relay::distribution::origin::OriginStore;
    use bilbycast_relay::distribution::{build_router, DistributionState};

    let cancel = CancellationToken::new();
    let hub = Arc::new(Hub::new());
    let (events, _rx) = event_channel();
    let cfg = DistributionConfig {
        require_viewer_token: false,
        require_ingest_token: false,
        ..Default::default()
    };
    let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
    let origin = Arc::new(OriginStore::new(test_origin_config(8, 1 << 30)).unwrap());
    let state = DistributionState::new(hub, origin, cfg, control, cancel.clone(), events);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(state);
    tokio::spawn(async move {
        let _ =
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    /// Returns (status, body). Written by hand rather than with a client crate
    /// so the test depends on nothing the relay does not already carry.
    async fn req(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: &str,
    ) -> (u16, String) {
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        if let Some(b) = body {
            head.push_str(&format!(
                "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        head.push_str("\r\n");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(head.as_bytes()).await.unwrap();
        if let Some(b) = body {
            s.write_all(b).await.unwrap();
        }
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        // Split head from body on the blank line; the body may be binary, and
        // lossy is fine because every assertion below is on ASCII.
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    const ASK: &str = r#"{"pre_secs":10,"post_secs":20,"clips":[
        {"at":"2026-09-07T10:00:00Z","name":"10-00-00-00 - Goal"}]}"#;

    // 1. Requesting a clip is accepted, and this is the route-ordering check:
    //    a POST that fell through to the object route could not answer 200.
    let (st, _) = req(addr, "POST", "/origin/feed/clips", Some(ASK.as_bytes()), "application/json").await;
    assert_eq!(st, 202, "POST /origin/feed/clips was not routed to the clip handler");

    // 2. It lists, unfinished. A `clips` swallowed by `{file}` would 404 here.
    let (st, body) = req(addr, "GET", "/origin/feed/clips", None, "").await;
    assert_eq!(st, 200, "GET /origin/feed/clips did not reach the list handler: {body}");
    assert!(body.contains("10-00-00-00 - Goal"), "the requested clip is not listed: {body}");
    assert!(body.contains("\"ready\":false"), "a clip nothing has cut yet reads as ready: {body}");

    // 3. The edge uploads the cut. Percent-encoded, as a browser would send it.
    let (st, _) = req(
        addr,
        "PUT",
        "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4",
        Some(b"ftypisomMOOVDATA"),
        "video/mp4",
    )
    .await;
    assert_eq!(st, 201, "the edge could not upload a finished clip");

    // 4. Now it is ready, and carries its size.
    let (_, body) = req(addr, "GET", "/origin/feed/clips", None, "").await;
    assert!(body.contains("\"ready\":true"), "an uploaded clip still reads as pending: {body}");
    assert!(body.contains("\"bytes\":16"), "the clip's size was not recorded: {body}");

    // 5. And downloads byte for byte.
    let (st, body) = req(addr, "GET", "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4", None, "").await;
    assert_eq!(st, 200, "a finished clip would not download");
    assert_eq!(body, "ftypisomMOOVDATA", "the download is not what was uploaded");

    // 6. Deleting it reclaims the space, and it stops being served.
    let (st, _) = req(addr, "DELETE", "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4", None, "").await;
    assert_eq!(st, 204, "a clip could not be deleted");
    let (st, _) = req(addr, "GET", "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4", None, "").await;
    assert_eq!(st, 404, "a deleted clip is still being served");

    // 7. A clip the edge gives up on says so, rather than pending for ever.
    let (st, _) = req(addr, "POST", "/origin/feed/clips", Some(ASK.as_bytes()), "application/json").await;
    assert_eq!(st, 202);
    let (st, _) = req(
        addr,
        "POST",
        "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4/failed",
        Some(br#"{"reason":"that moment is no longer in the window"}"#),
        "application/json",
    )
    .await;
    assert_eq!(st, 200, "the edge could not report a clip it cannot cut");
    let (_, body) = req(addr, "GET", "/origin/feed/clips", None, "").await;
    assert!(body.contains("\"failed\":true"), "a given-up clip does not read as failed: {body}");
    assert!(
        body.contains("no longer in the window"),
        "the reason the operator needs is not in the listing: {body}"
    );

    // 8. The one-minute ceiling is enforced at the door, with a sentence that
    //    names the limit — the player shows this text verbatim.
    let too_long = r#"{"pre_secs":40,"post_secs":40,"clips":[
        {"at":"2026-09-07T10:00:00Z","name":"long"}]}"#;
    let (st, body) = req(addr, "POST", "/origin/feed/clips", Some(too_long.as_bytes()), "application/json").await;
    assert_eq!(st, 400, "an 80-second clip was accepted");
    assert!(body.contains("60 seconds"), "the refusal does not name the limit: {body}");
}

/// The edge must be able to read its own work queue.
///
/// Two different callers poll `GET /origin/{stream}/clips` holding two
/// different credentials: a viewer's portal, which has a viewer token, and the
/// edge that does the cutting, which is an ingest client and carries the
/// ingest token it pushes segments with. Gating on the viewer token alone
/// admitted the portal and locked out the edge — every poll 403'd, no clip was
/// ever cut, and the poller's `Err(_) => continue` meant not one line of log
/// said so. The feature was inert end to end and every unit test was green.
#[tokio::test]
async fn the_clip_list_admits_the_edge_as_well_as_a_viewer() {
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use bilbycast_relay::distribution::hub::DistributionHub as Hub;
    use bilbycast_relay::distribution::origin::OriginStore;
    use bilbycast_relay::distribution::{build_router, token, DistributionState};
    use bilbycast_relay::distribution_control::DistUpdate;

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    let cancel = CancellationToken::new();
    let hub = Arc::new(Hub::new());
    let (events, _rx) = event_channel();
    let cfg = DistributionConfig::default();
    let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
    let origin = Arc::new(OriginStore::new(test_origin_config(8, 1 << 30)).unwrap());
    let state = DistributionState::new(hub, origin, cfg, control.clone(), cancel.clone(), events);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(state);
    tokio::spawn(async move {
        let _ =
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    // The gate only exists once the manager turns it on, which is how the
    // demo runs and how this went unnoticed in an ungated test.
    control.apply(DistUpdate {
        token_secret: Some(SECRET.into()),
        require_origin_token: Some(true),
        ..Default::default()
    });

    async fn list(addr: SocketAddr, bearer: Option<&str>) -> u16 {
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}
"))
            .unwrap_or_default();
        let req = format!(
            "GET /origin/feed/clips HTTP/1.1
Host: x
{auth}Connection: close

"
        );
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf)
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;

    assert_eq!(list(addr, None).await, 401, "the list must still need a credential");

    let viewer = token::mint_viewer_token(SECRET, "feed", exp).unwrap();
    assert_eq!(list(addr, Some(&viewer)).await, 200, "a viewer cannot see their own clips");

    let ingest = token::mint_ingest_token(SECRET, "feed", exp).unwrap();
    assert_eq!(
        list(addr, Some(&ingest)).await,
        200,
        "the edge cannot read its own work queue, so nothing will ever be cut"
    );

    // A token for someone else's stream is still no good, either way round.
    let wrong = token::mint_ingest_token(SECRET, "other", exp).unwrap();
    assert_ne!(list(addr, Some(&wrong)).await, 200, "a token for another stream was accepted");

    // The same applies to the objects themselves. Cutting a clip from whole
    // segments means fetching the manifest and the segments that cover the
    // moment, so an edge locked out of those cannot fall back either — which
    // is exactly what happened once the list was fixed and this was not.
    async fn get_obj(addr: SocketAddr, path: &str, bearer: Option<&str>) -> u16 {
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}
"))
            .unwrap_or_default();
        let req =
            format!("GET {path} HTTP/1.1
Host: x
{auth}Connection: close

");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf)
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }
    // 404, not 401/403: the credential was accepted and the object simply is
    // not there. Asserting "not refused" is the point.
    assert_eq!(
        get_obj(addr, "/origin/feed/manifest.m3u8", Some(&ingest)).await,
        404,
        "the edge cannot read the manifest it needs to cut a clip from segments"
    );
    assert_eq!(
        get_obj(addr, "/origin/feed/manifest.m3u8", Some(&wrong)).await,
        403,
        "an ingest token for another stream must not open this one"
    );
}
