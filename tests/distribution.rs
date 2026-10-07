// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

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
/// must not panic. An earlier level-5.1 H.264 workaround reused PT 111 — Opus's
/// PT — as an RTX slot, and str0m panicked "Pt locked multiple times: 111".
/// That workaround is gone: the codec set is now Opus plus str0m's own H.264
/// entries at level 5.1 (`H264_LEVEL_5_1` in `webrtc/session.rs`), whose RTX
/// slots never collide with 111. This keeps the cascade WHEP-client (which
/// pulls video+audio from an upstream relay) covered.
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

// ── H.264 over str0m's own packetizer, end to end ──
//
// The two tests above negotiate whatever a full str0m offer leads with, which
// is VP8: the relay sends on the first payload type it negotiated, so H.264
// bytes travel labelled VP8, and the VP8 (de)packetizer passes a payload
// through untouched — any byte stream at all survives it. These two keep only
// H.264 in the offer, so str0m's RFC 6184 packetizer and depacketizer carry
// the media, as they do for a browser. Neither depends on *which* H.264
// payload type the answer settles on.

/// GOP length and frame spacing (90 kHz) of the streams below.
const GOP: u64 = 10;
const FRAME_90K: u64 = 3000;

/// The parameter sets of the streams below. No zero bytes, so nothing in them
/// reads as a start code.
const TEST_SPS: &[u8] = &[0x67, 0x42, 0xe0, 0x1f, 0x8c, 0x8d, 0x40, 0x50, 0x1e, 0xd0];
const TEST_PPS: &[u8] = &[0x68, 0xce, 0x3c, 0x80];

/// Annex B: every NAL behind a 4-byte start code (the form str0m's
/// depacketizer emits).
fn annex_b(nalus: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nalus {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(n);
    }
    out
}

/// A NAL of `len` bytes behind `header`, different per `seed`, with no zero
/// byte in it.
fn nal_body(header: u8, len: usize, seed: u64) -> Vec<u8> {
    let mut nal = vec![header];
    nal.extend((0..len).map(|i| 1 + ((i as u64 * 7 + seed * 13) % 250) as u8));
    nal
}

/// The IDR slice: well past str0m's 1120-byte payload MTU, so it goes as
/// FU-A fragments.
fn test_idr_slice() -> Vec<u8> {
    nal_body(0x65, 4000, 1)
}

/// Frame `k` of the stream as a decoder must receive it: every IDR behind the
/// SPS and PPS, a P slice of its own per frame.
fn decodable_frame(k: u64) -> Vec<u8> {
    if k.is_multiple_of(GOP) {
        annex_b(&[TEST_SPS, TEST_PPS, &test_idr_slice()])
    } else {
        annex_b(&[&nal_body(0x41, 300, k)])
    }
}

/// Keep only H.264 — and the RTX that repairs it — in an SDP's video section.
/// A no-op on an offer that already carries only H.264.
fn h264_only(sdp: &str) -> String {
    use std::collections::HashSet;
    let pt_of = |line: &str, attr: &str| -> Option<String> {
        let rest = line.strip_prefix(attr)?;
        Some(rest.split_whitespace().next()?.to_string())
    };
    let h264 = h264_pts(sdp);
    let mut keep: HashSet<String> = h264.iter().map(|pt| pt.to_string()).collect();
    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("a=fmtp:")
            && let Some((pt, params)) = rest.split_once(' ')
            && let Some(apt) = params.split(';').find_map(|p| p.trim().strip_prefix("apt="))
            && apt.parse::<u8>().is_ok_and(|apt| h264.contains(&apt))
        {
            keep.insert(pt.to_string());
        }
    }

    let mut out = String::new();
    let mut in_video = false;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            in_video = line.starts_with("m=video");
            if in_video {
                // m=video <port> <proto> <fmt>... — keep the kept formats.
                let mut parts = line.split(' ');
                let head: Vec<&str> = parts.by_ref().take(3).collect();
                let fmts: Vec<&str> = parts.filter(|pt| keep.contains(*pt)).collect();
                out.push_str(&format!("{} {}\r\n", head.join(" "), fmts.join(" ")));
                continue;
            }
        }
        if in_video {
            let pt = ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
                .iter()
                .find_map(|attr| pt_of(line, attr));
            if pt.is_some_and(|pt| !keep.contains(&pt)) {
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// The payload types an SDP maps to H.264.
fn h264_pts(sdp: &str) -> std::collections::HashSet<u8> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=rtpmap:"))
        .filter_map(|rest| rest.split_once(' '))
        .filter(|(_, enc)| enc.starts_with("H264/"))
        .filter_map(|(pt, _)| pt.parse().ok())
        .collect()
}

/// The fault Chrome showed: relay WHEP video arrived, decoded never, and the
/// browser asked for a keyframe (PLI) forever.
///
/// The viewer joins a stream whose sender carried its SPS / PPS on the first
/// IDR only, after a later IDR. Every frame it receives must be one whole
/// access unit — at its own RTP timestamp, exactly the bytes a decoder needs,
/// with every IDR (the cached one it is primed with, and every live one)
/// behind the SPS and PPS. Before the fix the relay RTP-packetized each NAL
/// itself and wrote every packet to str0m as a frame, which str0m packetized
/// again: the viewer reassembled type-28 "NAL units" from the IDR, each
/// fragment its own frame, and no SPS or PPS ahead of an IDR that had none.
#[tokio::test]
async fn whep_viewer_receives_whole_h264_access_units_it_can_start_decoding_on() {
    use bilbycast_relay::distribution::webrtc::session::{
        SessionConfig, SessionEvent, WebrtcSession,
    };
    use bilbycast_relay::distribution::whep;

    let hub = Arc::new(DistributionHub::new());
    let cancel = CancellationToken::new();
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // What the sender sends: its parameter sets on frame 0 only.
    let sent = |k: u64| -> (Bytes, bool) {
        let idr = k.is_multiple_of(GOP);
        let au = match k {
            0 => annex_b(&[TEST_SPS, TEST_PPS, &test_idr_slice()]),
            _ if idr => annex_b(&[&test_idr_slice()]),
            _ => decodable_frame(k),
        };
        (au.into(), idr)
    };
    // The history the viewer missed, up to an IDR without parameter sets —
    // the keyframe it is primed with.
    for k in 0..=GOP {
        let (au, idr) = sent(k);
        hub.publish("mid-join", EsFrame::video(k * FRAME_90K, au, idr));
    }

    let client_cfg = SessionConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), public_ip: Some(lo), ice_lite: false };
    let mut client = WebrtcSession::new(&client_cfg).await.unwrap();
    let (offer_sdp, pending) = client.create_offer(true, false, false).unwrap();
    let offer_sdp = h264_only(&offer_sdp);
    let (whep_events, _whep_rx) = bilbycast_relay::manager::events::event_channel();
    let handle = whep::create_and_spawn_viewer(
        hub.clone(),
        "mid-join".to_string(),
        &offer_sdp,
        Some(lo),
        cancel.clone(),
        whep_events,
    )
    .await
    .expect("WHEP setup");
    let h264 = h264_pts(&handle.answer_sdp);
    assert!(!h264.is_empty(), "the answer must carry H.264:\n{}", handle.answer_sdp);
    client.apply_answer(&handle.answer_sdp, pending).unwrap();

    // The live stream, on from where the history stopped.
    let pub_hub = hub.clone();
    let pub_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut k = GOP;
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            tokio::select! {
                _ = pub_cancel.cancelled() => break,
                _ = tick.tick() => {
                    k += 1;
                    let (au, idr) = sent(k);
                    pub_hub.publish("mid-join", EsFrame::video(k * FRAME_90K, au, idr));
                }
            }
        }
    });

    // Every frame the viewer reassembles: (RTP timestamp, bytes).
    let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
    let client_cancel = CancellationToken::new();
    let done = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.poll_event(&client_cancel).await {
                SessionEvent::MediaData { pt, data, rtp_time, .. } => {
                    assert!(
                        h264.contains(&*pt),
                        "media on PT {pt}, not one of the H.264 PTs {h264:?}"
                    );
                    frames.push((rtp_time.numer(), data.to_vec()));
                    let idrs = frames
                        .iter()
                        .filter(|(t, _)| (t / FRAME_90K).is_multiple_of(GOP))
                        .map(|(t, _)| *t)
                        .collect::<std::collections::HashSet<_>>()
                        .len();
                    if idrs >= 2 && frames.len() > 2 * GOP as usize {
                        return true;
                    }
                }
                SessionEvent::Disconnected => return false,
                _ => {}
            }
        }
    })
    .await;
    cancel.cancel();
    assert!(
        matches!(done, Ok(true)),
        "viewer must receive two IDRs' worth of frames, got {done:?} after {} frames",
        frames.len()
    );

    for (i, (t, data)) in frames.iter().enumerate() {
        assert_eq!(t % FRAME_90K, 0, "frame {i}: RTP timestamp {t} is not a frame's");
        let k = t / FRAME_90K;
        assert!(k >= GOP, "frame {i}: k={k} predates the viewer's join");
        let expected = decodable_frame(k);
        assert!(
            data == &expected,
            "frame {i} (k={k}, {}): {} bytes, NAL types {:?}; expected {} bytes, NAL types {:?}",
            if k.is_multiple_of(GOP) { "IDR" } else { "P" },
            data.len(),
            nal_types(data),
            expected.len(),
            nal_types(&expected),
        );
    }
    assert!(
        frames.windows(2).all(|w| w[0].0 < w[1].0),
        "one frame per access unit, timestamps rising: {:?}",
        frames.iter().map(|(t, _)| t).collect::<Vec<_>>()
    );
}

/// NAL types of an Annex-B buffer, for assertion messages.
fn nal_types(au: &[u8]) -> Vec<u8> {
    bilbycast_relay::distribution::es::split_annex_b_nalus(au)
        .iter()
        .map(|n| n[0] & 0x1f)
        .collect()
}

/// `es::MAX_PARAM_SETS_ON_THE_WIRE` is str0m's real limit: an IDR whose SPS
/// and PPS add up to it reaches the viewer behind both, and one a byte over
/// it reaches the viewer bare — str0m's packetizer drops the STAP-A. The hub
/// does not insert parameter sets past that budget, because they would never
/// arrive; this pins the budget against the packetizer rather than against
/// a reading of its source.
#[tokio::test]
async fn parameter_sets_past_the_stap_a_budget_never_reach_a_viewer() {
    use bilbycast_relay::distribution::es::{MAX_PARAM_SET_BYTES, MAX_PARAM_SETS_ON_THE_WIRE};
    use bilbycast_relay::distribution::webrtc::session::{
        SessionConfig, SessionEvent, WebrtcSession,
    };
    use bilbycast_relay::distribution::whep;

    let hub = Arc::new(DistributionHub::new());
    let cancel = CancellationToken::new();
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // Even frames: SPS + PPS exactly at the budget. Odd: one byte over. Each
    // carries its own, so the hub inserts nothing and str0m gets them as sent.
    let frame = |k: u64| -> Vec<u8> {
        let pps_len = MAX_PARAM_SETS_ON_THE_WIRE - MAX_PARAM_SET_BYTES + (k % 2) as usize;
        annex_b(&[
            &nal_body(0x67, MAX_PARAM_SET_BYTES - 1, k),
            &nal_body(0x68, pps_len - 1, k),
            &test_idr_slice(),
        ])
    };
    let client_cfg = SessionConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        public_ip: Some(lo),
        ice_lite: false,
    };
    let mut client = WebrtcSession::new(&client_cfg).await.unwrap();
    let (offer_sdp, pending) = client.create_offer(true, false, false).unwrap();
    let (whep_events, _whep_rx) = bilbycast_relay::manager::events::event_channel();
    let handle = whep::create_and_spawn_viewer(
        hub.clone(),
        "budget".to_string(),
        &h264_only(&offer_sdp),
        Some(lo),
        cancel.clone(),
        whep_events,
    )
    .await
    .expect("WHEP setup");
    client.apply_answer(&handle.answer_sdp, pending).unwrap();

    let pub_hub = hub.clone();
    let pub_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut k = 0;
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            tokio::select! {
                _ = pub_cancel.cancelled() => break,
                _ = tick.tick() => {
                    pub_hub.publish("budget", EsFrame::video(k * FRAME_90K, frame(k).into(), true));
                    k += 1;
                }
            }
        }
    });

    let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
    let client_cancel = CancellationToken::new();
    let done = tokio::time::timeout(Duration::from_secs(20), async {
        while frames.len() < 6 {
            match client.poll_event(&client_cancel).await {
                SessionEvent::MediaData { data, rtp_time, .. } => {
                    frames.push((rtp_time.numer() / FRAME_90K, data.to_vec()));
                }
                SessionEvent::Disconnected => return false,
                _ => {}
            }
        }
        true
    })
    .await;
    cancel.cancel();
    assert!(
        matches!(done, Ok(true)),
        "got {} frames: {done:?}",
        frames.len()
    );

    for (k, data) in &frames {
        if k % 2 == 0 {
            assert_eq!(
                data,
                &frame(*k),
                "frame {k}: SPS + PPS at the budget arrive"
            );
        } else {
            assert_eq!(
                nal_types(data),
                vec![5],
                "frame {k}: SPS + PPS a byte past the budget are dropped by str0m"
            );
        }
    }
    assert!(frames.iter().any(|(k, _)| k % 2 == 0) && frames.iter().any(|(k, _)| k % 2 == 1));
}

/// WHIP ingest over str0m's H.264 packetizer: str0m hands the relay one whole
/// Annex-B frame per `MediaData`, and the access unit must reach the hub as
/// it came — no doubled start code — with every IDR flagged a keyframe. The
/// keyframe test used to read the frame's first byte, a start code's zero,
/// so no WHIP-ingested frame was ever flagged.
#[tokio::test]
async fn whip_ingest_publishes_whole_h264_access_units_and_flags_every_idr() {
    use bilbycast_relay::distribution::es::au_is_idr;
    use bilbycast_relay::distribution::webrtc::session::{
        SessionConfig, SessionEvent, WebrtcSession,
    };
    use bilbycast_relay::distribution::{whep, whip_ingest};

    let hub = Arc::new(DistributionHub::new());
    let cancel = CancellationToken::new();
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mut sub = hub.subscribe("whip-h264");

    let whip_cfg = SessionConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), public_ip: Some(lo), ice_lite: false };
    let mut whip = WebrtcSession::new(&whip_cfg).await.unwrap();
    let (offer, pending) = whip.create_offer(true, false, true).unwrap();
    let offer = h264_only(&offer);
    let handle = whip_ingest::create_and_spawn_ingest(
        hub.clone(),
        "whip-h264".to_string(),
        &offer,
        Some(lo),
        cancel.clone(),
    )
    .await
    .expect("WHIP ingest setup");
    assert!(!h264_pts(&handle.answer_sdp).is_empty(), "the answer must carry H.264");
    whip.apply_answer(&handle.answer_sdp, pending).unwrap();

    // The publisher: a libwebrtc-like sender, parameter sets on every IDR.
    let whip_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            match whip.poll_event(&whip_cancel).await {
                SessionEvent::Connected => break,
                SessionEvent::Disconnected => return,
                _ => {}
            }
        }
        whip.drain_pending_events();
        let mut k = 0;
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            tokio::select! {
                _ = whip_cancel.cancelled() => break,
                _ = tick.tick() => {
                    whep::write_video_au(&mut whip, k * FRAME_90K, &decodable_frame(k)).await;
                    let _ = whip.drive_udp_io().await;
                    k += 1;
                }
            }
        }
    });

    let mut frames = Vec::new();
    let done = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match sub.rx.recv().await {
                Ok(f) => {
                    frames.push(f);
                    if frames.iter().filter(|f| au_is_idr(&f.data)).count() >= 2 {
                        return true;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return false,
            }
        }
    })
    .await;
    cancel.cancel();
    assert!(
        matches!(done, Ok(true)),
        "two IDR access units must reach the hub, got {done:?} after {} frames; NAL types of the first: {:?}",
        frames.len(),
        frames.iter().take(12).map(|f| nal_types(&f.data)).collect::<Vec<_>>()
    );

    for f in &frames {
        assert_eq!(f.pts_90k % FRAME_90K, 0, "PTS {} is not a frame's", f.pts_90k);
        let k = f.pts_90k / FRAME_90K;
        let expected = decodable_frame(k);
        assert!(
            f.data[..] == expected[..],
            "k={k}: {} bytes, NAL types {:?}; expected {} bytes, NAL types {:?}",
            f.data.len(),
            nal_types(&f.data),
            expected.len(),
            nal_types(&expected),
        );
        assert_eq!(f.keyframe, k.is_multiple_of(GOP), "k={k}: keyframe flag");
    }
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
/// three things most likely to break here. The first is route ordering:
/// `/origin/{stream}/clips` and `/origin/{stream}/{file}` both match that
/// path, and if the object route wins, asking for the clip list serves a 404
/// for a segment named "clips" — with the store perfectly correct underneath.
/// The second is that the clips live on their own routers with their own body
/// limits, merged into the object router; a merge that drops them leaves every
/// helper green and every endpoint gone.
///
/// The third is the gate. Every clip verb needs a credential, and none of them
/// rides `require_origin_token` — the *read* flag, which ships off so a CDN can
/// pull a public feed. Hanging the origin's only destructive verb off that
/// switch meant a default-configured relay answered an anonymous
/// `DELETE .../clips/<name>.mp4` with 204, and an anonymous `POST .../clips`
/// with 202 — commissioning decode work on somebody's edge. This test drives
/// the whole lifecycle with credentials AND asserts the refusals, because an
/// earlier version of it pinned the unauthenticated 204 as correct.
#[tokio::test]
async fn the_clip_lifecycle_works_over_http() {
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
    // Both gates OFF, and the origin read gate at its shipped default — the
    // configuration in which the clip surface used to be wide open.
    let cfg = DistributionConfig {
        require_viewer_token: false,
        require_ingest_token: false,
        ..Default::default()
    };
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

    control.apply(DistUpdate {
        token_secret: Some(SECRET.into()),
        ..Default::default()
    });
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let viewer = token::mint_viewer_token(SECRET, "feed", exp).unwrap();
    let ingest = token::mint_ingest_token(SECRET, "feed", exp).unwrap();

    /// Returns (status, body). Written by hand rather than with a client crate
    /// so the test depends on nothing the relay does not already carry.
    async fn req(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: &str,
        bearer: Option<&str>,
    ) -> (u16, String) {
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        if let Some(t) = bearer {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
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
    const CLIP: &str = "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4";

    // 0. With no credential, nothing on the clip surface answers — whatever
    //    `require_origin_token` says. This is the whole point of the gate:
    //    POST commissions work on an edge and DELETE destroys an operator's
    //    footage, and neither may ride a read flag that ships off.
    for (method, path, payload) in [
        ("POST", "/origin/feed/clips", Some(ASK.as_bytes())),
        ("GET", "/origin/feed/clips", None),
        ("GET", CLIP, None),
        ("DELETE", CLIP, None),
        ("PUT", CLIP, Some(b"x".as_slice())),
    ] {
        let (st, _) = req(addr, method, path, payload, "application/json", None).await;
        assert_eq!(st, 401, "{method} {path} was answered without a credential");
    }

    // 0b. A feed the relay holds nothing for — dropped by the manager, under a
    //     token that outlived it — is refused with a sentence the player shows.
    //     Not `404`: the player reads that as a relay without clip export.
    let (st, body) = req(
        addr,
        "POST",
        "/origin/feed/clips",
        Some(ASK.as_bytes()),
        "application/json",
        Some(&viewer),
    )
    .await;
    assert_eq!(
        st, 410,
        "a clip was asked for on a feed the relay does not hold: {body}"
    );
    assert!(
        body.contains("no longer holds this feed"),
        "the refusal does not say why: {body}"
    );

    // The feed is ingested, which gives it the directory clips are filed in.
    let (st, body) = req(
        addr,
        "PUT",
        "/origin/feed/seg-00001.m4s",
        Some(b"x"),
        "video/iso.segment",
        Some(&ingest),
    )
    .await;
    assert_eq!(
        st, 201,
        "the segment PUT that gives the feed its directory failed: {body}"
    );

    // 1. Requesting a clip is accepted, and this is the route-ordering check:
    //    a POST that fell through to the object route could not answer 202.
    let (st, _) = req(addr, "POST", "/origin/feed/clips", Some(ASK.as_bytes()), "application/json", Some(&viewer)).await;
    assert_eq!(st, 202, "POST /origin/feed/clips was not routed to the clip handler");

    // 2. It lists, unfinished. A `clips` swallowed by `{file}` would 404 here.
    let (st, body) = req(addr, "GET", "/origin/feed/clips", None, "", Some(&viewer)).await;
    assert_eq!(st, 200, "GET /origin/feed/clips did not reach the list handler: {body}");
    assert!(body.contains("10-00-00-00 - Goal"), "the requested clip is not listed: {body}");
    assert!(body.contains("\"ready\":false"), "a clip nothing has cut yet reads as ready: {body}");

    // 3. The edge uploads the cut. Percent-encoded, as a browser would send it.
    //    A viewer token is not enough — writing here is the edge's job.
    let (st, _) = req(addr, "PUT", CLIP, Some(b"ftypisomMOOVDATA"), "video/mp4", Some(&viewer)).await;
    assert_eq!(st, 401, "a viewer token was allowed to write a clip");
    let (st, _) = req(addr, "PUT", CLIP, Some(b"ftypisomMOOVDATA"), "video/mp4", Some(&ingest)).await;
    assert_eq!(st, 201, "the edge could not upload a finished clip");

    // 4. Now it is ready, and carries its size.
    let (_, body) = req(addr, "GET", "/origin/feed/clips", None, "", Some(&viewer)).await;
    assert!(body.contains("\"ready\":true"), "an uploaded clip still reads as pending: {body}");
    assert!(body.contains("\"bytes\":16"), "the clip's size was not recorded: {body}");

    // 5. And downloads byte for byte.
    let (st, body) = req(addr, "GET", CLIP, None, "", Some(&viewer)).await;
    assert_eq!(st, 200, "a finished clip would not download");
    assert_eq!(body, "ftypisomMOOVDATA", "the download is not what was uploaded");

    // 5b. An interrupted download resumes instead of starting again: a clip is
    //     up to 256 MiB over whatever link the viewer has.
    let (st, body) = req(addr, "GET", CLIP, None, "", Some(&viewer)).await;
    assert_eq!(st, 200);
    assert_eq!(body, "ftypisomMOOVDATA");
    let ranged = {
        let head = format!(
            "GET {CLIP} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {viewer}\r\n\
             Range: bytes=4-7\r\nConnection: close\r\n\r\n"
        );
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(head.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    assert!(ranged.starts_with("HTTP/1.1 206"), "a Range request was not honoured: {ranged}");
    assert!(ranged.contains("content-range: bytes 4-7/16"), "no Content-Range: {ranged}");
    assert!(ranged.ends_with("isom"), "the wrong bytes came back: {ranged}");

    // 6. Deleting it reclaims the space, and it stops being served.
    let (st, _) = req(addr, "DELETE", CLIP, None, "", Some(&viewer)).await;
    assert_eq!(st, 204, "a clip could not be deleted");
    let (st, _) = req(addr, "GET", CLIP, None, "", Some(&viewer)).await;
    assert_eq!(st, 404, "a deleted clip is still being served");

    // 6b. And the upload that was already in flight when it was deleted is
    //     refused rather than stored: a `.mp4` with no record beside it is in
    //     no listing, in neither ceiling, and reachable by no delete button.
    let (st, _) = req(addr, "PUT", CLIP, Some(b"orphan"), "video/mp4", Some(&ingest)).await;
    assert_eq!(st, 404, "a clip upload nothing asked for was stored anyway");

    // 7. A clip the edge gives up on says so, rather than pending for ever.
    let (st, _) = req(addr, "POST", "/origin/feed/clips", Some(ASK.as_bytes()), "application/json", Some(&viewer)).await;
    assert_eq!(st, 202);
    let (st, _) = req(
        addr,
        "POST",
        "/origin/feed/clips/10-00-00-00%20-%20Goal.mp4/failed",
        Some(br#"{"reason":"that moment is no longer in the window"}"#),
        "application/json",
        Some(&ingest),
    )
    .await;
    assert_eq!(st, 200, "the edge could not report a clip it cannot cut");
    let (_, body) = req(addr, "GET", "/origin/feed/clips", None, "", Some(&viewer)).await;
    assert!(body.contains("\"failed\":true"), "a given-up clip does not read as failed: {body}");
    assert!(
        body.contains("no longer in the window"),
        "the reason the operator needs is not in the listing: {body}"
    );

    // 8. The one-minute ceiling is enforced at the door, with a sentence that
    //    names the limit — the player shows this text verbatim.
    let too_long = r#"{"pre_secs":40,"post_secs":40,"clips":[
        {"at":"2026-09-07T10:00:00Z","name":"long"}]}"#;
    let (st, body) = req(addr, "POST", "/origin/feed/clips", Some(too_long.as_bytes()), "application/json", Some(&viewer)).await;
    assert_eq!(st, 400, "an 80-second clip was accepted");
    assert!(body.contains("60 seconds"), "the refusal does not name the limit: {body}");
}

/// The 256 MiB ceiling belongs to the media PUT, not to the JSON routes.
///
/// `clips_request` and `clip_failed` take `axum::Json`, which collects the
/// whole body into heap before a single line of the handler runs — so a body
/// limit raised for a clip upload became the amount of memory an
/// unauthenticated caller could make the relay buffer per connection, on the
/// public listener, before the credential check it would then fail.
#[tokio::test]
async fn the_clip_json_routes_do_not_inherit_the_media_body_limit() {
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use bilbycast_relay::distribution::hub::DistributionHub as Hub;
    use bilbycast_relay::distribution::origin::OriginStore;
    use bilbycast_relay::distribution::{build_router, DistributionState};

    let cancel = CancellationToken::new();
    let hub = Arc::new(Hub::new());
    let (events, _rx) = event_channel();
    let cfg = DistributionConfig::default();
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

    // Comfortably over the JSON ceiling and a fraction of the media one.
    let big = vec![b'a'; 512 * 1024];
    let body = format!(
        "{{\"pre_secs\":1,\"post_secs\":1,\"clips\":[{{\"at\":\"2026-09-07T10:00:00Z\",\"name\":\"{}\"}}]}}",
        String::from_utf8_lossy(&big)
    );
    let head = format!(
        "POST /origin/feed/clips HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    let _ = s.write_all(body.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        text.starts_with("HTTP/1.1 413"),
        "a half-megabyte of JSON was buffered on an unauthenticated route: {}",
        text.lines().next().unwrap_or("")
    );
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

/// Shared marks, over HTTP: one viewer's mark is another viewer's list.
///
/// Three things only a real listener can show. The routes are reached at all —
/// `marks` is a static segment beside the `{file}` capture every segment GET
/// goes through, and a request that fell through to the object route would
/// come back with nothing in the log: 400 to a GET (the object route's name
/// check wants a `.`, and `marks` has none — which is also exactly what a
/// relay predating the list answers, and what the player takes as "no shared
/// marks here"), 405 to a POST (that route has only PUT and GET), and 404 to a
/// PATCH or DELETE of `marks/{id}` (no route has three segments there). The
/// gate holds on a relay whose read gate is at its shipped default (off):
/// marks are a shared write surface, so they must not ride the flag a CDN pull
/// needs open. And a poll with the current validator costs a 304, which is
/// what makes polling affordable.
#[tokio::test]
async fn shared_marks_work_over_http_and_need_a_viewer_token() {
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

    /// (status, head, body).
    async fn req(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<&str>,
        bearer: Option<&str>,
        if_none_match: Option<&str>,
    ) -> (u16, String, String) {
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        if let Some(t) = bearer {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        if let Some(e) = if_none_match {
            head.push_str(&format!("If-None-Match: {e}\r\n"));
        }
        if let Some(b) = body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        head.push_str("\r\n");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(head.as_bytes()).await.unwrap();
        if let Some(b) = body {
            s.write_all(b.as_bytes()).await.unwrap();
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
        let mut parts = text.splitn(2, "\r\n\r\n");
        let head = parts.next().unwrap_or("").to_string();
        let body = parts.next().unwrap_or("").to_string();
        (status, head, body)
    }
    fn etag_of(head: &str) -> String {
        head.lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("etag").then(|| v.trim().to_string())
            })
            .expect("no ETag on a marks reply")
    }

    const MARK: &str = r##"{"at":1790000000000,"name":"Goal","colour":"#ff4d4f"}"##;

    // 0. No token secret: the surface is closed, not open.
    let (st, _, _) = req(addr, "GET", "/origin/feed/marks", None, None, None).await;
    assert_eq!(st, 500, "a relay that cannot check a credential served the shared marks");

    control.apply(DistUpdate {
        token_secret: Some(SECRET.into()),
        ..Default::default()
    });
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let viewer = token::mint_viewer_token(SECRET, "feed", exp).unwrap();
    let other = token::mint_viewer_token(SECRET, "elsewhere", exp).unwrap();
    let ingest = token::mint_ingest_token(SECRET, "feed", exp).unwrap();

    // The feed is being ingested: marks are written only into a stream the
    // relay holds a directory for.
    let (st, _, body) = req(
        addr,
        "PUT",
        "/origin/feed/seg-00001.m4s",
        Some("x"),
        Some(&ingest),
        None,
    )
    .await;
    assert_eq!(
        st, 201,
        "the segment PUT that gives the feed its directory failed: {body}"
    );

    // 1. No credential, another stream's, or the edge's: refused, every verb.
    for (method, path, payload) in [
        ("GET", "/origin/feed/marks", None),
        ("POST", "/origin/feed/marks", Some(MARK)),
        ("PATCH", "/origin/feed/marks/abc", Some(r#"{"name":"x"}"#)),
        ("DELETE", "/origin/feed/marks/abc", None),
    ] {
        let (st, _, _) = req(addr, method, path, payload, None, None).await;
        assert_eq!(st, 401, "{method} {path} was answered without a credential");
        let (st, _, _) = req(addr, method, path, payload, Some(&other), None).await;
        assert_eq!(st, 403, "{method} {path} took another stream's token");
        let (st, _, _) = req(addr, method, path, payload, Some(&ingest), None).await;
        assert_eq!(st, 403, "{method} {path} took the edge's ingest token");
    }

    // 2. A viewer marks. 201 is only reachable through the marks handler.
    let (st, _, body) = req(addr, "POST", "/origin/feed/marks", Some(MARK), Some(&viewer), None).await;
    assert_eq!(st, 201, "POST /origin/feed/marks was not routed to the marks handler: {body}");
    let id = body
        .split("\"id\":\"")
        .nth(2) // the first is inside `marks`, the second is the reply's own
        .and_then(|s| s.split('"').next())
        .expect("no id in the reply")
        .to_string();

    // 3. Another viewer of the same feed reads it, and a repeat poll is a 304.
    let (st, head, body) = req(addr, "GET", "/origin/feed/marks", None, Some(&viewer), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"name\":\"Goal\""), "the mark is not in the list: {body}");
    assert!(head.to_ascii_lowercase().contains("cache-control: no-store"), "{head}");
    let etag = etag_of(&head);
    let (st, _, _) = req(addr, "GET", "/origin/feed/marks", None, Some(&viewer), Some(&etag)).await;
    assert_eq!(st, 304, "an unchanged list was sent again in full");

    // 4. An edit changes the validator, so the next poll sees it.
    let (st, _, body) = req(
        addr,
        "PATCH",
        &format!("/origin/feed/marks/{id}"),
        Some(r#"{"name":"Penalty"}"#),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let (st, _, body) = req(addr, "GET", "/origin/feed/marks", None, Some(&viewer), Some(&etag)).await;
    assert_eq!(st, 200, "a changed list answered 304");
    assert!(body.contains("\"name\":\"Penalty\""), "{body}");

    // 5. A refusal names what is wrong, for the player to show.
    let (st, _, body) = req(
        addr,
        "POST",
        "/origin/feed/marks",
        Some(r#"{"at":1790000000}"#),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(st, 400, "a mark in seconds rather than milliseconds was stored");
    assert!(body.contains("milliseconds"), "{body}");

    // 6. Delete, and it is gone for everyone.
    let (st, _, _) = req(addr, "DELETE", &format!("/origin/feed/marks/{id}"), None, Some(&viewer), None).await;
    assert_eq!(st, 200);
    let (_, _, body) = req(addr, "GET", "/origin/feed/marks", None, Some(&viewer), None).await;
    assert!(body.contains("\"marks\":[]"), "a deleted mark is still listed: {body}");

    // 7. A feed the relay holds nothing for — not ingested yet, or dropped by
    // the manager — reads as an empty list and refuses a mark with 404, which
    // the player keeps pending and retries. Its directory is not created.
    let (st, _, body) = req(
        addr,
        "GET",
        "/origin/elsewhere/marks",
        None,
        Some(&other),
        None,
    )
    .await;
    assert_eq!(
        st, 200,
        "a feed with no directory did not read as an empty list: {body}"
    );
    assert!(body.contains("\"marks\":[]"), "{body}");
    let (st, _, _) = req(
        addr,
        "POST",
        "/origin/elsewhere/marks",
        Some(MARK),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(
        st, 404,
        "a mark was written for a feed the relay holds nothing for"
    );
    let (st, _, body) = req(
        addr,
        "GET",
        "/origin/elsewhere/marks",
        None,
        Some(&other),
        None,
    )
    .await;
    assert_eq!(st, 200);
    assert!(
        body.contains("\"marks\":[]"),
        "a refused mark was stored after all: {body}"
    );

    // 8. The segment route beside it is untouched: what was PUT comes back.
    let (st, _, body) = req(addr, "GET", "/origin/feed/seg-00001.m4s", None, None, None).await;
    assert_eq!(
        st, 200,
        "the object route was disturbed by the marks routes"
    );
    assert_eq!(body, "x");
}

// ── Codec negotiation against real peers' SDP ──────────────────────────────
//
// Every WebRTC test above negotiates a `WebrtcSession` against another
// `WebrtcSession`. Both ends register the same codec set, so each offered PT
// matches exactly one local entry by construction — and the suite stayed green
// while every Chrome WHEP viewer panicked str0m ("Pt locked multiple times:
// 102") and the WHEP send loop labelled H.264 as VP8. These drive the session
// with SDP that real peers produce.

/// HeadlessChrome 124.0.6367.78's WHEP offer (`recvonly` video + audio,
/// default codec preferences), as POSTed to the relay in the 2026-10-07 str0m
/// 0.24.1 interop run and logged by `accept_offer`. That log line is taken
/// after `normalise_sdp_offer_for_str0m`, which leaves this offer unchanged:
/// its `s=` is already `-` and both BUNDLE mids exist.
const CHROME_WHEP_OFFER: &str = include_str!("fixtures/webrtc/chrome124-whep-recvonly-offer.sdp");

/// A HeadlessChrome 124 WHEP offer narrowed by `setCodecPreferences` to its
/// packetization-mode=0 H.264 entries (PTs 104, 108, 39, 43), from the same
/// interop run — bilbycast-edge's `testdata/chrome124-whep-recvonly-pm0.sdp`,
/// byte for byte.
const CHROME_WHEP_MODE_0_OFFER: &str =
    include_str!("fixtures/webrtc/chrome124-whep-recvonly-pm0.sdp");

/// A Chrome publisher's offer (`sendonly` audio + video, plus the data channel
/// that page also opened), captured 2022-08-18 and shipped by str0m 0.24.1 as
/// `docs/chrome-sdp.json`: the shape a browser WHIP client POSTs to
/// `/whip/{stream}`.
const CHROME_SENDONLY_OFFER: &str = include_str!("fixtures/webrtc/chrome-sendonly-offer.sdp");

/// ffmpeg 8.1's WHIP offer for a libx264 High@4.0 + Opus source, rendered from
/// the format string in `generate_sdp_offer` (`libavformat/whip.c`, n8.1): a
/// real session name, `setup:passive`, Opus on 111 and one H.264 PT (106) with
/// its RTX (105). Not a capture — ffmpeg is not installed here — but every
/// line is that function's.
const FFMPEG_WHIP_OFFER: &str = include_str!("fixtures/webrtc/ffmpeg81-whip-offer.sdp");

/// The codec facts the negotiation tests need from one `m=` section.
#[derive(Debug, Default)]
struct MSection {
    pts: Vec<u8>,
    /// PT -> encoding name as written (`H264`, `rtx`, `opus`, `VP8`, ...).
    codec: std::collections::HashMap<u8, String>,
    /// PT -> the `a=fmtp` value.
    fmtp: std::collections::HashMap<u8, String>,
    direction: Option<String>,
    mid: Option<String>,
}

/// The first `m=<kind>` section of `sdp`.
fn m_section(sdp: &str, kind: &str) -> Option<MSection> {
    let mut found: Option<MSection> = None;
    for line in sdp.lines().map(str::trim_end) {
        if let Some(rest) = line.strip_prefix("m=") {
            if found.is_some() {
                break;
            }
            if rest.split(' ').next() == Some(kind) {
                found = Some(MSection {
                    pts: rest
                        .split(' ')
                        .skip(3)
                        .filter_map(|p| p.parse().ok())
                        .collect(),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(m) = found.as_mut() else { continue };
        let pt_and_value = |rest: &str| {
            let (pt, value) = rest.split_once(' ')?;
            Some((pt.parse::<u8>().ok()?, value.to_string()))
        };
        if let Some((pt, value)) = line.strip_prefix("a=rtpmap:").and_then(pt_and_value) {
            m.codec
                .insert(pt, value.split('/').next().unwrap_or_default().to_string());
        } else if let Some((pt, value)) = line.strip_prefix("a=fmtp:").and_then(pt_and_value) {
            m.fmtp.insert(pt, value);
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            m.mid = Some(mid.to_string());
        } else if matches!(
            line,
            "a=sendonly" | "a=recvonly" | "a=sendrecv" | "a=inactive"
        ) {
            m.direction = Some(line[2..].to_string());
        }
    }
    found
}

/// One `key=value` out of an `a=fmtp` value.
fn fmtp_param<'a>(fmtp: &'a str, key: &str) -> Option<&'a str> {
    fmtp.split(';')
        .find_map(|kv| kv.trim().strip_prefix(key)?.strip_prefix('='))
}

/// The answer carries H.264 (with its RTX) and Opus and nothing else, and only
/// on PTs the offer gave those codecs to — never a PT the offer did not list,
/// never another codec's — with the offer's packetization mode and profile.
/// The level is the one thing allowed to differ: str0m answers with its own.
fn assert_h264_and_opus_on_offered_pts(offer: &str, answer: &str) {
    for name in ["VP8", "VP9", "AV1", "H265"] {
        assert!(
            !answer.contains(&format!(" {name}/")),
            "the answer offers {name}, which the relay can neither send nor depacketize:\n{answer}"
        );
    }
    let offered = m_section(offer, "video").expect("offer has video");
    let answered = m_section(answer, "video").expect("answer has video");
    assert!(!answered.pts.is_empty(), "video was rejected:\n{answer}");
    for pt in &answered.pts {
        assert!(
            offered.pts.contains(pt),
            "answer video PT {pt} is not in the offer's m-line {:?}:\n{answer}",
            offered.pts
        );
        let codec = answered.codec.get(pt).map(String::as_str);
        assert_eq!(
            codec,
            offered.codec.get(pt).map(String::as_str),
            "PT {pt} was relabelled"
        );
        match codec {
            Some("H264") => {
                let (o, a) = (&offered.fmtp[pt], &answered.fmtp[pt]);
                assert_eq!(
                    fmtp_param(a, "packetization-mode"),
                    fmtp_param(o, "packetization-mode"),
                    "PT {pt}: packetization mode changed"
                );
                let profile = |f: &str| {
                    fmtp_param(f, "profile-level-id").map(|p| p[..4].to_ascii_lowercase())
                };
                assert_eq!(profile(a), profile(o), "PT {pt}: profile changed");
            }
            Some("rtx") => assert_eq!(
                fmtp_param(&answered.fmtp[pt], "apt"),
                fmtp_param(&offered.fmtp[pt], "apt"),
                "RTX PT {pt} repairs a different PT than offered"
            ),
            other => panic!("answer video PT {pt} carries {other:?}, not H.264 or its RTX"),
        }
    }
    let offered = m_section(offer, "audio").expect("offer has audio");
    let answered = m_section(answer, "audio").expect("answer has audio");
    assert!(!answered.pts.is_empty(), "audio was rejected:\n{answer}");
    for pt in &answered.pts {
        assert!(
            offered.pts.contains(pt),
            "answer audio PT {pt} is not in the offer"
        );
        assert_eq!(
            answered.codec.get(pt).map(String::as_str),
            Some("opus"),
            "audio PT {pt}"
        );
        assert_eq!(
            offered.codec.get(pt).map(String::as_str),
            Some("opus"),
            "audio PT {pt}"
        );
    }
}

/// A relay-side (ICE-Lite) session, exactly as WHEP and WHIP ingest build one.
async fn ice_lite_session() -> bilbycast_relay::distribution::webrtc::session::WebrtcSession {
    use bilbycast_relay::distribution::webrtc::session::{SessionConfig, WebrtcSession};
    WebrtcSession::new(&SessionConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        public_ip: Some("127.0.0.1".parse().unwrap()),
        ice_lite: true,
    })
    .await
    .expect("bind")
}

/// The `(video, audio)` PTs `s` writes on — `get_pt`, as `whep::viewer_loop`
/// calls it — for the tracks `sdp` (the offer or the answer: the mids are the
/// same) describes. `viewer_loop` learns those mids from str0m's `MediaAdded`
/// events, which str0m holds back until DTLS completes; the writer and its
/// negotiated PTs exist as soon as the SDP exchange does.
fn send_pts(
    s: &mut bilbycast_relay::distribution::webrtc::session::WebrtcSession,
    sdp: &str,
) -> (u8, u8) {
    let mid = |kind: &str| {
        let mid = m_section(sdp, kind)
            .and_then(|m| m.mid)
            .unwrap_or_else(|| panic!("no {kind} mid"));
        str0m::media::Mid::from(mid.as_str())
    };
    (
        *s.get_pt(mid("video")).expect("a video PT was negotiated"),
        *s.get_pt(mid("audio")).expect("an audio PT was negotiated"),
    )
}

/// A real Chrome WHEP offer: answered without a panic, H.264 and Opus only,
/// and the send loop writes video on one of Chrome's H.264 PTs — the
/// packetization-mode=1 one, because the packetizer emits FU-A — and audio on
/// Chrome's Opus PT.
///
/// Before the codec set was rebuilt this panicked str0m in `accept_offer`:
/// Chrome's PT 102 (Baseline, mode 1, level 3.1) matched both str0m's
/// built-in Baseline entry and the extra level-5.1 Baseline entry, and since
/// str0m 0.22 a level mismatch only lowers the match score, so both locked 102.
#[tokio::test]
async fn a_real_chrome_whep_offer_negotiates_h264_and_opus() {
    let mut s = ice_lite_session().await;
    let answer = s
        .accept_offer(CHROME_WHEP_OFFER)
        .expect("Chrome's WHEP offer must be answered");
    assert_h264_and_opus_on_offered_pts(CHROME_WHEP_OFFER, &answer);

    let (video_pt, audio_pt) = send_pts(&mut s, &answer);
    let offered = m_section(CHROME_WHEP_OFFER, "video").unwrap();
    assert_eq!(
        offered.codec.get(&video_pt).map(String::as_str),
        Some("H264"),
        "video is written on PT {video_pt}, which Chrome did not offer as H.264"
    );
    assert_eq!(
        fmtp_param(&offered.fmtp[&video_pt], "packetization-mode"),
        Some("1"),
        "video is written on a packetization-mode=0 PT, which cannot carry FU-A"
    );
    assert_eq!(
        video_pt, 102,
        "Chrome's first packetization-mode=1 H.264 PT"
    );
    assert_eq!(audio_pt, 111, "Chrome's Opus PT");
}

/// `sdp` with its video section narrowed to the payload types in `keep` — what
/// `setCodecPreferences` does to a browser's offer.
fn keep_video_pts(sdp: &str, keep: &[u8]) -> String {
    let kept = |pt: &str| pt.parse::<u8>().is_ok_and(|pt| keep.contains(&pt));
    let mut out = String::new();
    let mut in_video = false;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            in_video = line.starts_with("m=video");
            if in_video {
                let mut parts = line.split(' ');
                let head: Vec<&str> = parts.by_ref().take(3).collect();
                let fmts: Vec<&str> = parts.filter(|pt| kept(pt)).collect();
                out.push_str(&format!("{} {}\r\n", head.join(" "), fmts.join(" ")));
                continue;
            }
        }
        let pt = ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
            .iter()
            .find_map(|attr| line.strip_prefix(attr)?.split_whitespace().next());
        if in_video && pt.is_some_and(|pt| !kept(pt)) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// A viewer that accepts Baseline only in packetization mode 0 (PT 104) and
/// Constrained Baseline in mode 1 (PT 106) is sent video on 106: str0m
/// packetizes into STAP-A and FU-A, which mode 0 forbids. One that accepts
/// only mode 0 still gets video, on its mode-0 PT.
///
/// Before, `get_pt` took the first negotiated H.264 entry in codec-config
/// order, Baseline before Constrained Baseline, and wrote on 104.
/// bilbycast-edge's `send_pt` already picked 106.
#[tokio::test]
async fn video_goes_out_on_a_packetization_mode_1_pt_whenever_the_viewer_took_one() {
    let offer = keep_video_pts(CHROME_WHEP_OFFER, &[104, 105, 106, 107]);
    let mut s = ice_lite_session().await;
    let answer = s.accept_offer(&offer).expect("answered");
    assert_eq!(
        m_section(&answer, "video").unwrap().pts,
        vec![104, 105, 106, 107]
    );
    let (video_pt, audio_pt) = send_pts(&mut s, &answer);
    assert_eq!(
        (video_pt, audio_pt),
        (106, 111),
        "Constrained Baseline in mode 1, and Opus"
    );

    let mut s = ice_lite_session().await;
    let answer = s.accept_offer(CHROME_WHEP_MODE_0_OFFER).expect("answered");
    let (video_pt, _) = send_pts(&mut s, &answer);
    assert_eq!(video_pt, 104, "only mode 0 was offered: its first PT");
}

/// A real Chrome publisher's (`sendonly`) offer, as a browser WHIP client POSTs
/// it: answered with H.264 and Opus only, on Chrome's own PTs.
///
/// Before, the answer listed VP8, VP9 and AV1 (str0m's default set, which the
/// relay can neither depacketize nor republish) plus H.264 PTs Chrome never
/// offered (the level-5.1 extras, remapped onto their own numbers).
#[tokio::test]
async fn a_real_chrome_publisher_offer_is_answered_with_h264_and_opus_only() {
    let mut s = ice_lite_session().await;
    let answer = s
        .accept_offer(CHROME_SENDONLY_OFFER)
        .expect("Chrome's publisher offer must be answered");
    assert_h264_and_opus_on_offered_pts(CHROME_SENDONLY_OFFER, &answer);
    assert_eq!(
        m_section(&answer, "video").unwrap().direction.as_deref(),
        Some("recvonly")
    );
}

/// ffmpeg's WHIP muxer sends on the PTs it offered whatever the answer says,
/// so the answer must keep them: 106 (+ RTX 105) for H.264, 111 for Opus, at
/// every level ffmpeg offers.
///
/// Before, a level-5.1 (4K) offer was answered on PT 118 — the extra High entry
/// outscored the built-in one and, the relay being the controlling side for a
/// `sendonly` offer, answered with its own number — so the relay listened on
/// 118 for a stream arriving on 106.
#[tokio::test]
async fn ffmpeg_whip_offers_are_answered_on_ffmpegs_own_pts() {
    for profile_level_id in ["640028", "640033", "42e01f"] {
        let offer = FFMPEG_WHIP_OFFER.replace(
            "profile-level-id=640028",
            &format!("profile-level-id={profile_level_id}"),
        );
        let mut s = ice_lite_session().await;
        let answer = s
            .accept_offer(&offer)
            .unwrap_or_else(|e| panic!("{profile_level_id}: {e:#}"));
        assert_h264_and_opus_on_offered_pts(&offer, &answer);
        assert_eq!(
            m_section(&answer, "video").unwrap().pts,
            vec![106, 105],
            "{profile_level_id}:\n{answer}"
        );
        assert_eq!(
            m_section(&answer, "audio").unwrap().pts,
            vec![111],
            "{profile_level_id}"
        );
    }
}

/// Between two `WebrtcSession`s — a WHEP viewer of this relay and a cascade
/// pull, or the edge's WHIP output and this relay's ingest — the sender writes
/// video on an H.264 PT and audio on Opus.
///
/// Before, both ends registered str0m's whole default set, whose first entry
/// is VP8, and `get_pt` takes the first negotiated entry: video went out on
/// PT 96, labelled VP8, and the far end depacketized H.264 as VP8.
#[tokio::test]
async fn between_two_sessions_video_is_written_as_h264() {
    use bilbycast_relay::distribution::webrtc::session::{SessionConfig, WebrtcSession};

    let client = || async {
        WebrtcSession::new(&SessionConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_ip: Some("127.0.0.1".parse().unwrap()),
            ice_lite: false,
        })
        .await
        .unwrap()
    };

    // The relay sends: a `recvonly` client offer (a cascade pull) to WHEP.
    let mut puller = client().await;
    let (offer, _pending) = puller.create_offer(true, true, false).unwrap();
    let mut relay = ice_lite_session().await;
    let answer = relay.accept_offer(&offer).unwrap();
    let (video_pt, audio_pt) = send_pts(&mut relay, &answer);
    let offered = m_section(&offer, "video").unwrap();
    assert_eq!(
        offered.codec.get(&video_pt).map(String::as_str),
        Some("H264"),
        "WHEP video PT {video_pt}"
    );
    assert_eq!(audio_pt, 111);
    assert_h264_and_opus_on_offered_pts(&offer, &answer);

    // The client sends: a `sendonly` offer (a WHIP publisher) to the ingest.
    let mut publisher = client().await;
    let (offer, pending) = publisher.create_offer(true, true, true).unwrap();
    let mut ingest = ice_lite_session().await;
    let answer = ingest.accept_offer(&offer).unwrap();
    publisher.apply_answer(&answer, pending).unwrap();
    let (video_pt, audio_pt) = send_pts(&mut publisher, &answer);
    let answered = m_section(&answer, "video").unwrap();
    assert_eq!(
        answered.codec.get(&video_pt).map(String::as_str),
        Some("H264"),
        "WHIP video PT {video_pt}"
    );
    assert_eq!(audio_pt, 111);
    assert_h264_and_opus_on_offered_pts(&offer, &answer);
}

/// An answer to one of our offers that keeps a single H.264 PT, as a WHIP or
/// WHEP server that picks one codec writes it. `direction` is the answerer's.
fn single_pt_answer(
    offer: &str,
    direction: &str,
    pt: u8,
    rtx: u8,
    profile_level_id: &str,
) -> String {
    const FP: &str = "5B:7E:0A:26:41:91:C4:7F:33:D8:12:6E:A0:5C:B9:E4:08:71:2D:9F:C6:3A:55:EB:10:84:7D:F2:69:0C:A3:1E";
    let video = m_section(offer, "video")
        .expect("offer has video")
        .mid
        .expect("video mid");
    let audio = m_section(offer, "audio")
        .expect("offer has audio")
        .mid
        .expect("audio mid");
    let common = |mid: &str| {
        format!(
            "c=IN IP4 0.0.0.0\r\na=ice-ufrag:srvu\r\na=ice-pwd:serverpasswordserverpw\r\n\
             a=fingerprint:sha-256 {FP}\r\na=setup:passive\r\na=mid:{mid}\r\na={direction}\r\n\
             a=rtcp-mux\r\n"
        )
    };
    format!(
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE {video} {audio}\r\n\
         a=ice-lite\r\n\
         m=video 9 UDP/TLS/RTP/SAVPF {pt} {rtx}\r\n{}\
         a=rtpmap:{pt} H264/90000\r\n\
         a=fmtp:{pt} level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={profile_level_id}\r\n\
         a=rtpmap:{rtx} rtx/90000\r\na=fmtp:{rtx} apt={pt}\r\n\
         a=candidate:1 1 udp 2130706431 127.0.0.1 9 typ host\r\n\
         m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n{}\
         a=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\n",
        common(&video),
        common(&audio),
    )
}

/// Single-PT answers, in both client roles: a `sendonly` offer (a WHIP client —
/// what the edge's WHIP output does, and what the tests above stand in for)
/// answered `recvonly`, and a `recvonly` offer (the cascade's WHEP pull)
/// answered `sendonly`. The answerer's level differs from ours, as a real
/// server's does.
///
/// Before, the `sendonly` case panicked str0m in `accept_answer`: the answer
/// dictates the PT, and the built-in and level-5.1 entries for that profile
/// both matched it.
#[tokio::test]
async fn single_pt_answers_negotiate_in_both_client_roles() {
    use bilbycast_relay::distribution::webrtc::session::{SessionConfig, WebrtcSession};

    for (pt, rtx, profile_level_id) in [
        (127, 121, "42001f"),
        (108, 109, "42e01f"),
        (114, 115, "640028"),
    ] {
        for (send_only, answerer) in [(true, "recvonly"), (false, "sendonly")] {
            let case = format!("PT {pt} ({profile_level_id}), answer {answerer}");
            let mut s = WebrtcSession::new(&SessionConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                public_ip: Some("127.0.0.1".parse().unwrap()),
                ice_lite: false,
            })
            .await
            .unwrap();
            let (offer, pending) = s.create_offer(true, true, send_only).unwrap();
            let answer = single_pt_answer(&offer, answerer, pt, rtx, profile_level_id);
            s.apply_answer(&answer, pending)
                .unwrap_or_else(|e| panic!("{case}: {e:#}"));
            if send_only {
                assert_eq!(
                    send_pts(&mut s, &answer),
                    (pt, 111),
                    "{case}: written on the answered PTs"
                );
            }
        }
    }
}

/// An offer whose one RTX PT repairs two H.264 PTs. str0m 0.24.1 locks that RTX
/// PT once per primary and panics ("Pt locked multiple times: 103") whatever
/// codecs are registered, because both of these primaries — Baseline in
/// packetization mode 1 and in mode 0 — are in every H.264 set str0m ships.
/// So it stands for any negotiation panic still left in str0m.
fn offer_with_an_rtx_pt_repairing_two_pts(direction: &str) -> String {
    const FP: &str = "5B:7E:0A:26:41:91:C4:7F:33:D8:12:6E:A0:5C:B9:E4:08:71:2D:9F:C6:3A:55:EB:10:84:7D:F2:69:0C:A3:1E";
    format!(
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=msid-semantic: WMS\r\n\
         m=video 9 UDP/TLS/RTP/SAVPF 102 104 103\r\nc=IN IP4 0.0.0.0\r\n\
         a=ice-ufrag:hstl\r\na=ice-pwd:hostilepasswordhostile\r\na=fingerprint:sha-256 {FP}\r\n\
         a=setup:actpass\r\na=mid:0\r\na={direction}\r\na=rtcp-mux\r\n\
         a=rtpmap:102 H264/90000\r\n\
         a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n\
         a=rtpmap:104 H264/90000\r\n\
         a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n\
         a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\na=fmtp:103 apt=104\r\n"
    )
}

/// A panic inside str0m's negotiation is an error for that one session, not a
/// crash: `accept_offer` (WHEP and WHIP ingest) and `apply_answer` (the
/// cascade pull) both return `Err`.
#[tokio::test]
async fn a_str0m_panic_during_negotiation_is_an_error() {
    use bilbycast_relay::distribution::webrtc::session::{SessionConfig, WebrtcSession};

    let mut s = ice_lite_session().await;
    let err = s
        .accept_offer(&offer_with_an_rtx_pt_repairing_two_pts("recvonly"))
        .expect_err("str0m cannot negotiate this offer");
    assert!(format!("{err:#}").contains("panicked"), "{err:#}");

    // The same SDP shape as an answer to a WHIP client's offer, on two PTs
    // that offer carries (Baseline in mode 1 and mode 0, one RTX for both).
    let mut c = WebrtcSession::new(&SessionConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        public_ip: Some("127.0.0.1".parse().unwrap()),
        ice_lite: false,
    })
    .await
    .unwrap();
    let (offer, pending) = c.create_offer(true, false, true).unwrap();
    let mid = m_section(&offer, "video").unwrap().mid.unwrap();
    let answer = offer_with_an_rtx_pt_repairing_two_pts("recvonly")
        .replace(
            "a=group:BUNDLE 0",
            &format!("a=group:BUNDLE {mid}\r\na=ice-lite"),
        )
        .replace("a=mid:0", &format!("a=mid:{mid}"))
        .replace("a=setup:actpass", "a=setup:passive")
        .replace(" 102 104 103\r\n", " 127 125 121\r\n")
        .replace(":102 ", ":127 ")
        .replace(":104 ", ":125 ")
        .replace(":103 ", ":121 ")
        .replace("apt=102", "apt=127")
        .replace("apt=104", "apt=125");
    let err = c
        .apply_answer(&answer, pending)
        .expect_err("str0m cannot accept this answer");
    assert!(format!("{err:#}").contains("panicked"), "{err:#}");
}

/// A distribution node on loopback, served as `run_distribution` serves it —
/// with connect info, so the per-IP cap sees the client's address — with
/// `max_viewers_per_ip` = `cap`, both token gates off and `127.0.0.1` as its
/// public IP. Returns the state, the address and the node's event queue.
async fn serve_distribution(
    cap: u32,
    cancel: &CancellationToken,
) -> (
    Arc<bilbycast_relay::distribution::DistributionState>,
    std::net::SocketAddr,
    tokio::sync::mpsc::Receiver<bilbycast_relay::manager::events::Event>,
) {
    use bilbycast_relay::distribution::{DistributionState, build_router};

    let (events, rx) = event_channel();
    let cfg = DistributionConfig {
        require_viewer_token: false,
        require_ingest_token: false,
        max_viewers_per_ip: cap,
        ..Default::default()
    };
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, Some(lo)), vec![]);
    let state = DistributionState::new(
        Arc::new(DistributionHub::new()),
        Arc::new(OriginStore::new(test_origin_config(8, 1 << 30)).unwrap()),
        cfg,
        control,
        cancel.clone(),
        events,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (state, addr, rx)
}

/// One HTTP/1.1 request to `addr`. `(status, Location, body)`; status 0 when
/// the connection closed without a response, which is what a panicking
/// handler leaves.
async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/sdp\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let location = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("location")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_default();
    (status, location, body.to_string())
}

/// The per-IP viewer slots `127.0.0.1` holds.
fn held(st: &bilbycast_relay::distribution::DistributionState) -> u32 {
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    st.viewers_by_ip
        .get(&lo)
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0)
}

/// The per-IP viewer cap, through the real router: offers that fail — here,
/// by panicking str0m — give their slot back, so no number of them shuts an IP
/// out, and a real viewer's slot comes back when it is deleted.
///
/// Before, the slot was released by hand in the handler's `Err` arm only. A
/// panic unwound straight past it (and dropped the connection with no
/// response), so each one leaked a slot for the life of the process; with the
/// default cap of 256, 256 Chrome WHEP attempts locked an IP out for good. The
/// WHIP ingest route had the same crash with nothing to leak.
#[tokio::test]
async fn failed_offers_never_exhaust_the_per_ip_viewer_cap() {
    const CAP: u32 = 2;
    let cancel = CancellationToken::new();
    let (state, addr, _events) = serve_distribution(CAP, &cancel).await;

    let hostile = offer_with_an_rtx_pt_repairing_two_pts("recvonly");
    for attempt in 1..=3 * CAP {
        let (status, _, body) = http(addr, "POST", "/whep/show", &hostile).await;
        assert_eq!(
            held(&state),
            0,
            "WHEP attempt {attempt} kept its per-IP slot"
        );
        assert_eq!(status, 400, "WHEP attempt {attempt}: {body}");
    }
    let (status, _, body) = http(addr, "POST", "/whip/show", &hostile).await;
    assert_eq!(status, 400, "WHIP ingest: {body}");

    // A real viewer still gets in after all that, holds one slot while it
    // lives, and gives it back when deleted.
    let (status, location, answer) = http(addr, "POST", "/whep/show", CHROME_WHEP_OFFER).await;
    assert_eq!(status, 201, "a real Chrome viewer: {answer}");
    assert_h264_and_opus_on_offered_pts(CHROME_WHEP_OFFER, &answer);
    assert_eq!(held(&state), 1, "a live viewer holds its slot");
    let (status, _, _) = http(addr, "DELETE", &location, "").await;
    assert_eq!(status, 200, "DELETE {location}");
    tokio::time::timeout(Duration::from_secs(5), async {
        while held(&state) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a deleted viewer gave its slot back");

    cancel.cancel();
}

/// A str0m session in the client role, as a browser stands in for it here:
/// it offers `recvonly` video and audio to `/whep/{stream}` and drives itself
/// until it has decoded media, which the relay sends only once its own side
/// has connected. Returns the session, still answering ICE while it is
/// polled; dropping it is a viewer that left without a DELETE.
async fn watch(
    addr: std::net::SocketAddr,
    stream: &str,
) -> bilbycast_relay::distribution::webrtc::session::WebrtcSession {
    use bilbycast_relay::distribution::webrtc::session::{
        SessionConfig, SessionEvent, WebrtcSession,
    };

    let mut client = WebrtcSession::new(&SessionConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        public_ip: Some("127.0.0.1".parse().unwrap()),
        ice_lite: false,
    })
    .await
    .unwrap();
    let (offer, pending) = client.create_offer(true, true, false).unwrap();
    let (status, _, answer) = http(addr, "POST", &format!("/whep/{stream}"), &offer).await;
    assert_eq!(status, 201, "WHEP {stream}: {answer}");
    client.apply_answer(&answer, pending).unwrap();
    let cancel = CancellationToken::new();
    let got_media = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.poll_event(&cancel).await {
                SessionEvent::MediaData { .. } => return true,
                SessionEvent::Disconnected => return false,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        matches!(got_media, Ok(true)),
        "viewer of '{stream}' must receive media, got {got_media:?}"
    );
    client
}

/// Wait up to `within` for `done` to hold, polling.
async fn eventually(within: Duration, done: impl Fn() -> bool) -> bool {
    tokio::time::timeout(within, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok()
}

/// A viewer that leaves without a DELETE — a closed tab, a lost network —
/// is reaped once ICE gives up on it, and gives its per-IP slot back: one
/// watching a live stream, and one watching a stream that has stalled (one
/// keyframe, then nothing).
///
/// Before, neither was reaped while its stream lived. str0m reports ICE
/// giving up from the timeout the send loop runs after each write, and that
/// drain threw the event away; the stalled viewer's session was not driven at
/// all once frames stopped. Both held their slot — and the live one kept
/// being sent the stream — until the relay shut down: reloads from one NAT
/// address locked it out of WHEP after `max_viewers_per_ip` of them.
#[tokio::test]
async fn a_viewer_that_leaves_without_a_delete_is_reaped_and_gives_its_slot_back() {
    let cancel = CancellationToken::new();
    let (state, addr, _events) = serve_distribution(8, &cancel).await;

    let hub = state.hub.clone();
    let pub_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(33));
        let mut k: u64 = 0;
        loop {
            tokio::select! {
                _ = pub_cancel.cancelled() => break,
                _ = tick.tick() => {
                    let pts = k * FRAME_90K;
                    hub.publish(
                        "live",
                        EsFrame::video(pts, decodable_frame(k).into(), k.is_multiple_of(GOP)),
                    );
                    hub.publish("live", EsFrame::audio(pts, Bytes::from_static(&[0xfc, 0x55])));
                    k += 1;
                }
            }
        }
    });
    // The stalled stream: one keyframe — which primes the viewer, proving its
    // session connected — and then nothing.
    state.hub.publish(
        "stalled",
        EsFrame::video(0, decodable_frame(0).into(), true),
    );

    let live = watch(addr, "live").await;
    let stalled = watch(addr, "stalled").await;
    assert_eq!(held(&state), 2, "two live viewers hold two slots");
    assert_eq!(state.sessions.len(), 2);

    drop(live);
    drop(stalled);
    let left = std::time::Instant::now();

    // `is` gives a silent peer 15 s from its last Binding Request
    // (`RECENT_BINDING_REQUEST`); measured here at about 15 s. The bound
    // leaves room for a loaded runner. Both sessions connected (each viewer
    // received media), so the setup deadline is not what ends them.
    let reaped = eventually(Duration::from_secs(40), || {
        held(&state) == 0 && state.sessions.is_empty()
    })
    .await;
    assert!(
        reaped,
        "after {:?}: {} slots held, {} sessions",
        left.elapsed(),
        held(&state),
        state.sessions.len()
    );
    for stream in ["live", "stalled"] {
        assert_eq!(
            state.hub.get(stream).unwrap().viewer_count(),
            0,
            "the '{stream}' viewer's subscription went with it"
        );
    }

    cancel.cancel();
}

/// A WHEP viewer or WHIP publisher whose offer is answered but never
/// connects — here an offer without `a=candidate` lines from a peer that
/// never sends STUN — is closed at `SETUP_DEADLINE`: its session ends, the
/// viewer's per-IP slot comes back and the ingest record goes.
///
/// Before, both waited for `Connected` for ever: an ICE-Lite agent with no
/// remote candidate stays in Checking (`is` counts "no candidates yet" as
/// still possible), so each such offer pinned a session, a UDP socket, a task
/// and — for a viewer — a per-IP slot until a DELETE that need never come.
#[tokio::test]
async fn an_offer_that_never_connects_is_closed_at_the_setup_deadline() {
    use bilbycast_relay::distribution::webrtc::SETUP_DEADLINE;
    use bilbycast_relay::distribution::webrtc::session::{SessionConfig, WebrtcSession};

    let cancel = CancellationToken::new();
    let (state, addr, _events) = serve_distribution(8, &cancel).await;

    let no_candidates = |sdp: String| -> String {
        sdp.split_inclusive('\n')
            .filter(|l| !l.starts_with("a=candidate"))
            .collect()
    };
    let client = || async {
        WebrtcSession::new(&SessionConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_ip: Some("127.0.0.1".parse().unwrap()),
            ice_lite: false,
        })
        .await
        .unwrap()
    };
    // Kept, undriven, for the whole test: neither says a word.
    let mut viewer = client().await;
    let (offer, _viewer_pending) = viewer.create_offer(true, true, false).unwrap();
    let (status, _, body) = http(addr, "POST", "/whep/quiet", &no_candidates(offer)).await;
    assert_eq!(status, 201, "WHEP: {body}");
    let mut publisher = client().await;
    let (offer, _publisher_pending) = publisher.create_offer(true, true, true).unwrap();
    let (status, _, body) = http(addr, "POST", "/whip/quiet-in", &no_candidates(offer)).await;
    assert_eq!(status, 201, "WHIP: {body}");
    let posted = std::time::Instant::now();
    assert_eq!(
        (held(&state), state.sessions.len(), state.ingests.len()),
        (1, 1, 1)
    );

    let closed = eventually(SETUP_DEADLINE + Duration::from_secs(10), || {
        held(&state) == 0 && state.sessions.is_empty() && state.ingests.is_empty()
    })
    .await;
    assert!(
        closed,
        "after {:?}: {} slots held, {} viewer sessions, {} ingests",
        posted.elapsed(),
        held(&state),
        state.sessions.len(),
        state.ingests.len()
    );
    assert!(
        posted.elapsed() >= SETUP_DEADLINE - Duration::from_secs(1),
        "closed after {:?}, before the deadline: something else ended them",
        posted.elapsed()
    );

    drop((viewer, publisher));
    cancel.cancel();
}

/// A str0m panic during negotiation on the public WHEP or WHIP endpoint
/// raises one Warning event naming the peer, the step, the panic and the
/// client's address — rate limited, so a flood of hostile offers raises one —
/// and a merely malformed offer raises none.
///
/// Before, the panic was caught and the request failed with a 400, but the
/// only trace was a `warn!` line on a headless relay; bilbycast-edge raises
/// `webrtc_negotiation_panic` for the same panic.
#[tokio::test]
async fn a_str0m_panic_in_negotiation_raises_one_rate_limited_warning() {
    use bilbycast_relay::manager::events::EventSeverity;

    let cancel = CancellationToken::new();
    let (_state, addr, mut events) = serve_distribution(8, &cancel).await;

    let (status, _, body) = http(addr, "POST", "/whep/show", "v=0\r\nnot an offer\r\n").await;
    assert_eq!(status, 400, "{body}");
    assert!(
        events.try_recv().is_err(),
        "a malformed offer raised an event"
    );

    let hostile = offer_with_an_rtx_pt_repairing_two_pts("recvonly");
    for _ in 0..3 {
        let (status, _, body) = http(addr, "POST", "/whep/show", &hostile).await;
        assert_eq!(status, 400, "{body}");
    }
    let (status, _, body) = http(addr, "POST", "/whip/show", &hostile).await;
    assert_eq!(status, 400, "{body}");

    let ev = events.try_recv().expect("one Warning event");
    assert_eq!(ev.severity, EventSeverity::Warning);
    assert_eq!(ev.category, "distribution");
    assert!(
        ev.message.starts_with(
            "WebRTC negotiation with WHEP viewer failed: str0m panicked during SDP offer"
        ),
        "{}",
        ev.message
    );
    let details = ev.details.expect("details");
    assert_eq!(details["error_code"], "webrtc_negotiation_panic");
    assert_eq!(details["peer"], "WHEP viewer");
    assert_eq!(details["stream"], "show");
    assert_eq!(details["step"], "SDP offer");
    assert!(
        details["panic"]
            .as_str()
            .unwrap()
            .contains("Pt locked multiple times"),
        "{details}"
    );
    assert_eq!(details["ip"], "127.0.0.1");
    assert_eq!(details["suppressed"], 0);
    assert!(
        events.try_recv().is_err(),
        "the other three inside the interval are held back"
    );

    cancel.cancel();
}
