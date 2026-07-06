// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Per-viewer WHEP session: SDP answer + the send loop that fans one
//! stream's elementary frames out to one browser over DTLS/SRTP.
//!
//! The relay is **not** a true encrypt-once SFU — like the edge, each viewer
//! owns an independent str0m PeerConnection with its own SRTP context. But
//! unlike the edge it does the expensive demux/transcode work **zero** times
//! (the edge already shipped browser-ready H.264+Opus), so the per-viewer
//! cost collapses to RTP-packetize + SRTP-encrypt — and, decisively, the
//! fan-out lives on the public relay instead of the NAT'd, uplink-capped edge.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use str0m::media::{Frequency, MediaTime};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;

use super::es::{split_annex_b_nalus, EsFrame, EsKind};
use super::hub::{DistributionHub, StreamSubscription};
use super::webrtc::rtp_h264::H264Packetizer;
use super::webrtc::session::{SessionConfig, SessionEvent, WebrtcSession};

/// Handle returned to the HTTP signaling layer once a viewer's SDP offer has
/// been accepted. The send loop is already running in a detached task.
pub struct ViewerHandle {
    pub session_id: String,
    pub answer_sdp: String,
    /// Cancels exactly this viewer (DELETE /whep/{session_id}).
    pub cancel: CancellationToken,
}

/// Create a WHEP viewer session from an SDP offer, answer it, and spawn the
/// per-viewer send loop. Returns the answer SDP + a session id + a cancel
/// token scoped to this one viewer.
pub async fn create_and_spawn_viewer(
    hub: Arc<DistributionHub>,
    stream_id: String,
    offer_sdp: &str,
    public_ip: Option<IpAddr>,
    parent_cancel: CancellationToken,
) -> Result<ViewerHandle> {
    // ICE-Lite server role. Bind to the public IP if pinned so the per-packet
    // destination matches the advertised host candidate; else 0.0.0.0:0.
    let bind_addr = match public_ip {
        Some(ip) => std::net::SocketAddr::new(ip, 0),
        None => "0.0.0.0:0".parse().unwrap(),
    };
    let session_config = SessionConfig { bind_addr, public_ip, ice_lite: true };

    let mut session = WebrtcSession::new(&session_config)
        .await
        .context("failed to create WebRTC session")?;

    let answer_sdp = session
        .accept_offer(offer_sdp)
        .context("failed to accept SDP offer")?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let cancel = parent_cancel.child_token();

    let subscription = hub.subscribe(&stream_id);

    let loop_cancel = cancel.clone();
    let loop_stream = stream_id.clone();
    let loop_sid = session_id.clone();
    tokio::spawn(async move {
        viewer_loop(session, subscription, loop_cancel.clone(), &loop_stream, &loop_sid).await;
        // Cancel our own token on natural exit (viewer disconnect / ingest
        // gone) so any lifecycle watcher — the per-IP reaper, the session
        // registry cleanup — fires on both explicit DELETE and natural end.
        loop_cancel.cancel();
    });

    Ok(ViewerHandle { session_id, answer_sdp, cancel })
}

/// The per-viewer send loop.
async fn viewer_loop(
    mut session: WebrtcSession,
    mut sub: StreamSubscription,
    cancel: CancellationToken,
    stream_id: &str,
    session_id: &str,
) {
    // 1. Wait for ICE + DTLS to complete.
    loop {
        match session.poll_event(&cancel).await {
            SessionEvent::Connected => {
                tracing::info!(
                    "WHEP viewer '{session_id}' connected on stream '{stream_id}'"
                );
                break;
            }
            SessionEvent::Disconnected => {
                tracing::info!(
                    "WHEP viewer '{session_id}' disconnected during setup (stream '{stream_id}')"
                );
                return;
            }
            _ => continue,
        }
    }

    // str0m may emit MediaAdded after Connected — flush so the MIDs are set.
    session.drain_pending_events();

    let Some(video_mid) = session.video_mid else {
        tracing::warn!("WHEP viewer '{session_id}': no video MID negotiated");
        return;
    };
    let Some(video_pt) = session.get_pt(video_mid) else {
        tracing::warn!("WHEP viewer '{session_id}': no video PT negotiated");
        return;
    };
    let audio = session
        .audio_mid
        .and_then(|mid| session.get_pt(mid).map(|pt| (mid, pt)));

    // 2. Prime the decoder with the cached keyframe so a late joiner starts
    //    immediately instead of waiting for the source's next IDR.
    if let Some(kf) = sub.keyframe.take() {
        write_video(&mut session, video_mid, video_pt, &kf.frame, &sub).await;
    }

    // 3. Main fan-out loop.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            recv = sub.rx.recv() => match recv {
                Ok(frame) => {
                    match frame.kind {
                        EsKind::VideoH264 => {
                            write_video(&mut session, video_mid, video_pt, &frame, &sub).await;
                        }
                        EsKind::AudioOpus => {
                            if let Some((amid, apt)) = audio {
                                write_audio(&mut session, amid, apt, &frame, &sub).await;
                            }
                        }
                    }
                    // Keep ICE/DTLS/RTCP alive between media writes.
                    if matches!(session.drive_udp_io().await, Some(SessionEvent::Disconnected)) {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    // Viewer fell behind — resync happens naturally on the
                    // next keyframe. Keep going.
                    continue;
                }
                Err(RecvError::Closed) => break, // ingest gone
            }
        }
    }

    tracing::info!("WHEP viewer '{session_id}' closed (stream '{stream_id}')");
}

/// Split a video access unit into NALUs, RFC 6184-packetize, and hand each
/// payload to str0m. Drains str0m between writes (required — consecutive
/// writes without a poll are silently rejected).
async fn write_video(
    session: &mut WebrtcSession,
    mid: str0m::media::Mid,
    pt: str0m::media::Pt,
    frame: &EsFrame,
    sub: &StreamSubscription,
) {
    let bytes = write_video_au_on(session, mid, pt, frame.pts_90k, &frame.data).await;
    sub.state.add_bytes_out(bytes as u64);
}

/// Packetize + send one H.264 access unit on a known (mid, pt). Returns the
/// number of payload bytes written.
async fn write_video_au_on(
    session: &mut WebrtcSession,
    mid: str0m::media::Mid,
    pt: str0m::media::Pt,
    pts_90k: u64,
    au: &[u8],
) -> usize {
    let media_time = MediaTime::new(pts_90k, Frequency::NINETY_KHZ);
    let nalus = split_annex_b_nalus(au);
    let n = nalus.len();
    let mut bytes = 0;
    for (i, nalu) in nalus.iter().enumerate() {
        let is_last = i == n - 1;
        for payload in H264Packetizer::packetize(nalu, is_last) {
            if let Err(e) = session.write_media(mid, pt, Instant::now(), media_time, &payload.data) {
                tracing::trace!("video write error: {e}");
            }
            session.drain_outputs().await;
            bytes += payload.data.len();
        }
    }
    bytes
}

/// Send one H.264 access unit over a session, resolving the video (mid, pt)
/// from the session's negotiated tracks. Used by a WHIP *client* (the edge,
/// or an integration test) to push media. No-op until video is negotiated.
pub async fn write_video_au(session: &mut WebrtcSession, pts_90k: u64, au: &[u8]) -> usize {
    let Some(mid) = session.video_mid else { return 0 };
    let Some(pt) = session.get_pt(mid) else { return 0 };
    write_video_au_on(session, mid, pt, pts_90k, au).await
}

/// Write one Opus frame to str0m at the 48 kHz audio clock.
async fn write_audio(
    session: &mut WebrtcSession,
    mid: str0m::media::Mid,
    pt: str0m::media::Pt,
    frame: &EsFrame,
    sub: &StreamSubscription,
) {
    // Source PTS is 90 kHz; Opus RTP runs at 48 kHz.
    let media_time = MediaTime::new(frame.pts_90k * 48_000 / 90_000, Frequency::FORTY_EIGHT_KHZ);
    if let Err(e) = session.write_media(mid, pt, Instant::now(), media_time, &frame.data) {
        tracing::trace!("WHEP audio write error: {e}");
    }
    session.drain_outputs().await;
    sub.state.add_bytes_out(frame.data.len() as u64);
}
