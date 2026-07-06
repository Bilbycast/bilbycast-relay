// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! WHIP ingest: an edge (or any WHIP client) pushes a browser-ready
//! H.264 + Opus WebRTC stream **into** the relay, which terminates DTLS/SRTP,
//! depacketizes to elementary frames, and feeds the [`DistributionHub`] for
//! WHEP fan-out.
//!
//! This is the **zero-edge-code** ingest path: bilbycast-edge already ships a
//! WHIP-client output (demux + AAC→Opus / HEVC→H.264 transcode + str0m,
//! broadcast-quality-gated). Pointing that output at the relay's WHIP ingest
//! URL is all an operator does — no new edge media path, no new quality gates.
//! (The QUIC ES ingest in [`super::ingest`] is the future lower-overhead path,
//! but WHIP-in reuses the proven edge encoder today.)
//!
//! str0m delivers **one depacketized NAL unit per `MediaData`** for H.264, so
//! this module reassembles an access unit by grouping consecutive NALs that
//! share a presentation timestamp (mirroring bilbycast-edge's WHIP-server
//! input), and publishes one [`EsFrame`] per AU. Opus frames pass straight
//! through.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use super::es::EsFrame;
use super::hub::DistributionHub;
use super::webrtc::session::{SessionConfig, SessionEvent, WebrtcSession};

/// Handle returned once a WHIP ingest offer has been accepted.
pub struct WhipIngestHandle {
    pub session_id: String,
    pub answer_sdp: String,
    pub cancel: CancellationToken,
}

/// Accept a WHIP ingest offer, answer it, and spawn the receive loop that
/// depacketizes media into the hub.
pub async fn create_and_spawn_ingest(
    hub: Arc<DistributionHub>,
    stream_id: String,
    offer_sdp: &str,
    public_ip: Option<IpAddr>,
    parent_cancel: CancellationToken,
) -> Result<WhipIngestHandle> {
    let bind_addr = match public_ip {
        Some(ip) => std::net::SocketAddr::new(ip, 0),
        None => "0.0.0.0:0".parse().unwrap(),
    };
    // WHIP ingest is the server side — ICE-Lite.
    let session_config = SessionConfig { bind_addr, public_ip, ice_lite: true };

    let mut session = WebrtcSession::new(&session_config)
        .await
        .context("failed to create WHIP ingest session")?;
    let answer_sdp = session
        .accept_offer(offer_sdp)
        .context("failed to accept WHIP offer")?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let cancel = parent_cancel.child_token();

    let loop_cancel = cancel.clone();
    let loop_stream = stream_id.clone();
    let loop_sid = session_id.clone();
    tokio::spawn(async move {
        ingest_loop(session, hub, loop_cancel.clone(), &loop_stream, &loop_sid).await;
        loop_cancel.cancel();
    });

    Ok(WhipIngestHandle { session_id, answer_sdp, cancel })
}

/// Accumulates NAL units into access units and publishes them to the hub.
struct AuAssembler {
    stream_id: String,
    cur_pts: Option<u64>,
    nalus: Vec<u8>,
    keyframe: bool,
}

impl AuAssembler {
    fn new(stream_id: String) -> Self {
        Self { stream_id, cur_pts: None, nalus: Vec::new(), keyframe: false }
    }

    /// Push one depacketized NAL. If it opens a new access unit (PTS change),
    /// flush the previous AU first.
    fn push(&mut self, hub: &DistributionHub, pts_90k: u64, nal: &[u8]) {
        if self.cur_pts.is_some() && self.cur_pts != Some(pts_90k) {
            self.flush(hub);
        }
        self.cur_pts = Some(pts_90k);
        // Annex-B: 4-byte start code + NAL payload.
        self.nalus.extend_from_slice(&[0, 0, 0, 1]);
        self.nalus.extend_from_slice(nal);
        if !nal.is_empty() && (nal[0] & 0x1f) == 5 {
            self.keyframe = true;
        }
    }

    /// Emit the accumulated access unit (if any) to the hub.
    fn flush(&mut self, hub: &DistributionHub) {
        if self.nalus.is_empty() {
            return;
        }
        let pts = self.cur_pts.unwrap_or(0);
        let au = Bytes::from(std::mem::take(&mut self.nalus));
        hub.publish(&self.stream_id, EsFrame::video(pts, au, self.keyframe));
        self.keyframe = false;
    }
}

async fn ingest_loop(
    mut session: WebrtcSession,
    hub: Arc<DistributionHub>,
    cancel: CancellationToken,
    stream_id: &str,
    session_id: &str,
) {
    // Wait for ICE + DTLS.
    loop {
        match session.poll_event(&cancel).await {
            SessionEvent::Connected => {
                tracing::info!("WHIP ingest '{session_id}' connected for stream '{stream_id}'");
                hub.register(stream_id);
                break;
            }
            SessionEvent::Disconnected => {
                tracing::info!("WHIP ingest '{session_id}' disconnected during setup");
                return;
            }
            _ => continue,
        }
    }
    session.drain_pending_events();

    let mut asm = AuAssembler::new(stream_id.to_string());

    loop {
        match session.poll_event(&cancel).await {
            SessionEvent::MediaData { mid, data, rtp_time, .. } => {
                let is_video = session.video_mid == Some(mid);
                let is_audio = session.audio_mid == Some(mid);
                if is_video {
                    // str0m video MediaTime is already the 90 kHz clock.
                    let pts_90k = rtp_time.numer() as u64;
                    asm.push(&hub, pts_90k, &data);
                } else if is_audio {
                    // Opus 48 kHz clock → 90 kHz.
                    let numer = rtp_time.numer() as u128;
                    let denom = rtp_time.denom() as u128;
                    let pts_90k = if denom == 0 {
                        0
                    } else {
                        (numer.saturating_mul(90_000) / denom) as u64
                    };
                    hub.publish(stream_id, EsFrame::audio(pts_90k, Bytes::from(data)));
                }
            }
            SessionEvent::Disconnected => break,
            _ => {}
        }
    }

    asm.flush(&hub);
    hub.remove(stream_id);
    tracing::info!("WHIP ingest '{session_id}' closed (stream '{stream_id}')");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn au_assembler_groups_by_pts_and_flags_keyframe() {
        let hub = DistributionHub::new();
        let mut sub = hub.subscribe("s");
        let mut asm = AuAssembler::new("s".to_string());

        // Frame 1 (keyframe): SPS + PPS + IDR at pts 0.
        asm.push(&hub, 0, &[0x67, 0x42]);
        asm.push(&hub, 0, &[0x68, 0xce]);
        asm.push(&hub, 0, &[0x65, 0x88]);
        // Frame 2 (P) at pts 3600 — pushing it flushes frame 1.
        asm.push(&hub, 3600, &[0x41, 0x9a]);

        let f1 = sub.rx.try_recv().unwrap();
        assert_eq!(f1.pts_90k, 0);
        assert!(f1.keyframe);
        // Frame 1 contains 3 start-code-separated NALs.
        assert_eq!(f1.data.windows(4).filter(|w| *w == [0, 0, 0, 1]).count(), 3);

        asm.flush(&hub);
        let f2 = sub.rx.try_recv().unwrap();
        assert_eq!(f2.pts_90k, 3600);
        assert!(!f2.keyframe);
    }
}
