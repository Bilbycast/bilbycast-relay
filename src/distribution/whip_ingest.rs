// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! For H.264, str0m delivers **one whole depacketized frame per `MediaData`**:
//! the RTP packets from a partition head up to the marker bit, already Annex
//! B — every NAL behind its own 4-byte start code. A sender that sets the
//! marker bit before the end of its access unit (one NAL per frame, say) still
//! arrives as several `MediaData` with one timestamp, so this module groups
//! consecutive frames that share a presentation timestamp into one access unit
//! and publishes one [`EsFrame`] per AU. A frame is used as it came: it gets a start code only
//! if it is a bare NAL, and the keyframe flag comes from its NAL types —
//! never from its first byte, which in Annex B is a start code's zero. Opus
//! frames pass straight through.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use super::es::{EsFrame, au_is_idr};
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

/// Accumulates depacketized frames into access units and publishes them to
/// the hub.
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

    /// Push one depacketized frame — Annex B, as str0m emits it, or one bare
    /// NAL. If it opens a new access unit (PTS change), flush the previous AU
    /// first. A payload-less frame (an RTP padding probe) is no part of any
    /// access unit and touches nothing.
    fn push(&mut self, hub: &DistributionHub, pts_90k: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.cur_pts.is_some() && self.cur_pts != Some(pts_90k) {
            self.flush(hub);
        }
        self.cur_pts = Some(pts_90k);
        // Annex B already: append as is. Only a bare NAL is framed — the
        // start code that used to be prefixed to every frame doubled
        // str0m's own. No NAL header byte is zero, so a leading zero is
        // a start code's.
        if data[0] != 0 {
            self.nalus.extend_from_slice(&[0, 0, 0, 1]);
        }
        self.nalus.extend_from_slice(data);
        // Scan the NAL types: the keyframe test used to read `data[0]`,
        // which in Annex B is the start code's first zero, so no WHIP or
        // cascade frame was ever flagged a keyframe.
        if au_is_idr(data) {
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

    republish_from_session(session, &hub, stream_id, &cancel).await;

    hub.remove(stream_id);
    tracing::info!("WHIP ingest '{session_id}' closed (stream '{stream_id}')");
}

/// Drive a **connected** WebRTC session, depacketizing its inbound media into
/// the hub: H.264 NALs are regrouped into access units (by PTS) and published
/// as video frames; Opus frames pass straight through. Returns when the
/// session disconnects or `cancel` fires. Shared by WHIP ingest (server role)
/// and the cascade WHEP-client (client role) — both receive WebRTC media and
/// republish it identically.
pub(crate) async fn republish_from_session(
    mut session: WebrtcSession,
    hub: &DistributionHub,
    stream_id: &str,
    cancel: &CancellationToken,
) {
    session.drain_pending_events();

    let mut asm = AuAssembler::new(stream_id.to_string());

    loop {
        match session.poll_event(cancel).await {
            SessionEvent::MediaData { mid, data, rtp_time, .. } => {
                let is_video = session.video_mid == Some(mid);
                let is_audio = session.audio_mid == Some(mid);
                if is_video {
                    // str0m video MediaTime is already the 90 kHz clock. One
                    // `MediaData` is one whole depacketized frame, Annex B.
                    let pts_90k = rtp_time.numer();
                    asm.push(hub, pts_90k, &data);
                } else if is_audio {
                    // Opus 48 kHz clock → 90 kHz.
                    let numer = rtp_time.numer() as u128;
                    let denom = rtp_time.denom() as u128;
                    let pts_90k = if denom == 0 {
                        0
                    } else {
                        (numer.saturating_mul(90_000) / denom) as u64
                    };
                    // `Bytes` has no `From<Arc<[u8]>>` (str0m 0.20 changed
                    // `MediaData.data` to that), but `from_owner` takes any
                    // `AsRef<[u8]> + Send + 'static` and keeps it alive — so
                    // handing over the `Arc` is zero-copy, where
                    // `copy_from_slice` would allocate per Opus frame.
                    hub.publish(stream_id, EsFrame::audio(pts_90k, Bytes::from_owner(data)));
                }
            }
            SessionEvent::Disconnected => break,
            _ => {}
        }
    }

    asm.flush(hub);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What str0m's H.264 depacketizer hands over: one whole frame, Annex B.
    /// It goes to the hub exactly as it came — no second start code — and an
    /// IDR in it flags the access unit a keyframe. Both used to fail: every
    /// frame got a start code prefixed to str0m's own, and the keyframe test
    /// read that start code's zero.
    #[test]
    fn a_whole_annex_b_frame_goes_through_unchanged_and_flags_its_idr() {
        let hub = DistributionHub::new();
        let mut sub = hub.subscribe("s");
        let mut asm = AuAssembler::new("s".to_string());

        let idr_au: &[u8] = &[
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, //
            0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, //
            0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x33, //
        ];
        let p_au: &[u8] = &[0, 0, 0, 1, 0x41, 0x9a, 0x21];
        asm.push(&hub, 0, idr_au);
        asm.push(&hub, 3600, p_au);
        asm.flush(&hub);

        let f1 = sub.rx.try_recv().unwrap();
        assert_eq!(f1.pts_90k, 0);
        assert!(f1.keyframe, "an IDR access unit must be flagged a keyframe");
        assert_eq!(&f1.data[..], idr_au, "no doubled start code");
        let f2 = sub.rx.try_recv().unwrap();
        assert_eq!(f2.pts_90k, 3600);
        assert!(!f2.keyframe);
        assert_eq!(&f2.data[..], p_au);
    }

    /// An RTP padding probe arrives as a payload-less frame. It is no access
    /// unit: it publishes nothing and does not flush the one being built.
    #[test]
    fn a_payload_less_frame_is_no_access_unit() {
        let hub = DistributionHub::new();
        let mut sub = hub.subscribe("s");
        let mut asm = AuAssembler::new("s".to_string());

        asm.push(&hub, 0, &[0, 0, 0, 1, 0x65, 0x88]);
        asm.push(&hub, 1800, &[]);
        asm.push(&hub, 0, &[0, 0, 0, 1, 0x65, 0x99]);
        assert!(sub.rx.try_recv().is_err(), "the probe flushed nothing");
        asm.flush(&hub);
        let f = sub.rx.try_recv().unwrap();
        assert_eq!(&f.data[..], &[0, 0, 0, 1, 0x65, 0x88, 0, 0, 0, 1, 0x65, 0x99]);
        assert!(sub.rx.try_recv().is_err(), "and published nothing of its own");
    }

    /// A sender that marks every NAL a frame of its own (bare NALs, one
    /// timestamp) is regrouped into one access unit.
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
