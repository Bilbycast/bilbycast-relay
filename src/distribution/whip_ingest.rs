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
//! but WHIP-in reuses the proven edge encoder today.) It does need an edge with
//! this crate's codec set: every edge released through v0.113.0 panics in its
//! WHIP output against this ingest's answer — upgrade edges before relays
//! (`docs/distribution.md`, "Upgrade order").
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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use super::es::{EsFrame, MAX_FRAME_BYTES, au_is_idr};
use super::hub::DistributionHub;
use super::webrtc::session::{SessionConfig, SessionEvent, WebrtcSession};
use super::webrtc::{SETUP_DEADLINE, Setup, await_connected};

/// The largest access unit a WHIP ingest builds out of RTP: the QUIC ingest's
/// frame cap, [`MAX_FRAME_BYTES`], so a stream enters the relay under one cap
/// whichever way it comes in.
const MAX_WHIP_AU_BYTES: usize = MAX_FRAME_BYTES;

/// The largest access unit a cascade pull builds out of RTP:
/// [`MAX_FRAME_BYTES`] plus 64 KiB of headroom for what the relays above it
/// add to a unit their origin took.
///
/// An upstream hub can put the stream's SPS and PPS back ahead of an IDR that
/// came without them (at most
/// [`MAX_PARAM_SETS_ON_THE_WIRE`](super::es::MAX_PARAM_SETS_ON_THE_WIRE) +
/// 8 bytes), and str0m's depacketizer puts a 4-byte start code ahead of every
/// NAL, one byte more than a 3-byte one. Each happens at most once along a
/// chain — after it the unit carries its sets and every start code is 4
/// bytes — so a unit of up to [`MAX_FRAME_BYTES`] that its origin took, by
/// either ingest, reaches every tier below it. Capped at [`MAX_FRAME_BYTES`],
/// a tier dropped such a unit whole; and while a WHIP ingest was capped here
/// too, an IDR it took within the headroom grew by the sets at its hub and
/// was dropped at the first tier. 64 KiB covers the sets and a byte for each
/// of some 64 000 NALs behind 3-byte start codes, far more than an access
/// unit carries. The cap bounds memory; it sets no policy, so the headroom
/// costs nothing.
pub(crate) const MAX_RTP_AU_BYTES: usize = MAX_FRAME_BYTES + 64 * 1024;

/// The oversized-access-unit warning is logged at most once per this interval
/// per session, with a count of the units dropped since. A publisher whose
/// timestamp is stuck trips the cap every 4 MiB it sends.
const OVERSIZE_WARN_INTERVAL: Duration = Duration::from_secs(10);

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
        // Cancel our own token however this task ends, a panic included, so
        // the reaper in `whip_ingest_offer` always drops the session record.
        let _cancel_on_exit = loop_cancel.clone().drop_guard();
        ingest_loop(session, hub, loop_cancel, &loop_stream, &loop_sid).await;
    });

    Ok(WhipIngestHandle { session_id, answer_sdp, cancel })
}

/// Accumulates depacketized frames into access units and publishes them to
/// the hub.
struct AuAssembler {
    stream_id: String,
    /// The largest access unit built: [`MAX_WHIP_AU_BYTES`] for a WHIP
    /// ingest, [`MAX_RTP_AU_BYTES`] for a cascade pull.
    max_bytes: usize,
    cur_pts: Option<u64>,
    nalus: Vec<u8>,
    keyframe: bool,
    /// The unit at `cur_pts` went past `max_bytes` and was dropped; the rest
    /// of it is discarded until the timestamp moves on.
    oversized: bool,
    /// Oversized units dropped since the last warning, and when that was.
    dropped_since_warn: u64,
    last_warn: Option<Instant>,
}

impl AuAssembler {
    fn new(stream_id: String, max_bytes: usize) -> Self {
        Self {
            stream_id,
            max_bytes,
            cur_pts: None,
            nalus: Vec::new(),
            keyframe: false,
            oversized: false,
            dropped_since_warn: 0,
            last_warn: None,
        }
    }

    /// Push one depacketized frame — Annex B, as str0m emits it, or one bare
    /// NAL. If it opens a new access unit (PTS change), flush the previous AU
    /// first. A payload-less frame (an RTP padding probe) is no part of any
    /// access unit and touches nothing.
    ///
    /// An access unit is capped at `max_bytes`. Nothing is published until
    /// the timestamp changes, so a publisher — or cascade upstream — whose
    /// timestamp stuck used to grow this buffer at its send rate until the
    /// relay ran out of memory, while its viewers got nothing. A unit that
    /// would pass the cap is dropped whole, and the rest of it with it:
    /// publishing its tail would hand viewers a fragment.
    fn push(&mut self, hub: &DistributionHub, pts_90k: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.cur_pts != Some(pts_90k) {
            self.flush(hub);
            self.cur_pts = Some(pts_90k);
            self.oversized = false;
        }
        if self.oversized {
            return;
        }
        // Annex B already: append as is. Only a bare NAL is framed — the
        // start code that used to be prefixed to every frame doubled
        // str0m's own. No NAL header byte is zero, so a leading zero is
        // a start code's.
        let framing: &[u8] = if data[0] != 0 { &[0, 0, 0, 1] } else { &[] };
        if self.nalus.len() + framing.len() + data.len() > self.max_bytes {
            self.drop_oversized(pts_90k);
            return;
        }
        self.nalus.extend_from_slice(framing);
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

    /// Drop the unit being built at `pts_90k` — it would pass `max_bytes` —
    /// and give its buffer back. Warns at most once per
    /// [`OVERSIZE_WARN_INTERVAL`].
    fn drop_oversized(&mut self, pts_90k: u64) {
        self.nalus = Vec::new();
        self.keyframe = false;
        self.oversized = true;
        self.dropped_since_warn += 1;
        let now = Instant::now();
        if self
            .last_warn
            .is_none_or(|t| now.duration_since(t) >= OVERSIZE_WARN_INTERVAL)
        {
            tracing::warn!(
                "WebRTC ingest for stream '{}': access unit at pts {pts_90k} passed \
                 {} bytes on one RTP timestamp; dropped ({} since the last warning)",
                self.stream_id,
                self.max_bytes,
                self.dropped_since_warn,
            );
            self.last_warn = Some(now);
            self.dropped_since_warn = 0;
        }
    }
}

async fn ingest_loop(
    mut session: WebrtcSession,
    hub: Arc<DistributionHub>,
    cancel: CancellationToken,
    stream_id: &str,
    session_id: &str,
) {
    // Wait for ICE + DTLS — for `SETUP_DEADLINE` at most; the drop guard in
    // `create_and_spawn_ingest` then ends the session either way.
    match await_connected(&mut session, &cancel, SETUP_DEADLINE).await {
        Setup::Connected => {
            tracing::info!("WHIP ingest '{session_id}' connected for stream '{stream_id}'");
            hub.register(stream_id);
        }
        Setup::Disconnected => {
            tracing::info!("WHIP ingest '{session_id}' disconnected during setup");
            return;
        }
        Setup::TimedOut => {
            tracing::warn!(
                "WHIP ingest '{session_id}' did not complete ICE + DTLS within \
                 {SETUP_DEADLINE:?} (stream '{stream_id}'); closing it"
            );
            return;
        }
    }

    republish_from_session(session, &hub, stream_id, &cancel, MAX_WHIP_AU_BYTES).await;

    hub.remove(stream_id);
    tracing::info!("WHIP ingest '{session_id}' closed (stream '{stream_id}')");
}

/// Drive a **connected** WebRTC session, depacketizing its inbound media into
/// the hub: H.264 NALs are regrouped into access units (by PTS) and published
/// as video frames; Opus frames pass straight through. Returns when the
/// session disconnects or `cancel` fires. Shared by WHIP ingest (server role)
/// and the cascade WHEP-client (client role) — both receive WebRTC media and
/// republish it identically, but for the access-unit cap, `max_au_bytes`:
/// [`MAX_WHIP_AU_BYTES`] for the one, [`MAX_RTP_AU_BYTES`] for the other.
pub(crate) async fn republish_from_session(
    mut session: WebrtcSession,
    hub: &DistributionHub,
    stream_id: &str,
    cancel: &CancellationToken,
    max_au_bytes: usize,
) {
    session.drain_pending_events();

    let mut asm = AuAssembler::new(stream_id.to_string(), max_au_bytes);

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
        let mut asm = AuAssembler::new("s".to_string(), MAX_WHIP_AU_BYTES);

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
        let mut asm = AuAssembler::new("s".to_string(), MAX_WHIP_AU_BYTES);

        asm.push(&hub, 0, &[0, 0, 0, 1, 0x65, 0x88]);
        asm.push(&hub, 1800, &[]);
        asm.push(&hub, 0, &[0, 0, 0, 1, 0x65, 0x99]);
        assert!(sub.rx.try_recv().is_err(), "the probe flushed nothing");
        asm.flush(&hub);
        let f = sub.rx.try_recv().unwrap();
        assert_eq!(&f.data[..], &[0, 0, 0, 1, 0x65, 0x88, 0, 0, 0, 1, 0x65, 0x99]);
        assert!(sub.rx.try_recv().is_err(), "and published nothing of its own");
    }

    /// A publisher whose RTP timestamp sticks — here 100 kB frames, all at
    /// one pts — cannot grow the unit being built past the assembler's cap,
    /// a WHIP ingest's or a cascade pull's. The oversized unit is dropped
    /// whole, its tail included, and the next timestamp starts afresh.
    /// Before, every frame was appended until the timestamp moved: 40 MB on
    /// one timestamp grew the relay by 40 MB, and the lot was then published
    /// as one frame.
    #[test]
    fn an_access_unit_is_capped_at_the_frame_limit_and_dropped_whole() {
        for cap in [MAX_WHIP_AU_BYTES, MAX_RTP_AU_BYTES] {
            let hub = DistributionHub::new();
            let mut sub = hub.subscribe("s");
            let mut asm = AuAssembler::new("s".to_string(), cap);

            let slice = vec![0x41u8; 100_000];
            for _ in 0..(cap / slice.len() + 20) {
                asm.push(&hub, 3000, &slice);
                assert!(
                    asm.nalus.len() <= cap,
                    "buffered {} bytes on one timestamp, cap {cap}",
                    asm.nalus.len()
                );
            }
            asm.push(&hub, 6000, &[0, 0, 0, 1, 0x65, 0x88]);
            asm.flush(&hub);
            let f = sub.rx.try_recv().expect("the next unit goes out");
            assert_eq!(
                (f.pts_90k, f.keyframe),
                (6000, true),
                "not the oversized one, nor its tail"
            );
            assert_eq!(&f.data[..], &[0, 0, 0, 1, 0x65, 0x88]);
            assert!(sub.rx.try_recv().is_err());

            // A unit of exactly the limit is not oversized.
            let mut whole = vec![0x65u8];
            whole.resize(cap - 4, 0x11);
            asm.push(&hub, 9000, &whole);
            asm.flush(&hub);
            let f = sub.rx.try_recv().expect("a unit at the limit goes out");
            assert_eq!(f.data.len(), cap);
        }
    }

    /// A unit at the QUIC ingest's frame cap, as an upstream relay publishes
    /// it, passes a cascade tier's assembler. The upstream hub put the
    /// stream's SPS and PPS back ahead of it — the most it inserts — and in
    /// rebuilding the unit put every NAL behind a 4-byte start code where the
    /// source used 3-byte ones; str0m's depacketizer hands it over that way.
    ///
    /// Capped at `MAX_FRAME_BYTES` itself, the assembler dropped it whole.
    #[test]
    fn a_unit_an_upstream_relay_publishes_at_the_frame_cap_passes_a_cascade_tier() {
        use crate::distribution::es::{MAX_PARAM_SET_BYTES, MAX_PARAM_SETS_ON_THE_WIRE};

        let upstream = DistributionHub::new();
        let mut published = upstream.subscribe("s");
        // The stream's parameter sets, as large as the upstream re-inserts.
        let sps_len = MAX_PARAM_SET_BYTES;
        let pps_len = MAX_PARAM_SETS_ON_THE_WIRE - sps_len;
        let mut first = vec![0, 0, 0, 1, 0x67];
        first.resize(4 + sps_len, 0x42);
        first.extend_from_slice(&[0, 0, 0, 1, 0x68]);
        first.resize(first.len() + pps_len - 1, 0xce);
        first.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88]);
        upstream.publish("s", EsFrame::video(0, first.into(), true));
        let _ = published.rx.try_recv().unwrap();

        // An IDR without its own sets, exactly at the QUIC ingest's cap: 512
        // slices, each behind a 3-byte start code.
        let slices = 512;
        let mut idr = Vec::with_capacity(MAX_FRAME_BYTES);
        for _ in 0..slices {
            idr.extend_from_slice(&[0, 0, 1, 0x65]);
            idr.resize(idr.len() + MAX_FRAME_BYTES / slices - 4, 0x11);
        }
        assert_eq!(idr.len(), MAX_FRAME_BYTES);
        upstream.publish("s", EsFrame::video(3000, idr.into(), true));
        let au = published.rx.try_recv().unwrap();
        assert_eq!(
            au.data.len(),
            MAX_FRAME_BYTES + slices + MAX_PARAM_SETS_ON_THE_WIRE + 8,
            "the sets went back in, and every start code grew a byte"
        );

        let downstream = DistributionHub::new();
        let mut sub = downstream.subscribe("s");
        let mut asm = AuAssembler::new("s".to_string(), MAX_RTP_AU_BYTES);
        asm.push(&downstream, 3000, &au.data);
        asm.flush(&downstream);
        let f = sub
            .rx
            .try_recv()
            .expect("the unit goes out at the cascade tier");
        assert_eq!(f.data, au.data);
        assert!(f.keyframe);
    }

    /// What a WHIP origin takes reaches every cascade tier below it, and what
    /// a tier would drop the origin refuses itself, where its publisher is.
    /// The unit is an IDR without its own SPS and PPS, which the origin's hub
    /// puts back ahead of it, as large as it inserts them.
    ///
    /// While a WHIP ingest was capped at the cascade's [`MAX_RTP_AU_BYTES`],
    /// an IDR within the headroom — `MAX_RTP_AU_BYTES - 200` below — passed
    /// the origin, grew by the sets and was dropped whole at the first tier.
    #[test]
    fn a_unit_a_whip_origin_takes_reaches_every_cascade_tier() {
        use crate::distribution::es::{MAX_PARAM_SET_BYTES, MAX_PARAM_SETS_ON_THE_WIRE};

        // A WHIP origin and two cascade tiers, each publishing into its own
        // hub. Between relays the unit goes through str0m, which hands over
        // what it was given when every start code is 4 bytes already.
        let hubs = [
            DistributionHub::new(),
            DistributionHub::new(),
            DistributionHub::new(),
        ];
        let mut subs = hubs.each_ref().map(|h| h.subscribe("s"));
        let mut asms = [MAX_WHIP_AU_BYTES, MAX_RTP_AU_BYTES, MAX_RTP_AU_BYTES]
            .map(|cap| AuAssembler::new("s".to_string(), cap));
        // How many of the three relays a unit at `pts` gets out of.
        let mut relay = |pts: u64, au: Vec<u8>| -> usize {
            let mut au = Bytes::from(au);
            for (tier, ((hub, sub), asm)) in hubs.iter().zip(&mut subs).zip(&mut asms).enumerate() {
                asm.push(hub, pts, &au);
                asm.flush(hub);
                match sub.rx.try_recv() {
                    Ok(f) => au = f.data.clone(),
                    Err(_) => return tier,
                }
            }
            hubs.len()
        };

        // The stream's parameter sets, as large as a hub re-inserts, which
        // every hub caches on the way down.
        let sps_len = MAX_PARAM_SET_BYTES;
        let pps_len = MAX_PARAM_SETS_ON_THE_WIRE - sps_len;
        let mut first = vec![0, 0, 0, 1, 0x67];
        first.resize(4 + sps_len, 0x42);
        first.extend_from_slice(&[0, 0, 0, 1, 0x68]);
        first.resize(first.len() + pps_len - 1, 0xce);
        first.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88]);
        assert_eq!(relay(0, first), 3);

        for (k, len) in [
            MAX_FRAME_BYTES - 1,
            MAX_FRAME_BYTES,
            MAX_FRAME_BYTES + 1,
            MAX_RTP_AU_BYTES - 200,
            MAX_RTP_AU_BYTES,
        ]
        .into_iter()
        .enumerate()
        {
            let mut idr = vec![0, 0, 0, 1, 0x65];
            idr.resize(len, 0x11);
            let reached = relay(3000 * (k as u64 + 1), idr);
            if len <= MAX_FRAME_BYTES {
                assert_eq!(reached, 3, "an IDR of {len} bytes reaches every tier");
            } else {
                assert_eq!(reached, 0, "an IDR of {len} bytes is refused at the origin");
            }
        }
    }

    /// A sender that marks every NAL a frame of its own (bare NALs, one
    /// timestamp) is regrouped into one access unit.
    #[test]
    fn au_assembler_groups_by_pts_and_flags_keyframe() {
        let hub = DistributionHub::new();
        let mut sub = hub.subscribe("s");
        let mut asm = AuAssembler::new("s".to_string(), MAX_WHIP_AU_BYTES);

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
