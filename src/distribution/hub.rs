// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The distribution hub: one fan-out point per live stream.
//!
//! The ingest side calls [`DistributionHub::publish`] once per elementary
//! frame; the WHEP side calls [`DistributionHub::subscribe`] once per viewer.
//! Each stream owns a `tokio::broadcast` channel (drop-on-lag, never blocks
//! ingest) plus a lock-free [`ArcSwapOption`] holding the most recent
//! keyframe access unit so late joiners decode immediately, and the latest
//! SPS / PPS the stream carried, which go back ahead of every IDR that
//! arrives without its own (see [`restore_param_sets`]).
//!
//! This is the deliberately-stateful heart of the viewer-distribution
//! subsystem — isolated behind the `viewer-distribution` feature so the
//! stateless opaque forwarder never carries any of it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use tokio::sync::broadcast;

use super::es::{EsFrame, EsKind, H264ParamSets, restore_param_sets};

/// Per-viewer broadcast depth. A viewer that falls this far behind is lagged
/// (drop-on-`Lagged`) — the relay never applies backpressure to ingest.
const VIEWER_CHANNEL_CAPACITY: usize = 1024;

/// The most recent keyframe, cached for instant late-join.
#[derive(Clone)]
pub struct CachedKeyframe {
    /// The IDR access unit, behind the stream's SPS / PPS — its own, or the
    /// ones [`DistributionHub::publish`] put back.
    pub frame: EsFrame,
}

/// Live state for one distributed stream.
pub struct StreamState {
    stream_id: String,
    tx: broadcast::Sender<Arc<EsFrame>>,
    keyframe: ArcSwapOption<CachedKeyframe>,
    /// The latest SPS / PPS the stream carried in-band. Written only by the
    /// ingest publishing this stream, read on each video frame it publishes.
    param_sets: ArcSwap<H264ParamSets>,
    /// True once at least one audio frame has been published — WHEP viewers
    /// use this to decide whether to negotiate an audio m-line.
    has_audio: std::sync::atomic::AtomicBool,
    viewers: AtomicU64,
    frames_in: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// Viewer sessions on this stream that had a datagram refused by the
    /// WebRTC ingress source pin (see `webrtc::session::PeerPin`). Counted
    /// once per session, never per datagram — a reflection attempt is a flood
    /// by construction and the alarm must not become its own amplifier.
    offpath_sessions: AtomicU64,
}

impl StreamState {
    fn new(stream_id: String) -> Self {
        let (tx, _rx) = broadcast::channel(VIEWER_CHANNEL_CAPACITY);
        Self {
            stream_id,
            tx,
            keyframe: ArcSwapOption::empty(),
            param_sets: ArcSwap::from_pointee(H264ParamSets::default()),
            has_audio: std::sync::atomic::AtomicBool::new(false),
            viewers: AtomicU64::new(0),
            frames_in: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            offpath_sessions: AtomicU64::new(0),
        }
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn viewer_count(&self) -> u64 {
        self.viewers.load(Ordering::Relaxed)
    }

    pub fn has_audio(&self) -> bool {
        self.has_audio.load(Ordering::Relaxed)
    }

    pub fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    pub fn frames_in(&self) -> u64 {
        self.frames_in.load(Ordering::Relaxed)
    }

    /// Snapshot of the cached keyframe (for a late joiner).
    pub fn keyframe(&self) -> Option<Arc<CachedKeyframe>> {
        self.keyframe.load_full()
    }

    /// Count bytes actually forwarded to viewers (per-viewer SRTP output is
    /// larger; this is the pre-encryption ES accounting for the traffic-share
    /// telemetry).
    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Sessions on this stream that hit the WebRTC ingress source pin.
    pub fn offpath_sessions(&self) -> u64 {
        self.offpath_sessions.load(Ordering::Relaxed)
    }

    /// Record that one viewer session refused an off-path datagram. Called
    /// once per session, on its first drop.
    pub fn add_offpath_session(&self) {
        self.offpath_sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// A viewer's handle onto a stream. Holds a broadcast receiver, a snapshot
/// of the current keyframe (may be `None` before the first IDR), and a guard
/// that decrements the viewer count on drop.
pub struct StreamSubscription {
    pub rx: broadcast::Receiver<Arc<EsFrame>>,
    pub keyframe: Option<Arc<CachedKeyframe>>,
    pub state: Arc<StreamState>,
    _guard: ViewerGuard,
}

/// RAII viewer-count guard.
pub struct ViewerGuard {
    state: Arc<StreamState>,
}

impl Drop for ViewerGuard {
    fn drop(&mut self) {
        self.state.viewers.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The distribution hub: a registry of live streams.
#[derive(Default)]
pub struct DistributionHub {
    streams: DashMap<String, Arc<StreamState>>,
}

impl DistributionHub {
    pub fn new() -> Self {
        Self { streams: DashMap::new() }
    }

    /// Get-or-create the state for a stream id.
    fn ensure(&self, stream_id: &str) -> Arc<StreamState> {
        if let Some(s) = self.streams.get(stream_id) {
            return s.clone();
        }
        self.streams
            .entry(stream_id.to_string())
            .or_insert_with(|| Arc::new(StreamState::new(stream_id.to_string())))
            .clone()
    }

    /// Look up an existing stream without creating it.
    pub fn get(&self, stream_id: &str) -> Option<Arc<StreamState>> {
        self.streams.get(stream_id).map(|s| s.clone())
    }

    /// Register a stream ahead of any media (ingest connect). Idempotent.
    pub fn register(&self, stream_id: &str) -> Arc<StreamState> {
        self.ensure(stream_id)
    }

    /// Publish one elementary frame to a stream. Never blocks: if no viewers
    /// are attached the frame is dropped after refreshing the keyframe cache.
    ///
    /// An IDR access unit that does not carry its own SPS / PPS goes out (and
    /// into the keyframe cache) behind the stream's latest ones, so every
    /// viewer — a late joiner primed from the cache included — can start
    /// decoding on any IDR. Every ingest path publishes through here, so this
    /// is done once per frame rather than once per viewer.
    pub fn publish(&self, stream_id: &str, mut frame: EsFrame) {
        let state = self.ensure(stream_id);

        state.frames_in.fetch_add(1, Ordering::Relaxed);
        state.bytes_in.fetch_add(frame.data.len() as u64, Ordering::Relaxed);

        if frame.kind == EsKind::AudioOpus {
            state.has_audio.store(true, Ordering::Relaxed);
        }

        if frame.kind == EsKind::VideoH264 {
            let restored = restore_param_sets(&frame.data, &state.param_sets.load());
            if let Some(sets) = restored.param_sets {
                state.param_sets.store(Arc::new(sets));
            }
            if let Some(au) = restored.au {
                frame.data = au.into();
            }
            // Refresh the keyframe cache on an IDR access unit. `keyframe` is
            // set by the ingest; the scan above catches a mis-flagged frame
            // so it still primes the cache.
            if frame.keyframe || restored.idr {
                state
                    .keyframe
                    .store(Some(Arc::new(CachedKeyframe { frame: frame.clone() })));
            }
        }

        // Drop-on-no-receiver / drop-on-lag: ignore the error.
        let _ = state.tx.send(Arc::new(frame));
    }

    /// Subscribe a viewer to a stream. Creates the stream if it doesn't yet
    /// exist (a viewer may connect before the first ingest frame).
    pub fn subscribe(&self, stream_id: &str) -> StreamSubscription {
        let state = self.ensure(stream_id);
        state.viewers.fetch_add(1, Ordering::Relaxed);
        // Snapshot the keyframe BEFORE subscribing the receiver. This
        // guarantees the cached IDR's PTS is ≤ every frame the receiver will
        // later deliver, so replaying it first keeps the viewer's RTP
        // timestamps monotonic. (Subscribing first could latch a newer IDR
        // than the receiver's start and emit a backwards timestamp step.)
        let keyframe = state.keyframe();
        let rx = state.tx.subscribe();
        StreamSubscription {
            rx,
            keyframe,
            state: state.clone(),
            _guard: ViewerGuard { state: state.clone() },
        }
    }

    /// Tear a stream down (ingest disconnected). Live viewers see their
    /// broadcast receiver close and exit.
    pub fn remove(&self, stream_id: &str) {
        self.streams.remove(stream_id);
    }

    /// Snapshot every live stream's counters for telemetry.
    pub fn snapshot(&self) -> Vec<StreamSnapshot> {
        self.streams
            .iter()
            .map(|e| {
                let s = e.value();
                StreamSnapshot {
                    stream_id: s.stream_id.clone(),
                    viewers: s.viewer_count(),
                    frames_in: s.frames_in(),
                    bytes_in: s.bytes_in.load(Ordering::Relaxed),
                    bytes_out: s.bytes_out(),
                    offpath_sessions: s.offpath_sessions(),
                    has_audio: s.has_audio(),
                    has_keyframe: s.keyframe.load().is_some(),
                }
            })
            .collect()
    }

    /// Total viewers across all streams.
    pub fn total_viewers(&self) -> u64 {
        self.streams.iter().map(|e| e.value().viewer_count()).sum()
    }

    /// Number of live streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

/// Per-stream telemetry snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamSnapshot {
    pub stream_id: String,
    pub viewers: u64,
    pub frames_in: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Viewer sessions that had a datagram refused by the WebRTC ingress
    /// source pin. Non-zero means either a source-spoofed ICE reflection
    /// attempt or a viewer whose IP changed mid-session.
    pub offpath_sessions: u64,
    pub has_audio: bool,
    pub has_keyframe: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn idr_au() -> Bytes {
        // SPS + PPS + IDR
        Bytes::from_static(&[
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, //
            0, 0, 0, 1, 0x68, 0xce, //
            0, 0, 0, 1, 0x65, 0x88, 0x84, //
        ])
    }

    #[test]
    fn publish_primes_keyframe_cache() {
        let hub = DistributionHub::new();
        hub.publish("s1", EsFrame::video(0, idr_au(), true));
        let st = hub.get("s1").unwrap();
        assert!(st.keyframe().is_some());
        assert_eq!(st.frames_in(), 1);
    }

    #[test]
    fn late_joiner_gets_cached_keyframe() {
        let hub = DistributionHub::new();
        hub.publish("s1", EsFrame::video(0, idr_au(), true));
        let sub = hub.subscribe("s1");
        assert!(sub.keyframe.is_some(), "late joiner must see the cached IDR");
        assert_eq!(sub.state.viewer_count(), 1);
    }

    #[test]
    fn viewer_guard_decrements_on_drop() {
        let hub = DistributionHub::new();
        hub.register("s1");
        let sub = hub.subscribe("s1");
        assert_eq!(hub.get("s1").unwrap().viewer_count(), 1);
        drop(sub);
        assert_eq!(hub.get("s1").unwrap().viewer_count(), 0);
    }

    /// An IDR that arrives without its own SPS / PPS goes out — live and from
    /// the keyframe cache — behind the stream's latest ones, so a viewer that
    /// joins after the IDR that carried them can decode. Before the hub put
    /// them back, a stream whose sender sent its parameter sets once left
    /// every later viewer with undecodable slices.
    #[tokio::test]
    async fn an_idr_without_parameter_sets_goes_out_behind_the_streams_own() {
        let hub = DistributionHub::new();
        let bare_idr = Bytes::from_static(&[0, 0, 0, 1, 0x65, 0x99, 0x77]);
        let p = Bytes::from_static(&[0, 0, 0, 1, 0x41, 0x9a]);

        // Nothing to put back before the stream has carried any.
        hub.publish("s1", EsFrame::video(0, bare_idr.clone(), true));
        assert_eq!(hub.get("s1").unwrap().keyframe().unwrap().frame.data, bare_idr);

        hub.publish("s1", EsFrame::video(3000, idr_au(), true));
        let mut sub = hub.subscribe("s1");
        hub.publish("s1", EsFrame::video(6000, p.clone(), false));
        hub.publish("s1", EsFrame::video(9000, bare_idr, true));

        let expected: &[u8] = &[
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, //
            0, 0, 0, 1, 0x68, 0xce, //
            0, 0, 0, 1, 0x65, 0x99, 0x77, //
        ];
        assert_eq!(sub.rx.recv().await.unwrap().data, p, "a P frame goes out as it came");
        let idr = sub.rx.recv().await.unwrap();
        assert_eq!(&idr.data[..], expected, "the live IDR carries the parameter sets");
        assert!(idr.keyframe);
        let cached = hub.get("s1").unwrap().keyframe().unwrap();
        assert_eq!(&cached.frame.data[..], expected, "so does the late joiner's");
        // Bytes in counts what the ingest sent, not what the hub added.
        assert_eq!(
            hub.snapshot()[0].bytes_in,
            (7 + idr_au().len() + p.len() + 7) as u64
        );
    }

    #[test]
    fn audio_flag_set_on_opus_publish() {
        let hub = DistributionHub::new();
        assert!(!hub.register("s1").has_audio());
        hub.publish("s1", EsFrame::audio(0, Bytes::from_static(&[0xfc, 0x01])));
        assert!(hub.get("s1").unwrap().has_audio());
    }

    #[tokio::test]
    async fn subscriber_receives_published_frame() {
        let hub = DistributionHub::new();
        let mut sub = hub.subscribe("s1");
        hub.publish("s1", EsFrame::video(3000, idr_au(), true));
        let f = sub.rx.recv().await.unwrap();
        assert_eq!(f.pts_90k, 3000);
        assert!(f.keyframe);
    }
}
