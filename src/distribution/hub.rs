// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The distribution hub: one fan-out point per live stream.
//!
//! An ingest — WHIP, the QUIC ES ingest or a cascade pull — takes its stream
//! with [`DistributionHub::claim`] and publishes each elementary frame
//! through the [`Publisher`] that returns; the WHEP side calls
//! [`DistributionHub::subscribe`] once per viewer. Each stream owns a
//! `tokio::broadcast` channel (drop-on-lag, never blocks ingest) plus a
//! lock-free [`ArcSwapOption`] holding the most recent keyframe access unit so
//! late joiners decode immediately, and the latest SPS / PPS the stream
//! carried — one of each, size-capped — which go back ahead of every IDR that
//! arrives without its own (see [`restore_param_sets`] for the limits).
//!
//! A stream lives as long as the ingest that claimed it. When that ingest
//! ends, or a newer one takes the stream id over, the stream closes: its
//! broadcast sender is dropped, every viewer's receiver ends, and each viewer
//! session ends with "stream closed". The newer ingest publishes into a
//! stream of its own, which an older ingest's end leaves alone; a viewer that
//! comes back subscribes to that one.
//!
//! This is the deliberately-stateful heart of the viewer-distribution
//! subsystem — isolated behind the `viewer-distribution` feature so the
//! stateless opaque forwarder never carries any of it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::broadcast;

use super::es::{EsFrame, EsKind, H264ParamSets, restore_param_sets};

/// Per-viewer broadcast depth. A viewer that falls this far behind is lagged
/// (drop-on-`Lagged`) — the relay never applies backpressure to ingest.
const VIEWER_CHANNEL_CAPACITY: usize = 1024;

/// The most recent keyframe, cached for instant late-join.
#[derive(Clone)]
pub struct CachedKeyframe {
    /// The IDR access unit, behind the stream's SPS / PPS — its own, or the
    /// ones [`StreamState::publish`] put back.
    pub frame: EsFrame,
}

/// Live state for one distributed stream.
pub struct StreamState {
    stream_id: String,
    /// The fan-out sender, `None` once the stream has closed. It is held here
    /// and nowhere else, so emptying it is what closes the channel: every
    /// viewer's receiver ends (`RecvError::Closed`) once it has taken what was
    /// sent before. Viewers hold this state for its counters, and used to hold
    /// the sender with it, so no receiver ever closed — a viewer whose ingest
    /// had gone stayed connected to a stream nothing would publish to again.
    tx: ArcSwapOption<broadcast::Sender<Arc<EsFrame>>>,
    /// Set once an ingest publishes this state. A state a viewer created
    /// ahead of any ingest is unclaimed, and the first ingest to come takes it
    /// over, viewers and all; one another ingest holds is replaced instead
    /// (see [`DistributionHub::claim`]).
    claimed: AtomicBool,
    keyframe: ArcSwapOption<CachedKeyframe>,
    /// The latest SPS / PPS the stream carried in-band. Written only by the
    /// ingest publishing this stream, read on each video frame it publishes.
    param_sets: ArcSwap<H264ParamSets>,
    /// True once at least one audio frame has been published — WHEP viewers
    /// use this to decide whether to negotiate an audio m-line.
    has_audio: AtomicBool,
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
    fn new(stream_id: String, claimed: bool) -> Self {
        let (tx, _rx) = broadcast::channel(VIEWER_CHANNEL_CAPACITY);
        Self {
            stream_id,
            tx: ArcSwapOption::from_pointee(tx),
            claimed: AtomicBool::new(claimed),
            keyframe: ArcSwapOption::empty(),
            param_sets: ArcSwap::from_pointee(H264ParamSets::default()),
            has_audio: AtomicBool::new(false),
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

    /// Publish one elementary frame. Never blocks: if no viewers are attached
    /// the frame is dropped after refreshing the keyframe cache, and on a
    /// stream that has closed it is dropped outright.
    ///
    /// An IDR access unit that does not carry its own SPS / PPS goes out (and
    /// into the keyframe cache) behind the stream's latest ones, so every
    /// viewer — a late joiner primed from the cache included — can start
    /// decoding on any IDR of a stream that uses one SPS and one PPS (the
    /// limits are on [`restore_param_sets`]). Every ingest path publishes
    /// through here, so this is done once per frame rather than once per
    /// viewer.
    pub fn publish(&self, mut frame: EsFrame) {
        let tx = self.tx.load();
        let Some(tx) = tx.as_deref() else {
            return;
        };

        self.frames_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(frame.data.len() as u64, Ordering::Relaxed);

        if frame.kind == EsKind::AudioOpus {
            self.has_audio.store(true, Ordering::Relaxed);
        }

        if frame.kind == EsKind::VideoH264 {
            let restored = restore_param_sets(&frame.data, &self.param_sets.load());
            if let Some(sets) = restored.param_sets {
                self.param_sets.store(Arc::new(sets));
            }
            if let Some(au) = restored.au {
                frame.data = au.into();
            }
            // Refresh the keyframe cache on an IDR access unit. `keyframe` is
            // set by the ingest; the scan above catches a mis-flagged frame
            // so it still primes the cache.
            if frame.keyframe || restored.idr {
                self.keyframe
                    .store(Some(Arc::new(CachedKeyframe { frame: frame.clone() })));
            }
        }

        // Drop-on-no-receiver / drop-on-lag: ignore the error.
        let _ = tx.send(Arc::new(frame));
    }

    /// Subscribe a viewer, or `None` once the stream has closed.
    fn subscribe(self: &Arc<Self>) -> Option<StreamSubscription> {
        let tx = self.tx.load();
        let tx = tx.as_deref()?;
        self.viewers.fetch_add(1, Ordering::Relaxed);
        // Snapshot the keyframe BEFORE subscribing the receiver. This
        // guarantees the cached IDR's PTS is ≤ every frame the receiver will
        // later deliver, so replaying it first keeps the viewer's RTP
        // timestamps monotonic. (Subscribing first could latch a newer IDR
        // than the receiver's start and emit a backwards timestamp step.)
        let keyframe = self.keyframe();
        let rx = tx.subscribe();
        Some(StreamSubscription {
            rx,
            keyframe,
            state: self.clone(),
            _guard: ViewerGuard { state: self.clone() },
        })
    }

    /// Close the stream: drop the sender, which ends every viewer's receiver.
    /// Idempotent.
    fn close(&self) {
        self.tx.store(None);
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

/// An ingest's hold on the stream it claimed ([`DistributionHub::claim`]).
/// It derefs to the [`StreamState`] the ingest publishes into.
///
/// Dropping it ends the stream however the ingest ends, a panic included:
/// the stream leaves the registry and closes, and its viewers with it. A
/// stream a newer ingest has taken over since is not this one's, so it stays
/// registered and its viewers keep playing. Before, an ingest's end removed
/// whatever was registered under its stream id, and its late end — an edge's
/// old WHIP session timing out after the restarted edge had pushed again —
/// took the new push's stream away from its viewers.
pub struct Publisher<'a> {
    hub: &'a DistributionHub,
    state: Arc<StreamState>,
}

impl std::ops::Deref for Publisher<'_> {
    type Target = StreamState;

    fn deref(&self) -> &StreamState {
        &self.state
    }
}

impl Drop for Publisher<'_> {
    fn drop(&mut self) {
        self.hub.release(&self.state);
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

    /// Get-or-create the state for a stream id. One created here is
    /// unclaimed: a viewer may connect before its stream's ingest has.
    fn ensure(&self, stream_id: &str) -> Arc<StreamState> {
        if let Some(s) = self.streams.get(stream_id) {
            return s.clone();
        }
        self.streams
            .entry(stream_id.to_string())
            .or_insert_with(|| Arc::new(StreamState::new(stream_id.to_string(), false)))
            .clone()
    }

    /// Look up an existing stream without creating it.
    pub fn get(&self, stream_id: &str) -> Option<Arc<StreamState>> {
        self.streams.get(stream_id).map(|s| s.clone())
    }

    /// An ingest takes a stream over (ingest connect) and publishes through
    /// the returned [`Publisher`] until it ends.
    ///
    /// A stream viewers are waiting on that no ingest holds is taken over as
    /// it is, so they get this ingest's media. A stream another ingest holds —
    /// one whose end the relay has not seen yet, such as an edge's WHIP
    /// session before it times out, when the restarted edge pushes again — is
    /// replaced by a fresh one and closed. Its viewers end ("stream closed")
    /// and those that come back get this ingest's stream, not one that
    /// nothing would publish to again; the older ingest goes on publishing to
    /// nobody until it ends, and its end leaves this stream alone.
    pub fn claim(&self, stream_id: &str) -> Publisher<'_> {
        let fresh = || Arc::new(StreamState::new(stream_id.to_string(), true));
        let (state, superseded) = match self.streams.entry(stream_id.to_string()) {
            Entry::Vacant(e) => (e.insert(fresh()).clone(), None),
            Entry::Occupied(mut e) => {
                if e.get().claimed.swap(true, Ordering::AcqRel) {
                    let state = fresh();
                    let old = e.insert(state.clone());
                    (state, Some(old))
                } else {
                    (e.get().clone(), None)
                }
            }
        };
        if let Some(old) = superseded {
            tracing::info!(
                "stream '{stream_id}': a new ingest took it over from one still registered; \
                 its {} viewer(s) end and come back for the new one",
                old.viewer_count()
            );
            old.close();
        }
        Publisher { hub: self, state }
    }

    /// An ingest ended: take its stream out of the registry, if it is still
    /// the one registered, and close it, which ends every viewer on it.
    fn release(&self, state: &Arc<StreamState>) {
        self.streams
            .remove_if(state.stream_id(), |_, current| Arc::ptr_eq(current, state));
        state.close();
    }

    /// Subscribe a viewer to a stream. Creates the stream if it doesn't yet
    /// exist (a viewer may connect before its ingest).
    pub fn subscribe(&self, stream_id: &str) -> StreamSubscription {
        // A stream is taken out of the registry before it is closed, so one
        // found closed here has already gone, and the next lookup finds its
        // successor or makes one.
        loop {
            if let Some(sub) = self.ensure(stream_id).subscribe() {
                return sub;
            }
        }
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
        let publisher = hub.claim("s1");
        publisher.publish(EsFrame::video(0, idr_au(), true));
        let st = hub.get("s1").unwrap();
        assert!(st.keyframe().is_some());
        assert_eq!(st.frames_in(), 1);
    }

    #[test]
    fn late_joiner_gets_cached_keyframe() {
        let hub = DistributionHub::new();
        let publisher = hub.claim("s1");
        publisher.publish(EsFrame::video(0, idr_au(), true));
        let sub = hub.subscribe("s1");
        assert!(sub.keyframe.is_some(), "late joiner must see the cached IDR");
        assert_eq!(sub.state.viewer_count(), 1);
    }

    #[test]
    fn viewer_guard_decrements_on_drop() {
        let hub = DistributionHub::new();
        let _publisher = hub.claim("s1");
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
        let publisher = hub.claim("s1");
        let bare_idr = Bytes::from_static(&[0, 0, 0, 1, 0x65, 0x99, 0x77]);
        let p = Bytes::from_static(&[0, 0, 0, 1, 0x41, 0x9a]);

        // Nothing to put back before the stream has carried any.
        publisher.publish(EsFrame::video(0, bare_idr.clone(), true));
        assert_eq!(hub.get("s1").unwrap().keyframe().unwrap().frame.data, bare_idr);

        publisher.publish(EsFrame::video(3000, idr_au(), true));
        let mut sub = hub.subscribe("s1");
        publisher.publish(EsFrame::video(6000, p.clone(), false));
        publisher.publish(EsFrame::video(9000, bare_idr, true));

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
        let publisher = hub.claim("s1");
        assert!(!publisher.has_audio());
        publisher.publish(EsFrame::audio(0, Bytes::from_static(&[0xfc, 0x01])));
        assert!(hub.get("s1").unwrap().has_audio());
    }

    #[tokio::test]
    async fn subscriber_receives_published_frame() {
        let hub = DistributionHub::new();
        let mut sub = hub.subscribe("s1");
        let publisher = hub.claim("s1");
        publisher.publish(EsFrame::video(3000, idr_au(), true));
        let f = sub.rx.recv().await.unwrap();
        assert_eq!(f.pts_90k, 3000);
        assert!(f.keyframe);
    }

    /// The first ingest takes over a stream viewers were already waiting on —
    /// the same stream, so they get its media.
    #[tokio::test]
    async fn an_ingest_takes_over_the_stream_its_viewers_wait_on() {
        let hub = DistributionHub::new();
        let mut early = hub.subscribe("s1");
        let publisher = hub.claim("s1");
        assert!(Arc::ptr_eq(&early.state, &hub.get("s1").unwrap()));
        publisher.publish(EsFrame::video(3000, idr_au(), true));
        assert_eq!(early.rx.recv().await.unwrap().pts_90k, 3000);
    }

    /// When its ingest ends, a stream closes: every viewer's receiver ends,
    /// after what was sent before, and the stream leaves the registry.
    ///
    /// Before, the stream only left the registry. A viewer held the state the
    /// broadcast sender lived in, so its receiver never closed and its
    /// session never ended; the ingest's next push went into a new state it
    /// never saw.
    #[tokio::test]
    async fn a_viewers_receiver_ends_with_its_ingest() {
        let hub = DistributionHub::new();
        let publisher = hub.claim("s1");
        let mut sub = hub.subscribe("s1");
        publisher.publish(EsFrame::video(3000, idr_au(), true));
        drop(publisher);

        assert_eq!(sub.rx.recv().await.unwrap().pts_90k, 3000, "what was sent arrives");
        assert!(
            matches!(sub.rx.recv().await, Err(broadcast::error::RecvError::Closed)),
            "and then the receiver ends"
        );
        assert!(hub.get("s1").is_none());
        assert_eq!(hub.stream_count(), 0);

        // A viewer that comes back waits on a stream of its own, which the
        // next ingest takes over.
        let mut back = hub.subscribe("s1");
        let next = hub.claim("s1");
        next.publish(EsFrame::video(9000, idr_au(), true));
        assert_eq!(back.rx.recv().await.unwrap().pts_90k, 9000);
    }

    /// An ingest that claims a stream another still holds gets a stream of
    /// its own; the older one closes, ending its viewers so they come back
    /// for the new one, and the older ingest's end leaves the new stream —
    /// and its viewers — alone.
    ///
    /// Before, the second ingest published into the first one's stream by
    /// name, and the first one's late end removed it: a viewer of the second
    /// went black for good.
    #[tokio::test]
    async fn an_older_ingests_end_leaves_a_newer_ones_stream_alone() {
        let hub = DistributionHub::new();
        let old = hub.claim("s1");
        let mut old_viewer = hub.subscribe("s1");

        let new = hub.claim("s1");
        assert!(
            matches!(old_viewer.rx.recv().await, Err(broadcast::error::RecvError::Closed)),
            "the older stream's viewers end"
        );
        let mut viewer = hub.subscribe("s1");
        assert!(Arc::ptr_eq(&viewer.state, &new.state));
        // Whatever the older ingest still publishes reaches nobody.
        old.publish(EsFrame::video(1, idr_au(), true));
        drop(old);

        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &new.state), "still registered");
        new.publish(EsFrame::video(3000, idr_au(), true));
        let f = viewer.rx.recv().await.unwrap();
        assert_eq!(f.pts_90k, 3000, "the newer ingest's viewer keeps playing");
        assert_eq!(hub.total_viewers(), 1);
    }

    /// A viewer that subscribes as its stream closes ends with the stream —
    /// or lands on its successor — rather than on a closed channel nothing
    /// would ever end.
    #[test]
    fn a_closed_stream_takes_no_new_viewers() {
        let hub = DistributionHub::new();
        let publisher = hub.claim("s1");
        let state = hub.get("s1").unwrap();
        drop(publisher);
        assert!(state.subscribe().is_none());
        let sub = hub.subscribe("s1");
        assert!(!Arc::ptr_eq(&sub.state, &state));
        assert_eq!(sub.state.viewer_count(), 1);
        assert_eq!(state.viewer_count(), 0);
    }
}
