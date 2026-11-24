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
//! **Who owns a stream.** The newest live ingest for a stream id owns it. A
//! stream lives as long as the ingest that owns it: when that ingest ends, or
//! a newer one takes the stream id over, the stream closes — its broadcast
//! sender is dropped, every viewer's receiver ends, and each viewer session
//! ends with "stream closed". A viewer that comes back subscribes to whatever
//! holds the stream id then. An ingest a newer one took the stream from is
//! not ended — its client would only push again and take the stream back,
//! and the two would trade it for as long as both lived — but its frames are
//! dropped until the newer ingest ends; its next frame after that takes the
//! stream back (see [`Publisher`]), so a stream is never dead while any
//! ingest of it is live. Taking back never takes a stream from a newer
//! ingest, so two live ingests settle on the newer one rather than trading.
//!
//! A stream that viewers opened ahead of any ingest is unclaimed: the first
//! ingest to arrive takes it over as it is, and it leaves the registry when
//! its last viewer does, so only real streams are counted.
//!
//! This is the deliberately-stateful heart of the viewer-distribution
//! subsystem — isolated behind the `viewer-distribution` feature so the
//! stateless opaque forwarder never carries any of it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::broadcast;

use super::es::{EsFrame, EsKind, H264ParamSets, restore_param_sets};

/// Per-viewer broadcast depth. A viewer that falls this far behind is lagged
/// (drop-on-`Lagged`) — the relay never applies backpressure to ingest.
const VIEWER_CHANNEL_CAPACITY: usize = 1024;

/// [`StreamState::owner`] of a stream no ingest has claimed. Ingests are
/// numbered from 1 in the order they claim.
const UNCLAIMED: u64 = 0;

/// The stream registry. Shared with every viewer's [`ViewerGuard`], which
/// takes an unclaimed stream out when its last viewer leaves.
type Registry = DashMap<String, Arc<StreamState>>;

/// The most recent keyframe, cached for instant late-join.
#[derive(Clone)]
pub struct CachedKeyframe {
    /// The IDR access unit, behind the stream's SPS / PPS — its own, or the
    /// ones the hub put back as it published it.
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
    ///
    /// A closed stream is never in the registry: it is taken out first.
    tx: ArcSwapOption<broadcast::Sender<Arc<EsFrame>>>,
    /// The number of the ingest that owns this stream (`Publisher::seq`),
    /// or [`UNCLAIMED`] for one a viewer created ahead of any ingest. Changed
    /// only under the registry's lock on this stream's entry, which
    /// [`ViewerGuard`] holds too when it reads it before taking an unclaimed
    /// stream out.
    owner: AtomicU64,
    keyframe: ArcSwapOption<CachedKeyframe>,
    /// The latest SPS / PPS the stream carried in-band. Written only by the
    /// ingest publishing this stream, read on each video frame it publishes.
    param_sets: ArcSwap<H264ParamSets>,
    /// True once at least one audio frame has been published. Telemetry only
    /// ([`StreamSnapshot::has_audio`]): a WHEP viewer's answer takes its
    /// audio m-line from the viewer's own offer, never from this.
    has_audio: AtomicBool,
    // This stream's own counts, for the per-stream breakdown
    // ([`StreamSnapshot`]). They restart with the stream: a newer ingest that
    // takes a held stream over, and an older one that takes it back, publish
    // into a fresh `StreamState` (or the unclaimed one viewers wait on), and
    // the viewers of the closed one end with it. They are not carried over
    // ([`StreamState::inherit`]): a viewer of the closed stream still counts
    // into that one until it ends, so a copied figure would be neither
    // stream's. Relay-wide totals are the hub's.
    viewers: AtomicU64,
    frames_in: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// Viewer sessions on this stream that had a datagram refused by the
    /// WebRTC ingress source pin (see `webrtc::session::PeerPin`). Counted
    /// once per session, never per datagram — a reflection attempt is a flood
    /// by construction and the alarm must not become its own amplifier.
    offpath_sessions: AtomicU64,
    /// The hub's relay-wide totals of the two above
    /// ([`DistributionHub::bytes_out`], [`DistributionHub::offpath_sessions`]),
    /// counted with them, so what a viewer still counts on a stream that has
    /// closed is in the totals too.
    hub_bytes_out: Arc<AtomicU64>,
    hub_offpath_sessions: Arc<AtomicU64>,
}

impl StreamState {
    fn new(hub: &DistributionHub, stream_id: &str, owner: u64) -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(VIEWER_CHANNEL_CAPACITY);
        Arc::new(Self {
            stream_id: stream_id.to_string(),
            tx: ArcSwapOption::from_pointee(tx),
            owner: AtomicU64::new(owner),
            keyframe: ArcSwapOption::empty(),
            param_sets: ArcSwap::from_pointee(H264ParamSets::default()),
            has_audio: AtomicBool::new(false),
            viewers: AtomicU64::new(0),
            frames_in: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            offpath_sessions: AtomicU64::new(0),
            hub_bytes_out: hub.bytes_out.clone(),
            hub_offpath_sessions: hub.offpath_sessions.clone(),
        })
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

    /// Bytes forwarded to this stream's viewers since it opened.
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
    /// telemetry), on this stream and on the hub's total.
    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
        self.hub_bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Sessions on this stream that hit the WebRTC ingress source pin since
    /// it opened.
    pub fn offpath_sessions(&self) -> u64 {
        self.offpath_sessions.load(Ordering::Relaxed)
    }

    /// Record that one viewer session refused an off-path datagram, on this
    /// stream and on the hub's total. Called once per session, on its first
    /// drop.
    pub fn add_offpath_session(&self) {
        self.offpath_sessions.fetch_add(1, Ordering::Relaxed);
        self.hub_offpath_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish one elementary frame, or hand it back (`Err`) when the stream
    /// has closed. Never blocks: with no viewers attached the frame is
    /// dropped after refreshing the keyframe cache. Only a [`Publisher`] —
    /// the ingest that owns the stream — calls this.
    ///
    /// An IDR access unit that does not carry its own SPS / PPS goes out (and
    /// into the keyframe cache) behind the stream's latest ones, so every
    /// viewer — a late joiner primed from the cache included — can start
    /// decoding on any IDR of a stream that uses one SPS and one PPS (the
    /// limits are on [`restore_param_sets`]). Every ingest path publishes
    /// through here, so this is done once per frame rather than once per
    /// viewer.
    fn send(&self, mut frame: EsFrame) -> Result<(), EsFrame> {
        let tx = self.tx.load();
        let Some(tx) = tx.as_deref() else {
            return Err(frame);
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
        Ok(())
    }

    /// Refresh the SPS / PPS from a video frame that is not sent: one a
    /// superseded ingest published into this, its closed stream. A stream it
    /// takes back inherits them, so they are the ones its source uses now —
    /// a source that changed them while superseded (a resolution change, the
    /// new sets sent once) would otherwise have every bare IDR after the
    /// take-back go out behind the old ones.
    fn track_param_sets(&self, frame: &EsFrame) {
        if frame.kind != EsKind::VideoH264 {
            return;
        }
        if let Some(sets) = restore_param_sets(&frame.data, &self.param_sets.load()).param_sets {
            self.param_sets.store(Arc::new(sets));
        }
    }

    /// Carry over what an ingest's stream knew about its media into the
    /// stream it took back: the SPS / PPS it would put back ahead of a bare
    /// IDR — a sender that sends them once would otherwise leave every viewer
    /// of the taken-back stream undecodable — and whether it carries audio,
    /// so the stream's telemetry does not read audio-less until the next
    /// audio frame (a viewer's answer takes its audio from the viewer's
    /// offer, not from this). Not the keyframe: the cached one is from before
    /// the stream was taken, so viewers start on the next. Nor the counts,
    /// which are the stream's own.
    fn inherit(&self, from: &StreamState) {
        self.param_sets.store(from.param_sets.load_full());
        if from.has_audio() {
            self.has_audio.store(true, Ordering::Relaxed);
        }
    }

    /// Subscribe a viewer, or `None` once the stream has closed. Called with
    /// the registry's lock on this stream's entry held, so a viewer cannot
    /// join a stream its last viewer's guard is taking out.
    fn subscribe(self: &Arc<Self>, registry: &Arc<Registry>) -> Option<StreamSubscription> {
        let tx = self.tx.load();
        let tx = tx.as_deref()?;
        self.viewers.fetch_add(1, Ordering::AcqRel);
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
            _guard: ViewerGuard {
                state: self.clone(),
                registry: Arc::downgrade(registry),
            },
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

/// RAII viewer-count guard. The last viewer of a stream no ingest has claimed
/// takes it out of the registry as it leaves. Before, nothing did: a viewer
/// that came back for a stream whose ingest had gone — which the `/watch`
/// player and the edge's WHEP input both do — left an entry behind, counted
/// as a live stream on `/metrics` and in health for good.
pub struct ViewerGuard {
    state: Arc<StreamState>,
    registry: Weak<Registry>,
}

impl Drop for ViewerGuard {
    fn drop(&mut self) {
        let state = &self.state;
        if state.viewers.fetch_sub(1, Ordering::AcqRel) != 1
            || state.owner.load(Ordering::Acquire) != UNCLAIMED
        {
            return;
        }
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        // Checked again under the lock on this entry's shard of the
        // registry, which `remove_if` holds for writing and a claim and a
        // subscribe hold too (a subscribe that finds the stream, for
        // reading): an ingest that takes the stream at this moment, or a
        // viewer that joins it, keeps it.
        let gone = registry.remove_if(state.stream_id(), |_, current| {
            Arc::ptr_eq(current, state)
                && current.owner.load(Ordering::Acquire) == UNCLAIMED
                && current.viewers.load(Ordering::Acquire) == 0
        });
        if gone.is_some() {
            state.close();
        }
    }
}

/// An ingest's hold on the stream it claimed ([`DistributionHub::claim`]),
/// through which it publishes ([`Publisher::publish`]).
///
/// Dropping it — or [`Publisher::end`] — ends the stream however the ingest
/// ends, a panic included: the stream leaves the registry and closes, and its
/// viewers with it. A stream a newer ingest has taken over since is not this
/// one's, so it stays registered and its viewers keep playing. Before, an
/// ingest's end removed whatever was registered under its stream id, and its
/// late end — an edge's old WHIP session timing out after the restarted edge
/// had pushed again — took the new push's stream away from its viewers.
///
/// **Superseded.** While a newer ingest holds the stream, this one's frames
/// are dropped: its stream was closed under it, which its next publish
/// notices. Each such frame asks the registry, at the cost of one lookup,
/// whether a newer ingest still holds the stream; once none does, this
/// ingest takes the stream back and publishes into it. Its session is left
/// alone throughout: ending it would only have its client push again and
/// take the stream from the newer ingest, and then the reverse. An ingest
/// that is ending ([`Publisher::mark_ending`]) never takes it back.
pub struct Publisher<'a> {
    hub: &'a DistributionHub,
    stream_id: String,
    /// This ingest's number: ingests are numbered in the order they claim,
    /// and a stream is taken back only from an older one.
    seq: u64,
    /// The stream this ingest publishes into: the one it claimed, or the one
    /// it took back.
    state: ArcSwap<StreamState>,
    /// Frames dropped since a newer ingest took the stream; 0 while this one
    /// holds it. The first drop of an episode is logged, and the count with
    /// the take-back.
    dropped: AtomicU64,
    /// [`Publisher::mark_ending`]: the ingest is ending, so it no longer
    /// takes its stream back.
    ending: AtomicBool,
    /// [`Publisher::end`] released the stream already.
    released: bool,
}

/// What an ingest's end found of its stream ([`Publisher::end`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// The ingest held its stream, which closed with it: its viewers end.
    Closed,
    /// A newer ingest had taken the stream from this one, and another ingest
    /// holds it now, which plays on: that newer one, or an older one that
    /// took the stream back once the ingests newer than it had ended.
    HeldByAnother,
    /// A newer ingest had taken the stream from this one, and no ingest holds
    /// it now: every ingest that held it since has ended. Nothing is
    /// registered under the stream id, or viewers wait there, sent nothing,
    /// for the next ingest.
    Unheld,
}

impl StreamEnd {
    /// Who held the stream when the ingest ended, as event details name it:
    /// `"this"`, `"another"` or `"none"`.
    pub fn held_by(self) -> &'static str {
        match self {
            StreamEnd::Closed => "this",
            StreamEnd::HeldByAnother => "another",
            StreamEnd::Unheld => "none",
        }
    }
}

impl Publisher<'_> {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Publish one elementary frame into this ingest's stream. Never blocks.
    pub fn publish(&self, frame: EsFrame) {
        let Err(frame) = self.state.load().send(frame) else {
            return;
        };
        self.publish_superseded(frame);
    }

    /// The closed path: a newer ingest took the stream. Take it back if that
    /// ingest has gone, else drop the frame — keeping the SPS / PPS it
    /// carried, which a stream taken back later inherits. An ingest that is
    /// ending drops it outright.
    #[cold]
    fn publish_superseded(&self, frame: EsFrame) {
        if self.ending.load(Ordering::Relaxed) {
            return;
        }
        let current = self.state.load_full();
        if let Some(stream) = self.hub.take_back(&current, self.seq) {
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            tracing::info!(
                "stream '{}': the newer ingest that held it has gone; this one takes it back \
                 ({dropped} frame(s) dropped while it was held)",
                self.stream_id
            );
            let _ = stream.send(frame);
            self.state.store(stream);
            return;
        }
        current.track_param_sets(&frame);
        self.hub.superseded_frames.fetch_add(1, Ordering::Relaxed);
        if self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!(
                "stream '{}': a newer ingest holds it, so this one's frames are dropped until that \
                 one ends, when this one takes the stream back",
                self.stream_id
            );
        }
    }

    /// The ingest is ending: what it publishes from now on — the unit its
    /// depacketizer still held, flushed as its session ends — goes into its
    /// stream if it still holds it, and is dropped otherwise. It never takes
    /// the stream back: it would hold it only until its end, a moment later,
    /// closed it again, ending the viewers that were waiting on it — or those
    /// of an older live ingest that had taken it back, which would then take
    /// it back once more on its next frame.
    pub fn mark_ending(&self) {
        self.ending.store(true, Ordering::Relaxed);
    }

    /// End this ingest's hold on its stream now, and say what that found:
    /// the stream closed with it ([`StreamEnd::Closed`]), or a newer ingest
    /// had taken it, and another ingest holds it now
    /// ([`StreamEnd::HeldByAnother`]) or none does ([`StreamEnd::Unheld`]).
    pub fn end(mut self) -> StreamEnd {
        self.released = true;
        if self.hub.release(&self.state.load()) {
            return StreamEnd::Closed;
        }
        let held = self
            .hub
            .streams
            .get(&self.stream_id)
            .is_some_and(|s| s.owner.load(Ordering::Acquire) != UNCLAIMED);
        if held {
            StreamEnd::HeldByAnother
        } else {
            StreamEnd::Unheld
        }
    }
}

impl Drop for Publisher<'_> {
    fn drop(&mut self) {
        if !self.released {
            self.hub.release(&self.state.load());
        }
    }
}

/// The distribution hub: a registry of live streams.
#[derive(Default)]
pub struct DistributionHub {
    streams: Arc<Registry>,
    /// The last ingest number handed out (`Publisher::seq`).
    claims: AtomicU64,
    /// Frames live ingests published while a newer ingest held their stream,
    /// dropped. Relay-wide, for the life of the subsystem.
    superseded_frames: AtomicU64,
    /// Datagrams the WebRTC ingress source pin dropped from another of a
    /// peer's paths within its grace (`webrtc::session::PeerPin`), which
    /// raise no alarm. Shared with every session (see
    /// [`DistributionHub::other_path_counter`]).
    other_path_datagrams: Arc<AtomicU64>,
    /// Bytes forwarded to viewers on every stream there has been. Shared with
    /// every [`StreamState`], which counts into it beside its own figure.
    bytes_out: Arc<AtomicU64>,
    /// Viewer sessions, on every stream there has been, that had a datagram
    /// refused by the WebRTC ingress source pin. Shared likewise.
    offpath_sessions: Arc<AtomicU64>,
}

impl DistributionHub {
    pub fn new() -> Self {
        Self::default()
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
    /// nothing would publish to again. The older ingest's frames are dropped
    /// from then on; if this ingest ends first, the older one takes the
    /// stream back (see [`Publisher`]), and if the older one ends first, its
    /// end leaves this stream alone.
    pub fn claim(&self, stream_id: &str) -> Publisher<'_> {
        let seq = self.claims.fetch_add(1, Ordering::Relaxed) + 1;
        let fresh = || StreamState::new(self, stream_id, seq);
        let (state, superseded) = match self.streams.entry(stream_id.to_string()) {
            Entry::Vacant(e) => (e.insert(fresh()).clone(), None),
            Entry::Occupied(mut e) => {
                if e.get().owner.load(Ordering::Acquire) == UNCLAIMED {
                    e.get().owner.store(seq, Ordering::Release);
                    (e.get().clone(), None)
                } else {
                    let state = fresh();
                    let old = e.insert(state.clone());
                    (state, Some(old))
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
        Publisher {
            hub: self,
            stream_id: stream_id.to_string(),
            seq,
            state: ArcSwap::new(state),
            dropped: AtomicU64::new(0),
            ending: AtomicBool::new(false),
            released: false,
        }
    }

    /// A superseded ingest (`seq`, whose stream `from` a newer one closed)
    /// asks for its stream back: it gets it — a fresh stream, or one viewers
    /// are waiting on with no ingest, which it takes over as it is — when no
    /// newer ingest holds it. One an older ingest took back meanwhile it
    /// takes over, closing it, so of several live ingests the newest ends up
    /// holding the stream. `None` while a newer one holds it.
    fn take_back(&self, from: &Arc<StreamState>, seq: u64) -> Option<Arc<StreamState>> {
        let stream_id = from.stream_id();
        // The common answer while superseded, without the entry lock.
        if self
            .streams
            .get(stream_id)
            .is_some_and(|s| s.owner.load(Ordering::Acquire) > seq)
        {
            return None;
        }
        let fresh = || StreamState::new(self, stream_id, seq);
        let (state, displaced) = match self.streams.entry(stream_id.to_string()) {
            Entry::Vacant(e) => (e.insert(fresh()).clone(), None),
            Entry::Occupied(mut e) => {
                let owner = e.get().owner.load(Ordering::Acquire);
                if owner == UNCLAIMED {
                    e.get().owner.store(seq, Ordering::Release);
                    (e.get().clone(), None)
                } else if owner < seq {
                    let state = fresh();
                    let old = e.insert(state.clone());
                    (state, Some(old))
                } else {
                    return None;
                }
            }
        };
        state.inherit(from);
        if let Some(old) = displaced {
            tracing::info!(
                "stream '{stream_id}': a newer ingest takes it back from an older one; \
                 its {} viewer(s) end and come back for the newer one",
                old.viewer_count()
            );
            old.close();
        }
        Some(state)
    }

    /// An ingest ended: take its stream out of the registry, if it is still
    /// the one registered, and close it, which ends every viewer on it.
    /// `true` when it was still registered.
    fn release(&self, state: &Arc<StreamState>) -> bool {
        let held = self
            .streams
            .remove_if(state.stream_id(), |_, current| Arc::ptr_eq(current, state))
            .is_some();
        state.close();
        held
    }

    /// Subscribe a viewer to a stream. Creates the stream if it doesn't yet
    /// exist (a viewer may connect before its ingest).
    pub fn subscribe(&self, stream_id: &str) -> StreamSubscription {
        // A closed stream is never in the registry — it is taken out first —
        // so the second lookup finds a successor or makes one. Each viewer
        // joins with the lock on the stream's entry held (see `ViewerGuard`).
        loop {
            let sub = match self.streams.get(stream_id) {
                Some(s) => s.subscribe(&self.streams),
                None => self
                    .streams
                    .entry(stream_id.to_string())
                    .or_insert_with(|| StreamState::new(self, stream_id, UNCLAIMED))
                    .subscribe(&self.streams),
            };
            if let Some(sub) = sub {
                return sub;
            }
        }
    }

    /// The counter every WebRTC session's source pin adds its tolerated
    /// other-path drops to (`WebrtcSession::count_other_paths_into`).
    pub fn other_path_counter(&self) -> Arc<AtomicU64> {
        self.other_path_datagrams.clone()
    }

    /// Datagrams the source pins dropped from a peer's other paths within
    /// their grace, relay-wide.
    pub fn other_path_datagrams(&self) -> u64 {
        self.other_path_datagrams.load(Ordering::Relaxed)
    }

    /// Frames live ingests published while a newer ingest held their stream,
    /// relay-wide.
    pub fn superseded_frames(&self) -> u64 {
        self.superseded_frames.load(Ordering::Relaxed)
    }

    /// Bytes forwarded to viewers, relay-wide, for the life of the process.
    /// A stream that ends, or is taken over, leaves what it counted here.
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    /// Viewer sessions that hit the WebRTC ingress source pin, relay-wide,
    /// for the life of the process, likewise.
    pub fn offpath_sessions(&self) -> u64 {
        self.offpath_sessions.load(Ordering::Relaxed)
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

/// Per-stream telemetry snapshot. Its counts are the stream's own, so they
/// restart with it — when it ends and is published again, and when another
/// ingest takes it over or back. The figures that never fall are the hub's
/// ([`DistributionHub::bytes_out`], [`DistributionHub::offpath_sessions`]).
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
        assert!(!hub.get("s1").unwrap().has_audio());
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
        assert!(Arc::ptr_eq(&viewer.state, &new.state.load_full()));
        // Whatever the older ingest still publishes reaches nobody.
        old.publish(EsFrame::video(1, idr_au(), true));
        assert_eq!(hub.superseded_frames(), 1);
        assert_eq!(old.end(), StreamEnd::HeldByAnother, "the newer ingest holds the stream");

        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &new.state.load_full()), "still registered");
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
        assert!(state.subscribe(&hub.streams).is_none());
        let sub = hub.subscribe("s1");
        assert!(!Arc::ptr_eq(&sub.state, &state));
        assert_eq!(sub.state.viewer_count(), 1);
        assert_eq!(state.viewer_count(), 0);
    }

    /// A bare IDR: no SPS / PPS of its own.
    fn bare_idr() -> Bytes {
        Bytes::from_static(&[0, 0, 0, 1, 0x65, 0x99, 0x77])
    }

    /// Two live ingests on one stream id, and the newer one ends first: the
    /// older one's next frame takes the stream back, so a viewer that comes
    /// back plays it, its SPS / PPS and audio carried over. While the newer
    /// one held the stream the older one's frames were dropped and counted.
    ///
    /// Before, the older ingest published into its closed stream for as long
    /// as it lived, dropping every frame without a word, and the stream id
    /// stayed dead although a publisher of it was live and connected.
    #[tokio::test]
    async fn a_live_ingest_takes_its_stream_back_when_the_newer_one_ends() {
        let hub = DistributionHub::new();
        let old = hub.claim("s1");
        old.publish(EsFrame::video(0, idr_au(), true));
        old.publish(EsFrame::audio(0, Bytes::from_static(&[0xfc, 0x01])));

        let new = hub.claim("s1");
        let mut viewer = hub.subscribe("s1");
        for k in 1..=3 {
            old.publish(EsFrame::video(k * 3000, bare_idr(), true));
        }
        assert_eq!(hub.superseded_frames(), 3, "dropped and counted");
        assert_eq!(old.dropped.load(Ordering::Relaxed), 3);
        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &new.state.load_full()));
        new.publish(EsFrame::video(5000, idr_au(), true));
        assert_eq!(viewer.rx.recv().await.unwrap().pts_90k, 5000, "the newer one plays on");

        assert_eq!(new.end(), StreamEnd::Closed, "the newer ingest's end is its stream's");
        assert!(matches!(viewer.rx.recv().await, Err(broadcast::error::RecvError::Closed)));
        drop(viewer);

        // The viewer comes back before the older ingest's next frame, and
        // waits on a stream no ingest holds; that frame takes it over.
        let mut back = hub.subscribe("s1");
        old.publish(EsFrame::video(9000, bare_idr(), true));
        let f = back.rx.try_recv().expect("the older ingest's frame reaches the viewer");
        assert_eq!(f.pts_90k, 9000, "the older ingest's media");
        assert_eq!(
            &f.data[..],
            &[
                0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, //
                0, 0, 0, 1, 0x68, 0xce, //
                0, 0, 0, 1, 0x65, 0x99, 0x77, //
            ],
            "behind the SPS / PPS it sent before it was superseded"
        );
        let stream = hub.get("s1").unwrap();
        assert!(Arc::ptr_eq(&stream, &back.state));
        assert!(Arc::ptr_eq(&stream, &old.state.load_full()));
        assert!(stream.has_audio(), "the stream's telemetry still reports audio");
        assert_eq!(old.dropped.load(Ordering::Relaxed), 0, "the episode is over");

        // A viewer joining now is primed with its keyframe.
        assert_eq!(hub.subscribe("s1").keyframe.unwrap().frame.pts_90k, 9000);
        assert_eq!(old.end(), StreamEnd::Closed);
        assert_eq!(hub.stream_count(), 0);
    }

    /// The older ingest takes back a stream nobody is waiting on as well: a
    /// fresh one, registered under the stream id, which a viewer that joins
    /// later finds.
    #[tokio::test]
    async fn a_taken_back_stream_is_there_for_the_next_viewer() {
        let hub = DistributionHub::new();
        let old = hub.claim("s1");
        drop(hub.claim("s1"));
        assert_eq!(hub.stream_count(), 0, "the newer one's end left nothing");

        old.publish(EsFrame::video(3000, idr_au(), true));
        let sub = hub.subscribe("s1");
        assert_eq!(sub.keyframe.unwrap().frame.pts_90k, 3000);
    }

    /// Two live ingests never trade the stream: the older one's frames never
    /// take it from the newer one, however many it sends, and the newer
    /// one's viewer is never ended by them.
    #[test]
    fn two_live_ingests_settle_on_the_newer_one() {
        let hub = DistributionHub::new();
        let old = hub.claim("s1");
        let new = hub.claim("s1");
        let mut viewer = hub.subscribe("s1");
        for k in 0..100 {
            old.publish(EsFrame::video(k, idr_au(), true));
            new.publish(EsFrame::video(k, idr_au(), true));
        }
        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &new.state.load_full()));
        let mut received = 0;
        while let Ok(f) = viewer.rx.try_recv() {
            assert_eq!(f.pts_90k, received, "only the newer ingest's frames, in order");
            received += 1;
        }
        assert_eq!(received, 100);
        assert_eq!(hub.superseded_frames(), 100);
    }

    /// Of several live ingests, the newest one left holds the stream: when
    /// the newest ends, an older one may take the stream back first, and a
    /// newer one still live then takes it from that one.
    #[test]
    fn of_several_live_ingests_the_newest_left_holds_the_stream() {
        let hub = DistributionHub::new();
        let a = hub.claim("s1");
        let b = hub.claim("s1");
        let c = hub.claim("s1");
        let held_by = |p: &Publisher<'_>| Arc::ptr_eq(&hub.get("s1").unwrap(), &p.state.load_full());

        a.publish(EsFrame::video(0, idr_au(), true));
        b.publish(EsFrame::video(0, idr_au(), true));
        assert!(held_by(&c));
        assert_eq!(c.end(), StreamEnd::Closed);

        a.publish(EsFrame::video(1, idr_au(), true));
        assert!(held_by(&a), "the first to publish takes it back");
        b.publish(EsFrame::video(1, idr_au(), true));
        assert!(held_by(&b), "and the newer one takes it from that one");
        a.publish(EsFrame::video(2, idr_au(), true));
        assert!(held_by(&b), "but not the reverse");

        assert_eq!(b.end(), StreamEnd::Closed);
        a.publish(EsFrame::video(3, idr_au(), true));
        assert!(held_by(&a));
    }

    /// An ingest that ends while a newer one holds its stream leaves that
    /// stream alone, even with frames of its own still coming.
    #[tokio::test]
    async fn a_superseded_ingests_end_leaves_the_newer_stream_alone() {
        let hub = DistributionHub::new();
        let old = hub.claim("s1");
        let new = hub.claim("s1");
        let mut viewer = hub.subscribe("s1");
        old.publish(EsFrame::video(1, idr_au(), true));
        assert_eq!(old.end(), StreamEnd::HeldByAnother);
        new.publish(EsFrame::video(2, idr_au(), true));
        assert_eq!(viewer.rx.recv().await.unwrap().pts_90k, 2);
        assert_eq!(hub.stream_count(), 1);
    }

    /// A stream viewers opened ahead of any ingest leaves the registry with
    /// its last viewer, so the stream count and telemetry hold only streams
    /// an ingest publishes or a viewer waits on. One an ingest holds stays.
    ///
    /// Before, the entry stayed for good: the `/watch` player and the edge's
    /// WHEP input come back for a stream whose ingest has gone, and each such
    /// return left a stream counted live with nothing published.
    #[test]
    fn an_unclaimed_stream_leaves_with_its_last_viewer() {
        let hub = DistributionHub::new();
        let a = hub.subscribe("s1");
        let b = hub.subscribe("s1");
        assert_eq!(hub.stream_count(), 1);
        drop(a);
        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &b.state), "a viewer is still waiting");
        let state = b.state.clone();
        drop(b);
        assert_eq!(hub.stream_count(), 0);
        assert!(hub.snapshot().is_empty());
        assert!(state.subscribe(&hub.streams).is_none(), "and it is closed");

        // One an ingest took over stays when its viewers leave.
        let c = hub.subscribe("s2");
        let publisher = hub.claim("s2");
        drop(c);
        assert!(Arc::ptr_eq(&hub.get("s2").unwrap(), &publisher.state.load_full()));
        drop(publisher);
        assert_eq!(hub.stream_count(), 0);
    }

    /// The last viewer of an unclaimed stream leaving races an ingest
    /// claiming it, and viewers joining it: the stream is taken out only
    /// when, under the registry's entry lock, no ingest holds it and no
    /// viewer is on it. So a claimed stream is never taken out from under
    /// its ingest — a viewer that joins after the claim is on the ingest's
    /// stream — and nothing is left behind.
    #[test]
    fn the_last_viewer_leaving_never_takes_a_claimed_stream_out() {
        const ROUNDS: usize = 20_000;
        let hub = DistributionHub::new();
        std::thread::scope(|s| {
            for _ in 0..2 {
                s.spawn(|| {
                    for _ in 0..ROUNDS {
                        drop(hub.subscribe("s1"));
                    }
                });
            }
            s.spawn(|| {
                for k in 0..ROUNDS as u64 {
                    let publisher = hub.claim("s1");
                    let sub = hub.subscribe("s1");
                    assert!(
                        Arc::ptr_eq(&sub.state, &publisher.state.load_full()),
                        "round {k}: a viewer joined after the claim is on another stream"
                    );
                    publisher.publish(EsFrame::video(k, idr_au(), true));
                    assert!(sub.state.tx.load().is_some(), "round {k}: the stream closed");
                }
            });
        });
        assert_eq!(hub.stream_count(), 0);
        assert_eq!(hub.superseded_frames(), 0);
    }

    /// A superseded ingest that is ending — its session gone, flushing the
    /// last unit its depacketizer held — never takes its stream back, so it
    /// churns nobody's viewers.
    ///
    /// Before, that flush took the stream back for the instant until the
    /// ingest's end closed it again: viewers waiting on a stream no ingest
    /// held got a stale frame and then "stream closed", and an older live
    /// ingest that had taken the stream back had it closed under its viewers.
    #[test]
    fn an_ending_ingest_never_takes_its_stream_back() {
        use broadcast::error::TryRecvError;

        // Viewers wait on a stream no ingest holds: the newer ingest ended,
        // and the superseded one's session ends before it sent again.
        let hub = DistributionHub::new();
        let dead = hub.claim("s1");
        dead.publish(EsFrame::video(0, idr_au(), true));
        assert_eq!(hub.claim("s1").end(), StreamEnd::Closed);
        let mut waiting = hub.subscribe("s1");
        dead.mark_ending();
        dead.publish(EsFrame::video(3000, idr_au(), true));
        assert!(
            matches!(waiting.rx.try_recv(), Err(TryRecvError::Empty)),
            "the ending ingest's frame reaches nobody"
        );
        assert_eq!(dead.end(), StreamEnd::Unheld);
        assert!(
            matches!(waiting.rx.try_recv(), Err(TryRecvError::Empty)),
            "and the waiting viewer is not ended"
        );
        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &waiting.state));
        let next = hub.claim("s1");
        next.publish(EsFrame::video(6000, idr_au(), true));
        assert_eq!(waiting.rx.try_recv().unwrap().pts_90k, 6000, "it plays the next ingest");

        // An older live ingest took the stream back once the newest ended;
        // an ingest between the two, superseded too, then ends.
        let hub = DistributionHub::new();
        let older = hub.claim("s1");
        let dead = hub.claim("s1");
        assert_eq!(hub.claim("s1").end(), StreamEnd::Closed);
        older.publish(EsFrame::video(0, idr_au(), true));
        let mut viewer = hub.subscribe("s1");
        dead.mark_ending();
        dead.publish(EsFrame::video(3000, idr_au(), true));
        assert_eq!(dead.end(), StreamEnd::HeldByAnother);
        older.publish(EsFrame::video(6000, idr_au(), true));
        assert_eq!(
            viewer.rx.try_recv().unwrap().pts_90k,
            6000,
            "the older ingest's viewer plays on, never ended"
        );
        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &older.state.load_full()));
        assert!(Arc::ptr_eq(&viewer.state, &older.state.load_full()));
    }

    /// An ingest's end says what it found of its stream: its own, which
    /// closed; held by another ingest — the newer one that took it, or an
    /// older one that took it back since — which plays on; or held by none,
    /// whether nothing is registered under the stream id or viewers wait
    /// there for the next ingest.
    ///
    /// Before, any end that did not hold the stream read as a newer ingest
    /// holding it, which plays on, while its viewers were black.
    #[test]
    fn an_ingests_end_says_what_holds_the_stream() {
        let hub = DistributionHub::new();
        assert_eq!(hub.claim("s1").end(), StreamEnd::Closed);

        // A newer ingest holds the stream.
        let old = hub.claim("s1");
        let new = hub.claim("s1");
        assert_eq!(old.end(), StreamEnd::HeldByAnother);
        assert_eq!(new.end(), StreamEnd::Closed);

        // An older ingest took it back once the newest had ended.
        let older = hub.claim("s1");
        let middle = hub.claim("s1");
        assert_eq!(hub.claim("s1").end(), StreamEnd::Closed);
        older.publish(EsFrame::video(0, idr_au(), true));
        assert_eq!(middle.end(), StreamEnd::HeldByAnother);
        assert_eq!(older.end(), StreamEnd::Closed);

        // Nothing is registered under the stream id.
        let old = hub.claim("s1");
        assert_eq!(hub.claim("s1").end(), StreamEnd::Closed);
        assert!(hub.get("s1").is_none());
        assert_eq!(old.end(), StreamEnd::Unheld);

        // Viewers wait on the stream id, which no ingest holds.
        let old = hub.claim("s1");
        assert_eq!(hub.claim("s1").end(), StreamEnd::Closed);
        let waiting = hub.subscribe("s1");
        assert_eq!(old.end(), StreamEnd::Unheld);
        assert!(Arc::ptr_eq(&hub.get("s1").unwrap(), &waiting.state), "they wait on");
        assert_eq!(StreamEnd::Unheld.held_by(), "none");
    }

    /// The SPS / PPS a superseded ingest sends while its frames are dropped
    /// are the ones a stream it takes back goes out behind: a source that
    /// changed them meanwhile — a resolution change, the new sets sent once,
    /// with an IDR that was dropped — has its next bare IDR carry the new
    /// ones.
    ///
    /// Before, the take-back inherited the sets from before the stream was
    /// taken, and every bare IDR went out behind the old SPS, undecodable.
    #[test]
    fn a_take_back_goes_out_behind_the_parameter_sets_sent_while_superseded() {
        let hub = DistributionHub::new();
        let old = hub.claim("s1");
        old.publish(EsFrame::video(0, idr_au(), true));
        let new = hub.claim("s1");

        let changed = Bytes::from_static(&[
            0, 0, 0, 1, 0x67, 0x64, 0x00, 0x28, //
            0, 0, 0, 1, 0x68, 0xee, 0x3c, //
            0, 0, 0, 1, 0x65, 0x88, 0x84, //
        ]);
        old.publish(EsFrame::video(3000, changed, true));
        old.publish(EsFrame::audio(3000, Bytes::from_static(&[0xfc, 0x01])));
        assert_eq!(hub.superseded_frames(), 2, "dropped");

        assert_eq!(new.end(), StreamEnd::Closed);
        let mut viewer = hub.subscribe("s1");
        old.publish(EsFrame::video(6000, bare_idr(), true));
        let f = viewer.rx.try_recv().expect("the older ingest takes the stream back");
        assert_eq!(
            &f.data[..],
            &[
                0, 0, 0, 1, 0x67, 0x64, 0x00, 0x28, //
                0, 0, 0, 1, 0x68, 0xee, 0x3c, //
                0, 0, 0, 1, 0x65, 0x99, 0x77, //
            ],
            "behind the SPS / PPS its source sent last"
        );
    }

    /// The relay-wide bytes-out and off-path counts never fall — not when a
    /// viewer leaves, a stream ends, a newer ingest takes one over, the older
    /// one takes it back, or a stream no ingest ever held goes with its last
    /// viewer — and are the sum over every stream there has been, what a
    /// viewer counts on one that has closed included.
    ///
    /// Until 2026-11 `/metrics` exported the sum over the streams the hub held
    /// as two counters, so what a stream had counted left them with it: when
    /// it ended, when a newer ingest's took its place (a take-over, or a
    /// take-back from an older ingest), and when it went with its last viewer.
    #[test]
    fn the_relay_wide_counts_never_fall_and_sum_every_stream_there_has_been() {
        struct Watch<'a> {
            hub: &'a DistributionHub,
            /// Every stream there has been, so far.
            ever: Vec<Arc<StreamState>>,
            /// What was counted, and so what the hub must read, always.
            counted: (u64, u64),
        }
        impl Watch<'_> {
            /// A viewer of `state` is sent `bytes`, and `offpath` of them hit
            /// the source pin.
            fn count(&mut self, state: &Arc<StreamState>, bytes: u64, offpath: u64) {
                if !self.ever.iter().any(|s| Arc::ptr_eq(s, state)) {
                    self.ever.push(state.clone());
                }
                state.add_bytes_out(bytes);
                for _ in 0..offpath {
                    state.add_offpath_session();
                }
                self.counted.0 += bytes;
                self.counted.1 += offpath;
                self.check("a viewer counted");
            }
            fn check(&self, when: &str) {
                assert_eq!((self.hub.bytes_out(), self.hub.offpath_sessions()), self.counted, "{when}");
                let sum = self
                    .ever
                    .iter()
                    .fold((0, 0), |(b, o), s| (b + s.bytes_out(), o + s.offpath_sessions()));
                assert_eq!(sum, self.counted, "{when}: the sum over every stream there has been");
            }
        }

        let hub = DistributionHub::new();
        let mut w = Watch { hub: &hub, ever: Vec::new(), counted: (0, 0) };
        w.check("nothing counted");

        let old = hub.claim("s1");
        let viewer = hub.subscribe("s1");
        w.count(&viewer.state, 1000, 1);
        drop(viewer);
        w.check("a viewer left");
        let other = hub.claim("s2");
        w.count(&hub.subscribe("s2").state, 70, 2);

        let old_viewer = hub.subscribe("s1");
        let new = hub.claim("s1");
        w.check("a newer ingest took the stream over");
        // The older stream's viewer takes what was sent before it closed.
        w.count(&old_viewer.state, 500, 1);
        w.count(&hub.subscribe("s1").state, 30, 1);

        assert_eq!(new.end(), StreamEnd::Closed);
        w.check("the newer ingest's stream ended");
        old.publish(EsFrame::video(0, idr_au(), true));
        w.check("the older ingest took the stream back");
        w.count(&hub.subscribe("s1").state, 9, 1);

        // A newer ingest displaces one that took the stream back.
        let a = hub.claim("s3");
        let b = hub.claim("s3");
        assert_eq!(hub.claim("s3").end(), StreamEnd::Closed);
        a.publish(EsFrame::video(0, idr_au(), true));
        w.count(&hub.subscribe("s3").state, 11, 1);
        b.publish(EsFrame::video(0, idr_au(), true));
        w.check("a newer ingest took it back from an older one");
        w.count(&hub.subscribe("s3").state, 13, 1);

        let waiting = hub.subscribe("s4");
        w.count(&waiting.state, 0, 1);
        drop(waiting);
        w.check("a stream no ingest held left with its last viewer");

        drop((old, other, a, b));
        assert_eq!(hub.stream_count(), 0);
        w.check("every stream ended");
        assert_eq!(w.counted, (1633, 9));
        assert_eq!(w.ever.len(), 7, "each a stream of its own");
    }

    /// A stream's own counts are its own: they carry on over an ingest that
    /// takes a stream viewers wait on, and start from nothing in the one a
    /// newer ingest takes over and the one an older one takes back. A viewer
    /// of a closed stream goes on counting into that one until it ends, so a
    /// figure copied at the take-over would be neither stream's.
    #[test]
    fn a_streams_own_counts_start_again_at_a_take_over_and_a_take_back() {
        let hub = DistributionHub::new();
        let counts = || {
            let snap = hub.snapshot();
            assert_eq!(snap.len(), 1);
            let s = &snap[0];
            (s.frames_in, s.bytes_in, s.bytes_out, s.offpath_sessions)
        };
        let count = |state: &StreamState| {
            state.add_bytes_out(100);
            state.add_offpath_session();
        };
        let au = idr_au().len() as u64;

        let waiting = hub.subscribe("s1");
        waiting.state.add_offpath_session();
        let old = hub.claim("s1");
        assert_eq!(counts(), (0, 0, 0, 1), "the stream viewers waited on, as it was");
        old.publish(EsFrame::video(0, idr_au(), true));
        count(&waiting.state);
        assert_eq!(counts(), (1, au, 100, 2));

        let new = hub.claim("s1");
        assert_eq!(counts(), (0, 0, 0, 0), "a newer ingest's stream");
        count(&waiting.state);
        assert_eq!(counts(), (0, 0, 0, 0), "which the closed one's viewer is not on");

        assert_eq!(new.end(), StreamEnd::Closed);
        old.publish(EsFrame::video(0, idr_au(), true));
        assert_eq!(counts(), (1, au, 0, 0), "the stream the older ingest took back");
        assert_eq!((hub.bytes_out(), hub.offpath_sessions()), (200, 3));
    }
}
