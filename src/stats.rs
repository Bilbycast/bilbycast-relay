// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use serde::Serialize;
use uuid::Uuid;

/// Per-tunnel stats tracked atomically.
pub struct TunnelStats {
    pub bytes_ingress: AtomicU64,
    pub bytes_egress: AtomicU64,
    pub tcp_streams_total: AtomicU64,
    pub tcp_streams_active: AtomicU64,
    pub udp_datagrams_total: AtomicU64,
    pub created_at: Instant,
}

impl TunnelStats {
    pub fn new() -> Self {
        Self {
            bytes_ingress: AtomicU64::new(0),
            bytes_egress: AtomicU64::new(0),
            tcp_streams_total: AtomicU64::new(0),
            tcp_streams_active: AtomicU64::new(0),
            udp_datagrams_total: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    pub fn snapshot(&self) -> TunnelStatsSnapshot {
        TunnelStatsSnapshot {
            bytes_ingress: self.bytes_ingress.load(Ordering::Relaxed),
            bytes_egress: self.bytes_egress.load(Ordering::Relaxed),
            tcp_streams_total: self.tcp_streams_total.load(Ordering::Relaxed),
            tcp_streams_active: self.tcp_streams_active.load(Ordering::Relaxed),
            udp_datagrams_total: self.udp_datagrams_total.load(Ordering::Relaxed),
            uptime_secs: self.created_at.elapsed().as_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatsSnapshot {
    pub bytes_ingress: u64,
    pub bytes_egress: u64,
    pub tcp_streams_total: u64,
    pub tcp_streams_active: u64,
    pub udp_datagrams_total: u64,
    pub uptime_secs: u64,
}

/// What all the tunnels a router has held since the relay started have
/// counted. No figure falls while the relay runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelTotals {
    pub bytes_ingress: u64,
    pub bytes_egress: u64,
    pub tcp_streams_total: u64,
    pub udp_datagrams_total: u64,
}

impl TunnelTotals {
    pub fn bytes_forwarded(&self) -> u64 {
        self.bytes_ingress + self.bytes_egress
    }

    fn add(&mut self, stats: &TunnelStats) {
        self.bytes_ingress += stats.bytes_ingress.load(Ordering::Relaxed);
        self.bytes_egress += stats.bytes_egress.load(Ordering::Relaxed);
        self.tcp_streams_total += stats.tcp_streams_total.load(Ordering::Relaxed);
        self.udp_datagrams_total += stats.udp_datagrams_total.load(Ordering::Relaxed);
    }
}

/// An entry of a router's map, and the stats it counts into.
pub trait Counted {
    fn stats(&self) -> &Arc<TunnelStats>;
}

/// The counts of the tunnels that have left a router's map. With the counts of
/// those still in it they make the router's [`TunnelTotals`].
///
/// A datagram is counted in its own tunnel's atomics only. A relay-wide atomic
/// beside them would be one cache line written by every forwarding thread, so
/// a tunnel's counts are added up here instead, once it has left the map.
///
/// Every method takes the lock first and the map's second, so none may be
/// called with a reference into the map held.
#[derive(Default)]
pub struct DepartedTunnels(Mutex<Departed>);

#[derive(Default)]
struct Departed {
    /// The sum of the tunnels nothing holds any more.
    finished: TunnelTotals,
    /// The tunnels a forwarding task may still hold. One that looked its
    /// tunnel up before it left the map counts into it afterwards.
    leaving: Vec<Arc<TunnelStats>>,
}

impl DepartedTunnels {
    /// Take a tunnel out of `held`. Every removal from a router's map goes
    /// through here or through [`Self::remove_if`].
    pub fn remove<T: Counted>(&self, held: &DashMap<Uuid, T>, id: &Uuid) -> Option<T> {
        self.remove_if(held, id, |_| true)
    }

    /// Take a tunnel out of `held` if it is `gone`. That is asked under the
    /// map's lock: nothing reaches the tunnel through the map between the
    /// answer and the removal. The tunnel goes on `leaving` under that lock
    /// too, and the lock here spans both, so [`Self::totals`] finds it in
    /// `held` or in `leaving`, never in both or in neither.
    pub fn remove_if<T: Counted>(
        &self,
        held: &DashMap<Uuid, T>,
        id: &Uuid,
        gone: impl FnOnce(&T) -> bool,
    ) -> Option<T> {
        let mut departed = self.0.lock().unwrap();
        let Departed { finished, leaving } = &mut *departed;
        leaving.retain_mut(|stats| match Arc::get_mut(stats) {
            // Nothing else holds it, so nothing counts into it again.
            Some(stats) => {
                finished.add(stats);
                false
            }
            None => true,
        });
        let removed = held.remove_if(id, |_, tunnel| {
            let gone = gone(tunnel);
            if gone {
                leaving.push(tunnel.stats().clone());
            }
            gone
        });
        removed.map(|(_, tunnel)| tunnel)
    }

    /// What every tunnel that is or has been in `held` has counted.
    pub fn totals<T: Counted>(&self, held: &DashMap<Uuid, T>) -> TunnelTotals {
        let departed = self.0.lock().unwrap();
        let mut totals = departed.finished;
        for stats in &departed.leaving {
            totals.add(stats);
        }
        for tunnel in held {
            totals.add(tunnel.stats());
        }
        totals
    }
}

/// Bandwidth sample for throughput estimation.
struct BandwidthSample {
    total_bytes: u64,
    timestamp: Instant,
}

/// Global relay stats.
pub struct RelayStats {
    pub start_time: Instant,
    /// High watermark: peak simultaneous active tunnels.
    pub peak_tunnels: AtomicU64,
    /// High watermark: peak simultaneous connected edges.
    pub peak_edges: AtomicU64,
    /// Total QUIC connections accepted since startup.
    pub connections_total: AtomicU64,
    /// Previous bandwidth sample for throughput calculation.
    prev_sample: Mutex<BandwidthSample>,
    /// Manager-link state, surfaced on the relay's OWN local REST API
    /// (/health, /api/v1/stats, /metrics). This is purely local
    /// observability — it does NOT change the WS protocol or anything the
    /// relay reports to the manager. Set by the manager-client loop in
    /// `manager/client.rs`: `true` on successful auth, `false` on
    /// disconnect/reconnect. Lock-free.
    ///
    /// When `manager` is not configured at all, `manager_configured` is
    /// false and the surfaced object is omitted.
    pub manager_configured: AtomicBool,
    /// Whether the manager WS link is currently up (authenticated).
    pub manager_connected: AtomicBool,
    /// Epoch-millis of the last successful manager auth (0 if never).
    pub manager_last_connect_ms: AtomicU64,
    /// Epoch-millis of the last manager disconnect (0 if never disconnected
    /// since the last connect). Used to compute `disconnected_secs`.
    pub manager_last_disconnect_ms: AtomicU64,

    // ── Viewer-distribution subsystem telemetry ───────────────────────────
    // Updated periodically by the distribution subsystem's telemetry task
    // (when the `viewer-distribution` feature is on AND enabled). Read by the
    // manager-client health builder + the local REST/metrics surfaces. Always
    // present in the struct so the base build compiles unchanged; stays zero /
    // false on a plain forwarder.
    /// Whether the distribution subsystem is running.
    pub distribution_enabled: AtomicBool,
    /// Live distributed streams.
    pub distribution_streams: AtomicU64,
    /// Total concurrent viewers across all streams.
    pub distribution_viewers: AtomicU64,
    /// Total bytes fanned out to viewers (pre-SRTP ES accounting), on every
    /// stream there has been: it never falls.
    pub distribution_bytes_out: AtomicU64,
    /// Bytes currently held in the LL-HLS origin cache.
    pub distribution_origin_bytes: AtomicU64,
    /// Per-stream breakdown of the above. An `ArcSwap` rather than an atomic
    /// because it is a list; published on the same slow telemetry tick, read
    /// by the health builder — never on a media path.
    pub distribution_origin_streams: arc_swap::ArcSwap<Vec<OriginStreamUsage>>,
    /// What each viewer's player last reported about its playback. Published
    /// on the same slow tick as the per-stream list, for the same reason, and
    /// kept out of [`DistributionStatsSnapshot`]: only the health builder
    /// reads it, and the 1 s stats tick and `/metrics` would otherwise copy
    /// every report to read five counters.
    pub distribution_viewer_metrics: arc_swap::ArcSwap<ViewerMetricsSnapshot>,
    /// Viewer sessions that had a datagram refused by the WebRTC ingress
    /// source pin (`webrtc::session::PeerPin`). One per session, not per
    /// datagram. Non-zero means a source-spoofed ICE reflection attempt, or a
    /// viewer whose IP changed mid-session. Relay-wide, on every stream there
    /// has been: it never falls.
    pub distribution_offpath_sessions: AtomicU64,
    /// Datagrams the WebRTC ingress source pin dropped from another of a
    /// peer's paths inside its grace, which raised no alarm (an off-path
    /// datagram past the grace raises it and counts in
    /// `distribution_offpath_sessions` instead). Relay-wide, every session
    /// kind — WHEP viewers, WHIP ingests, cascade pulls.
    pub distribution_other_path_datagrams: AtomicU64,
    /// Frames live ingests published while a newer ingest held their stream,
    /// dropped. Non-zero while two publishers push one stream id.
    pub distribution_superseded_frames: AtomicU64,

    // ── Optional subsystems that stopped ──
    //
    // The viewer-distribution subsystem and the native-UDP plane are optional:
    // when either stops, the relay keeps forwarding QUIC tunnels rather than
    // exiting (relay#15), and records why here. Distribution's is never
    // cleared — it is not restarted in-process. The native-UDP plane's is
    // cleared when a retried bind succeeds (`supervise::supervise_udp_relay`).
    /// Why the distribution subsystem stopped. While set, no telemetry sample
    /// is published, so the `viewer-distribution` / `origin-policy`
    /// capabilities are withdrawn and the manager stops pushing to a dead
    /// origin.
    distribution_stopped: arc_swap::ArcSwapOption<String>,
    /// Why the native-UDP plane stopped. While set, `udp-relay` is withdrawn.
    udp_relay_stopped: arc_swap::ArcSwapOption<String>,
}

/// What one origin stream is costing on disk.
///
/// `origin_bytes` alone says the node is full but not which stream filled it,
/// which is the question actually asked at that moment. Plain data (no
/// feature-gated types) so this compiles on a plain forwarder build.
#[derive(Debug, Clone, Serialize)]
pub struct OriginStreamUsage {
    pub stream: String,
    pub segments: u64,
    pub bytes: u64,
    /// Seconds since the last successful PUT.
    pub idle_secs: u64,
    /// Whether a per-stream retention override is in force, so the operator
    /// can tell a deliberately long window from a drifted one.
    pub policy_overridden: bool,
}

/// What one viewer's player reported about its own playback, as the relay
/// carries it to the manager on the health tick.
///
/// Plain data, no feature-gated types, so a plain forwarder build compiles the
/// health builder unchanged. The fields are the player's own measurements —
/// the relay checks the credential and bounds the numbers, nothing more. See
/// `distribution::origin::metrics` for the surface that collects them.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ViewerMetricReport {
    /// The origin stream the player is reporting against.
    pub stream: String,
    /// The player's own id for its tab, kept across reloads. Opaque; the
    /// manager joins it to a portal login through the beat, which carries the
    /// same id.
    pub client: String,
    /// Seconds since the relay received this report.
    ///
    /// No address, deliberately. The relay sits behind a TLS terminator, so
    /// the peer it sees is loopback for every viewer; and this list rides the
    /// relay's health message, which a manager that predates the viewer roll
    /// keeps whole and shows to anyone with View on the relay — an address
    /// here would walk past the Admin-only gate the manager keeps on a
    /// viewer's address.
    pub age_secs: u64,
    /// `full`, `balanced` or `low`.
    pub quality: String,
    /// Whether the page dropped itself to Low after repeated stalls.
    pub auto_low: bool,
    /// `live`, `scrub`, `jog` or `shuttle`.
    pub mode: String,
    /// Whether the picture was running when the report was taken.
    pub playing: bool,
    /// Seconds of hold-back behind the live edge the player is aiming for.
    pub holdback_s: f32,
    /// Seconds of media buffered ahead of the playhead.
    pub ahead_s: f32,
    /// Seconds between the playhead and the end of the seekable range.
    pub behind_live_s: f32,
    /// hls.js's bandwidth estimate, kbit/s. 0 when it has none yet.
    pub bw_kbps: u32,
    /// Stall episodes since the page loaded, and in the last five minutes.
    pub stalls: u32,
    pub stalls_5m: u32,
    /// Rebuffer holds (picture paused to refill) likewise, and the total time
    /// held, milliseconds.
    pub holds: u32,
    pub holds_5m: u32,
    pub hold_ms: u32,
    /// Reconnect attempts after hls.js called an error fatal.
    pub reconnects: u32,
    pub reconnects_5m: u32,
    /// Frames the browser decoded and dropped, from `getVideoPlaybackQuality`.
    pub decoded: u32,
    pub dropped: u32,
    /// The last main-rendition segment: time to first byte, total load time,
    /// size.
    pub seg_ttfb_ms: u32,
    pub seg_load_ms: u32,
    pub seg_kb: u32,
    /// Seconds since the page loaded.
    pub up_s: u32,
    /// The report's own version. 2 and later carry the last-minute counts,
    /// the event history, the preferred delay and `catching_up`; the manager
    /// judges an older report by the five-minute counts alone. 0 from a page
    /// that predates the field.
    pub v: u32,
    /// The same three counters over the last minute, so a viewer who has
    /// recovered is not read as struggling for five.
    pub stalls_1m: u32,
    pub holds_1m: u32,
    pub reconnects_1m: u32,
    /// Seconds behind live the viewer prefers (their setting); `holdback_s`
    /// is where the link has pushed it for now.
    pub delay_pref_s: f32,
    /// Whether the player is running a touch fast to win back delay.
    pub catching_up: bool,
    /// The most recent trouble, oldest first: at most eight.
    pub events: Vec<ViewerEvent>,
    /// The browser, truncated — enough to tell a tablet from a desktop.
    pub ua: String,
}

/// One stall, rebuffer pause, reconnect or downgrade a player went through.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ViewerEvent {
    /// Seconds before the report it happened.
    pub ago_s: u32,
    /// `stall`, `hold`, `reconnect` or `downgrade`.
    pub kind: String,
    /// Seconds buffered ahead when it happened.
    pub ahead_s: f32,
    /// For a hold: the buffer it waited for, and how long it held (ms).
    pub goal_s: f32,
    pub ms: u32,
}

/// How one stream fared in the cut of playback reports carried on health.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ViewerMetricStream {
    pub stream: String,
    /// Clients holding a live report for this stream.
    pub reporting: usize,
    /// How many of those reports are in the list. Fewer than `reporting` when
    /// the cut left some out, which the manager must read as "not listed",
    /// never as "not reporting".
    pub listed: usize,
}

/// The players' reports as the health message carries them: the list itself,
/// shared fairly across streams, and per stream how much of it was cut.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ViewerMetricsSnapshot {
    /// Grouped by stream, freshest first within each.
    pub reports: Vec<ViewerMetricReport>,
    /// One entry per stream with at least one live report.
    pub streams: Vec<ViewerMetricStream>,
}

/// Snapshot of the distribution subsystem telemetry.
#[derive(Debug, Clone, Serialize)]
pub struct DistributionStatsSnapshot {
    pub enabled: bool,
    pub streams: u64,
    pub viewers: u64,
    pub bytes_out: u64,
    pub origin_bytes: u64,
    pub offpath_sessions: u64,
    pub other_path_datagrams: u64,
    pub superseded_frames: u64,
    /// Per-stream breakdown of `origin_bytes`.
    pub origin_streams: Vec<OriginStreamUsage>,
}

/// Current wall-clock epoch in milliseconds (saturating to 0 before 1970).
pub fn now_epoch_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Snapshot of the manager-link state for local surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct ManagerLinkStatus {
    /// Whether the manager WS link is currently authenticated/up.
    pub connected: bool,
    /// Seconds since the link went down (0 while connected or never down).
    pub disconnected_secs: u64,
    /// True when the link is down but the relay is actively retrying
    /// (the reconnect loop runs whenever a manager is configured).
    pub reconnecting: bool,
}

impl RelayStats {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            peak_tunnels: AtomicU64::new(0),
            peak_edges: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            prev_sample: Mutex::new(BandwidthSample {
                total_bytes: 0,
                timestamp: now,
            }),
            manager_configured: AtomicBool::new(false),
            manager_connected: AtomicBool::new(false),
            manager_last_connect_ms: AtomicU64::new(0),
            manager_last_disconnect_ms: AtomicU64::new(0),
            distribution_enabled: AtomicBool::new(false),
            distribution_streams: AtomicU64::new(0),
            distribution_viewers: AtomicU64::new(0),
            distribution_bytes_out: AtomicU64::new(0),
            distribution_origin_bytes: AtomicU64::new(0),
            distribution_origin_streams: arc_swap::ArcSwap::from_pointee(Vec::new()),
            distribution_viewer_metrics: arc_swap::ArcSwap::from_pointee(
                ViewerMetricsSnapshot::default(),
            ),
            distribution_offpath_sessions: AtomicU64::new(0),
            distribution_other_path_datagrams: AtomicU64::new(0),
            distribution_superseded_frames: AtomicU64::new(0),
            distribution_stopped: arc_swap::ArcSwapOption::empty(),
            udp_relay_stopped: arc_swap::ArcSwapOption::empty(),
        }
    }

    /// Publish a distribution telemetry sample (called by the subsystem).
    pub fn set_distribution(
        &self,
        streams: u64,
        viewers: u64,
        bytes_out: u64,
        origin_bytes: u64,
        offpath_sessions: u64,
        origin_streams: Vec<OriginStreamUsage>,
    ) {
        if self.distribution_stopped().is_some() {
            return;
        }
        self.distribution_origin_streams
            .store(std::sync::Arc::new(origin_streams));
        self.distribution_enabled.store(true, Ordering::Relaxed);
        self.distribution_streams.store(streams, Ordering::Relaxed);
        self.distribution_viewers.store(viewers, Ordering::Relaxed);
        self.distribution_bytes_out.store(bytes_out, Ordering::Relaxed);
        self.distribution_origin_bytes.store(origin_bytes, Ordering::Relaxed);
        self.distribution_offpath_sessions.store(offpath_sessions, Ordering::Relaxed);
    }

    /// Publish the distribution hub's relay-wide drop counters (called by the
    /// subsystem on the same tick as [`Self::set_distribution`]).
    pub fn set_distribution_drops(&self, other_path_datagrams: u64, superseded_frames: u64) {
        self.distribution_other_path_datagrams
            .store(other_path_datagrams, Ordering::Relaxed);
        self.distribution_superseded_frames
            .store(superseded_frames, Ordering::Relaxed);
    }

    /// Publish what the viewers' players last reported (called by the
    /// subsystem on its telemetry tick).
    pub fn set_viewer_metrics(&self, snapshot: ViewerMetricsSnapshot) {
        self.distribution_viewer_metrics
            .store(std::sync::Arc::new(snapshot));
    }

    /// The players' reports last published, shared rather than copied.
    pub fn viewer_metrics(&self) -> std::sync::Arc<ViewerMetricsSnapshot> {
        self.distribution_viewer_metrics.load_full()
    }

    /// Snapshot the distribution telemetry. Returns `None` when the subsystem
    /// is not running (so the field is omitted from health/REST payloads).
    pub fn distribution_snapshot(&self) -> Option<DistributionStatsSnapshot> {
        // The stopped check is what closes the race with a telemetry tick
        // already past `set_distribution`'s own check when the stop lands.
        if !self.distribution_enabled.load(Ordering::Relaxed)
            || self.distribution_stopped().is_some()
        {
            return None;
        }
        Some(DistributionStatsSnapshot {
            enabled: true,
            streams: self.distribution_streams.load(Ordering::Relaxed),
            viewers: self.distribution_viewers.load(Ordering::Relaxed),
            bytes_out: self.distribution_bytes_out.load(Ordering::Relaxed),
            origin_bytes: self.distribution_origin_bytes.load(Ordering::Relaxed),
            offpath_sessions: self.distribution_offpath_sessions.load(Ordering::Relaxed),
            other_path_datagrams: self.distribution_other_path_datagrams.load(Ordering::Relaxed),
            superseded_frames: self.distribution_superseded_frames.load(Ordering::Relaxed),
            origin_streams: self.distribution_origin_streams.load().as_ref().clone(),
        })
    }

    /// Record that the distribution subsystem stopped, and why. Withdraws its
    /// telemetry (and with it the capabilities the manager gates on) for the
    /// rest of the process's life.
    pub fn mark_distribution_stopped(&self, reason: String) {
        self.distribution_stopped.store(Some(std::sync::Arc::new(reason)));
        self.distribution_enabled.store(false, Ordering::Relaxed);
    }

    /// Why the distribution subsystem stopped, if it did.
    pub fn distribution_stopped(&self) -> Option<std::sync::Arc<String>> {
        self.distribution_stopped.load_full()
    }

    /// Record that the native-UDP plane stopped, and why.
    pub fn mark_udp_relay_stopped(&self, reason: String) {
        self.udp_relay_stopped.store(Some(std::sync::Arc::new(reason)));
    }

    /// Why the native-UDP plane stopped, if it did.
    pub fn udp_relay_stopped(&self) -> Option<std::sync::Arc<String>> {
        self.udp_relay_stopped.load_full()
    }

    /// The native-UDP plane is running again.
    pub fn clear_udp_relay_stopped(&self) {
        self.udp_relay_stopped.store(None);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Record a successful manager authentication.
    pub fn mark_manager_connected(&self) {
        self.manager_connected.store(true, Ordering::Relaxed);
        self.manager_last_connect_ms
            .store(now_epoch_ms(), Ordering::Relaxed);
        self.manager_last_disconnect_ms.store(0, Ordering::Relaxed);
    }

    /// Record a manager-link disconnect. Idempotent — only stamps the
    /// disconnect time on the first transition from connected → down so
    /// `disconnected_secs` measures from the actual drop, not each retry.
    pub fn mark_manager_disconnected(&self) {
        let was_connected = self.manager_connected.swap(false, Ordering::Relaxed);
        if was_connected || self.manager_last_disconnect_ms.load(Ordering::Relaxed) == 0 {
            self.manager_last_disconnect_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Snapshot the manager-link state for local REST/metrics surfaces.
    /// Returns `None` when no manager is configured (the link object is
    /// then omitted from the response).
    pub fn manager_link_status(&self) -> Option<ManagerLinkStatus> {
        if !self.manager_configured.load(Ordering::Relaxed) {
            return None;
        }
        let connected = self.manager_connected.load(Ordering::Relaxed);
        let disconnected_secs = if connected {
            0
        } else {
            let last = self.manager_last_disconnect_ms.load(Ordering::Relaxed);
            if last == 0 {
                0
            } else {
                now_epoch_ms().saturating_sub(last) / 1000
            }
        };
        Some(ManagerLinkStatus {
            connected,
            disconnected_secs,
            // A configured manager always has the reconnect loop running,
            // so any not-connected state is an active retry.
            reconnecting: !connected,
        })
    }

    /// Update peak watermarks given current counts.
    pub fn update_peaks(&self, current_tunnels: u64, current_edges: u64) {
        self.peak_tunnels
            .fetch_max(current_tunnels, Ordering::Relaxed);
        self.peak_edges
            .fetch_max(current_edges, Ordering::Relaxed);
    }

    /// Compute current aggregate throughput in bits per second.
    /// Call this at a regular interval (e.g., 1s) with the current total bytes forwarded.
    pub fn compute_bandwidth_bps(&self, current_total_bytes: u64) -> u64 {
        let mut prev = self.prev_sample.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(prev.timestamp);
        let elapsed_secs = elapsed.as_secs_f64();

        let bps = if elapsed_secs > 0.1 {
            let delta_bytes = current_total_bytes.saturating_sub(prev.total_bytes);
            (delta_bytes as f64 / elapsed_secs * 8.0) as u64
        } else {
            0
        };

        prev.total_bytes = current_total_bytes;
        prev.timestamp = now;

        bps
    }
}

#[cfg(test)]
mod tunnel_totals_tests {
    use super::*;

    impl Counted for Arc<TunnelStats> {
        fn stats(&self) -> &Arc<TunnelStats> {
            self
        }
    }

    /// Count `n` on a tunnel, weighted so that no two counters, and no two
    /// sums of them, can be taken for each other.
    fn count(stats: &TunnelStats, n: u64) {
        stats.bytes_ingress.fetch_add(n, Ordering::Relaxed);
        stats.bytes_egress.fetch_add(100 * n, Ordering::Relaxed);
        stats.tcp_streams_total.fetch_add(10_000 * n, Ordering::Relaxed);
        stats.udp_datagrams_total.fetch_add(1_000_000 * n, Ordering::Relaxed);
        // Not a total: a gauge of the streams open now.
        stats.tcp_streams_active.fetch_add(7, Ordering::Relaxed);
    }

    /// The totals of tunnels on which `n` was counted in all.
    fn counted(n: u64) -> TunnelTotals {
        TunnelTotals {
            bytes_ingress: n,
            bytes_egress: 100 * n,
            tcp_streams_total: 10_000 * n,
            udp_datagrams_total: 1_000_000 * n,
        }
    }

    fn add(held: &DashMap<Uuid, Arc<TunnelStats>>) -> (Uuid, Arc<TunnelStats>) {
        let (id, stats) = (Uuid::new_v4(), Arc::new(TunnelStats::new()));
        held.insert(id, stats.clone());
        (id, stats)
    }

    fn leaving(departed: &DepartedTunnels) -> usize {
        departed.0.lock().unwrap().leaving.len()
    }

    #[test]
    fn bytes_forwarded_are_both_directions() {
        assert_eq!(counted(3).bytes_forwarded(), 303);
    }

    /// Every tunnel is in the totals once, wherever it is: in the map, out of
    /// it and still held by a forwarding task, or out of it and held by none.
    #[test]
    fn a_tunnel_is_counted_once_wherever_it_is() {
        let (held, departed) = (DashMap::new(), DepartedTunnels::default());
        assert_eq!(departed.totals(&held), counted(0));

        let (a, a_stats) = add(&held);
        let (b, b_stats) = add(&held);
        let (c, c_stats) = add(&held);
        count(&a_stats, 1);
        count(&b_stats, 2);
        count(&c_stats, 4);
        assert_eq!(departed.totals(&held), counted(7), "all three in the map");

        drop(departed.remove(&held, &a).unwrap());
        assert_eq!((held.len(), leaving(&departed)), (2, 1));
        assert_eq!(departed.totals(&held), counted(7), "one left, still held");

        drop(a_stats);
        drop(departed.remove(&held, &b).unwrap());
        assert_eq!((held.len(), leaving(&departed)), (1, 1), "the first is folded in");
        assert_eq!(departed.totals(&held), counted(7), "one folded in, one leaving, one in the map");

        drop(b_stats);
        drop(departed.remove(&held, &c).unwrap());
        drop(c_stats);
        assert_eq!(departed.totals(&held), counted(7), "none in the map");
        assert_eq!(departed.totals(&held), counted(7), "reading folds nothing in twice");
    }

    /// What a task counts after its tunnel left the map is kept, whatever
    /// else leaves meanwhile and whoever holds the tunnel longest.
    #[test]
    fn a_count_after_the_tunnel_left_is_kept() {
        let (held, departed) = (DashMap::new(), DepartedTunnels::default());
        let (id, task) = add(&held);
        let other_task = task.clone();
        count(&task, 1);
        drop(departed.remove(&held, &id).unwrap());

        count(&task, 2);
        assert_eq!(departed.totals(&held), counted(3));
        for _ in 0..3 {
            let (id, _) = add(&held);
            departed.remove(&held, &id).unwrap();
            count(&task, 1);
        }
        assert_eq!(departed.totals(&held), counted(6), "others left meanwhile");

        drop(task);
        let (id, _) = add(&held);
        departed.remove(&held, &id).unwrap();
        count(&other_task, 10);
        assert_eq!(departed.totals(&held), counted(16), "the last holder counted last");
        drop(other_task);
        let (id, _) = add(&held);
        departed.remove(&held, &id).unwrap();
        assert_eq!(departed.totals(&held), counted(16), "folded in");
    }

    /// A tunnel nothing holds any more is let go at the next removal, so a
    /// relay whose totals nobody reads keeps none of the tunnels it has had.
    #[test]
    fn a_finished_tunnel_is_let_go_without_a_reader() {
        let (held, departed) = (DashMap::new(), DepartedTunnels::default());
        let (id, task) = add(&held);
        departed.remove(&held, &id).unwrap();
        for _ in 0..1000 {
            let (id, stats) = add(&held);
            count(&stats, 1);
            drop(stats);
            departed.remove(&held, &id).unwrap();
        }
        assert_eq!(leaving(&departed), 2, "the one a task holds, and the last to leave");
        drop(task);
        let (id, _) = add(&held);
        departed.remove(&held, &id).unwrap();
        assert_eq!(leaving(&departed), 1);
        assert_eq!(departed.totals(&held), counted(1000));
    }

    /// A tunnel that is not gone after all stays in the map, and nowhere else.
    #[test]
    fn a_tunnel_that_is_not_gone_stays() {
        let (held, departed) = (DashMap::new(), DepartedTunnels::default());
        let (id, stats) = add(&held);
        count(&stats, 1);
        assert!(departed.remove_if(&held, &id, |_| false).is_none());
        assert_eq!((held.len(), leaving(&departed)), (1, 0));
        assert_eq!(departed.totals(&held), counted(1));
        assert!(departed.remove_if(&held, &id, |found| Arc::ptr_eq(found, &stats)).is_some());
        assert_eq!((held.len(), leaving(&departed)), (0, 1));
        assert_eq!(departed.totals(&held), counted(1));
    }

    /// An entry that checks, whenever its stats are asked for, that the lock is
    /// held and that the map has not let go of it.
    struct Probe {
        departed: &'static DepartedTunnels,
        held: &'static DashMap<Uuid, Probe>,
        id: Uuid,
        stats: Arc<TunnelStats>,
    }

    impl Probe {
        fn locked(&self) -> bool {
            self.departed.0.try_lock().is_err()
        }
    }

    impl Counted for Probe {
        fn stats(&self) -> &Arc<TunnelStats> {
            assert!(self.locked(), "counted without the lock");
            assert!(!self.held.try_get(&self.id).is_absent(), "counted once out of the map");
            &self.stats
        }
    }

    /// A removal waits for a read to end. It then asks whether the tunnel is
    /// gone with both locks held, and puts it on the list before the map lets
    /// go of it: a read never sees a tunnel half way out of the map.
    #[test]
    fn the_lock_spans_a_removal_and_a_read() {
        let departed: &DepartedTunnels = Box::leak(Box::default());
        let held: &DashMap<Uuid, Probe> = Box::leak(Box::default());
        let id = Uuid::new_v4();
        let stats = Arc::new(TunnelStats::new());
        count(&stats, 1);
        held.insert(id, Probe { departed, held, id, stats });
        assert_eq!(departed.totals(held), counted(1));

        std::thread::scope(|s| {
            let reading = departed.0.lock().unwrap();
            let removal = s.spawn(|| {
                let gone = |probe: &Probe| probe.locked() && held.try_get(&id).is_locked();
                departed.remove_if(held, &id, gone).is_some()
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(held.try_get(&id).is_present(), "a removal waits for a read to end");
            drop(reading);
            assert!(removal.join().unwrap(), "asked with both locks held");
        });
        assert_eq!(departed.totals(held), counted(1));
    }

    #[test]
    fn removing_a_tunnel_that_is_not_there_changes_nothing() {
        let (held, departed) = (DashMap::new(), DepartedTunnels::default());
        let (id, stats) = add(&held);
        count(&stats, 1);
        assert!(departed.remove(&held, &Uuid::new_v4()).is_none());
        assert!(departed.remove(&held, &id).is_some());
        assert!(departed.remove(&held, &id).is_none(), "it left once");
        assert_eq!(leaving(&departed), 1);
        assert_eq!(departed.totals(&held), counted(1));
    }
}

#[cfg(test)]
mod manager_link_tests {
    use super::*;

    #[test]
    fn unconfigured_manager_omits_link_status() {
        let stats = RelayStats::new();
        assert!(stats.manager_link_status().is_none());
    }

    #[test]
    fn connect_then_disconnect_transitions() {
        let stats = RelayStats::new();
        stats.manager_configured.store(true, Ordering::Relaxed);

        // Initially configured but not yet connected → reconnecting.
        let s = stats.manager_link_status().unwrap();
        assert!(!s.connected);
        assert!(s.reconnecting);
        assert_eq!(s.disconnected_secs, 0); // never disconnected yet

        // Authenticated.
        stats.mark_manager_connected();
        let s = stats.manager_link_status().unwrap();
        assert!(s.connected);
        assert!(!s.reconnecting);
        assert_eq!(s.disconnected_secs, 0);

        // Dropped.
        stats.mark_manager_disconnected();
        let s = stats.manager_link_status().unwrap();
        assert!(!s.connected);
        assert!(s.reconnecting);
        // disconnected_secs computed from a just-stamped timestamp → 0.
        assert_eq!(s.disconnected_secs, 0);
        assert_ne!(stats.manager_last_disconnect_ms.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn repeated_disconnect_does_not_reset_drop_time() {
        let stats = RelayStats::new();
        stats.manager_configured.store(true, Ordering::Relaxed);
        stats.mark_manager_connected();
        stats.mark_manager_disconnected();
        let first = stats.manager_last_disconnect_ms.load(Ordering::Relaxed);
        // A retry that fails again must NOT re-stamp the drop time.
        stats.mark_manager_disconnected();
        let second = stats.manager_last_disconnect_ms.load(Ordering::Relaxed);
        assert_eq!(first, second);
    }
}
