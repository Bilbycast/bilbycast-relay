// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

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
    /// Total bytes fanned out to viewers (pre-SRTP ES accounting).
    pub distribution_bytes_out: AtomicU64,
    /// Bytes currently held in the LL-HLS origin cache.
    pub distribution_origin_bytes: AtomicU64,
}

/// Snapshot of the distribution subsystem telemetry.
#[derive(Debug, Clone, Serialize)]
pub struct DistributionStatsSnapshot {
    pub enabled: bool,
    pub streams: u64,
    pub viewers: u64,
    pub bytes_out: u64,
    pub origin_bytes: u64,
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
        }
    }

    /// Publish a distribution telemetry sample (called by the subsystem).
    pub fn set_distribution(&self, streams: u64, viewers: u64, bytes_out: u64, origin_bytes: u64) {
        self.distribution_enabled.store(true, Ordering::Relaxed);
        self.distribution_streams.store(streams, Ordering::Relaxed);
        self.distribution_viewers.store(viewers, Ordering::Relaxed);
        self.distribution_bytes_out.store(bytes_out, Ordering::Relaxed);
        self.distribution_origin_bytes.store(origin_bytes, Ordering::Relaxed);
    }

    /// Snapshot the distribution telemetry. Returns `None` when the subsystem
    /// is not running (so the field is omitted from health/REST payloads).
    pub fn distribution_snapshot(&self) -> Option<DistributionStatsSnapshot> {
        if !self.distribution_enabled.load(Ordering::Relaxed) {
            return None;
        }
        Some(DistributionStatsSnapshot {
            enabled: true,
            streams: self.distribution_streams.load(Ordering::Relaxed),
            viewers: self.distribution_viewers.load(Ordering::Relaxed),
            bytes_out: self.distribution_bytes_out.load(Ordering::Relaxed),
            origin_bytes: self.distribution_origin_bytes.load(Ordering::Relaxed),
        })
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
