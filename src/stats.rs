// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

use std::sync::atomic::{AtomicU64, Ordering};
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
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
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
