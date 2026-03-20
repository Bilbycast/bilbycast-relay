use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

/// Per-tunnel stats tracked atomically.
pub struct TunnelStats {
    pub bytes_ingress: AtomicU64,
    pub bytes_egress: AtomicU64,
    pub tcp_streams_total: AtomicU64,
    pub udp_datagrams_total: AtomicU64,
    pub created_at: Instant,
}

impl TunnelStats {
    pub fn new() -> Self {
        Self {
            bytes_ingress: AtomicU64::new(0),
            bytes_egress: AtomicU64::new(0),
            tcp_streams_total: AtomicU64::new(0),
            udp_datagrams_total: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    pub fn snapshot(&self) -> TunnelStatsSnapshot {
        TunnelStatsSnapshot {
            bytes_ingress: self.bytes_ingress.load(Ordering::Relaxed),
            bytes_egress: self.bytes_egress.load(Ordering::Relaxed),
            tcp_streams_total: self.tcp_streams_total.load(Ordering::Relaxed),
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
    pub udp_datagrams_total: u64,
    pub uptime_secs: u64,
}

/// Global relay stats.
pub struct RelayStats {
    pub start_time: Instant,
}

impl RelayStats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}
