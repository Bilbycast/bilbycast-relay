// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Event sender for forwarding operational events to the manager.
//!
//! Components throughout the relay (session handler, tunnel router, etc.) hold
//! an `EventSender` clone and call its helper methods to report state changes.
//! Events are queued in a **bounded** mpsc channel
//! ([`EVENT_CHANNEL_CAPACITY`]) and drained by the manager WebSocket client
//! loop. It was unbounded until the event queue itself turned out to be the
//! leak: with no manager attached, one rejected native-UDP datagram per packet
//! queued an `Event` nothing ever drained. Over capacity, events are dropped
//! and counted rather than retained — see [`Drops`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

/// Bounded so a packet flood cannot retain unbounded heap.
///
/// Every rejected native-UDP `Register` datagram used to queue one `Event`
/// carrying two `String`s and a `serde_json::Value`, on an *unbounded*
/// channel drained only by the manager WebSocket loop. At even 50k pps that
/// is tens of MB/s of permanently-retained heap on a relay with no manager
/// attached — the queue is the leak, not the events.
///
/// Sized like the log shipper's 2048 (`observability.rs`) but halved, since
/// an `Event` is fatter than a log line: ~0.5 MB worst case.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Drop bookkeeping shared by every clone of an [`EventSender`].
#[derive(Debug, Default)]
struct Drops {
    total: AtomicU64,
    last_warn_us: AtomicU64,
}

impl Drops {
    /// Count a dropped event and log at most once a second. Mirrors
    /// `JsonLogShipper::note_drop`, including the monotonic clock — a
    /// wall-clock step must not silence or spam the warning.
    fn note(&self) {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        let now_us = crate::observability::monotonic_us();
        let last = self.last_warn_us.load(Ordering::Relaxed);
        if now_us.saturating_sub(last) >= 1_000_000
            && self
                .last_warn_us
                .compare_exchange(last, now_us, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                dropped_total = total,
                "event queue full — dropping events (manager slow or absent, or an \
                 inbound flood is generating them faster than they can be shipped)"
            );
        }
    }
}

/// Well-known event category constants.
pub mod category {
    pub const EDGE: &str = "edge";
    pub const TUNNEL: &str = "tunnel";
    pub const MANAGER: &str = "manager";
    /// Viewer-distribution subsystem (WHEP SFU + LL-HLS origin).
    pub const DISTRIBUTION: &str = "distribution";
}

/// Event severity levels matching the manager's `EventSeverity` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

impl EventSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// A single event to be sent to the manager.
#[derive(Debug, Clone)]
pub struct Event {
    pub severity: EventSeverity,
    pub category: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub flow_id: Option<String>,
}

/// Clonable handle for sending events from any component.
///
/// Sending never blocks or fails — if the receiver is dropped (manager client
/// not running), events are silently discarded.
///
/// When the structured-JSON `log_shipper` is configured, every event also
/// fans out to it so SIEM / NMS pickup is independent of manager
/// connectivity. The shipper is set once at startup before the first
/// clone; clones inherit the same `Option<JsonLogShipper>` value (the
/// shipper is cheaply clonable internally).
#[derive(Debug, Clone)]
pub struct EventSender {
    tx: mpsc::Sender<Event>,
    drops: Arc<Drops>,
    log_shipper: Option<crate::observability::JsonLogShipper>,
}

impl EventSender {
    /// Install the structured-JSON log shipper. Must be called once at
    /// startup *before* any clone of the original sender is handed out.
    pub fn set_log_shipper(&mut self, shipper: crate::observability::JsonLogShipper) {
        self.log_shipper = Some(shipper);
    }

    /// Send an event to the manager.
    ///
    /// Never blocks and never awaits — callers include the native-UDP receive
    /// loop, which must not stall media forwarding to report an error. A full
    /// queue drops the event and bumps a counter rather than growing the
    /// backlog; `Closed` stays silent to preserve the documented
    /// "receiver dropped -> events discarded" contract.
    pub fn send(&self, event: Event) {
        if let Some(ref shipper) = self.log_shipper {
            shipper.ship_event(&event);
        }
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => self.drops.note(),
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Total events dropped because the queue was full. Non-destructive.
    pub fn dropped_total(&self) -> u64 {
        self.drops.total.load(Ordering::Relaxed)
    }

    /// Convenience: send an event with just severity, category, and message.
    pub fn emit(&self, severity: EventSeverity, category: &str, message: impl Into<String>) {
        self.send(Event {
            severity,
            category: category.to_string(),
            message: message.into(),
            details: None,
            flow_id: None,
        });
    }

    /// Convenience: send an event with a tunnel/flow ID.
    pub fn emit_with_id(
        &self,
        severity: EventSeverity,
        category: &str,
        message: impl Into<String>,
        id: &str,
    ) {
        self.send(Event {
            severity,
            category: category.to_string(),
            message: message.into(),
            details: None,
            flow_id: Some(id.to_string()),
        });
    }

    /// Convenience: send an event with structured details.
    pub fn emit_with_details(
        &self,
        severity: EventSeverity,
        category: &str,
        message: impl Into<String>,
        details: serde_json::Value,
    ) {
        self.send(Event {
            severity,
            category: category.to_string(),
            message: message.into(),
            details: Some(details),
            flow_id: None,
        });
    }

    /// Convenience: send an event with a tunnel/flow ID and structured details.
    pub fn emit_with_id_and_details(
        &self,
        severity: EventSeverity,
        category: &str,
        message: impl Into<String>,
        id: &str,
        details: serde_json::Value,
    ) {
        self.send(Event {
            severity,
            category: category.to_string(),
            message: message.into(),
            details: Some(details),
            flow_id: Some(id.to_string()),
        });
    }
}

/// Create an event sender/receiver pair.
pub fn event_channel() -> (EventSender, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    (
        EventSender {
            tx,
            drops: Arc::new(Drops::default()),
            log_shipper: None,
        },
        rx,
    )
}

/// Build a WebSocket event envelope from an `Event`.
pub fn build_event_envelope(event: &Event) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "severity": event.severity.as_str(),
        "category": event.category,
        "message": event.message,
    });
    if let Some(ref details) = event.details {
        payload["details"] = details.clone();
    }
    if let Some(ref flow_id) = event.flow_id {
        payload["flow_id"] = serde_json::Value::String(flow_id.clone());
    }
    serde_json::json!({
        "type": "event",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "payload": payload
    })
}

#[cfg(test)]
mod bounded_queue_tests {
    use super::*;

    fn ev(n: usize) -> Event {
        Event {
            severity: EventSeverity::Warning,
            category: category::TUNNEL.to_string(),
            message: format!("register rejected {n}"),
            details: Some(serde_json::json!({ "remote_ip": "203.0.113.7" })),
            flow_id: None,
        }
    }

    /// The queue must bound. Before this, one rejected native-UDP `Register`
    /// datagram queued one `Event` on an *unbounded* channel — a remote
    /// unauthenticated packet flood was therefore an unbounded memory leak on
    /// any relay whose manager was slow or absent.
    #[test]
    fn flood_is_dropped_not_queued() {
        let (tx, _rx) = event_channel();
        let flood = EVENT_CHANNEL_CAPACITY * 10;
        for i in 0..flood {
            tx.send(ev(i));
        }
        let dropped = tx.dropped_total();
        assert!(
            dropped >= (flood - EVENT_CHANNEL_CAPACITY) as u64,
            "expected the overflow to be dropped and counted; capacity={} sent={} dropped={}",
            EVENT_CHANNEL_CAPACITY,
            flood,
            dropped
        );
    }

    /// A dropped receiver must stay silent — the documented contract is that
    /// events are discarded when no manager client is running, and that is a
    /// normal standalone-relay state, not an error worth counting or logging.
    #[test]
    fn closed_receiver_is_silent_and_not_counted_as_a_drop() {
        let (tx, rx) = event_channel();
        drop(rx);
        tx.send(ev(0));
        assert_eq!(tx.dropped_total(), 0, "Closed is not a queue-full drop");
    }

    /// Every clone shares one drop counter, so the number reported is the
    /// relay's total rather than one emitter's view of it.
    #[test]
    fn clones_share_drop_accounting() {
        let (tx, _rx) = event_channel();
        let tx2 = tx.clone();
        for i in 0..(EVENT_CHANNEL_CAPACITY * 2) {
            tx2.send(ev(i));
        }
        assert!(tx.dropped_total() > 0, "clone's drops must be visible here");
        assert_eq!(tx.dropped_total(), tx2.dropped_total());
    }
}
