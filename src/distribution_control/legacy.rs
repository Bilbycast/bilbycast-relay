// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the previous distribution key has admitted.
//!
//! While the manager moves its relays off the one installation-wide signing
//! key, a relay holds its own key and, until a deadline, the old one as well
//! (`previous_token_secret` / `previous_token_until`). Every token the old key
//! admits is a credential that stops working at that deadline — a WHIP output,
//! a hand-configured CMAF upload, a cascade, a link — so the relay counts them
//! per stream and scope, and says so: a Warning `legacy_token_accepted` the
//! first time each is seen, and `distribution.legacy_tokens` on the health
//! message for the manager to list.
//!
//! Touched only when the previous key matched (a lock-free `DashMap` entry and
//! two atomics), never for a token the relay's own key admits. Bounded at
//! [`LEGACY_REGISTRY_CAP`] entries, past which an acceptance is only counted
//! in `overflow`, and one more event says so — so whoever holds the old key
//! cannot grow the registry, or the event queue, without limit. Always
//! compiled, because the runtime config that carries it is, and the health
//! builder reads it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use serde::Serialize;

use crate::manager::events::{EventSender, EventSeverity, category};

/// At most this many `(stream, scope)` entries are listed.
pub const LEGACY_REGISTRY_CAP: usize = 256;

/// Which kind of token the previous key admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Viewer,
    Ingest,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Ingest => "ingest",
        }
    }
}

/// How often one `(stream, scope)` was admitted by the previous key.
#[derive(Debug, Default)]
struct Seen {
    count: AtomicU64,
    last_unix: AtomicU64,
}

/// The registry: one per previous key, kept for as long as that key is held
/// (`DistributionControl::apply` starts a fresh one when the key is cleared
/// or changed).
#[derive(Debug, Default)]
pub struct LegacyTokens {
    entries: DashMap<(String, Scope), Seen>,
    /// Slots taken in `entries`, reserved before an insert so two first
    /// sightings at once cannot take the registry past its cap.
    reserved: AtomicUsize,
    /// Acceptances not listed because the registry was full.
    overflow: AtomicU64,
}

/// One listed entry, as `distribution.legacy_tokens.entries[]` carries it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyTokenEntry {
    pub stream: String,
    pub scope: Scope,
    /// Requests the previous key admitted for this stream and scope.
    pub count: u64,
    /// When the last of them came, unix seconds.
    pub last_unix: u64,
}

/// `distribution.legacy_tokens` on the health message.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyTokensReport {
    /// The unix second the previous key stops being accepted.
    pub until: u64,
    /// At most [`LEGACY_REGISTRY_CAP`], sorted by stream then scope.
    pub entries: Vec<LegacyTokenEntry>,
    /// Acceptances past the cap, counted but not listed.
    pub overflow: u64,
}

/// What one acceptance was, for the event it may raise.
#[derive(Debug, PartialEq, Eq)]
enum Noted {
    /// The first of its stream and scope.
    First,
    Again,
    /// The first that did not fit.
    FirstOverflow,
    Overflow,
}

impl LegacyTokens {
    /// Count one request the previous key admitted, and raise
    /// `legacy_token_accepted` if it is the first of its stream and scope, or
    /// the first the registry had no room for. `until` is the previous key's.
    pub fn note(&self, events: &EventSender, stream: &str, scope: Scope, until: u64) {
        match self.record(stream, scope, crate::stats::now_epoch_ms() / 1000) {
            Noted::First => {
                tracing::warn!(
                    stream = %stream, scope = scope.as_str(), until,
                    "distribution: a token signed with the previous key was accepted"
                );
                events.emit_with_details(
                    EventSeverity::Warning,
                    category::DISTRIBUTION,
                    format!(
                        "A {} token for stream '{stream}' was accepted under the previous \
                         distribution key, which this relay accepts only until {until} (unix); \
                         it stops working then unless it is issued again",
                        scope.as_str()
                    ),
                    serde_json::json!({
                        "error_code": "legacy_token_accepted",
                        "stream": stream,
                        "scope": scope.as_str(),
                        "until": until,
                    }),
                );
            }
            Noted::FirstOverflow => {
                tracing::warn!(
                    until,
                    "distribution: tokens signed with the previous key arrived for more than \
                     {LEGACY_REGISTRY_CAP} streams; the rest are counted, not listed"
                );
                events.emit_with_details(
                    EventSeverity::Warning,
                    category::DISTRIBUTION,
                    format!(
                        "Tokens signed with the previous distribution key were accepted for more \
                         than {LEGACY_REGISTRY_CAP} streams; the rest are counted, not listed, \
                         and stop working at {until} (unix)"
                    ),
                    serde_json::json!({
                        "error_code": "legacy_token_accepted",
                        "overflow": true,
                        "until": until,
                    }),
                );
            }
            Noted::Again | Noted::Overflow => {}
        }
    }

    fn record(&self, stream: &str, scope: Scope, now: u64) -> Noted {
        let key = (stream.to_string(), scope);
        if let Some(seen) = self.entries.get(&key) {
            seen.count.fetch_add(1, Ordering::Relaxed);
            seen.last_unix.fetch_max(now, Ordering::Relaxed);
            return Noted::Again;
        }
        if self.reserved.fetch_add(1, Ordering::Relaxed) >= LEGACY_REGISTRY_CAP {
            self.reserved.fetch_sub(1, Ordering::Relaxed);
            return match self.overflow.fetch_add(1, Ordering::Relaxed) {
                0 => Noted::FirstOverflow,
                _ => Noted::Overflow,
            };
        }
        match self.entries.entry(key) {
            // Another request inserted it after the lookup above: give the
            // slot back and count this one on that entry.
            Entry::Occupied(seen) => {
                self.reserved.fetch_sub(1, Ordering::Relaxed);
                seen.get().count.fetch_add(1, Ordering::Relaxed);
                seen.get().last_unix.fetch_max(now, Ordering::Relaxed);
                Noted::Again
            }
            Entry::Vacant(slot) => {
                slot.insert(Seen { count: AtomicU64::new(1), last_unix: AtomicU64::new(now) });
                Noted::First
            }
        }
    }

    /// Everything counted so far, for a key that stops at `until`.
    pub fn report(&self, until: u64) -> LegacyTokensReport {
        let mut entries: Vec<LegacyTokenEntry> = self
            .entries
            .iter()
            .map(|e| LegacyTokenEntry {
                stream: e.key().0.clone(),
                scope: e.key().1,
                count: e.value().count.load(Ordering::Relaxed),
                last_unix: e.value().last_unix.load(Ordering::Relaxed),
            })
            .collect();
        entries.sort_by(|a, b| {
            (a.stream.as_str(), a.scope.as_str()).cmp(&(b.stream.as_str(), b.scope.as_str()))
        });
        LegacyTokensReport { until, entries, overflow: self.overflow.load(Ordering::Relaxed) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_stream_and_scope_is_counted_and_raises_one_event() {
        let (events, mut rx) = crate::manager::events::event_channel();
        let seen = LegacyTokens::default();
        seen.note(&events, "show", Scope::Viewer, 2_000_000_000);
        seen.note(&events, "show", Scope::Viewer, 2_000_000_000);
        seen.note(&events, "show", Scope::Ingest, 2_000_000_000);

        let first = rx.try_recv().unwrap();
        assert_eq!(first.severity, EventSeverity::Warning);
        assert_eq!(first.category, category::DISTRIBUTION);
        let details = first.details.unwrap();
        assert_eq!(details["error_code"], "legacy_token_accepted");
        assert_eq!(details["stream"], "show");
        assert_eq!(details["scope"], "viewer");
        assert_eq!(details["until"], 2_000_000_000u64);
        assert_eq!(rx.try_recv().unwrap().details.unwrap()["scope"], "ingest");
        assert!(rx.try_recv().is_err(), "a second use raises nothing");

        let report = seen.report(2_000_000_000);
        assert_eq!(report.until, 2_000_000_000);
        assert_eq!(report.overflow, 0);
        let counts: Vec<(&str, Scope, u64)> =
            report.entries.iter().map(|e| (e.stream.as_str(), e.scope, e.count)).collect();
        assert_eq!(counts, [("show", Scope::Ingest, 1), ("show", Scope::Viewer, 2)]);
        assert!(report.entries.iter().all(|e| e.last_unix > 0));
    }

    /// Past the cap an acceptance is counted, not listed, and only the first
    /// of those raises an event — whatever whoever holds the old key sends.
    #[test]
    fn the_registry_and_its_events_stay_bounded() {
        let (events, mut rx) = crate::manager::events::event_channel();
        let seen = LegacyTokens::default();
        for i in 0..300 {
            seen.note(&events, &format!("s{i}"), Scope::Viewer, 2_000_000_000);
        }
        seen.note(&events, "s0", Scope::Viewer, 2_000_000_000);
        let report = seen.report(2_000_000_000);
        assert_eq!(report.entries.len(), LEGACY_REGISTRY_CAP);
        assert_eq!(report.overflow, (300 - LEGACY_REGISTRY_CAP) as u64);

        let mut raised = Vec::new();
        while let Ok(e) = rx.try_recv() {
            raised.push(e.details.unwrap());
        }
        assert_eq!(raised.len(), LEGACY_REGISTRY_CAP + 1);
        let overflow = raised.last().unwrap();
        assert_eq!(overflow["overflow"], true);
        assert_eq!(overflow["until"], 2_000_000_000u64);
        assert!(overflow.get("stream").is_none());
    }

    #[test]
    fn the_report_serialises_as_the_manager_reads_it() {
        let (events, _rx) = crate::manager::events::event_channel();
        let seen = LegacyTokens::default();
        seen.note(&events, "feed", Scope::Ingest, 1_900_000_000);
        let v = serde_json::to_value(seen.report(1_900_000_000)).unwrap();
        assert_eq!(v["until"], 1_900_000_000u64);
        assert_eq!(v["overflow"], 0);
        assert_eq!(v["entries"][0]["stream"], "feed");
        assert_eq!(v["entries"][0]["scope"], "ingest");
        assert_eq!(v["entries"][0]["count"], 1);
        assert!(v["entries"][0]["last_unix"].as_u64().unwrap() > 0);
    }
}
