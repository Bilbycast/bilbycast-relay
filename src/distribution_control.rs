// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime, manager-overridable distribution config.
//!
//! The bootstrap distribution config comes from the relay's `config.json`, but
//! the manager owns the operational policy — this relay's token key (and, for
//! a bounded grace, the previous one), the auth gates, the advertised public
//! IP / base URL, and the cascade sources —
//! and pushes them over the WS `configure_distribution` command so an operator
//! never hand-edits the relay's config. This module is the shared cell both
//! sides read/write: the manager-client command handler calls
//! [`DistributionControl::apply`] / [`DistributionControl::set_cascade`]; the
//! viewer-distribution subsystem reads the live values on each request.
//!
//! It is **always compiled** (not behind the `viewer-distribution` feature) so
//! the non-feature-gated manager client can hold an `Option<Arc<...>>` handle
//! without a cfg gate. The values are plain data (no str0m types).

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::watch;

use crate::config::{CascadeSource, DistributionConfig};
use crate::manager::events::EventSender;

pub mod legacy;

use self::legacy::{LegacyTokens, LegacyTokensReport, Scope};

/// How far ahead a pushed `previous_token_until` may lie: 31 days, a day past
/// the longest grace the manager gives (30 days).
pub const MAX_PREVIOUS_AHEAD_SECS: u64 = 31 * 24 * 60 * 60;

/// Now, in unix seconds.
pub fn now_unix() -> u64 {
    crate::stats::now_epoch_ms() / 1000
}

/// The id of a key: the first 16 hex of SHA-256 over a fixed label and the
/// key's hex — the manager's `key_id_of`, byte for byte, so the id this relay
/// reports for the key it holds is the one the manager names it by. It names
/// a key without revealing it.
pub fn key_id_of(key_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("bilbycast:distribution-key-id:v1:{key_hex}").as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// `distribution.token_key` on the health message: which keys this relay
/// verifies with now, by id. The manager compares it with what the relay
/// should hold and pushes again when they differ — a relay restored from an
/// old `config.json`, or one whose last push was overtaken by another, is put
/// right on the next pass instead of verifying with a key the manager no
/// longer signs with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TokenKeyReport {
    /// The id of `token_secret`.
    pub key_id: String,
    /// The id of the previous key, while it is held and its `until` is ahead.
    pub previous_key_id: Option<String>,
    /// Until when the previous key is accepted (unix seconds); 0 when none is.
    pub previous_until: u64,
}

/// The subset of distribution config the manager can change at runtime.
#[derive(Clone, Debug, Default)]
pub struct RuntimeDistConfig {
    /// This relay's key: what every viewer and ingest token it accepts is
    /// verified with first. Its own, generated per relay by the manager.
    pub token_secret: Option<String>,
    /// The key this relay verified with before `token_secret`, held only for
    /// the grace the manager gives while it moves relays off the one
    /// installation-wide key. Tried only when `token_secret` refuses a token,
    /// and only while now is below `previous_token_until`.
    pub previous_token_secret: Option<String>,
    /// Unix seconds; 0 when no previous key is held.
    pub previous_token_until: u64,
    /// What the previous key has admitted, for as long as that key is held.
    pub legacy_tokens: Arc<LegacyTokens>,
    pub require_viewer_token: bool,
    /// Gate `GET /origin/...` as well as WHEP. Default false — see
    /// [`crate::config::DistributionConfig::require_origin_token`].
    pub require_origin_token: bool,
    pub require_ingest_token: bool,
    /// Public IP advertised in WHEP ICE candidates.
    pub public_ip: Option<IpAddr>,
    /// Public base URL used to build shareable viewer links (reported to the
    /// manager on health).
    pub public_base_url: Option<String>,

    /// Where a viewer whose access has expired goes to get more.
    ///
    /// The player cannot work this out and must not guess. A viewer who came
    /// through the **portal** landed here with a token in the URL, so
    /// reloading re-presents the dead one and changes nothing — the honest
    /// instruction is "sign in again", and that needs somewhere to point.
    ///
    /// It comes from the relay's own config (pushed by the manager), never
    /// from a query parameter: a URL the page will offer as a link, taken from
    /// the request that asked for the page, is a phishing hop with extra steps.
    /// `None` means say what happened without offering a link.
    pub portal_url: Option<String>,
}

impl RuntimeDistConfig {
    /// Derive from the static config, with an optional `public_ip` override.
    ///
    /// A previous key whose `until` has passed (or that has none) is dropped:
    /// the grace it was given is over, whatever the file says.
    pub fn from_config(cfg: &DistributionConfig, public_ip: Option<IpAddr>) -> Self {
        let previous = match (&cfg.previous_token_secret, cfg.previous_token_until) {
            (Some(secret), Some(until)) if until > now_unix() => Some((secret.clone(), until)),
            _ => None,
        };
        Self {
            token_secret: cfg.token_secret.clone(),
            previous_token_until: previous.as_ref().map_or(0, |(_, until)| *until),
            previous_token_secret: previous.map(|(secret, _)| secret),
            legacy_tokens: Arc::default(),
            require_viewer_token: cfg.require_viewer_token,
            require_origin_token: cfg.require_origin_token,
            require_ingest_token: cfg.require_ingest_token,
            public_ip: public_ip.or_else(|| cfg.public_ip_parsed()),
            public_base_url: cfg.public_base_url.clone(),
            portal_url: cfg.portal_url.clone(),
        }
    }

    /// The keys tokens are verified with: `None` when the relay holds no key
    /// at all, and every gated surface then fails closed as it always has.
    /// The previous key rides along with its `until`, which the verifier
    /// checks on every use, so an expired one is never tried however long it
    /// stays held.
    #[cfg(feature = "viewer-distribution")]
    pub fn keyring(&self) -> Option<crate::distribution::token::Keyring<'_>> {
        Some(crate::distribution::token::Keyring {
            current: self.token_secret.as_deref()?,
            previous: self
                .previous_token_secret
                .as_deref()
                .map(|previous| (previous, self.previous_token_until)),
        })
    }

    /// Count a request the previous key admitted, raising
    /// `legacy_token_accepted` the first time its stream and scope is seen.
    pub fn note_previous_key(&self, events: &EventSender, stream: &str, scope: Scope) {
        self.legacy_tokens.note(events, stream, scope, self.previous_token_until);
    }

    /// `distribution.legacy_tokens` for the health message: present only
    /// while a previous key is held and has not expired.
    pub fn legacy_tokens_report(&self, now: u64) -> Option<LegacyTokensReport> {
        (self.previous_token_secret.is_some() && self.previous_token_until > now)
            .then(|| self.legacy_tokens.report(self.previous_token_until))
    }

    /// `distribution.token_key` for the health message: present while the
    /// relay holds a key at all.
    pub fn token_key_report(&self, now: u64) -> Option<TokenKeyReport> {
        let current = self.token_secret.as_deref()?;
        let previous = self
            .previous_token_secret
            .as_deref()
            .filter(|_| self.previous_token_until > now);
        Some(TokenKeyReport {
            key_id: key_id_of(current),
            previous_key_id: previous.map(key_id_of),
            previous_until: if previous.is_some() { self.previous_token_until } else { 0 },
        })
    }
}

/// A partial change to one origin retention policy. Every field is optional;
/// an absent field inherits whatever it is being applied to.
///
/// Seconds and bytes rather than `Duration` because this is the wire shape the
/// manager sends, and it is applied on the far side of a JSON boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OriginPolicyPatch {
    pub retention_secs: Option<u64>,
    pub max_bytes_per_stream: Option<u64>,
    pub min_segments: Option<usize>,
    pub idle_grace_secs: Option<u64>,
}

impl OriginPolicyPatch {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The manager's storage-policy push: a node-wide default plus per-stream
/// overrides.
///
/// A per-stream entry is applied **on top of the resulting default**, so an
/// override that names only `retention_secs` still gets the node's byte bound
/// and floor rather than zeroes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginPolicyUpdate {
    pub default: Option<OriginPolicyPatch>,
    /// `Some` **replaces** the whole override set (an ended session's override
    /// must not survive); `None` leaves the existing set untouched.
    pub per_stream: Option<Vec<(String, OriginPolicyPatch)>>,
}

/// Marks a stream name on the drop channel as a retirement rather than a
/// deletion. A stream id cannot contain it — `sanitize_stream_id` admits only
/// alphanumerics, `_`, `-` and `.` — so it cannot be forged by a stream name.
pub const RETIRE_PREFIX: &str = "retire:";

/// Shared, lock-free runtime config + a cascade-source change channel.
pub struct DistributionControl {
    cfg: ArcSwap<RuntimeDistConfig>,
    cascade_tx: watch::Sender<Vec<CascadeSource>>,
    /// Streams the manager has asked to drop outright.
    ///
    /// An **mpsc**, not a `watch` like the two below, and that is the whole
    /// point: a `watch` keeps only the latest value, so two drops arriving
    /// between polls would silently become one and a stream would keep its
    /// disk for ever. A policy is a state and may be coalesced; a drop is an
    /// event and may not.
    drop_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Held so `drop_tx.send` cannot fail before the origin subscribes.
    drop_rx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    /// Storage-policy pushes. A `watch` like the cascade channel: the origin
    /// store is the single consumer and only ever needs the latest value.
    origin_tx: watch::Sender<OriginPolicyUpdate>,
    /// Keeps `origin_tx` with a receiver so `send` never errors before the
    /// origin subscribes.
    origin_keep: watch::Receiver<OriginPolicyUpdate>,
    /// Kept so `cascade_tx.send` always has a receiver (never errors) even
    /// before the cascade supervisor subscribes; also read by `cascade_now`.
    cascade_keep: watch::Receiver<Vec<CascadeSource>>,
}

impl DistributionControl {
    pub fn new(initial: RuntimeDistConfig, cascade: Vec<CascadeSource>) -> Arc<Self> {
        let (cascade_tx, keep) = watch::channel(cascade);
        let (origin_tx, origin_keep) = watch::channel(OriginPolicyUpdate::default());
        let (drop_tx, drop_rx) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            cfg: ArcSwap::from_pointee(initial),
            cascade_tx,
            cascade_keep: keep,
            origin_tx,
            origin_keep,
            drop_tx,
            drop_rx: std::sync::Mutex::new(Some(drop_rx)),
        })
    }

    /// Subscribe to storage-policy pushes (the origin store).
    pub fn subscribe_origin(&self) -> watch::Receiver<OriginPolicyUpdate> {
        self.origin_tx.subscribe()
    }

    /// Take the stream-drop queue. The origin store is the single consumer, so
    /// this yields the receiver once and `None` thereafter.
    pub fn take_drops(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<String>> {
        self.drop_rx.lock().ok().and_then(|mut g| g.take())
    }

    /// The origin took the drop queue and has since let it go: the
    /// subsystem has stopped, and a drop sent now would be lost.
    pub fn drops_closed(&self) -> bool {
        self.drop_tx.is_closed()
    }

    /// Retire a stream: its media goes, its clips stay.
    ///
    /// Carried on the same channel as a drop, distinguished by a prefix, so
    /// the origin's single receiver does not have to grow a second one for a
    /// message that arrives at the same rate as the first (rarely).
    pub fn retire_stream(&self, stream: &str) {
        let _ = self.drop_tx.send(format!("{RETIRE_PREFIX}{stream}"));
    }

    /// Ask the origin to drop a stream's storage outright.
    ///
    /// Distinct from retention. Retention answers "how much history is worth
    /// keeping"; this answers "nothing is going to want this again" — a
    /// session deleted, its streams never to be written to. Without it a
    /// deleted session holds its disk until the *node default* retention
    /// expires, which has nothing to do with the window that session asked
    /// for: on the demo rig, 2h40m for a session the operator deleted to
    /// reclaim space.
    pub fn drop_stream(&self, stream: &str) {
        let _ = self.drop_tx.send(stream.to_string());
    }

    /// Current storage policy push (for persistence / reporting).
    pub fn origin_policy_now(&self) -> OriginPolicyUpdate {
        self.origin_keep.borrow().clone()
    }

    /// Push a storage-policy change (manager). The origin store applies it.
    ///
    /// Merged into the retained value rather than replacing it. This is a
    /// **delta** — a `None` field means "unchanged" — but it travels on a
    /// latest-value-wins `watch`, so two pushes landing between receiver wakeups
    /// would drop the first: a `{default, no per_stream}` push followed by a
    /// `{no default, per_stream}` one loses the new default entirely.
    ///
    /// Merging also gives a late subscriber a complete picture, which
    /// `subscribe_origin` needs — `watch::Sender::subscribe` marks the current
    /// value as already seen, so anything pushed before the origin task starts
    /// is never delivered by `changed()`.
    pub fn set_origin_policy(&self, update: OriginPolicyUpdate) {
        let prev = self.origin_keep.borrow().clone();
        let merged = OriginPolicyUpdate {
            default: update.default.or(prev.default),
            per_stream: update.per_stream.or(prev.per_stream),
        };
        let _ = self.origin_tx.send(merged);
    }

    /// Current cascade-source list (for persistence to config.json).
    pub fn cascade_now(&self) -> Vec<CascadeSource> {
        self.cascade_keep.borrow().clone()
    }

    /// Current runtime config snapshot (cheap, lock-free).
    pub fn load(&self) -> Arc<RuntimeDistConfig> {
        self.cfg.load_full()
    }

    /// Replace the whole runtime config (manager push).
    pub fn store(&self, cfg: RuntimeDistConfig) {
        self.cfg.store(Arc::new(cfg));
    }

    /// Apply a partial manager update: any `Some` field overrides; `None`
    /// leaves the current value. Booleans are always applied.
    ///
    /// The previous key carries its registry of what it admitted with it:
    /// kept while the same key stays held (a new `until` included), and
    /// started afresh when the key is cleared, replaced, or pushed again after
    /// it had lapsed — what an old count said belongs to the grace it was made
    /// in.
    pub fn apply(&self, update: DistUpdate) {
        let cur = self.load();
        let (previous_token_secret, previous_token_until, legacy_tokens) = match update.previous {
            None => (
                cur.previous_token_secret.clone(),
                cur.previous_token_until,
                cur.legacy_tokens.clone(),
            ),
            Some(None) => (None, 0, Arc::default()),
            Some(Some((secret, until))) => {
                let same_live_key = cur.previous_token_secret.as_deref() == Some(secret.as_str())
                    && cur.previous_token_until > now_unix();
                let seen = if same_live_key { cur.legacy_tokens.clone() } else { Arc::default() };
                (Some(secret), until, seen)
            }
        };
        let next = RuntimeDistConfig {
            token_secret: update.token_secret.or_else(|| cur.token_secret.clone()),
            previous_token_secret,
            previous_token_until,
            legacy_tokens,
            require_viewer_token: update.require_viewer_token.unwrap_or(cur.require_viewer_token),
            require_origin_token: update.require_origin_token.unwrap_or(cur.require_origin_token),
            require_ingest_token: update.require_ingest_token.unwrap_or(cur.require_ingest_token),
            public_ip: update.public_ip.or(cur.public_ip),
            public_base_url: update.public_base_url.or_else(|| cur.public_base_url.clone()),
            portal_url: update.portal_url.or_else(|| cur.portal_url.clone()),
        };
        self.store(next);
    }

    /// Subscribe to cascade-source changes (the supervisor).
    pub fn subscribe_cascade(&self) -> watch::Receiver<Vec<CascadeSource>> {
        self.cascade_tx.subscribe()
    }

    /// Push a new cascade-source list (manager). The supervisor reconciles.
    pub fn set_cascade(&self, sources: Vec<CascadeSource>) {
        let _ = self.cascade_tx.send(sources);
    }
}

/// A partial runtime update from the manager's `configure_distribution` command.
/// `None` fields are left unchanged; `Some` fields override.
#[derive(Debug, Default, Clone)]
pub struct DistUpdate {
    pub token_secret: Option<String>,
    /// The previous key and its `until`: `None` leaves what is held,
    /// `Some(None)` clears it, `Some(Some(..))` sets it. Already validated and
    /// resolved (a redaction marker replaced by the held key) by the command
    /// handler.
    pub previous: Option<Option<(String, u64)>>,
    pub require_viewer_token: Option<bool>,
    pub require_origin_token: Option<bool>,
    pub require_ingest_token: Option<bool>,
    pub public_ip: Option<IpAddr>,
    pub public_base_url: Option<String>,
    pub portal_url: Option<String>,
}

/// Validate + normalize a stream id from the URL path. Streams are named by
/// the manager; keep the character set tight to avoid path/URL abuse.
///
/// The character set alone is not enough now that a stream id names a
/// **directory** under the origin root: `.` and `..` are built entirely from
/// allowed characters, and `root.join("..")` is the origin's parent. Require at
/// least one alphanumeric, which rejects every all-dot name without having to
/// enumerate them.
pub fn sanitize_stream_id(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    if !s.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        Some(s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RuntimeDistConfig {
        RuntimeDistConfig {
            token_secret: Some("aa".into()),
            previous_token_secret: None,
            previous_token_until: 0,
            legacy_tokens: Arc::default(),
            require_viewer_token: false,
            require_origin_token: false,
            require_ingest_token: true,
            public_ip: None,
            public_base_url: None,
            portal_url: None,
        }
    }

    #[test]
    fn apply_overrides_some_leaves_none() {
        let c = DistributionControl::new(base(), vec![]);
        c.apply(DistUpdate {
            token_secret: Some("bb".into()),
            require_viewer_token: Some(true),
            public_base_url: Some("https://r".into()),
            portal_url: Some("https://portal.example".into()),
            ..Default::default()
        });
        let g = c.load();
        assert_eq!(g.token_secret.as_deref(), Some("bb"));
        assert!(g.require_viewer_token);
        // Untouched fields keep their prior value.
        assert!(g.require_ingest_token);
        assert_eq!(g.public_base_url.as_deref(), Some("https://r"));
        assert_eq!(g.portal_url.as_deref(), Some("https://portal.example"));
    }

    /// A previous key on disk is taken up while its `until` is ahead, and
    /// dropped once it has passed or when it has none.
    #[test]
    fn from_config_drops_a_previous_key_whose_until_has_passed() {
        let key = "bb".repeat(32);
        let at = |until: Option<u64>| {
            RuntimeDistConfig::from_config(
                &DistributionConfig {
                    previous_token_secret: Some(key.clone()),
                    previous_token_until: until,
                    ..Default::default()
                },
                None,
            )
        };
        let live = at(Some(now_unix() + 600));
        assert_eq!(live.previous_token_secret.as_deref(), Some(key.as_str()));
        assert!(live.previous_token_until > now_unix());
        for gone in [at(Some(now_unix() - 1)), at(Some(0)), at(None)] {
            assert!(gone.previous_token_secret.is_none());
            assert_eq!(gone.previous_token_until, 0);
            assert!(gone.legacy_tokens_report(now_unix()).is_none());
        }
    }

    /// What the previous key admitted stays with that key: kept across a
    /// push that leaves it or moves its `until`, started afresh when it is
    /// cleared or replaced.
    #[test]
    fn the_legacy_registry_lives_and_dies_with_its_previous_key() {
        let (events, _rx) = crate::manager::events::event_channel();
        let c = DistributionControl::new(base(), vec![]);
        let until = now_unix() + 600;
        let set = |key: &str, until: u64| DistUpdate {
            previous: Some(Some((key.to_string(), until))),
            ..Default::default()
        };
        let listed = |c: &DistributionControl| {
            c.load().legacy_tokens_report(now_unix()).map(|r| r.entries.len())
        };

        c.apply(set("k1", until));
        c.load().note_previous_key(&events, "show", Scope::Viewer);
        assert_eq!(listed(&c), Some(1));

        c.apply(DistUpdate { require_viewer_token: Some(true), ..Default::default() });
        assert_eq!(listed(&c), Some(1), "a push that leaves the key keeps its count");
        c.apply(set("k1", until + 60));
        assert_eq!(listed(&c), Some(1), "a new until for the same key keeps its count");
        assert_eq!(c.load().previous_token_until, until + 60);

        c.apply(set("k2", until));
        assert_eq!(listed(&c), Some(0), "another key starts its own count");

        c.load().note_previous_key(&events, "show", Scope::Ingest);
        c.apply(DistUpdate { previous: Some(None), ..Default::default() });
        let rt = c.load();
        assert!(rt.previous_token_secret.is_none());
        assert_eq!(rt.previous_token_until, 0);
        assert_eq!(listed(&c), None, "no key held, nothing reported");
        c.apply(set("k2", until));
        assert_eq!(listed(&c), Some(0), "the cleared registry is gone for good");
    }

    /// Reported only while a key is held and live.
    #[test]
    fn legacy_tokens_are_reported_only_while_the_previous_key_is_live() {
        let mut rt = base();
        assert!(rt.legacy_tokens_report(now_unix()).is_none());
        rt.previous_token_secret = Some("cc".repeat(32));
        rt.previous_token_until = now_unix() + 60;
        let report = rt.legacy_tokens_report(now_unix()).expect("held and live");
        assert_eq!(report.until, rt.previous_token_until);
        assert!(rt.legacy_tokens_report(rt.previous_token_until).is_none(), "at until, gone");
    }

    /// The id the relay reports for a key is the manager's own `key_id_of`:
    /// the same vectors pin it on both sides.
    #[test]
    fn a_key_id_matches_the_managers() {
        assert_eq!(
            key_id_of("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
            "35502dabf9d7d53a"
        );
        assert_eq!(
            key_id_of("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"),
            "0f44205bdd1b60de"
        );
    }

    /// Which keys the relay holds, by id: the previous one only while it is
    /// still accepted.
    #[test]
    fn the_key_report_names_what_the_relay_verifies_with() {
        let mut rt = base();
        let now = now_unix();
        assert_eq!(
            rt.token_key_report(now),
            Some(TokenKeyReport { key_id: key_id_of("aa"), previous_key_id: None, previous_until: 0 })
        );
        rt.previous_token_secret = Some("cc".repeat(32));
        rt.previous_token_until = now + 60;
        let report = rt.token_key_report(now).expect("a key");
        assert_eq!(report.previous_key_id, Some(key_id_of(&"cc".repeat(32))));
        assert_eq!(report.previous_until, now + 60);
        let lapsed = rt.token_key_report(now + 60).expect("a key");
        assert_eq!((lapsed.previous_key_id, lapsed.previous_until), (None, 0), "at until, gone");
        rt.token_secret = None;
        assert!(rt.token_key_report(now).is_none(), "no key, no report");
    }

    #[tokio::test]
    async fn cascade_changes_are_observable() {
        let c = DistributionControl::new(base(), vec![]);
        let mut rx = c.subscribe_cascade();
        c.set_cascade(vec![CascadeSource {
            upstream_whep_url: "http://x/whep/s".into(),
            local_stream: "s".into(),
            token: None,
        }]);
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }
}
