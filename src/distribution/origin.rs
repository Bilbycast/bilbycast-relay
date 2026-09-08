// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Tier 1 — LL-HLS / CMAF HTTP origin, disk-backed.
//!
//! Media segments are written to disk and retained by age, bounded by a
//! per-stream byte cap and floored at a segment count. Manifests and init
//! segments stay in memory: they are rewritten every segment and never
//! evicted, so persisting them would be churn on the hottest objects here
//! for no durability benefit — nothing reads them back after a restart,
//! because the segments they reference are gone too.
//!
//! The edge's existing CMAF output PUTs browser-playable fMP4 segments +
//! HLS/DASH manifests to `{ingest_url}/{file}`. Point that `ingest_url` at
//! `https://{relay}/origin/{stream}` and this module becomes the in-ecosystem
//! HTTP origin: it accepts the authenticated PUTs, keeps a small sliding
//! window of the most recent media segments (manifests are kept and
//! overwritten in place), and serves GETs with correct content types + CORS.
//!
//! This is the CDN-scalable, no-per-viewer-state browser tier. It preserves
//! the relay's opacity in spirit — the relay stores and serves opaque bytes
//! like any HTTP cache, and never parses the media. Front it with a real CDN
//! for large audiences; a single relay origin suits modest audiences.
//!
//! P0 limitation: whole-object PUT/GET (segment-granularity latency). True
//! LL-HLS partial-object streaming (serving byte ranges of an in-progress
//! chunked-transfer PUT) is a follow-up; the sub-second tier is WHEP.

use std::collections::VecDeque;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::extract::DefaultBodyLimit;
use axum::routing::put;
use axum::Router;
use dashmap::DashMap;
use tokio::sync::Mutex;

use super::{token, DistributionState};

/// How the origin store is sized. Bundled so the knobs travel together — they
/// interact, and reading one without the others is misleading.
#[derive(Debug, Clone)]
pub struct OriginConfig {
    /// Directory media segments are written under, one sub-directory per
    /// stream. Adopted on startup — see [`OriginStore::new`].
    pub root: PathBuf,
    /// Primary policy: evict a segment once it is older than this. Size it to
    /// the DVR window the edge advertises **plus headroom** — a viewer parked
    /// mid-window must not have the segment under them deleted.
    pub retention: Duration,
    /// Safety bound, per stream. A bitrate spike must not fill the volume just
    /// because `retention` has not elapsed yet. Total disk is roughly this
    /// times the number of live streams.
    pub max_bytes_per_stream: u64,
    /// Floor: never evict below this many recent segments, whatever the other
    /// two say. Stops a stalled or very-low-bitrate stream having its whole
    /// window aged out from under a live player.
    pub min_segments: usize,
    /// Never let the filesystem fall below this many bytes free.
    ///
    /// The guard of last resort, and the only one that cannot be got wrong
    /// from outside. `retention` and `max_bytes_per_stream` are both pushed by
    /// the manager, which sizes them from the DVR window it was asked for and
    /// **cannot see this relay's disk** — nothing in a node's health payload
    /// reports free space. So a 2h30m window on a small VPS is a policy the
    /// manager will happily push and the relay will happily honour, right up
    /// until the volume fills.
    ///
    /// It did: the demo rig filled its disk and took Postgres down with it,
    /// which is what this exists to stop. The relay owns the disk, so the
    /// relay has to be the one that refuses.
    ///
    /// Enforced across *all* streams, oldest first, because the failure is
    /// node-wide: one stream inside its own byte cap can still be the one that
    /// fills the volume when there are four of them.
    pub min_free_bytes: u64,
    /// How long past `retention` a stream may sit without a PUT before it is
    /// reclaimed outright — segments, manifest, init and directory.
    ///
    /// By `retention` the segments have expired anyway; this is the pause
    /// before the stream entry itself goes, so a producer that blips does not
    /// lose it. Separate from `retention` because the two answer different
    /// questions: how much history to keep, versus how long to believe a
    /// silent producer is coming back.
    pub idle_grace: Duration,
}

impl OriginConfig {
    /// The retention knobs on their own, as the store's starting policy.
    pub fn policy(&self) -> OriginPolicy {
        OriginPolicy {
            retention: self.retention,
            max_bytes_per_stream: self.max_bytes_per_stream,
            min_segments: self.min_segments,
            idle_grace: self.idle_grace,
        }
    }
}

/// The retention knobs, separated from `root` because these four are the ones
/// the manager owns and can change while the relay runs — per relay, or for
/// one stream.
///
/// A DVR session is the reason it has to be per stream: a 60-minute window on
/// one feed and a 5-minute window on the rest of the node are not reconcilable
/// through a single node-wide number, and sizing the node-wide number to the
/// longest session would hold every other stream's disk for an hour.
///
/// `root` deliberately stays out: moving the storage directory under a running
/// store would strand every segment already written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginPolicy {
    pub retention: Duration,
    pub max_bytes_per_stream: u64,
    pub min_segments: usize,
    pub idle_grace: Duration,
}

impl OriginPolicy {
    /// This policy with the patch's present fields overlaid.
    ///
    /// The floor is held at 1: a `min_segments` of 0 lets a live stream be
    /// evicted to nothing between a player's manifest fetch and its segment
    /// fetch, which is a 404 mid-playback rather than a shorter window.
    pub fn patched(self, p: &crate::distribution_control::OriginPolicyPatch) -> Self {
        Self {
            retention: p
                .retention_secs
                .map(Duration::from_secs)
                .unwrap_or(self.retention),
            max_bytes_per_stream: p
                .max_bytes_per_stream
                .unwrap_or(self.max_bytes_per_stream),
            min_segments: p.min_segments.unwrap_or(self.min_segments).max(1),
            idle_grace: p
                .idle_grace_secs
                .map(Duration::from_secs)
                .unwrap_or(self.idle_grace),
        }
    }
}

/// What one stream is currently costing, for the manager's health report.
///
/// Without this the operator can see the node's total disk but not which
/// stream is spending it, which is the question actually asked when a volume
/// fills.
#[derive(Debug, Clone)]
pub struct StreamUsage {
    pub stream: String,
    pub segments: usize,
    pub bytes: u64,
    /// Seconds since the last successful PUT — how stale this stream is.
    pub idle_secs: u64,
    /// True when a per-stream override is in force rather than the node
    /// default, so the operator can tell a deliberate window from a drifted one.
    pub policy_overridden: bool,
}

/// An object served to a player or CDN.
pub struct ObjectResponse {
    pub bytes: Bytes,
    pub content_type: &'static str,
    /// Strong validator over the bytes.
    ///
    /// Everything here is served `must-revalidate`, because a name in a live
    /// stream is not stable across restarts — but a revalidation with no
    /// validator to compare is a full re-download every time. Scrubbing a
    /// 60-minute DVR window re-fetches segments constantly, so the difference
    /// is the whole window's bytes versus a few hundred 304s.
    ///
    /// Derived from the content, so a re-PUT under the same name changes it,
    /// which is exactly the case a date-based validator would get wrong.
    pub etag: String,
}

/// Is this object an HLS playlist, whose URIs a viewer will fetch next?
fn is_hls_playlist(file: &str) -> bool {
    file.ends_with(".m3u8")
}

/// Re-emit a playlist with `?token=` appended to every URI it names.
///
/// Two kinds of URI appear: a bare line (a media segment) and a quoted
/// `URI="..."` attribute (`EXT-X-MAP`, `EXT-X-PART`, `EXT-X-PRELOAD-HINT`,
/// `EXT-X-RENDITION-REPORT`). Both are relative, and both are fetched without
/// the query the playlist itself arrived with.
fn playlist_with_token(body: &[u8], token: &str) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return body.to_vec(); // not a playlist after all; leave it alone
    };
    let enc = percent_encode_token(token);
    let add = |uri: &str| -> String {
        let sep = if uri.contains('?') { '&' } else { '?' };
        format!("{uri}{sep}token={enc}")
    };

    let mut out = String::with_capacity(text.len() + 64);
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let eol = &line[trimmed.len()..];
        if trimmed.is_empty() {
            out.push_str(line);
        } else if let Some(rest) = trimmed.strip_prefix('#') {
            // Rewrite each quoted URI attribute in place.
            match rest.find("URI=\"") {
                Some(i) => {
                    let start = 1 + i + 5; // '#' + prefix + `URI="`
                    match trimmed[start..].find('"') {
                        Some(len) => {
                            out.push_str(&trimmed[..start]);
                            out.push_str(&add(&trimmed[start..start + len]));
                            out.push_str(&trimmed[start + len..]);
                        }
                        None => out.push_str(trimmed),
                    }
                }
                None => out.push_str(trimmed),
            }
            out.push_str(eol);
        } else {
            out.push_str(&add(trimmed));
            out.push_str(eol);
        }
    }
    out.into_bytes()
}

/// Percent-encode the characters a token can carry that are not safe to drop
/// unescaped into a query. A multi-stream token carries `,`; nothing else in
/// the alphabet (`0-9 a-z A-Z . - _ ,`) needs escaping.
fn percent_encode_token(token: &str) -> String {
    token.replace(',', "%2C")
}

/// RFC 9110 8.8.3.2: `If-None-Match` is `*` or a comma-separated list, and the
/// comparison is weak — a `W/` prefix on either side still matches.
fn if_none_match_matches(header_value: &str, etag: &str) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").trim().to_string();
    let want = strip(etag);
    header_value
        .split(',')
        .any(|t| t.trim() == "*" || strip(t) == want)
}

/// A strong ETag over an object's bytes.
fn etag_for(bytes: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    // Not a cryptographic digest: this distinguishes versions of an object the
    // relay itself wrote, it is not a trust boundary. Length is mixed in so a
    // hash collision also has to match the size.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    format!("\"{:016x}-{:x}\"", h.finish(), bytes.len())
}

/// A small, hot object held in memory: manifests and init segments.
///
/// These are rewritten in place (a manifest changes every segment) and are
/// never evicted, so putting them on disk would be churn on the hottest object
/// in the system for no durability benefit — nothing reads them back after a
/// restart, because the segments they reference are gone too.
struct KeptObject {
    bytes: Bytes,
    content_type: &'static str,
}

/// Index entry for a media segment. The bytes live on disk; this is only what
/// eviction needs in order to make a decision.
struct SegmentMeta {
    path: PathBuf,
    content_type: &'static str,
    len: u64,
    stored_at: Instant,
}

/// Per-stream store.
struct StreamOrigin {
    /// Manifests + init segments, in memory, never evicted.
    kept: DashMap<String, Arc<KeptObject>>,
    /// Media segments, bytes on disk.
    segments: DashMap<String, Arc<SegmentMeta>>,
    /// Eviction order, oldest at the front.
    ///
    /// The in-memory store this replaces found the oldest segment by scanning
    /// the map, which was fine at a window of 8. A DVR window is thousands of
    /// segments, where a scan per PUT turns quadratic — hence an explicit
    /// queue. The `Mutex` is only held for queue surgery, never across the
    /// file I/O it schedules.
    order: Mutex<VecDeque<String>>,
    bytes: AtomicU64,
    dir: PathBuf,
    /// Milliseconds since [`OriginStore::started`] at the last successful PUT.
    ///
    /// Eviction used to run only when a segment arrived, so a stream whose
    /// producer stopped kept its disk indefinitely — past retention, with its
    /// manifest still being served. The sweep uses this to tell "quiet" from
    /// "gone".
    last_put_ms: AtomicU64,
}

impl StreamOrigin {
    fn new(dir: PathBuf, now_ms: u64) -> Self {
        Self {
            kept: DashMap::new(),
            segments: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            bytes: AtomicU64::new(0),
            dir,
            last_put_ms: AtomicU64::new(now_ms),
        }
    }
}

/// The origin store: per-stream caches of manifests (memory) and media
/// segments (disk), with age- and size-bounded retention.
///
/// The store still never parses the media. It decides what to keep from the
/// filename, the arrival time and the byte count alone — the same
/// opaque-bytes contract the in-memory version had.
pub struct OriginStore {
    cfg: OriginConfig,
    /// Live node-wide retention policy. Seeded from `cfg`, then owned by the
    /// manager. Read on every PUT and every sweep, so it is an `ArcSwap`
    /// rather than a lock.
    policy: arc_swap::ArcSwap<OriginPolicy>,
    /// Per-stream overrides, keyed by stream id. An entry here wins over
    /// `policy` for that stream and nothing else.
    stream_policy: DashMap<String, OriginPolicy>,
    streams: DashMap<String, Arc<StreamOrigin>>,
    total_bytes: AtomicU64,
    /// Anchor for `last_put_ms`, so idle time needs no wall clock.
    started: Instant,
}

/// Marker written into the origin root, so the store can tell a directory it
/// owns — and may therefore adopt from, and evict within — from one an
/// operator pointed it at by mistake.
const ORIGIN_MARKER: &str = ".bilbycast-origin";

/// Exported clips, inside the stream they were cut from.
///
/// Inside rather than beside, so the existing teardown gets them for free: the
/// `remove_dir_all` in `remove_stream` already takes the whole stream
/// directory, which is exactly the retention the clips are supposed to have —
/// as long as the session, gone with it.
///
/// They are deliberately outside the segment bookkeeping. The sweep works from
/// an in-memory queue that only `put` and adoption add to, so a clip is never
/// a candidate for eviction by age or by byte cap: a clip that aged out at the
/// same rate as the media it was cut from would vanish while the session that
/// owns it is still running.
const CLIPS_DIR: &str = "clips";

/// Does this directory look like a store an older relay wrote?
///
/// Used only when the marker is absent, to tell "our own store, from before
/// the marker existed" from "somebody else's directory". The guard exists for
/// the home directory or mount point somebody names by typo, and that must
/// still be refused — so this is deliberately narrow:
///
/// * every top-level entry is a directory (a home directory has files in it);
/// * every file inside those is a segment, a thumbnail or an interrupted PUT;
/// * and at least one is a `.m4s` segment.
///
/// That last clause is what keeps a photo library out. Thumbnails are `.jpg`,
/// so folders-of-jpgs would otherwise pass — and this store ages its contents
/// out, which makes a false positive expensive.
fn looks_like_origin_store(root: &std::path::Path) -> std::io::Result<bool> {
    let mut saw_segment = false;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == std::ffi::OsStr::new(ORIGIN_MARKER) {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Ok(false);
        }
        for f in std::fs::read_dir(entry.path())? {
            let f = f?;
            // Exported clips live in their own subdirectory of the stream, so a
            // directory here is expected as long as it is that one.
            if f.file_type()?.is_dir() {
                if f.file_name() == std::ffi::OsStr::new(CLIPS_DIR) {
                    continue;
                }
                return Ok(false);
            }
            if !f.file_type()?.is_file() {
                return Ok(false);
            }
            let name = f.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".m4s") {
                saw_segment = true;
            } else if !(name.ends_with(".mp4") || name.ends_with(".jpg") || name.ends_with(".part"))
            {
                return Ok(false);
            }
        }
    }
    Ok(saw_segment)
}

impl OriginStore {
    /// Build the store, adopting whatever is already in `root`.
    ///
    /// This used to delete the root, on the reasoning that the manifests
    /// referencing those segments lived in memory and died with the process,
    /// so nothing could address them. That holds only when the **producer**
    /// restarts too. The edge usually does not: it re-publishes a manifest
    /// describing its whole window within a segment or two, and each segment
    /// is PUT exactly once as it is produced — so everything older than the
    /// restart was gone for good, and the demo rig lost a 2h30m window and
    /// 2h30m of wall time rebuilding it, every time.
    ///
    /// Adopting them instead makes a relay restart cost nothing: the files
    /// were on disk and readable throughout. What bounds the directory is the
    /// retention and byte-cap sweep that runs anyway — the wipe was a blunt
    /// substitute for it, and one that could only be applied at startup.
    ///
    /// Manifests and `init.mp4` are memory-only and still die with the
    /// process. That is already handled: the edge re-publishes both, which is
    /// what `init_last_upload` exists for on that side.
    ///
    /// A directory that already exists, is not empty and carries no
    /// `.bilbycast-origin` marker is refused rather than adopted: the root is
    /// operator-supplied and everything under it becomes evictable, so a typo
    /// naming a home directory must not enrol it into the sweep.
    pub fn new(cfg: OriginConfig) -> std::io::Result<Self> {
        // Only ever adopt — and evict from — a directory this store made.
        // `origin_storage_dir` is operator-supplied and everything under it
        // becomes deletable: `remove_stream` does a `remove_dir_all` from the
        // idle sweep, and the free-space floor evicts across every stream it
        // finds. Pointed at a home directory or a mount point by a typo, the
        // store would index whatever is there and then age it out. A
        // directory that exists, is not empty, and has no marker is somebody
        // else's.
        //
        // The startup wipe this guard was written for is gone — the window on
        // disk is adopted now — but the guard matters more without it, not
        // less: adoption pulls whatever it finds *into* the store's
        // bookkeeping, so the recursive delete simply moved from here to the
        // sweep.
        let marker = cfg.root.join(ORIGIN_MARKER);
        if cfg.root.exists() {
            let empty = std::fs::read_dir(&cfg.root)?.next().is_none();
            if !empty && !marker.exists() {
                // The marker landed after relays were already in the field, so a
                // store written by an older one carries no marker and the test
                // above cannot tell it from a stranger's directory. Refusing it
                // means a relay that will not start after an upgrade, reporting
                // what reads like a misconfiguration — measured on the demo rig
                // upgrading 0.10.6 -> 0.13.0.
                //
                // Recognise the shape instead of the marker.
                if looks_like_origin_store(&cfg.root)? {
                    tracing::warn!(
                        root = %cfg.root.display(),
                        "origin storage dir has no {ORIGIN_MARKER} but holds only segment \
                         directories; adopting it as this relay's own — a store written \
                         before the marker existed. Writing the marker now."
                    );
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "origin storage dir {} is not empty and was not created by the relay \
                             (no {ORIGIN_MARKER}); refusing to adopt or erase it — point \
                             distribution.origin_storage_dir at a directory of its own",
                            cfg.root.display()
                        ),
                    ));
                }
            }
        }
        std::fs::create_dir_all(&cfg.root)?;
        // Re-written on every start: a marker lost to a hand clean-out must not
        // turn the relay's own root into a foreign directory it then refuses.
        std::fs::write(&marker, b"bilbycast-relay origin store\n")?;
        let policy = arc_swap::ArcSwap::from_pointee(cfg.policy());
        let store = Self {
            cfg,
            policy,
            stream_policy: DashMap::new(),
            streams: DashMap::new(),
            total_bytes: AtomicU64::new(0),
            started: Instant::now(),
        };
        store.adopt_existing();
        Ok(store)
    }

    /// Index the segments already on disk, so a restart keeps the window.
    ///
    /// Failures here are logged and skipped rather than fatal: an
    /// unreadable file from a previous run must not stop the relay coming up,
    /// and a segment that cannot be indexed is simply one the store does not
    /// know it has — which the playlist trim then declines to advertise.
    fn adopt_existing(&self) {
        let root = match std::fs::read_dir(&self.cfg.root) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("origin: cannot read {}: {e}", self.cfg.root.display());
                return;
            }
        };
        let now = std::time::SystemTime::now();
        let mut streams = 0usize;
        let mut adopted = 0usize;
        let mut bytes = 0u64;

        for entry in root.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let Some(stream) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let files = match std::fs::read_dir(entry.path()) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!("origin: cannot read stream dir '{stream}': {e}");
                    continue;
                }
            };
            // Collect first so the queue can be built oldest-first. Eviction
            // drops from the front, so directory order would drop whichever
            // end the filesystem happened to list first.
            let mut found: Vec<(String, PathBuf, u64, std::time::Duration)> = Vec::new();
            for f in files.flatten() {
                let name = match f.file_name().to_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                // Exported clips are not segments: they must survive a restart
                // untouched, and must not enter the eviction queue.
                //
                // Skipped explicitly rather than relying on what follows. The
                // debris sweep below uses `remove_file`, which refuses a
                // directory, so the clips would survive without this — but that
                // is an accident of the call used, not a decision, and a later
                // change to `remove_dir_all` would silently delete every
                // exported clip on the next restart. Stating the intent here
                // costs one comparison.
                if name == CLIPS_DIR {
                    continue;
                }
                // Only media segments live on disk, so anything else here is
                // debris — including a `.part`, which is a PUT interrupted by
                // the very restart being recovered from and truncated by
                // definition. `is_media_segment` already rejects it on the
                // extension; the point is that it is removed rather than left
                // to accumulate across restarts.
                if !is_media_segment(&name) {
                    let _ = std::fs::remove_file(f.path());
                    continue;
                }
                let Ok(meta) = f.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                let age = meta
                    .modified()
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .unwrap_or_default();
                found.push((name, f.path(), meta.len(), age));
            }
            if found.is_empty() {
                continue;
            }
            // Descending age, so the oldest segment is at the front — the end
            // eviction drops from. `Reverse` reads backwards next to that:
            // reversing the age *ordering* is what puts the largest age first.
            found.sort_by_key(|f| std::cmp::Reverse(f.3));

            let origin = self.ensure(&stream);
            // `try_lock`, not `blocking_lock`: the store is constructed inside
            // the async runtime (`run_distribution`), where blocking on a
            // tokio mutex panics outright. It cannot contend here — nothing
            // else holds a reference to the store yet — so a failure to
            // acquire means something is wrong enough to skip the stream
            // rather than to stall startup.
            let Ok(mut order) = origin.order.try_lock() else {
                tracing::warn!("origin: stream '{stream}' busy during adoption; skipped");
                continue;
            };
            for (name, path, len, age) in found {
                // `stored_at` has to carry the file's real age, or the
                // retention sweep treats a whole recovered window as brand
                // new and holds it well past its span.
                let stored_at = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
                origin.segments.insert(
                    name.clone(),
                    Arc::new(SegmentMeta {
                        path,
                        content_type: content_type_for(&name),
                        len,
                        stored_at,
                    }),
                );
                order.push_back(name);
                origin.bytes.fetch_add(len, Ordering::Relaxed);
                self.total_bytes.fetch_add(len, Ordering::Relaxed);
                adopted += 1;
                bytes += len;
            }
            drop(order);
            streams += 1;
        }
        if adopted > 0 {
            tracing::info!(
                adopted,
                streams,
                megabytes = bytes as f64 / 1e6,
                "origin: adopted segments from a previous run; retention trims them as normal"
            );
        }
    }

    /// The policy in force for one stream: its override if it has one, else
    /// the node-wide default.
    pub fn policy_for(&self, stream: &str) -> OriginPolicy {
        if let Some(p) = self.stream_policy.get(stream) {
            return *p;
        }
        **self.policy.load()
    }

    /// The node-wide default currently in force.
    pub fn default_policy(&self) -> OriginPolicy {
        **self.policy.load()
    }

    /// Replace the node-wide default (manager push). Streams carrying an
    /// override are unaffected.
    pub fn set_default_policy(&self, policy: OriginPolicy) {
        self.policy.store(Arc::new(policy));
    }

    /// Apply a manager storage-policy push.
    ///
    /// Per-stream entries are patched against the **resulting** default, so an
    /// override naming only one field inherits the rest of the node policy
    /// rather than defaulting it to zero.
    pub fn apply_policy_update(
        &self,
        update: &crate::distribution_control::OriginPolicyUpdate,
    ) {
        let base = self.default_policy();
        let next_default = match &update.default {
            Some(p) => base.patched(p),
            None => base,
        };
        self.set_default_policy(next_default);
        if let Some(list) = &update.per_stream {
            self.set_stream_policies(
                list.iter()
                    .map(|(s, p)| (s.clone(), next_default.patched(p)))
                    .collect(),
            );
        }
    }

    /// Replace the whole set of per-stream overrides.
    ///
    /// Deliberately a replace rather than a merge: the manager holds the
    /// authoritative session list, and a merge would leave an override behind
    /// after its session ended, quietly pinning that stream's disk at the old
    /// window for as long as the relay ran.
    pub fn set_stream_policies(&self, policies: Vec<(String, OriginPolicy)>) {
        let incoming: std::collections::HashSet<&str> =
            policies.iter().map(|(s, _)| s.as_str()).collect();
        self.stream_policy
            .retain(|k, _| incoming.contains(k.as_str()));
        for (stream, p) in policies {
            self.stream_policy.insert(stream, p);
        }
    }

    /// Per-stream disk usage, newest-first by idle time, for health reporting.
    pub fn usage(&self) -> Vec<StreamUsage> {
        let now_ms = self.now_ms();
        let mut out: Vec<StreamUsage> = self
            .streams
            .iter()
            .map(|e| {
                let o = e.value();
                StreamUsage {
                    stream: e.key().clone(),
                    segments: o.segments.len(),
                    bytes: o.bytes.load(Ordering::Relaxed),
                    idle_secs: now_ms
                        .saturating_sub(o.last_put_ms.load(Ordering::Relaxed))
                        / 1000,
                    policy_overridden: self.stream_policy.contains_key(e.key()),
                }
            })
            .collect();
        out.sort_by(|a, b| a.idle_secs.cmp(&b.idle_secs).then(a.stream.cmp(&b.stream)));
        out
    }

    /// A stream name must resolve to exactly one ordinary directory under the
    /// root — not `.`, not `..`, not a nested or absolute path.
    ///
    /// The HTTP handlers validate the name before it reaches here, but this
    /// store's methods are `pub` and every one of them turns the name into a
    /// filesystem path. `remove_stream` in particular does a
    /// `remove_dir_all`, so a name of `..` would recursively delete the
    /// origin root's *parent* — the relay's whole data directory.
    fn safe_stream_name(stream: &str) -> bool {
        let mut components = FsPath::new(stream).components();
        matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none()
    }

    fn ensure(&self, stream: &str) -> Arc<StreamOrigin> {
        if let Some(s) = self.streams.get(stream) {
            return s.clone();
        }
        let now_ms = self.now_ms();
        self.streams
            .entry(stream.to_string())
            .or_insert_with(|| Arc::new(StreamOrigin::new(self.cfg.root.join(stream), now_ms)))
            .clone()
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Store an object.
    ///
    /// Manifests and init segments overwrite in place in memory. Media
    /// segments are written to disk and joined to the retention queue; the
    /// index entry is published only once the bytes are in place, so a reader
    /// can never observe a half-written segment.
    pub async fn put(&self, stream: &str, file: &str, bytes: Bytes) -> std::io::Result<()> {
        if !Self::safe_stream_name(stream) || !valid_object_name(file) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "origin: unsafe stream or object name",
            ));
        }
        let content_type = content_type_for(file);
        let origin = self.ensure(stream);
        origin.last_put_ms.store(self.now_ms(), Ordering::Relaxed);

        if !is_media_segment(file) {
            // A media playlist may not advertise segments this store cannot
            // serve. See `trim_unbacked_head`.
            //
            // The producer's window and this store's holdings move
            // independently. The edge re-publishes its whole window on every
            // manifest refresh and PUTs each segment exactly once, as it is
            // produced — while retention, the per-stream byte cap and the
            // node-wide free-space floor all evict from the head here. So an
            // entry this store has dropped names a file that will never arrive
            // again, and the relay's window is free to be the shorter of the
            // two. Trimming on every manifest PUT rather than once at startup
            // is what keeps the advertised window meaning what it says.
            let bytes = if file.to_ascii_lowercase().ends_with(".m3u8") {
                let segments = &origin.segments;
                match trim_unbacked_head(&bytes, &|uri| segments.contains_key(uri)) {
                    Some(trimmed) => Bytes::from(trimmed),
                    None => bytes,
                }
            } else {
                bytes
            };
            origin
                .kept
                .insert(file.to_string(), Arc::new(KeptObject { bytes, content_type }));
            return Ok(());
        }

        let len = bytes.len() as u64;
        let path = origin.dir.join(file);
        let tmp = origin.dir.join(format!("{file}.part"));
        tokio::fs::create_dir_all(&origin.dir).await?;
        // A `.part` left behind is invisible to every bound in this file: it is
        // in no index, counted in no byte total, and in no eviction queue, so
        // nothing ever reclaims it. Clean up on the failure paths rather than
        // waiting for the next restart's adoption pass to clear it, which on a
        // long-lived relay may be months away.
        if let Err(e) = tokio::fs::write(&tmp, &bytes).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }

        let meta = Arc::new(SegmentMeta {
            path,
            content_type,
            len,
            stored_at: Instant::now(),
        });
        // Re-PUT under the same name must not double-count the bytes, and
        // must not leave the name where it was in the queue.
        //
        // `evict` only ever inspects `order.front()` and stops as soon as that
        // one is young enough, which is sound only while the queue is ordered
        // by `stored_at`. A re-PUT refreshes `stored_at`; leaving the name at
        // its old position puts a young entry in front of genuinely expired
        // ones, and eviction then stops at it — retention and the byte bound
        // both quietly stop being enforced for that stream.
        //
        // This is not hypothetical: segment numbering restarts at `seg-00000`
        // every time the producing flow restarts, so the first segment after a
        // restart is a re-PUT of the oldest name in the queue.
        let mut order = origin.order.lock().await;
        if let Some(prev) = origin.segments.insert(file.to_string(), meta) {
            origin.bytes.fetch_sub(prev.len, Ordering::Relaxed);
            self.total_bytes.fetch_sub(prev.len, Ordering::Relaxed);
            if let Some(pos) = order.iter().position(|n| n == file) {
                order.remove(pos);
            }
        }
        order.push_back(file.to_string());
        drop(order);
        origin.bytes.fetch_add(len, Ordering::Relaxed);
        self.total_bytes.fetch_add(len, Ordering::Relaxed);

        let pol = self.policy_for(stream);
        self.evict(&origin, &pol, pol.min_segments).await;
        Ok(())
    }

    /// Drop segments that are too old, or that push the stream past its byte
    /// bound, oldest first — never going below `floor`.
    ///
    /// `floor` is `min_segments` for a live stream, protecting a slow or
    /// stalled producer from having its whole window aged out. The sweep
    /// passes 0 for a stream that has stopped publishing: there is no live
    /// player to protect and the floor would otherwise pin those segments on
    /// disk forever.
    async fn evict(&self, origin: &StreamOrigin, pol: &OriginPolicy, floor: usize) {
        loop {
            let mut order = origin.order.lock().await;
            if order.len() <= floor {
                break;
            }
            let Some(front) = order.front().cloned() else {
                break;
            };
            let Some(meta) = origin.segments.get(&front).map(|m| m.clone()) else {
                // Queued name with no index entry: drop it and carry on.
                order.pop_front();
                continue;
            };
            let too_old = meta.stored_at.elapsed() >= pol.retention;
            let too_big = origin.bytes.load(Ordering::Relaxed) > pol.max_bytes_per_stream;
            if !too_old && !too_big {
                break;
            }
            order.pop_front();
            drop(order);

            origin.segments.remove(&front);
            origin.bytes.fetch_sub(meta.len, Ordering::Relaxed);
            self.total_bytes.fetch_sub(meta.len, Ordering::Relaxed);
            if let Err(e) = tokio::fs::remove_file(&meta.path).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    path = %meta.path.display(),
                    error = %e,
                    "origin: could not delete evicted segment"
                );
            }
        }
    }

    /// Fetch an object, reading from disk for media segments.
    ///
    /// A segment evicted between the index lookup and the read reports as
    /// absent rather than as an error — that is a normal race against
    /// retention, not a fault.
    pub async fn get(&self, stream: &str, file: &str) -> Option<ObjectResponse> {
        if !Self::safe_stream_name(stream) || !valid_object_name(file) {
            return None;
        }
        let origin = self.streams.get(stream)?.clone();
        if let Some(kept) = origin.kept.get(file) {
            return Some(ObjectResponse {
                etag: etag_for(&kept.bytes),
                bytes: kept.bytes.clone(),
                content_type: kept.content_type,
            });
        }
        let meta = origin.segments.get(file).map(|m| m.clone())?;
        match tokio::fs::read(&meta.path).await {
            Ok(b) => Some(ObjectResponse {
                etag: etag_for(&b),
                bytes: Bytes::from(b),
                content_type: meta.content_type,
            }),
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        path = %meta.path.display(),
                        error = %e,
                        "origin: could not read stored segment"
                    );
                }
                None
            }
        }
    }

    fn clips_dir(&self, stream: &str) -> PathBuf {
        self.cfg.root.join(stream).join(CLIPS_DIR)
    }

    /// Record what was asked for. The media follows later, from the edge.
    ///
    /// Re-requesting the **same mark** is idempotent: the existing record is
    /// left alone, so asking again for something already cut does not throw
    /// away the clip sitting there ready.
    ///
    /// A **different** mark that happens to produce the same name is a
    /// different clip and gets a suffix. The name is built from a timecode and
    /// a label, so two marks in the same second with the same label collide —
    /// and silently dropping the second, which is what skipping on name alone
    /// did, loses an export the operator asked for and reported nothing.
    pub fn record_clip_requests(
        &self,
        stream: &str,
        req: &ClipRequest,
    ) -> std::io::Result<Vec<ClipRecord>> {
        let dir = self.clips_dir(stream);
        std::fs::create_dir_all(&dir)?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut out = Vec::new();
        for ask in &req.clips {
            let Some(name) = self.free_clip_name(&dir, &ask.name, &ask.at)? else {
                // Same mark, already recorded. Hand back what is there so the
                // caller sees its real state rather than a fresh pending one.
                if let Some(existing) = self
                    .list_clips(stream)
                    .into_iter()
                    .find(|c| c.name == ask.name)
                {
                    out.push(existing);
                }
                continue;
            };
            let rec = ClipRecord {
                name,
                at: ask.at.clone(),
                pre_secs: req.pre_secs.min(MAX_CLIP_TOTAL_SECS),
                post_secs: req.post_secs.min(MAX_CLIP_TOTAL_SECS),
                requested_at: now.clone(),
                bytes: 0,
                ready: false,
                failed: false,
                error: None,
            };
            let body = serde_json::to_vec_pretty(&rec).map_err(std::io::Error::other)?;
            std::fs::write(dir.join(format!("{}.json", rec.name)), body)?;
            out.push(rec);
        }
        Ok(out)
    }

    /// A name to file this request under, or `None` if this exact mark is
    /// already recorded.
    ///
    /// Bounded: after a handful of collisions this gives up and reuses the
    /// name, because an unbounded search is a way to spend a request's time on
    /// a filesystem rather than a way to be correct.
    fn free_clip_name(
        &self,
        dir: &std::path::Path,
        wanted: &str,
        at: &str,
    ) -> std::io::Result<Option<String>> {
        for n in 1..=9u32 {
            let candidate = if n == 1 {
                wanted.to_string()
            } else {
                format!("{wanted} ({n})")
            };
            let path = dir.join(format!("{candidate}.json"));
            let Ok(raw) = std::fs::read(&path) else {
                return Ok(Some(candidate)); // free
            };
            // Taken — by this same mark, or a different one?
            match serde_json::from_slice::<ClipRecord>(&raw) {
                Ok(existing) if existing.at == at => return Ok(None),
                _ => continue,
            }
        }
        Ok(Some(wanted.to_string()))
    }

    /// Every clip this stream knows about, ready or not.
    ///
    /// `ready` and `bytes` come from the media file on disk, never from the
    /// record: a record that claimed ready without the bytes behind it would
    /// offer the portal a download that 404s.
    pub fn list_clips(&self, stream: &str) -> Vec<ClipRecord> {
        let dir = self.clips_dir(stream);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let file = e.file_name().to_string_lossy().to_string();
            let Some(stem) = file.strip_suffix(".json") else {
                continue;
            };
            let Ok(raw) = std::fs::read(e.path()) else {
                continue;
            };
            let Ok(mut rec) = serde_json::from_slice::<ClipRecord>(&raw) else {
                continue;
            };
            match std::fs::metadata(dir.join(format!("{stem}.mp4"))) {
                Ok(m) if m.is_file() => {
                    rec.ready = true;
                    rec.bytes = m.len();
                }
                _ => {
                    rec.ready = false;
                    rec.bytes = 0;
                }
            }
            out.push(rec);
        }
        out.sort_by(|a, b| a.at.cmp(&b.at));
        out
    }

    /// The edge hands the finished media over.
    ///
    /// Written to `.part` and renamed, so a half-uploaded clip is never
    /// visible as ready — `list_clips` decides on the media file existing.
    pub async fn put_clip(&self, stream: &str, name: &str, body: &[u8]) -> std::io::Result<()> {
        let dir = self.clips_dir(stream);
        tokio::fs::create_dir_all(&dir).await?;
        let tmp = dir.join(format!("{name}.mp4.part"));
        tokio::fs::write(&tmp, body).await?;
        tokio::fs::rename(&tmp, dir.join(format!("{name}.mp4"))).await
    }

    /// The same, streamed to disk rather than buffered whole.
    ///
    /// A clip is up to 256 MiB, and holding one entirely in memory to write it
    /// out again is a quarter-gigabyte spike per concurrent upload on a service
    /// whose other objects are two-second segments. The bytes go to the `.part`
    /// file as they arrive, so the peak is a chunk rather than a clip.
    ///
    /// The ceiling is enforced *while* reading: a body that lies about its
    /// length, or sends none, would otherwise be bounded by nothing.
    pub async fn put_clip_streaming(
        &self,
        stream: &str,
        name: &str,
        body: axum::body::Body,
        max_bytes: u64,
    ) -> std::io::Result<u64> {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;

        let dir = self.clips_dir(stream);
        tokio::fs::create_dir_all(&dir).await?;
        let tmp = dir.join(format!("{name}.mp4.part"));
        let mut file = tokio::fs::File::create(&tmp).await?;
        let mut written: u64 = 0;
        let mut stream_body = body.into_data_stream();

        while let Some(chunk) = stream_body.next().await {
            let chunk = chunk.map_err(std::io::Error::other)?;
            written += chunk.len() as u64;
            if written > max_bytes {
                // Abandon the part file rather than leave a truncated clip that
                // `list_clips` would never see but the disk would still hold.
                drop(file);
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "clip exceeds the maximum size",
                ));
            }
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        drop(file);
        tokio::fs::rename(&tmp, dir.join(format!("{name}.mp4"))).await?;
        Ok(written)
    }

    /// How many clips this stream holds, and how much disk they occupy.
    ///
    /// Counts records, not just finished media: a hundred pending requests are
    /// a hundred clips' worth of edge work and disk on the way.
    pub fn clip_usage(&self, stream: &str) -> (usize, u64) {
        let listed = self.list_clips(stream);
        let bytes = listed.iter().map(|c| c.bytes).sum();
        (listed.len(), bytes)
    }

    /// Remove one clip — its media and its record.
    ///
    /// Clips outlive the sweep, so without this the only way to reclaim the
    /// space was to end the session. Returns whether anything was there.
    pub async fn delete_clip(&self, stream: &str, name: &str) -> bool {
        let dir = self.clips_dir(stream);
        let media = tokio::fs::remove_file(dir.join(format!("{name}.mp4")))
            .await
            .is_ok();
        let record = tokio::fs::remove_file(dir.join(format!("{name}.json")))
            .await
            .is_ok();
        media || record
    }

    /// Mark a clip as one the edge could not produce.
    ///
    /// Terminal by design: the exporter skips a failed record, so this is what
    /// stops a clip that can never be cut from being attempted for the life of
    /// the session. An operator who wants another go re-exports the mark, which
    /// writes a fresh record.
    pub fn fail_clip(&self, stream: &str, name: &str, reason: &str) -> std::io::Result<bool> {
        let path = self.clips_dir(stream).join(format!("{name}.json"));
        let Ok(raw) = std::fs::read(&path) else {
            return Ok(false);
        };
        let mut rec: ClipRecord = serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
        rec.failed = true;
        rec.error = Some(reason.chars().take(300).collect());
        let body = serde_json::to_vec_pretty(&rec).map_err(std::io::Error::other)?;
        std::fs::write(&path, body)?;
        Ok(true)
    }

    pub async fn read_clip(&self, stream: &str, name: &str) -> Option<Vec<u8>> {
        tokio::fs::read(self.clips_dir(stream).join(format!("{name}.mp4")))
            .await
            .ok()
    }

    pub async fn remove_stream(&self, stream: &str) {
        if !Self::safe_stream_name(stream) {
            return;
        }
        let Some((_, origin)) = self.streams.remove(stream) else {
            return;
        };
        self.total_bytes
            .fetch_sub(origin.bytes.load(Ordering::Relaxed), Ordering::Relaxed);
        if let Err(e) = tokio::fs::remove_dir_all(&origin.dir).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                dir = %origin.dir.display(),
                error = %e,
                "origin: could not remove stream directory"
            );
        }
    }

    /// Apply retention to every stream, whether or not it is still ingesting.
    ///
    /// Eviction is otherwise driven entirely by arriving segments, which means
    /// a stream whose producer stops is frozen exactly as it was: past its
    /// retention, holding its disk, still serving its manifest, and only
    /// reclaimed by restarting the relay. Measured on a live system, a pair of
    /// abandoned streams held 416 MiB across 1200 files long after expiry.
    ///
    /// Streams idle beyond `retention + IDLE_GRACE` are dropped outright —
    /// their segments have expired by then, so what remains is an empty
    /// directory plus a manifest advertising nothing.
    pub async fn sweep(&self) {
        let now_ms = self.now_ms();

        let names: Vec<String> = self.streams.iter().map(|e| e.key().clone()).collect();
        for name in names {
            let Some(origin) = self.streams.get(&name).map(|s| s.clone()) else {
                continue;
            };
            // Resolved per stream, so a stream with a long session window is
            // not reclaimed on the node's shorter default.
            let pol = self.policy_for(&name);
            let idle_cutoff = (pol.retention + pol.idle_grace).as_millis() as u64;
            let idle_ms = now_ms.saturating_sub(origin.last_put_ms.load(Ordering::Relaxed));
            let dead = idle_ms >= idle_cutoff;

            self.evict(&origin, &pol, if dead { 0 } else { pol.min_segments })
                .await;

            if dead && origin.order.lock().await.is_empty() {
                tracing::info!(
                    stream = %name,
                    idle_secs = idle_ms / 1000,
                    "origin: reclaiming idle stream"
                );
                self.remove_stream(&name).await;
            }
        }

        self.enforce_free_space().await;
    }

    /// Give disk back until the volume is above its floor.
    ///
    /// Runs after the per-stream policies, not instead of them: this is the
    /// guard for when those policies are simply too large for the disk they
    /// landed on, which the manager cannot detect because no node health
    /// payload reports free space.
    ///
    /// Oldest first across every stream, which is the only fair order — a DVR
    /// window gives up its back end first, exactly as retention would. Taking
    /// a whole stream instead would silently end one session to save another.
    async fn enforce_free_space(&self) {
        if self.cfg.min_free_bytes == 0 {
            return;
        }
        let Some(free) = free_bytes(&self.cfg.root) else {
            return;
        };
        if free >= self.cfg.min_free_bytes {
            return;
        }

        let want = self.cfg.min_free_bytes.saturating_sub(free);
        let mut freed: u64 = 0;
        // Round-robin the streams rather than draining one: with several
        // sessions, emptying the first alphabetically would take one feed's
        // whole window while the others kept theirs.
        let names: Vec<String> = self.streams.iter().map(|e| e.key().clone()).collect();
        let mut progress = true;
        while freed < want && progress {
            progress = false;
            for name in &names {
                if freed >= want {
                    break;
                }
                let Some(origin) = self.streams.get(name).map(|s| s.clone()) else {
                    continue;
                };
                // Leave the newest few whatever happens: a player parked at
                // the live edge must still have something to read, and a
                // relay that deletes everything is not more useful than one
                // that is short of space.
                let mut order = origin.order.lock().await;
                if order.len() <= EMERGENCY_KEEP_SEGMENTS {
                    continue;
                }
                let Some(file) = order.pop_front() else { continue };
                drop(order);
                if let Some((_, meta)) = origin.segments.remove(&file) {
                    let _ = tokio::fs::remove_file(&meta.path).await;
                    origin.bytes.fetch_sub(meta.len, Ordering::Relaxed);
                    self.total_bytes.fetch_sub(meta.len, Ordering::Relaxed);
                    freed = freed.saturating_add(meta.len);
                    progress = true;
                }
            }
        }

        // Say it every sweep it is needed, not once on the transition: this is
        // the operator being told their window does not fit the disk, and it
        // stays true until they change something.
        tracing::warn!(
            free_mb = free / 1_048_576,
            floor_mb = self.cfg.min_free_bytes / 1_048_576,
            freed_mb = freed / 1_048_576,
            "origin: below the free-space floor, evicting across all streams; the configured window does not fit this volume"
        );
    }

    /// Bytes of media segments currently on disk across all streams
    /// (telemetry). Excludes the in-memory manifests, which are bounded by
    /// neither policy and are negligible next to the segments.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Directory the store writes under (telemetry / diagnostics).
    pub fn root(&self) -> &FsPath {
        &self.cfg.root
    }
}

/// Trim leading media-playlist entries whose segments the store does not hold.
///
/// The edge re-publishes a manifest describing its **whole** window on every
/// refresh, and PUTs each segment exactly once, as it is produced. So an entry
/// this store no longer holds names a file that will never arrive: the two
/// windows move independently, and the relay's is free to be the shorter one.
///
/// It routinely is. Retention, the per-stream byte cap and the node-wide
/// free-space floor all evict from the head while the producer goes on
/// advertising those entries, and the manager sizes the first two without
/// being able to see this relay's disk at all — a window that does not fit the
/// volume is a policy it will happily push, which is the whole reason
/// `min_free_bytes` exists.
///
/// A relay-only restart is the acute case, and adopting the window rather than
/// wiping it did not remove it, only shrink it. Adoption stamps each segment
/// with its real file age, so anything already past retention is evicted by
/// the first sweep — and the still-running edge advertises exactly those. It
/// used to be the whole window, because the store deleted its root; now it is
/// the expired head. Either way the manifest has to be trimmed to what can
/// actually be served.
///
/// Measured on the demo rig while a restart still wiped the root — the worst
/// case rather than the current one: the playlist advertised 4500 segments and
/// **24 of 42 probed across the window 404'd**, for the 2h30m it takes the
/// window to roll past the restart. To a player
/// that is not a clean error — the scrub bar is calibrated on the advertised
/// window, so more than half of it addressed footage the origin could not
/// serve, and both renditions failed independently.
///
/// So make the advertised window mean what it says. Only the *head* is
/// trimmed: a trailing entry may legitimately name a segment whose PUT is
/// still in flight, and dropping that would fight the producer.
///
/// Returns `None` when nothing needs changing, which is the ordinary case.
///
/// ## Two playlist shapes, one rule for `#EXT-X-PROGRAM-DATE-TIME`
///
/// The relay serves whatever edge is pointed at it, and two date shapes are
/// in service:
///
/// * **A tag per segment** (edge #143 onward), each one an independent
///   absolute time read off the media timeline against a per-flow epoch.
/// * **One tag at the playlist head** (older edges), standing for the whole
///   window; the player derives every other segment's time by accumulating
///   `EXTINF` forward from it.
///
/// They need opposite treatment, and the shape is not declared anywhere — so
/// this reads it off *position* rather than counting tags. A tag belongs to
/// the next entry that follows it, which is true of both shapes: the head tag
/// is simply the degenerate case where that entry is the first one. That
/// gives one rule:
///
/// * A tag after the trimmed run already describes a segment that survived,
///   so it is **passed through untouched**. Advancing it — which is what the
///   head-tag shape needs — misdates the entire remaining window by the
///   dropped duration. On the 4500-segment case above that is up to ~9000 s,
///   for the 2h30m the window takes to roll past.
/// * A tag inside the trimmed run describes a segment that is gone, so it is
///   **dropped** — except for the last one, which is kept and advanced by the
///   dropped duration that follows it if, and only if, the first surviving
///   entry carries no tag of its own. That single exception is what keeps a
///   head-tag playlist's only clock, and it lands on exactly the right
///   instant because the run it advances across is the run being removed.
///
/// Counting tags would not do: #143 omits the tag on any segment whose time
/// the media timeline does not give, so a per-segment playlist can carry
/// fewer tags than segments and still be that shape.
///
/// Why it matters beyond one stream's clock being wrong: main and proxy are
/// separate streams here with separate eviction, so they routinely hold
/// different heads. The DVR page relates their two timelines *only* through
/// these dates — `wallOn` / `mediaOn` in `dvr.html` binary-search them as
/// exact wall clock. Shifting each rendition's dates by its own dropped
/// duration throws the two apart by the difference, which is the wrong-frame
/// failure edge#139 was fixed to stop.
fn trim_unbacked_head(body: &[u8], has: &dyn Fn(&str) -> bool) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let is_uri = |l: &str| !l.is_empty() && !l.starts_with('#');
    let is_date = |l: &str| l.starts_with("#EXT-X-PROGRAM-DATE-TIME:");

    // Walk entries from the head, counting those that name a segment we do not
    // hold. Stop at the first one we do: a hole further in is a different
    // fault, and silently closing it would report the window as contiguous
    // when it is not.
    let mut dropped = 0usize;
    let mut dropped_secs = 0f64;
    let mut last_line = None;
    let mut extinf: Option<f64> = None;
    // A date and the entry it belongs to are two separate lines, and only the
    // entry says whether the pair is being dropped — so a date is held until
    // its entry is reached. `carried` ends up holding the last date in the
    // trimmed run, with the dropped duration that had accumulated *before*
    // the entry it describes; the difference from the total is how far that
    // date has to move to land on the first survivor.
    let mut pending_date: Option<(usize, f64)> = None;
    let mut carried: Option<(usize, f64)> = None;
    for (i, raw) in lines.iter().enumerate() {
        let l = raw.trim();
        if let Some(rest) = l.strip_prefix("#EXTINF:") {
            extinf = rest
                .split(',')
                .next()
                .and_then(|v| v.trim().parse::<f64>().ok())
                .or(Some(0.0));
        } else if is_date(l) {
            pending_date = Some((i, dropped_secs));
        } else if is_uri(l) {
            let Some(secs) = extinf.take() else { continue };
            if has(l) {
                break;
            }
            if let Some(d) = pending_date.take() {
                carried = Some(d);
            }
            dropped += 1;
            dropped_secs += secs;
            last_line = Some(i);
        }
    }
    let last_line = last_line?;

    // If nothing after the dropped run is backed either, this is a stream that
    // has published nothing yet rather than one with a hole. Rewriting that
    // into an empty playlist would turn a momentary cold start into a hard
    // player error, so leave it as the producer wrote it.
    if !lines[last_line + 1..].iter().any(|l| is_uri(l.trim())) {
        return None;
    }

    // Does the first entry left standing bring its own clock? A date reached
    // before any `EXTINF` or URI belongs to that entry; one reached after it
    // belongs to a later one and cannot speak for the head of the window.
    let first_survivor_dated = lines[last_line + 1..]
        .iter()
        .map(|l| l.trim())
        .find(|l| is_date(l) || l.starts_with("#EXTINF:") || is_uri(l))
        .is_some_and(is_date);
    // Nothing to carry forward when the survivor is already dated: every date
    // in the trimmed run then describes a segment that is gone, and keeping
    // one would leave it standing in front of a segment it does not describe.
    // hls.js takes the last tag it saw, so that is not a redundant tag — it
    // overrides the correct one.
    let carried = if first_survivor_dated { None } else { carried };

    let mut out = String::with_capacity(text.len());
    for (i, raw) in lines.iter().enumerate() {
        let l = raw.trim();
        // Says *which* segment the playlist starts at, so it moves by what was
        // dropped. Everything else in the header stands.
        if let Some(rest) = l.strip_prefix("#EXT-X-MEDIA-SEQUENCE:") {
            let n = rest.trim().parse::<u64>().unwrap_or(0);
            out.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{}\n", n + dropped as u64));
            continue;
        }
        // Inside the dropped run, the entries go and the header stays. Dates
        // are decided here rather than above this test, because a date's fate
        // depends on which side of the run it sits on.
        if i <= last_line {
            if l.starts_with("#EXTINF:") || is_uri(l) {
                continue;
            }
            if let Some(rest) = l.strip_prefix("#EXT-X-PROGRAM-DATE-TIME:") {
                let Some((keep_at, before)) = carried else { continue };
                if i != keep_at {
                    continue;
                }
                let shift = dropped_secs - before;
                match chrono::DateTime::parse_from_rfc3339(rest.trim()) {
                    Ok(t) => out.push_str(&format!(
                        "#EXT-X-PROGRAM-DATE-TIME:{}\n",
                        (t + chrono::Duration::nanoseconds((shift * 1e9) as i64))
                            .with_timezone(&chrono::Utc)
                            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    )),
                    // An unparseable date is passed through rather than
                    // dropped: a wrong clock is recoverable, no clock at all
                    // is not.
                    Err(_) => out.push_str(&format!("{raw}\n")),
                }
                continue;
            }
        }
        // Past the run, a date is already an absolute statement about a
        // segment that survived, so it needs no adjustment — and must not be
        // given one.
        out.push_str(&format!("{raw}\n"));
    }
    Some(out.into_bytes())
}

/// Segments a stream keeps even when the volume is below its floor.
///
/// A relay that deleted everything to make room is not more useful than one
/// that is short of space — a player at the live edge still needs something to
/// read. Small, because this only runs when the disk is already in trouble.
const EMERGENCY_KEEP_SEGMENTS: usize = 4;

/// Bytes free on the filesystem holding `path`, or `None` if it cannot be
/// asked.
///
/// `None` is not "full": every caller treats it as "no opinion" and falls back
/// to the byte and retention policies. A guard that failed closed on a
/// `statvfs` error would stop a working relay for no reason.
#[cfg(unix)]
fn free_bytes(path: &FsPath) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `buf` is written only by `statvfs`, and only read on success.
    unsafe {
        let mut buf: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut buf) != 0 {
            return None;
        }
        // `f_bavail` is what a non-root process may actually use, which is the
        // honest number here: `f_bfree` includes the reserved blocks the relay
        // cannot touch, and counting them is how a "safe" floor still fills
        // the disk.
        Some((buf.f_bavail as u64).saturating_mul(buf.f_frsize as u64))
    }
}

#[cfg(not(unix))]
fn free_bytes(_path: &FsPath) -> Option<u64> {
    None
}

/// Content-Type for a distribution object by extension.
fn content_type_for(file: &str) -> &'static str {
    let lower = file.to_ascii_lowercase();
    if lower.ends_with(".m3u8") {
        "application/vnd.apple.mpegurl"
    } else if lower.ends_with(".mpd") {
        "application/dash+xml"
    } else if lower.ends_with(".m4s") || lower.ends_with(".mp4") || lower.ends_with(".cmfv")
        || lower.ends_with(".cmfa") || lower.ends_with(".cmf") || lower.ends_with(".init")
    {
        "video/mp4"
    } else if lower.ends_with(".ts") {
        "video/mp2t"
    } else if lower.ends_with(".vtt") {
        "text/vtt"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".png") {
        "image/png"
    } else {
        "application/octet-stream"
    }
}

/// Is this a media segment/part (evictable), vs a manifest (kept)?
///
/// Thumbnail sprite sheets count as media. They describe a span of the DVR
/// window and are worthless once that span has aged out — kept, they would
/// accumulate for the life of the stream while the pictures they show no
/// longer exist. Their `.vtt` index is a manifest: one object, rewritten in
/// place, listing only the sheets still present.
fn is_media_segment(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.ends_with(".m4s") || lower.ends_with(".ts") || lower.ends_with(".cmfv")
        || lower.ends_with(".cmfa") || lower.ends_with(".cmf")
        || lower.ends_with(".jpg") || lower.ends_with(".jpeg")
        || lower.ends_with(".webp") || lower.ends_with(".png")
        || (lower.ends_with(".mp4") && !lower.contains("init"))
}

/// Validate the object filename: one path segment, tight char set, has an
/// extension. axum's `{file}` already forbids `/`; this is defense in depth.
fn valid_object_name(file: &str) -> bool {
    !file.is_empty()
        && file.len() <= 128
        && file.contains('.')
        && !file.contains("..")
        && file
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Origin routes, merged into the distribution router.
/// Largest object the origin will accept in one PUT.
///
/// This must be applied as an axum body limit as well as checked in the
/// handler: axum's default is 2 MiB and it rejects *before* the handler runs,
/// which made the handler's own check unreachable. A 2 s segment of 8 Mbps
/// video is already past 2 MiB, so real broadcast bitrates failed with an
/// opaque 413 while a low-bitrate test pattern sailed through.
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// A clip export: what was asked for, and whether the media has arrived.
///
/// The record *is* the job. There is no separate queue, in memory or in a
/// database: a `.json` beside the media is the whole state, so a relay restart
/// loses nothing and the portal can list what is still coming as well as what
/// is ready. `ready` is derived from the media file existing and is never
/// trusted from disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClipRecord {
    /// `<Marker TC> - <Marker name>`, sanitised by the player and re-checked
    /// here — it becomes a filename and arrives from a browser.
    pub name: String,
    /// The marked instant, as the published clock saw it.
    pub at: String,
    pub pre_secs: u32,
    pub post_secs: u32,
    pub requested_at: String,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default, skip_deserializing)]
    pub ready: bool,
    /// Set when the edge has given up. A clip that cannot be produced must say
    /// so: without this the record stays pending for ever, the exporter retries
    /// it every five seconds until the session ends, and the viewer's page
    /// reads "being cut" indefinitely for something that is never coming.
    #[serde(default)]
    pub failed: bool,
    /// Why, in words an operator can act on — the window aged out, the clip was
    /// too large, the recording had no media there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ClipRequest {
    pub pre_secs: u32,
    pub post_secs: u32,
    pub clips: Vec<ClipAsk>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ClipAsk {
    pub at: String,
    pub name: String,
}

/// One request may not ask for an unbounded amount of edge work.
const MAX_CLIPS_PER_REQUEST: usize = 50;

/// How many clips one stream may hold at once.
const MAX_CLIPS_PER_STREAM: usize = 100;

/// How much disk one stream's clips may hold.
///
/// Clips are deliberately outside the retention sweep — that is the point of
/// exporting one — but being outside the sweep is not the same as being free.
/// When the free-space floor trips it evicts from the segment queue, which
/// clips are not in, so without a bound of their own an operator exporting
/// steadily would have the origin delete *recorded footage* to make room for
/// clips: the DVR window silently shrinking to hold its own excerpts.
///
/// So clips get their own ceiling and are refused at it, rather than being
/// paid for out of the window.
const MAX_CLIP_BYTES_PER_STREAM: u64 = 4 * 1024 * 1024 * 1024;

/// The longest clip anyone may export, pre-roll and post-roll together.
///
/// A review clip is a moment, not a passage of play, and the length has to be
/// bounded somewhere: the edge assembles a clip whole in memory and the relay
/// holds it whole as a request body, so an unbounded length is an unbounded
/// allocation on two machines. A minute is long enough for the thing an
/// operator marked and short enough to stay a sane object.
const MAX_CLIP_TOTAL_SECS: u32 = 60;

/// The largest clip body the origin will accept.
///
/// Derived from [`MAX_CLIP_TOTAL_SECS`], not chosen freely: sixty seconds of
/// source at 35 Mbit/s is about 260 MB, and the source is what a clip is cut
/// from — not the 3 Mbit/s proxy. The segment limit cannot serve here, because
/// a segment is two seconds and a clip is up to thirty times that; sharing one
/// number meant every clip over roughly twenty seconds on a contribution feed
/// failed the upload with a 413, stayed pending, and was retried forever.
pub const MAX_CLIP_BYTES: usize = 256 * 1024 * 1024;

/// A clip name becomes a filename, and it arrives from a browser.
///
/// Deliberately stricter than `valid_object_name`: no separators, no leading
/// dot, nothing that could climb out of the clips directory, and a length a
/// filesystem will actually accept once the extension is added.
fn valid_clip_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 180
        && !name.starts_with('.')
        && !name.contains("..")
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '(' | ')' | '[' | ']')
        })
}

pub fn routes() -> Router<Arc<DistributionState>> {
    // A clip is up to thirty segments of media in one object, so it cannot
    // share the segment limit. Its own route carries its own bound rather than
    // raising the limit for every PUT on the origin — a 256 MiB ceiling on
    // segment ingest would turn a runaway encoder into a memory problem.
    let clips = Router::new()
        // Static segments beat the `{file}` capture, so these do not shadow the
        // segment routes below.
        .route(
            "/origin/{stream}/clips",
            axum::routing::post(clips_request).get(clips_list),
        )
        .route(
            "/origin/{stream}/clips/{file}",
            put(clip_put).get(clip_get).delete(clip_delete),
        )
        .route(
            "/origin/{stream}/clips/{file}/failed",
            axum::routing::post(clip_failed),
        )
        .layer(DefaultBodyLimit::max(MAX_CLIP_BYTES));

    Router::new()
        .route("/origin/{stream}/{file}", put(origin_put).get(origin_get))
        .layer(DefaultBodyLimit::max(MAX_OBJECT_BYTES))
        .merge(clips)
}

/// `PUT /origin/{stream}/{file}` — accept an edge CMAF/HLS upload.
/// `POST /origin/{stream}/clips` — ask for clips around marks.
///
/// Gated exactly like a segment read: whoever may watch this feed may cut from
/// it. The cut itself happens on the edge — the only component with a decoder
/// — so all this does is record the ask where the portal and the edge can both
/// see it.
async fn clips_request(
    State(st): State<Arc<DistributionState>>,
    Path(stream): Path<String>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    axum::Json(req): axum::Json<ClipRequest>,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    if st.control.load().require_origin_token
        && let Err(resp) = super::check_viewer_token(&st, &stream, &headers, query.as_deref())
    {
        return resp;
    }
    if req.clips.is_empty() {
        return (StatusCode::BAD_REQUEST, "no clips requested").into_response();
    }
    if req.clips.len() > MAX_CLIPS_PER_REQUEST {
        return (StatusCode::BAD_REQUEST, "too many clips in one request").into_response();
    }
    // Checked on the total, not each end: two 40-second halves are an
    // 80-second clip however they are split.
    if req.pre_secs.saturating_add(req.post_secs) > MAX_CLIP_TOTAL_SECS {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "a clip may be at most {MAX_CLIP_TOTAL_SECS} seconds long; \
                 this one asks for {}",
                req.pre_secs.saturating_add(req.post_secs)
            ),
        )
            .into_response();
    }
    if req.pre_secs == 0 && req.post_secs == 0 {
        return (StatusCode::BAD_REQUEST, "a clip of zero seconds is not a clip").into_response();
    }
    for ask in &req.clips {
        if !valid_clip_name(&ask.name) {
            return (StatusCode::BAD_REQUEST, "invalid clip name").into_response();
        }
        if chrono::DateTime::parse_from_rfc3339(&ask.at).is_err() {
            return (StatusCode::BAD_REQUEST, "invalid clip timestamp").into_response();
        }
    }

    // Clips are outside the retention sweep, so they need a bound of their own
    // or they are paid for out of the DVR window when the disk floor trips.
    let (have, bytes) = st.origin.clip_usage(&stream);
    if have + req.clips.len() > MAX_CLIPS_PER_STREAM {
        return (
            StatusCode::CONFLICT,
            format!(
                "this feed already holds {have} clips, and the limit is \
                 {MAX_CLIPS_PER_STREAM} — delete some before exporting more"
            ),
        )
            .into_response();
    }
    if bytes >= MAX_CLIP_BYTES_PER_STREAM {
        return (
            StatusCode::CONFLICT,
            format!(
                "this feed's clips already use {:.1} GB, which is the limit — \
                 delete some before exporting more",
                bytes as f64 / 1024.0 / 1024.0 / 1024.0
            ),
        )
            .into_response();
    }

    match st.origin.record_clip_requests(&stream, &req) {
        Ok(recs) => {
            tracing::info!(
                stream = %stream, clips = recs.len(),
                pre = req.pre_secs, post = req.post_secs,
                "origin: clip export requested"
            );
            (StatusCode::ACCEPTED, axum::Json(recs)).into_response()
        }
        Err(e) => {
            tracing::warn!(stream = %stream, error = %e, "origin: could not record clip request");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not record the request").into_response()
        }
    }
}

/// Who may READ from the origin: a viewer, or the edge that fills it.
///
/// Two callers with two credentials. A player or portal holds a viewer token.
/// The edge holds the ingest token it pushes with — and it reads too, because
/// cutting a clip means fetching the manifest and the segments that cover the
/// moment. Gating reads on the viewer token alone locked the edge out of its
/// own stream: the clip list 403'd, and so did every manifest fetch behind it.
///
/// Admitting ingest here grants nothing new. That token already authorises
/// *writing* this stream's objects, so a holder that could not read them was
/// an inconsistency, not a boundary.
fn check_origin_read(
    st: &Arc<DistributionState>,
    stream: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<(), Response> {
    let rt = st.control.load();
    if !rt.require_origin_token {
        return Ok(());
    }
    let ingest_ok = rt.token_secret.as_ref().is_some_and(|secret| {
        super::bearer(headers)
            .and_then(|t| token::verify_ingest_token(secret, stream, &t).ok())
            .is_some()
    });
    if ingest_ok {
        return Ok(());
    }
    super::check_viewer_token(st, stream, headers, query)
}
/// `GET /origin/{stream}/clips` — what has been asked for, and what is ready.
async fn clips_list(
    State(st): State<Arc<DistributionState>>,
    Path(stream): Path<String>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    if let Err(resp) = check_origin_read(&st, &stream, &headers, query.as_deref()) {
        return resp;
    }
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(st.origin.list_clips(&stream)),
    )
        .into_response()
}

/// `GET /origin/{stream}/clips/{file}` — download a finished clip.
async fn clip_get(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    let Some(name) = file.strip_suffix(".mp4") else {
        return (StatusCode::BAD_REQUEST, "clips are .mp4").into_response();
    };
    if !valid_clip_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid clip name").into_response();
    }
    if st.control.load().require_origin_token
        && let Err(resp) = super::check_viewer_token(&st, &stream, &headers, query.as_deref())
    {
        return resp;
    }
    match st.origin.read_clip(&stream, name).await {
        Some(bytes) => (
            [
                (header::CONTENT_TYPE, "video/mp4".to_string()),
                // The name the operator asked for, on their disk.
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{file}\""),
                ),
                (header::CACHE_CONTROL, "private, max-age=300".to_string()),
            ],
            bytes,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            "clip not ready",
        )
            .into_response(),
    }
}

/// `PUT /origin/{stream}/clips/{file}` — the edge hands over a finished clip.
///
/// Ingest-gated, like a segment PUT: this is a write surface, and the only
/// thing that should be writing here is the edge that cut the clip.
async fn clip_put(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    let Some(name) = file.strip_suffix(".mp4") else {
        return (StatusCode::BAD_REQUEST, "clips are .mp4").into_response();
    };
    if !valid_clip_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid clip name").into_response();
    }
    let rt = st.control.load();
    if rt.require_ingest_token {
        let Some(ref secret) = rt.token_secret else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "ingest token gate misconfigured")
                .into_response();
        };
        let tok = super::bearer(&headers);
        if tok
            .and_then(|t| token::verify_ingest_token(secret, &stream, &t).ok())
            .is_none()
        {
            return (StatusCode::UNAUTHORIZED, "ingest token required").into_response();
        }
    }
    match st
        .origin
        .put_clip_streaming(&stream, name, body, MAX_CLIP_BYTES as u64)
        .await
    {
        Ok(bytes) => {
            tracing::info!(stream = %stream, clip = %name, bytes, "origin: clip stored");
            (StatusCode::CREATED, "stored").into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            tracing::warn!(stream = %stream, clip = %name, "origin: clip exceeded the size limit");
            (StatusCode::PAYLOAD_TOO_LARGE, "clip too large").into_response()
        }
        Err(e) => {
            tracing::warn!(stream = %stream, clip = %name, error = %e, "origin: clip write failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not store the clip").into_response()
        }
    }
}

/// `DELETE /origin/{stream}/clips/{file}` — remove a clip and its record.
///
/// Viewer-gated, like the download: clips belong to the session, so anyone who
/// may watch the feed may tidy them. Without this the only way to reclaim clip
/// space was to end the session, and clips are exempt from the sweep by design.
async fn clip_delete(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    let name = file.strip_suffix(".mp4").unwrap_or(&file);
    if !valid_clip_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid clip name").into_response();
    }
    if st.control.load().require_origin_token
        && let Err(resp) = super::check_viewer_token(&st, &stream, &headers, query.as_deref())
    {
        return resp;
    }
    if st.origin.delete_clip(&stream, name).await {
        tracing::info!(stream = %stream, clip = %name, "origin: clip deleted");
        (StatusCode::NO_CONTENT, [(header::CACHE_CONTROL, "no-store")]).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            "no such clip",
        )
            .into_response()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ClipFailure {
    pub reason: String,
}

/// `POST /origin/{stream}/clips/{file}/failed` — the edge gave up on this one.
///
/// Ingest-gated like the upload: only whatever is cutting clips may declare one
/// impossible. Without it a clip that can never be produced is retried every
/// five seconds for the life of the session and shows as "being cut" for ever.
async fn clip_failed(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ClipFailure>,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    let name = file.strip_suffix(".mp4").unwrap_or(&file);
    if !valid_clip_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid clip name").into_response();
    }
    let rt = st.control.load();
    if rt.require_ingest_token {
        let Some(ref secret) = rt.token_secret else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "ingest token gate misconfigured")
                .into_response();
        };
        if super::bearer(&headers)
            .and_then(|t| token::verify_ingest_token(secret, &stream, &t).ok())
            .is_none()
        {
            return (StatusCode::UNAUTHORIZED, "ingest token required").into_response();
        }
    }
    match st.origin.fail_clip(&stream, name, &body.reason) {
        Ok(true) => {
            tracing::warn!(
                stream = %stream, clip = %name, reason = %body.reason,
                "origin: clip marked as one the edge could not produce"
            );
            (StatusCode::OK, "recorded").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such clip request").into_response(),
        Err(e) => {
            tracing::warn!(stream = %stream, clip = %name, error = %e, "origin: could not record clip failure");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not record it").into_response()
        }
    }
}

async fn origin_put(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    if !valid_object_name(&file) {
        return (StatusCode::BAD_REQUEST, "invalid object name").into_response();
    }

    // Ingest is a write surface — token-gate it unless explicitly disabled
    // (runtime, manager-overridable).
    let rt = st.control.load();
    if rt.require_ingest_token {
        if let Some(ref secret) = rt.token_secret {
            // Header-only is correct here: the CMAF uploader is the edge
            // (`bilbycast-edge/src/engine/cmaf/upload.rs` sets
            // `Authorization: Bearer`), never a browser. This used to call a
            // second, subtly divergent bearer+query parser whose query half
            // was dead (`None` was the only argument ever passed) and whose
            // empty-value policy disagreed with the shared one. One credential
            // parser, one policy.
            let tok = super::bearer(&headers);
            match tok.and_then(|t| token::verify_ingest_token(secret, &stream, &t).ok()) {
                Some(()) => {}
                None => return (StatusCode::UNAUTHORIZED, "ingest token required").into_response(),
            }
        } else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "ingest token gate misconfigured").into_response();
        }
    }

    if body.len() > MAX_OBJECT_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "object too large").into_response();
    }

    // A failed write is the edge's problem to see: it retries and warns, and
    // silently 201-ing a segment we did not store would strand every viewer
    // that later asks for it.
    match st.origin.put(&stream, &file, body).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => {
            tracing::warn!(stream = %stream, file = %file, error = %e, "origin: store failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not store object").into_response()
        }
    }
}

/// `GET /origin/{stream}/{file}` — serve a cached object to a player/CDN.
///
/// **Unauthenticated by default, and `require_viewer_token` does NOT gate
/// it** — that flag covers the WHEP tier only. The default is deliberate:
/// this route is the CDN-facing half of the distribution surface, a CDN pulls
/// it with no credential of the relay's, and that is the point of having an
/// HTTP origin at all.
///
/// The consequence of the default is worth stating plainly, because it is
/// easy to assume otherwise: for any stream that also runs the CMAF/LL-HLS
/// tier, a WHEP viewer gate is bypassable by fetching
/// `/origin/{stream}/index.m3u8` directly.
///
/// `require_origin_token` closes that. It is off by default to preserve the
/// CDN case and is expected to be turned on **per session**, by the manager,
/// for a gated audience with no CDN in front. It accepts the same credential
/// as WHEP — `Authorization: Bearer` or `?token=` — because a segment fetch
/// from hls.js can carry a header but the first manifest fetch on native HLS
/// cannot. Documented in `docs/distribution.md` under "Access tokens".
async fn origin_get(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CACHE_CONTROL, "no-store")],
            "invalid stream id",
        )
            .into_response();
    };
    if !valid_object_name(&file) {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CACHE_CONTROL, "no-store")],
            "invalid object name",
        )
            .into_response();
    }
    // Checked before the store is touched, so a rejected request cannot be
    // used to probe which streams or segments exist.
    if let Err(resp) = check_origin_read(&st, &stream, &headers, query.as_deref()) {
        return resp;
    }
    match st.origin.get(&stream, &file).await {
        Some(mut obj) => {
            // Carry a query-borne credential into the playlist's own URIs.
            //
            // Native HLS (Safari, iOS) cannot set a request header, which is
            // why `?token=` exists — but HLS resolves a playlist's URIs
            // against the playlist's URL *without* its query, so every segment
            // fetch that follows an authenticated manifest fetch arrives with
            // no credential and is refused. Gated playback was therefore
            // impossible on native HLS: the manifest loaded and nothing after
            // it did.
            //
            // Only for the query form. hls.js sets `Authorization` on every
            // request of its own, and rewriting for it would put a credential
            // into URLs it did not need there.
            if st.control.load().require_origin_token
                && is_hls_playlist(&file)
                && let Some(tok) = super::token_from_query(query.as_deref())
            {
                let rewritten = playlist_with_token(&obj.bytes, &tok);
                obj.etag = etag_for(&rewritten);
                obj.bytes = Bytes::from(rewritten);
            }
            // Nothing here may be cached immutably, because no filename in a
            // live stream is stable across restarts.
            //
            // `init.mp4` is rewritten whenever the stream is reconfigured
            // (resolution, codec, track layout) and keeps its name. Media
            // segment numbering restarts from `seg-00000` every time the
            // producing flow restarts, so the same URL serves entirely
            // different pictures from one run to the next.
            //
            // `immutable` is a promise about a *URL*, not about a file. Making
            // it here pins viewers to whatever they fetched first, and the
            // resulting failure is brutal to diagnose: current segments get
            // appended against a stale init, or a stale segment against a
            // current one, so playback dies inside the media stack with
            // nothing wrong on the wire — and it survives restarts and fixes,
            // because the browser never refetches. A fresh profile always
            // works, which makes a server bug look like a client quirk.
            //
            // Restoring immutable caching (worthwhile in front of a CDN) needs
            // globally unique object names — a per-run prefix or an origin-side
            // rewrite — not a header change. Until then, revalidate.
            let cache = if is_media_segment(&file) {
                // Still cacheable, but never without checking.
                "no-cache, max-age=0, must-revalidate"
            } else {
                "no-cache, no-store, must-revalidate"
            };
            // `must-revalidate` with no validator to compare means every
            // revalidation is a full re-download. Answer the client's
            // `If-None-Match` so the check costs a header exchange.
            if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok())
                && if_none_match_matches(inm, &obj.etag)
            {
                return (
                    StatusCode::NOT_MODIFIED,
                    [
                        (header::CACHE_CONTROL, cache.to_string()),
                        (header::ETAG, obj.etag),
                    ],
                )
                    .into_response();
            }
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, obj.content_type.to_string()),
                    (header::CACHE_CONTROL, cache.to_string()),
                    (header::ETAG, obj.etag),
                ],
                obj.bytes,
            )
                .into_response()
        }
        // A miss is not durable: a segment the player is a moment early for
        // becomes available seconds later, and one just evicted never does.
        // Without a directive a fronting CDN is free to pick its own
        // heuristic freshness for the 404 and keep serving it after the object
        // lands — the negative-caching twin of the immutable trap above.
        None => (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store rooted in a fresh temp dir. `retention` and byte bound are set
    /// wide so a test only exercises the policy it names.
    fn store(tmp: &tempfile::TempDir, min_segments: usize) -> OriginStore {
        OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_secs(3600),
            max_bytes_per_stream: 1 << 30,
            min_segments,
            // Off by default in tests: the guard is about the *real* volume,
            // and a temp dir on a roomy disk would never trip it.
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .expect("store should build")
    }

    async fn put_seg(s: &OriginStore, stream: &str, name: &str, len: usize) {
        s.put(stream, name, Bytes::from(vec![0u8; len]))
            .await
            .expect("put should succeed");
    }

    use crate::distribution_control::{OriginPolicyPatch, OriginPolicyUpdate};

    /// Thumbnail sprite sheets must age out with the pictures they show.
    ///
    /// They are classified by extension, and everything not recognised as a
    /// segment is treated as a manifest and **kept**. A sheet kept forever is
    /// a slow leak that also lies: it depicts a span of the window that has
    /// long since been evicted. The `.vtt` index is genuinely a manifest —
    /// one object, rewritten in place — and must survive.
    #[tokio::test]
    async fn sprite_sheets_are_evicted_with_the_media_and_their_index_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 1);
        s.apply_policy_update(&OriginPolicyUpdate {
            per_stream: Some(vec![("match".into(), patch_bytes(30))]),
            ..Default::default()
        });

        s.put("match", "thumbs.vtt", Bytes::from_static(b"WEBVTT
"))
            .await
            .unwrap();
        for i in 0..6 {
            put_seg(&s, "match", &format!("thumbs-{i}.jpg"), 10).await;
        }

        assert!(
            s.get("match", "thumbs-0.jpg").await.is_none(),
            "an old sprite sheet outlived the window it depicts"
        );
        assert!(s.get("match", "thumbs-5.jpg").await.is_some());
        assert!(
            s.get("match", "thumbs.vtt").await.is_some(),
            "the index was evicted as if it were a segment"
        );
    }

    /// A sprite sheet must be served as an image.
    ///
    /// `application/octet-stream` is what every unrecognised extension gets,
    /// and an `<img>` pointed at one is at the mercy of content sniffing —
    /// which is exactly the thing a security header turns off. The failure is
    /// a scrub preview that silently shows nothing.
    #[test]
    fn thumbnail_objects_are_served_as_images_and_text() {
        assert_eq!(content_type_for("thumbs-001.jpg"), "image/jpeg");
        assert_eq!(content_type_for("thumbs-001.JPEG"), "image/jpeg");
        assert_eq!(content_type_for("thumbs-001.webp"), "image/webp");
        assert_eq!(content_type_for("thumbs.vtt"), "text/vtt");
        // And the media path is untouched.
        assert_eq!(content_type_for("seg-1.m4s"), "video/mp4");
        assert_eq!(content_type_for("manifest.m3u8"), "application/vnd.apple.mpegurl");
    }

    fn patch_bytes(n: u64) -> OriginPolicyPatch {
        OriginPolicyPatch {
            max_bytes_per_stream: Some(n),
            ..Default::default()
        }
    }

    /// A per-stream override must bound only its own stream.
    ///
    /// This is the whole point of the per-stream layer: a DVR session's long
    /// window must not be imposed on every other stream on the node, and the
    /// node default must not truncate the session.
    #[tokio::test]
    async fn a_stream_override_bounds_only_that_stream() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 1);
        s.apply_policy_update(&OriginPolicyUpdate {
            default: Some(patch_bytes(16 * 1024 * 1024)),
            per_stream: Some(vec![("tight".into(), patch_bytes(30))]),
        });

        for i in 0..6 {
            put_seg(&s, "tight", &format!("seg{i}.m4s"), 10).await;
            put_seg(&s, "roomy", &format!("seg{i}.m4s"), 10).await;
        }

        // 30-byte bound at 10 bytes a segment: the oldest are gone.
        assert!(s.get("tight", "seg0.m4s").await.is_none());
        assert!(s.get("tight", "seg5.m4s").await.is_some());
        // The node default is 16 MiB, so nothing was evicted here.
        assert!(
            s.get("roomy", "seg0.m4s").await.is_some(),
            "the override must not apply to a stream it does not name"
        );
    }

    /// An override that names one field must inherit the rest of the node
    /// policy, not zero it. A `max_bytes` of 0 would evict every segment on
    /// arrival -- a stream that accepts PUTs and serves an empty window.
    #[test]
    fn an_override_inherits_the_fields_it_does_not_name() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 4);
        s.apply_policy_update(&OriginPolicyUpdate {
            default: None,
            per_stream: Some(vec![(
                "one".into(),
                OriginPolicyPatch {
                    retention_secs: Some(60),
                    ..Default::default()
                },
            )]),
        });
        let p = s.policy_for("one");
        assert_eq!(p.retention, Duration::from_secs(60));
        assert_eq!(p.max_bytes_per_stream, 1 << 30, "byte bound must be inherited");
        assert_eq!(p.min_segments, 4, "floor must be inherited");
    }

    /// Pushing a new override set must drop the overrides it omits.
    ///
    /// A merge would leave an ended session's window in force for the life of
    /// the relay, pinning that stream's disk with nothing left to say so.
    #[test]
    fn a_new_override_set_replaces_the_old_one() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 1);
        s.apply_policy_update(&OriginPolicyUpdate {
            default: None,
            per_stream: Some(vec![
                ("a".into(), patch_bytes(30)),
                ("b".into(), patch_bytes(30)),
            ]),
        });
        assert_eq!(s.policy_for("a").max_bytes_per_stream, 30);

        // "a" is not named this time, so it must fall back to the default.
        s.apply_policy_update(&OriginPolicyUpdate {
            default: None,
            per_stream: Some(vec![("b".into(), patch_bytes(30))]),
        });
        assert_eq!(
            s.policy_for("a").max_bytes_per_stream,
            1 << 30,
            "an omitted stream must revert to the node default"
        );
        assert_eq!(s.policy_for("b").max_bytes_per_stream, 30);
    }

    /// `min_segments` may never reach 0: a live stream evicted to nothing
    /// between a player's manifest fetch and its segment fetch is a 404
    /// mid-playback, not a shorter window.
    #[test]
    fn the_segment_floor_never_reaches_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        s.apply_policy_update(&OriginPolicyUpdate {
            default: Some(OriginPolicyPatch {
                min_segments: Some(0),
                ..Default::default()
            }),
            per_stream: None,
        });
        assert_eq!(s.default_policy().min_segments, 1);
    }

    /// Usage has to name the stream spending the disk -- a node total cannot
    /// answer the question an operator actually asks when a volume fills.
    #[tokio::test]
    async fn usage_reports_bytes_per_stream() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        put_seg(&s, "big", "seg0.m4s", 500).await;
        put_seg(&s, "big", "seg1.m4s", 500).await;
        put_seg(&s, "small", "seg0.m4s", 100).await;
        s.apply_policy_update(&OriginPolicyUpdate {
            default: None,
            per_stream: Some(vec![("big".into(), patch_bytes(16 * 1024 * 1024))]),
        });

        let u = s.usage();
        assert_eq!(u.len(), 2);
        let big = u.iter().find(|x| x.stream == "big").unwrap();
        let small = u.iter().find(|x| x.stream == "small").unwrap();
        assert_eq!((big.segments, big.bytes), (2, 1000));
        assert_eq!((small.segments, small.bytes), (1, 100));
        assert!(big.policy_overridden, "an override must be visible to the operator");
        assert!(!small.policy_overridden);
    }

    /// A gated playlist must carry its credential into its own URIs.
    ///
    /// Native HLS cannot set a header, so `?token=` is how it authenticates —
    /// but HLS resolves a playlist's URIs against the playlist URL *without*
    /// its query, so without this every segment fetch after an authenticated
    /// manifest fetch arrives bare and is refused.
    #[test]
    fn a_gated_playlist_carries_its_token_into_every_uri() {
        let body = b"#EXTM3U\n\
                     #EXT-X-VERSION:9\n\
                     #EXT-X-MAP:URI=\"init.mp4\"\n\
                     #EXTINF:2.000,\n\
                     seg-00001.m4s\n\
                     #EXT-X-PART:DURATION=0.5,URI=\"seg-00002.m4s?part=0\"\n\
                     seg-00002.m4s\n";
        let out = String::from_utf8(playlist_with_token(body, "1770000000.abc")).unwrap();

        assert!(out.contains("#EXT-X-MAP:URI=\"init.mp4?token=1770000000.abc\""));
        assert!(out.contains("\nseg-00001.m4s?token=1770000000.abc\n"));
        // An existing query keeps it, and gets `&`.
        assert!(out.contains("seg-00002.m4s?part=0&token=1770000000.abc"));
        // Tags that name no URI are untouched.
        assert!(out.contains("#EXT-X-VERSION:9\n"));
        assert!(out.starts_with("#EXTM3U\n"));
        // A comma in a multi-stream token has to survive the round trip.
        let multi = String::from_utf8(playlist_with_token(body, "1770000000.a,b.abc")).unwrap();
        assert!(multi.contains("seg-00001.m4s?token=1770000000.a%2Cb.abc"));
        assert_eq!(
            crate::distribution::token_from_query(Some("token=1770000000.a%2Cb.abc")).as_deref(),
            Some("1770000000.a,b.abc"),
            "the encoded form must decode back to the signed bytes"
        );
    }

    /// A stream id names a directory under the origin root, so a name that is
    /// a relative-path token escapes it. `remove_stream` does a
    /// `remove_dir_all`, so `..` would recursively delete the relay's data
    /// directory — the origin root's parent.
    #[tokio::test]
    async fn origin_refuses_stream_names_that_escape_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        let sibling = tmp.path().join("keep-me");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("important"), b"x").unwrap();
        let s = store(&tmp, 8);

        for escape in ["..", ".", "a/b", "/abs"] {
            assert!(
                s.put(escape, "seg0.m4s", Bytes::from_static(b"x")).await.is_err(),
                "put accepted {escape:?}"
            );
            assert!(s.get(escape, "seg0.m4s").await.is_none(), "get accepted {escape:?}");
            s.remove_stream(escape).await;
        }

        assert!(
            sibling.join("important").exists(),
            "a sibling of the origin root was deleted"
        );
        assert!(tmp.path().join("origin").exists(), "the origin root was deleted");
        assert!(
            !tmp.path().join("seg0.m4s").exists(),
            "a segment was written outside the origin root"
        );
    }

    /// The HTTP layer's own guard, which is what actually runs in production.
    #[test]
    fn stream_id_sanitiser_rejects_relative_path_tokens() {
        use crate::distribution::sanitize_stream_id;
        for bad in ["..", ".", "...", "....", " .. "] {
            assert!(sanitize_stream_id(bad).is_none(), "accepted {bad:?}");
        }
        // Dots are still legal *inside* a real name.
        assert_eq!(sanitize_stream_id("show.proxy").as_deref(), Some("show.proxy"));
        assert_eq!(sanitize_stream_id("a").as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn segments_round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        s.put("s", "seg0.m4s", Bytes::from_static(b"abcd")).await.unwrap();

        // Served from disk, byte-identical.
        let got = s.get("s", "seg0.m4s").await.expect("segment should be served");
        assert_eq!(&got.bytes[..], b"abcd");
        assert_eq!(got.content_type, "video/mp4");

        // And it really is on disk, not held in memory.
        assert!(tmp.path().join("origin/s/seg0.m4s").exists());
        assert_eq!(s.total_bytes(), 4);
    }

    #[tokio::test]
    async fn evicts_oldest_segments_beyond_byte_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_secs(3600),
            max_bytes_per_stream: 30,
            min_segments: 1,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();
        for i in 0..6 {
            put_seg(&s, "s", &format!("seg{i}.m4s"), 10).await;
        }
        // Bound is 30 bytes at 10 bytes each, so the oldest go first.
        assert!(s.get("s", "seg0.m4s").await.is_none());
        assert!(s.get("s", "seg2.m4s").await.is_none());
        assert!(s.get("s", "seg5.m4s").await.is_some());
        assert!(s.total_bytes() <= 30);
        // Evicted bytes leave the disk too, not just the index.
        assert!(!tmp.path().join("origin/s/seg0.m4s").exists());
    }

    #[tokio::test]
    async fn evicts_segments_past_the_retention_window() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_millis(40),
            max_bytes_per_stream: 1 << 30,
            min_segments: 1,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();
        put_seg(&s, "s", "old.m4s", 8).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Eviction runs on PUT, so the new arrival is what retires the old one.
        put_seg(&s, "s", "new.m4s", 8).await;

        assert!(s.get("s", "old.m4s").await.is_none(), "aged-out segment should be gone");
        assert!(s.get("s", "new.m4s").await.is_some());
    }

    #[tokio::test]
    async fn min_segments_floor_beats_both_bounds() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            // Both policies say "evict everything"...
            retention: Duration::from_millis(1),
            max_bytes_per_stream: 1,
            min_segments: 3,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();
        for i in 0..6 {
            put_seg(&s, "s", &format!("seg{i}.m4s"), 100).await;
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        // ...but the floor keeps the three most recent addressable.
        assert!(s.get("s", "seg5.m4s").await.is_some());
        assert!(s.get("s", "seg4.m4s").await.is_some());
        assert!(s.get("s", "seg3.m4s").await.is_some());
        assert!(s.get("s", "seg0.m4s").await.is_none());
    }

    /// Retention must not depend on ingest.
    ///
    /// Eviction runs on PUT, so a stream whose producer stops was frozen as it
    /// was — past retention, holding its disk, still serving its manifest, and
    /// only reclaimed by restarting the relay.
    #[tokio::test]
    async fn sweep_expires_segments_with_no_further_puts() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_millis(40),
            max_bytes_per_stream: 1 << 30,
            // A floor high enough that PUT-driven eviction would keep everything.
            min_segments: 8,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();

        for i in 0..3 {
            put_seg(&s, "gone", &format!("seg{i}.m4s"), 100).await;
        }
        assert_eq!(s.total_bytes(), 300);

        // No more PUTs, ever. Wait past retention + idle_grace, so the
        // stream is treated as gone rather than merely quiet.
        tokio::time::sleep(Duration::from_millis(200)).await;
        s.sweep().await;

        assert_eq!(
            s.total_bytes(),
            0,
            "expired segments must be reclaimed without a PUT to trigger it"
        );
        assert!(s.get("gone", "seg0.m4s").await.is_none());
        assert!(!tmp.path().join("origin/gone/seg0.m4s").exists());
    }

    /// A live stream keeps its floor: the sweep must not treat "slow" as
    /// "gone" and age out the window under a viewer.
    #[tokio::test]
    async fn sweep_respects_the_floor_while_a_stream_is_still_publishing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_millis(30),
            max_bytes_per_stream: 1 << 30,
            min_segments: 2,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();

        for i in 0..4 {
            put_seg(&s, "live", &format!("seg{i}.m4s"), 50).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Still publishing, so this is a live stream however old its backlog.
        put_seg(&s, "live", "seg4.m4s", 50).await;
        s.sweep().await;

        assert!(
            s.total_bytes() > 0,
            "a publishing stream must keep its floor, not be drained"
        );
        assert!(s.get("live", "seg4.m4s").await.is_some());
    }

    #[tokio::test]
    async fn manifests_are_kept_in_memory_and_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_millis(1),
            max_bytes_per_stream: 1,
            min_segments: 0,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();
        s.put("s", "index.m3u8", Bytes::from_static(b"#v1")).await.unwrap();
        for i in 0..5 {
            put_seg(&s, "s", &format!("seg{i}.m4s"), 4).await;
        }
        // Manifest survives eviction that clears every segment.
        assert_eq!(&s.get("s", "index.m3u8").await.unwrap().bytes[..], b"#v1");
        s.put("s", "index.m3u8", Bytes::from_static(b"#v2")).await.unwrap();
        assert_eq!(&s.get("s", "index.m3u8").await.unwrap().bytes[..], b"#v2");

        // Manifests never touch the disk, so they cost nothing against the
        // byte bound the segments are competing for.
        assert!(!tmp.path().join("origin/s/index.m3u8").exists());
    }

    #[tokio::test]
    async fn init_segment_is_kept_not_evicted() {
        let tmp = tempfile::tempdir().unwrap();
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_millis(1),
            max_bytes_per_stream: 1,
            min_segments: 0,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .unwrap();
        // A WebCodecs jog player needs init.mp4 to stay fetchable for the
        // decoder config, however long the viewer has been parked.
        s.put("s", "init.mp4", Bytes::from_static(b"ftyp")).await.unwrap();
        for i in 0..5 {
            put_seg(&s, "s", &format!("seg{i}.m4s"), 4).await;
        }
        assert!(s.get("s", "init.mp4").await.is_some());
        assert!(!is_media_segment("init.mp4"));
        assert!(is_media_segment("seg1.m4s"));
    }

    #[tokio::test]
    async fn re_put_same_name_does_not_double_count() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        put_seg(&s, "s", "seg0.m4s", 100).await;
        put_seg(&s, "s", "seg0.m4s", 100).await;
        assert_eq!(s.total_bytes(), 100, "a rewrite replaces, it does not add");
    }

    #[tokio::test]
    async fn remove_stream_clears_disk_and_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        put_seg(&s, "s", "seg0.m4s", 50).await;
        assert_eq!(s.total_bytes(), 50);
        s.remove_stream("s").await;
        assert_eq!(s.total_bytes(), 0);
        assert!(s.get("s", "seg0.m4s").await.is_none());
        assert!(!tmp.path().join("origin/s").exists());
    }

    /// Dropping a stream reclaims its disk immediately, not on retention.
    ///
    /// Releasing a retention override is not the same as reclaiming space:
    /// with the override gone the stream falls back to the *node default*,
    /// which has nothing to do with the window its session asked for. Measured
    /// on the demo rig — two deleted sessions left 2.9 GB held, and the node
    /// default would have held it for 2h40m. An operator who deletes a session
    /// to reclaim space should get it back.
    #[tokio::test]
    async fn dropping_a_stream_gives_the_disk_back_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        // A retention long enough that nothing would age out on its own, so
        // whatever goes, goes because it was dropped.
        let s = OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_secs(86_400),
            max_bytes_per_stream: 1 << 40,
            min_segments: 0,
            min_free_bytes: 0,
            idle_grace: Duration::from_secs(86_400),
        })
        .expect("store should build");

        for i in 0..5 {
            put_seg(&s, "gone", &format!("seg-{i:05}.m4s"), 2048).await;
            put_seg(&s, "stays", &format!("seg-{i:05}.m4s"), 2048).await;
        }
        assert_eq!(s.total_bytes(), 10 * 2048);

        s.remove_stream("gone").await;

        assert!(
            s.get("gone", "seg-00000.m4s").await.is_none(),
            "the dropped stream still serves segments"
        );
        assert_eq!(
            s.total_bytes(),
            5 * 2048,
            "the dropped stream's bytes are still counted against the node"
        );
        // And its neighbour is untouched: a drop is one stream, not a purge.
        assert!(s.get("stays", "seg-00000.m4s").await.is_some());
        assert!(
            !tmp.path().join("origin/gone").exists(),
            "the directory is still on disk, so the space is not actually back"
        );
    }

    /// The origin gives disk back before the volume fills.
    ///
    /// `retention` and `max_bytes_per_stream` both arrive from the manager,
    /// which sizes them from the DVR window it was asked for and cannot see
    /// this relay's disk — no node health payload reports free space. So a
    /// window too large for the volume is a policy the manager will push and
    /// the relay will honour, until the disk fills. On the demo rig it did,
    /// and took the manager's own Postgres down with it.
    ///
    /// Driven by setting the floor above whatever the test volume actually
    /// has free, so the guard is genuinely triggered rather than asserted
    /// about.
    #[tokio::test]
    async fn the_origin_evicts_rather_than_filling_the_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(&root).unwrap();
        // A floor no real filesystem will be above forces the guard on.
        let s = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(86_400),
            max_bytes_per_stream: 1 << 40,
            min_segments: 0,
            min_free_bytes: u64::MAX,
            idle_grace: Duration::from_secs(3600),
        })
        .expect("store should build");

        for i in 0..12 {
            put_seg(&s, "a", &format!("seg-{i:05}.m4s"), 1024).await;
        }
        assert_eq!(s.total_bytes(), 12 * 1024, "all twelve should be held first");

        s.sweep().await;

        // Neither retention nor the byte cap would have removed anything —
        // both are enormous here — so whatever went, went for space.
        assert!(
            s.total_bytes() < 12 * 1024,
            "the floor did not reclaim anything: {} bytes still held",
            s.total_bytes()
        );
        // But not everything: a player at the live edge still needs something.
        assert!(
            s.get("a", "seg-00011.m4s").await.is_some(),
            "the newest segment was evicted, leaving a live player nothing"
        );
    }

    /// The floor is off when it is set to zero, and off when the filesystem
    /// cannot be asked.
    ///
    /// A guard that failed closed on a `statvfs` error would stop a working
    /// relay for no reason, so both routes fall back to the byte and retention
    /// policies rather than to eviction.
    #[tokio::test]
    async fn a_zero_floor_evicts_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        for i in 0..6 {
            put_seg(&s, "a", &format!("seg-{i:05}.m4s"), 1024).await;
        }
        s.sweep().await;
        assert_eq!(s.total_bytes(), 6 * 1024, "a zero floor reclaimed something");
    }

    /// The advertised window may not promise segments the store cannot serve.
    ///
    /// The edge re-publishes its whole window on every manifest refresh and
    /// PUTs each segment exactly once, so anything this store has evicted — by
    /// retention, by the byte cap, or by the free-space floor — stays
    /// advertised but unfetchable until the producer's own window rolls past
    /// it. What this sets up, two of four segments held, is that state; it is
    /// deliberately indifferent to *how* the store came to be missing the
    /// other two, which is why it kept testing the right thing when the
    /// startup wipe was replaced by adoption.
    ///
    /// Measured on the demo rig while a restart still wiped the root — the
    /// worst case rather than the current one: 4500 segments
    /// advertised, **24 of 42 probed across the window 404'd**, and it stayed
    /// that way for the 2h30m the window takes to roll past. The player
    /// calibrates its scrub bar on the advertised window, so more than half
    /// the bar addressed footage that could not be served.
    #[tokio::test]
    async fn a_manifest_does_not_advertise_segments_the_store_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        // Only the last two of four exist, as after a restart mid-window.
        s.put("s", "seg-3.m4s", Bytes::from_static(b"c")).await.unwrap();
        s.put("s", "seg-4.m4s", Bytes::from_static(b"d")).await.unwrap();

        let m = "#EXTM3U
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:1
                 #EXT-X-PROGRAM-DATE-TIME:2026-08-27T00:00:00.000Z
                 #EXT-X-MAP:URI=\"init.mp4\"
                 #EXTINF:2.000,
seg-1.m4s
#EXTINF:2.000,
seg-2.m4s
                 #EXTINF:2.000,
seg-3.m4s
#EXTINF:2.000,
seg-4.m4s
";
        s.put("s", "manifest.m3u8", Bytes::from(m)).await.unwrap();

        let got = s.get("s", "manifest.m3u8").await.unwrap();
        let body = String::from_utf8(got.bytes.to_vec()).unwrap();
        assert!(
            !body.contains("seg-1.m4s") && !body.contains("seg-2.m4s"),
            "still advertising segments the store does not hold:
{body}"
        );
        assert!(
            body.contains("seg-3.m4s") && body.contains("seg-4.m4s"),
            "dropped segments the store does hold:
{body}"
        );
        // The two tags that say *which* segment the window starts at have to
        // move with it, or the player's clock and the numbering both lie.
        assert!(
            body.contains("#EXT-X-MEDIA-SEQUENCE:3"),
            "media sequence not advanced by the two dropped entries:
{body}"
        );
        assert!(
            body.contains("#EXT-X-PROGRAM-DATE-TIME:2026-08-27T00:00:04.000Z"),
            "the clock still points at a segment that is gone:
{body}"
        );
        // The rest of the header is not this function's business.
        assert!(body.contains("#EXT-X-MAP:URI=\"init.mp4\""), "{body}");
        assert!(body.contains("#EXT-X-TARGETDURATION:2"), "{body}");
    }
    /// The absolute time this file's playlists give to `secs` past their epoch.
    fn stamp(secs: u32) -> String {
        format!("2026-08-27T00:00:{secs:02}.000Z")
    }

    /// The date belonging to segment `n`, which covers the two seconds
    /// starting `2·(n-1)` past the epoch.
    fn date_line(n: u32) -> String {
        format!("#EXT-X-PROGRAM-DATE-TIME:{}\n", stamp(2 * (n - 1)))
    }

    /// A media playlist in the shape edge #143 publishes: one
    /// `#EXT-X-PROGRAM-DATE-TIME` immediately before the `#EXTINF` it
    /// describes, rather than one at the head standing for the whole window.
    fn per_segment_dated(segments: &[u32]) -> String {
        let mut m = String::from(concat!(
            "#EXTM3U\n",
            "#EXT-X-TARGETDURATION:2\n",
            "#EXT-X-MEDIA-SEQUENCE:1\n",
            "#EXT-X-MAP:URI=\"init.mp4\"\n",
        ));
        for &n in segments {
            m.push_str(&date_line(n));
            m.push_str(&format!("#EXTINF:2.000,\nseg-{n}.m4s\n"));
        }
        m
    }

    /// The date a player would attach to `uri`: the last one it saw at or
    /// before that segment. This mirrors hls.js rather than the spec — a
    /// second tag with no segment between overrides the first — which is the
    /// whole reason a stale tag left behind by a trim is not a cosmetic
    /// defect.
    fn date_a_player_reads(body: &str, uri: &str) -> Option<String> {
        let mut last = None;
        for l in body.lines().map(str::trim) {
            if let Some(rest) = l.strip_prefix("#EXT-X-PROGRAM-DATE-TIME:") {
                last = Some(rest.trim().to_string());
            } else if l == uri {
                return last;
            }
        }
        None
    }

    /// Dates with no segment between them. Any at all is a date orphaned by
    /// the trim: the entry it described is gone, so it now speaks for the
    /// next surviving one and misdates it.
    fn orphaned_dates(body: &str) -> usize {
        let mut orphans = 0usize;
        let mut pending = false;
        for l in body.lines().map(str::trim) {
            if l.starts_with("#EXT-X-PROGRAM-DATE-TIME:") {
                if pending {
                    orphans += 1;
                }
                pending = true;
            } else if l.starts_with("#EXTINF:") {
                pending = false;
            }
        }
        orphans
    }

    /// Surviving per-segment dates are already right and must not be moved.
    ///
    /// This is the contract edge #143 shipped: every entry carries its own
    /// absolute time, derived from the media timeline rather than sampled
    /// from `Utc::now()` at publish. So a date that survives the trim is a
    /// statement about a segment that also survived — trimming the head in
    /// front of it changes nothing about when it happened.
    ///
    /// Advancing all of them by the dropped duration, which is what a
    /// head-tag playlist needs, misdates the *whole* remaining window by that
    /// amount. On the case `trim_unbacked_head` documents — a relay-only
    /// restart against a 4500-segment window — that is up to ~9000 s, and it
    /// persists for the 2h30m the window takes to roll past.
    #[tokio::test]
    async fn surviving_per_segment_dates_are_not_shifted_by_the_trim() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        for n in 3..=6 {
            s.put("s", &format!("seg-{n}.m4s"), Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        s.put("s", "manifest.m3u8", Bytes::from(per_segment_dated(&[1, 2, 3, 4, 5, 6])))
            .await
            .unwrap();

        let body =
            String::from_utf8(s.get("s", "manifest.m3u8").await.unwrap().bytes.to_vec()).unwrap();

        assert!(
            !body.contains("seg-1.m4s") && !body.contains("seg-2.m4s"),
            "still advertising segments the store does not hold:\n{body}"
        );
        // Each survivor keeps the time it was actually published at.
        for (n, secs) in [(3, 4), (4, 6), (5, 8), (6, 10)] {
            assert_eq!(
                date_a_player_reads(&body, &format!("seg-{n}.m4s")).as_deref(),
                Some(stamp(secs).as_str()),
                "seg-{n} is not dated from its own position:\n{body}"
            );
        }
        // The two dropped entries' dates go with them, rather than piling up
        // in front of the first survivor.
        assert_eq!(
            body.matches("#EXT-X-PROGRAM-DATE-TIME").count(),
            4,
            "one date per surviving segment, no more:\n{body}"
        );
        assert_eq!(orphaned_dates(&body), 0, "a date outlived its segment:\n{body}");
        // The shifted values the old arithmetic produced. Naming them keeps
        // this test failing loudly if the head-tag rule is ever reapplied to
        // this shape.
        for secs in [14, 16, 18, 20] {
            assert!(
                !body.contains(&stamp(secs)),
                "a surviving date was advanced by the dropped duration:\n{body}"
            );
        }
        assert!(body.contains("#EXT-X-MEDIA-SEQUENCE:3"), "{body}");
    }

    /// A trim that drops nothing changes nothing.
    ///
    /// The ordinary case, and worth pinning separately: the dates are the
    /// part of a playlist a rewrite is most likely to disturb by accident,
    /// and a byte-identical result is the only assertion that covers all of
    /// them at once.
    #[tokio::test]
    async fn a_fully_backed_window_is_passed_through_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        for n in 1..=4 {
            s.put("s", &format!("seg-{n}.m4s"), Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        let m = per_segment_dated(&[1, 2, 3, 4]);
        s.put("s", "manifest.m3u8", Bytes::from(m.clone())).await.unwrap();

        let body =
            String::from_utf8(s.get("s", "manifest.m3u8").await.unwrap().bytes.to_vec()).unwrap();
        assert_eq!(body, m, "a playlist needing no trim was rewritten anyway");
    }

    /// An edge that dates only the playlist head still gets its clock moved.
    ///
    /// The relay serves whatever edge is pointed at it, including one built
    /// before #143, and that shape has exactly one clock: the player derives
    /// every other segment's time by accumulating `EXTINF` from it. Dropping
    /// it — which is right for a date belonging to a trimmed entry when a
    /// survivor carries its own — would leave that playlist with no clock at
    /// all, and the DVR page's scrub, marks and still all convert through it.
    ///
    /// So the head tag is kept and advanced by what was dropped, which is the
    /// behaviour this file has always had. It is restated as its own case now
    /// that a second shape shares the function.
    #[tokio::test]
    async fn an_older_edge_that_dates_only_the_head_keeps_a_clock() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        s.put("s", "seg-3.m4s", Bytes::from_static(b"c")).await.unwrap();
        s.put("s", "seg-4.m4s", Bytes::from_static(b"d")).await.unwrap();

        let m = format!(
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:1\n{}\
             #EXT-X-MAP:URI=\"init.mp4\"\n\
             #EXTINF:2.000,\nseg-1.m4s\n\
             #EXTINF:2.000,\nseg-2.m4s\n\
             #EXTINF:2.000,\nseg-3.m4s\n\
             #EXTINF:2.000,\nseg-4.m4s\n",
            date_line(1)
        );
        s.put("s", "manifest.m3u8", Bytes::from(m)).await.unwrap();

        let body =
            String::from_utf8(s.get("s", "manifest.m3u8").await.unwrap().bytes.to_vec()).unwrap();
        assert_eq!(
            body.matches("#EXT-X-PROGRAM-DATE-TIME").count(),
            1,
            "the only clock in a head-tag playlist was dropped or duplicated:\n{body}"
        );
        assert_eq!(
            date_a_player_reads(&body, "seg-3.m4s").as_deref(),
            Some(stamp(4).as_str()),
            "the head clock still points at a segment that is gone:\n{body}"
        );
    }

    /// A survivor with no date of its own inherits a corrected one.
    ///
    /// #143 emits a tag per segment but omits it where the media timeline
    /// gives no time (`an_undated_segment_is_left_undated`, edge-side), so
    /// the first entry left standing may carry none. Dropping every date
    /// belonging to a trimmed entry would then hand the player a window whose
    /// head is undated and whose first date arrives some segments in — it
    /// would accumulate backwards from that, or give up on wall clock.
    ///
    /// The last date in the trimmed run is therefore kept and advanced by the
    /// dropped duration that follows it, which lands it exactly on the first
    /// survivor. This is the same rule as the head-tag case above; that shape
    /// is just the special case where the run's only date is the first one.
    #[tokio::test]
    async fn a_survivor_that_carries_no_date_is_given_the_corrected_one() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        s.put("s", "seg-3.m4s", Bytes::from_static(b"c")).await.unwrap();
        s.put("s", "seg-4.m4s", Bytes::from_static(b"d")).await.unwrap();

        // seg-3 is the undated one, and it is the first survivor.
        let m = format!(
            "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:1\n\
             {}#EXTINF:2.000,\nseg-1.m4s\n\
             {}#EXTINF:2.000,\nseg-2.m4s\n\
             #EXTINF:2.000,\nseg-3.m4s\n\
             {}#EXTINF:2.000,\nseg-4.m4s\n",
            date_line(1),
            date_line(2),
            date_line(4)
        );
        s.put("s", "manifest.m3u8", Bytes::from(m)).await.unwrap();

        let body =
            String::from_utf8(s.get("s", "manifest.m3u8").await.unwrap().bytes.to_vec()).unwrap();
        assert_eq!(
            date_a_player_reads(&body, "seg-3.m4s").as_deref(),
            Some(stamp(4).as_str()),
            "the first survivor was left with a date belonging to a trimmed segment:\n{body}"
        );
        assert_eq!(
            date_a_player_reads(&body, "seg-4.m4s").as_deref(),
            Some(stamp(6).as_str()),
            "seg-4's own date was disturbed:\n{body}"
        );
        assert_eq!(orphaned_dates(&body), 0, "a date outlived its segment:\n{body}");
        assert_eq!(
            body.matches("#EXT-X-PROGRAM-DATE-TIME").count(),
            2,
            "expected one carried-forward date and seg-4's own:\n{body}"
        );
    }

    /// Two renditions that lose different amounts of head still agree.
    ///
    /// This is the failure that matters operationally. Main and proxy are
    /// separate streams in this store with separate eviction, so a restart or
    /// a byte cap routinely leaves them holding different heads. The DVR page
    /// relates the two timelines *only* through `#EXT-X-PROGRAM-DATE-TIME`
    /// (`docs/distribution.md`, "Relating the two renditions"): `wallOn` and
    /// `mediaOn` binary-search these dates as exact wall clock.
    ///
    /// Shifting every surviving date by that rendition's own dropped duration
    /// therefore throws the two apart by the *difference* — a per-rendition
    /// offset that lands the still on the wrong frame, which is precisely
    /// what edge #139 was fixed to stop.
    #[tokio::test]
    async fn two_renditions_that_lose_different_heads_still_date_a_segment_alike() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        // Same content, same epoch, different survivors: main keeps four,
        // proxy keeps three.
        for n in 3..=6 {
            s.put("main", &format!("seg-{n}.m4s"), Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        for n in 4..=6 {
            s.put("proxy", &format!("seg-{n}.m4s"), Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        let m = per_segment_dated(&[1, 2, 3, 4, 5, 6]);
        for stream in ["main", "proxy"] {
            s.put(stream, "manifest.m3u8", Bytes::from(m.clone()))
                .await
                .unwrap();
        }

        let read = |body: Vec<u8>| String::from_utf8(body).unwrap();
        let main = read(s.get("main", "manifest.m3u8").await.unwrap().bytes.to_vec());
        let proxy = read(s.get("proxy", "manifest.m3u8").await.unwrap().bytes.to_vec());

        let m4 = date_a_player_reads(&main, "seg-4.m4s");
        let p4 = date_a_player_reads(&proxy, "seg-4.m4s");
        assert_eq!(
            m4, p4,
            "the two renditions date the same content differently, by the \
             difference in what each lost:\nmain:\n{main}\nproxy:\n{proxy}"
        );
        assert_eq!(
            m4.as_deref(),
            Some(stamp(6).as_str()),
            "they agree, but on the wrong time:\n{main}"
        );
        assert_eq!(orphaned_dates(&main), 0, "{main}");
        assert_eq!(orphaned_dates(&proxy), 0, "{proxy}");
    }

    /// A hole *inside* the window is left alone.
    ///
    /// Trimming to the first backed entry would report the window as
    /// contiguous when it is not, which is a worse failure than a 404: the
    /// player would calibrate its bar on a span it cannot actually play
    /// through, with nothing to indicate why.
    #[tokio::test]
    async fn a_hole_in_the_middle_is_not_silently_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        s.put("s", "seg-1.m4s", Bytes::from_static(b"a")).await.unwrap();
        s.put("s", "seg-3.m4s", Bytes::from_static(b"c")).await.unwrap();
        let m = "#EXTM3U
#EXT-X-MEDIA-SEQUENCE:1
                 #EXTINF:2.000,
seg-1.m4s
#EXTINF:2.000,
seg-2.m4s
                 #EXTINF:2.000,
seg-3.m4s
";
        s.put("s", "manifest.m3u8", Bytes::from(m)).await.unwrap();
        let body = String::from_utf8(
            s.get("s", "manifest.m3u8").await.unwrap().bytes.to_vec()).unwrap();
        assert!(body.contains("seg-2.m4s"), "an interior hole was closed:
{body}");
        assert!(body.contains("#EXT-X-MEDIA-SEQUENCE:1"), "{body}");
    }

    /// A stream that has published nothing yet is not rewritten to empty.
    ///
    /// At cold start the manifest can arrive before the first segment. An
    /// empty playlist is a hard player error; a manifest a beat ahead of its
    /// media resolves itself on the next PUT.
    #[tokio::test]
    async fn a_manifest_ahead_of_its_first_segment_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 8);
        let m = "#EXTM3U
#EXT-X-MEDIA-SEQUENCE:1
#EXTINF:2.000,
seg-1.m4s
";
        s.put("s", "manifest.m3u8", Bytes::from(m)).await.unwrap();
        let body = String::from_utf8(
            s.get("s", "manifest.m3u8").await.unwrap().bytes.to_vec()).unwrap();
        assert!(body.contains("seg-1.m4s"), "cold start rewritten to empty:
{body}");
    }

    #[tokio::test]
    async fn startup_adopts_the_window_already_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("s")).unwrap();
        // What a previous run of this store would have left behind: the
        // marker, so the foreign-directory guard adopts this root rather
        // than refusing it as somebody else's.
        std::fs::write(root.join(ORIGIN_MARKER), b"x").unwrap();
        std::fs::write(root.join("s/seg-00001.m4s"), b"old").unwrap();
        std::fs::write(root.join("s/seg-00002.m4s"), b"newer").unwrap();
        // A PUT interrupted by the very restart being recovered from. It is
        // truncated by definition, so it goes.
        std::fs::write(root.join("s/seg-00003.m4s.part"), b"half").unwrap();

        // This asserted the opposite — that a stale root is wiped — on the
        // reasoning that the manifests referencing those segments died with
        // the process. They do; the *producer* does not. The edge keeps
        // running and re-publishes a manifest naming every one of these, and
        // it never sends them again, so wiping cost the whole window.
        let s = store(&tmp, 8);
        assert!(
            s.get("s", "seg-00001.m4s").await.is_some(),
            "a segment on disk was discarded on startup"
        );
        assert!(s.get("s", "seg-00002.m4s").await.is_some());
        assert!(
            !root.join("s/seg-00003.m4s.part").exists(),
            "an interrupted PUT was adopted as if it were a whole segment"
        );
        // And the bytes are accounted for, or the byte cap is blind to
        // everything recovered and the stream overruns its bound.
        assert_eq!(s.total_bytes(), 8, "adopted bytes are not accounted for");
        // Re-written on every start, so a root an operator cleaned out by
        // hand is not refused as somebody else's on the next one.
        assert!(root.join(ORIGIN_MARKER).exists(), "marker must be re-written");
    }

    /// An adopted segment keeps its real age.
    ///
    /// `stored_at` decides retention. Stamped with "now" at adoption, a
    /// recovered window looks brand new and is held for a full retention
    /// period again — on the demo rig, 2h30m of footage the operator was told
    /// had aged out.
    #[tokio::test]
    async fn an_adopted_segment_ages_from_its_file_not_from_startup() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("s")).unwrap();
        // What a previous run of this store would have left behind, so the
        // foreign-directory guard adopts this root instead of refusing it.
        std::fs::write(root.join(ORIGIN_MARKER), b"x").unwrap();
        let old = root.join("s/seg-00001.m4s");
        std::fs::write(&old, b"xx").unwrap();
        let f = std::fs::File::options().write(true).open(&old).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(
            std::time::SystemTime::now() - std::time::Duration::from_secs(600),
        ))
        .unwrap();

        let s = store(&tmp, 0);
        s.set_default_policy(OriginPolicy {
            retention: std::time::Duration::from_secs(60),
            max_bytes_per_stream: u64::MAX,
            min_segments: 0,
            idle_grace: std::time::Duration::from_secs(60),
        });
        // Any PUT runs the sweep.
        s.put("s", "seg-00002.m4s", Bytes::from_static(b"zz")).await.unwrap();
        assert!(
            s.get("s", "seg-00001.m4s").await.is_none(),
            "a ten-minute-old segment survived a one-minute retention"
        );
        assert!(s.get("s", "seg-00002.m4s").await.is_some());
    }

    /// Adoption puts the queue in age order, not directory order.
    ///
    /// Eviction drops from the front. Ordered by whatever the filesystem
    /// happened to list first, a restart would start deleting the newest
    /// footage while keeping the oldest — the opposite of a DVR window.
    #[tokio::test]
    async fn an_adopted_window_evicts_its_oldest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("s")).unwrap();
        // What a previous run of this store would have left behind, so the
        // foreign-directory guard adopts this root instead of refusing it.
        std::fs::write(root.join(ORIGIN_MARKER), b"x").unwrap();
        // The names run *opposite* to the ages on purpose. Sorted by name —
        // which is roughly what `read_dir` returns — the queue comes out
        // exactly backwards, so a missing sort cannot pass by luck. An earlier
        // version of this fixture had name and age agreeing and did.
        for (name, age_secs) in [("seg-00001.m4s", 1u64), ("seg-00009.m4s", 600)] {
            let p = root.join("s").join(name);
            std::fs::write(&p, b"xx").unwrap();
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
            let f = std::fs::File::options().write(true).open(&p).unwrap();
            f.set_times(std::fs::FileTimes::new().set_modified(t)).unwrap();
        }
        let s = store(&tmp, 0);

        // Assert the queue itself. Reaching this through eviction depended on
        // whatever order `read_dir` happened to return, so it passed with the
        // sort removed — a test that agreed by luck rather than by reason.
        let origin = s.streams.get("s").expect("stream adopted").clone();
        let queued: Vec<String> = origin.order.lock().await.iter().cloned().collect();
        assert_eq!(
            queued,
            vec!["seg-00009.m4s".to_string(), "seg-00001.m4s".to_string()],
            "the eviction queue is not in age order"
        );

        // And the consequence: a bound that forces one eviction drops the
        // oldest, not whichever the filesystem listed first.
        s.set_default_policy(OriginPolicy {
            retention: std::time::Duration::from_secs(86_400),
            max_bytes_per_stream: 4,
            min_segments: 0,
            idle_grace: std::time::Duration::from_secs(60),
        });
        s.put("s", "seg-00010.m4s", Bytes::from_static(b"zz")).await.unwrap();
        assert!(
            s.get("s", "seg-00009.m4s").await.is_none(),
            "the oldest adopted segment survived eviction"
        );
        assert!(
            s.get("s", "seg-00010.m4s").await.is_some(),
            "the newest segment was evicted instead"
        );
    }

    /// A clip is pending until its media lands, and ready the moment it does.
    ///
    /// `ready` is read off the filesystem rather than the record, so a job that
    /// was recorded but never cut cannot advertise a download that 404s.
    #[tokio::test]
    async fn a_clip_is_pending_until_its_media_arrives() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        let req = ClipRequest {
            pre_secs: 10,
            post_secs: 20,
            clips: vec![ClipAsk {
                at: "2026-09-07T23:06:53.200Z".into(),
                name: "09-06-53-05 - Goal".into(),
            }],
        };
        s.record_clip_requests("feed", &req).unwrap();

        let listed = s.list_clips("feed");
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].ready, "a clip with no media must not read ready");
        assert_eq!(listed[0].pre_secs, 10);
        assert_eq!(listed[0].post_secs, 20);
        assert!(s.read_clip("feed", "09-06-53-05 - Goal").await.is_none());

        s.put_clip("feed", "09-06-53-05 - Goal", b"fake mp4 bytes")
            .await
            .unwrap();
        let listed = s.list_clips("feed");
        assert!(listed[0].ready, "media on disk must make the clip ready");
        assert_eq!(listed[0].bytes, 14);
        assert!(s.read_clip("feed", "09-06-53-05 - Goal").await.is_some());
    }

    /// Clips outlive the media they were cut from.
    ///
    /// The whole point of exporting is to keep a moment past the window. A clip
    /// swept out with the segments would disappear while the session that owns
    /// it is still running.
    #[tokio::test]
    async fn clips_are_not_evicted_with_the_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk {
                    at: "2026-09-07T23:06:53.200Z".into(),
                    name: "keeper".into(),
                }],
            },
        )
        .unwrap();
        s.put_clip("feed", "keeper", b"clip").await.unwrap();

        // A bound tight enough to evict everything the sweep can reach.
        s.set_default_policy(OriginPolicy {
            retention: Duration::from_millis(1),
            max_bytes_per_stream: 1,
            min_segments: 0,
            idle_grace: Duration::from_secs(60),
        });
        for i in 0..6 {
            put_seg(&s, "feed", &format!("seg-{i:05}.m4s"), 64).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        put_seg(&s, "feed", "seg-00099.m4s", 64).await;

        assert!(
            s.read_clip("feed", "keeper").await.is_some(),
            "the sweep took a clip with the segments"
        );
        assert!(s.list_clips("feed")[0].ready);
    }

    /// ...but they do not outlive the session.
    #[tokio::test]
    async fn dropping_a_stream_takes_its_clips_too() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk {
                    at: "2026-09-07T23:06:53.200Z".into(),
                    name: "keeper".into(),
                }],
            },
        )
        .unwrap();
        s.put_clip("feed", "keeper", b"clip").await.unwrap();
        put_seg(&s, "feed", "seg-00001.m4s", 64).await;

        s.remove_stream("feed").await;
        assert!(s.read_clip("feed", "keeper").await.is_none());
        assert!(s.list_clips("feed").is_empty());
    }

    /// A restart must not sweep the clips up as debris.
    ///
    /// Adoption deletes anything in a stream directory that is not a segment,
    /// which is right for a truncated `.part` and catastrophic for a clip.
    #[tokio::test]
    async fn adoption_leaves_the_clips_directory_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("feed").join(CLIPS_DIR)).unwrap();
        std::fs::write(root.join("feed/seg-00001.m4s"), b"xx").unwrap();
        std::fs::write(root.join("feed").join(CLIPS_DIR).join("keeper.mp4"), b"clip").unwrap();
        std::fs::write(root.join(ORIGIN_MARKER), b"x").unwrap();

        let s = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(3600),
            max_bytes_per_stream: 1 << 30,
            min_segments: 0,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .expect("store should build");

        assert!(
            root.join("feed").join(CLIPS_DIR).join("keeper.mp4").exists(),
            "adoption deleted an exported clip"
        );
        assert!(s.read_clip("feed", "keeper").await.is_some());
        // And the clip is not counted as adopted media, or the byte cap would
        // evict segments to make room for something it must never evict.
        assert_eq!(s.total_bytes(), 2, "the clip was adopted as a segment");
    }

    /// A clip is bounded in length, and the bound is on the total.
    ///
    /// The edge assembles a clip whole in memory and this holds it whole as a
    /// request body, so length is an allocation on two machines. Checking each
    /// end separately would let two forty-second halves through as an
    /// eighty-second clip.
    #[test]
    fn a_clip_may_not_exceed_a_minute_however_it_is_split() {
        assert!(MAX_CLIP_TOTAL_SECS == 60);
        // The body ceiling has to hold the longest clip the rule permits, at a
        // contribution-feed rate — this pair is the whole reason clips do not
        // share the segment limit.
        let sixty_secs_at_35mbit = 60usize * 35_000_000 / 8;
        assert!(
            MAX_CLIP_BYTES >= sixty_secs_at_35mbit,
            "MAX_CLIP_BYTES {MAX_CLIP_BYTES} cannot hold {sixty_secs_at_35mbit} bytes"
        );
        assert!(
            MAX_CLIP_BYTES > MAX_OBJECT_BYTES,
            "a clip is up to thirty segments; it cannot share the segment limit"
        );
    }

    /// A failed clip is terminal, and says why.
    #[tokio::test]
    async fn a_clip_the_edge_gave_up_on_stops_being_pending() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 10,
                post_secs: 20,
                clips: vec![ClipAsk {
                    at: "2026-09-07T23:06:53.200Z".into(),
                    name: "gone".into(),
                }],
            },
        )
        .unwrap();
        assert!(!s.list_clips("feed")[0].failed);

        assert!(s.fail_clip("feed", "gone", "the window aged out").unwrap());
        let listed = s.list_clips("feed");
        assert!(listed[0].failed, "the record must carry the failure");
        assert_eq!(listed[0].error.as_deref(), Some("the window aged out"));
        assert!(!listed[0].ready);

        // Nothing to mark for a clip nobody asked for.
        assert!(!s.fail_clip("feed", "never-requested", "x").unwrap());
    }

    /// Two different marks that produce the same name are two clips.
    ///
    /// The name is a timecode plus a label, so two marks in the same second
    /// with the same label collide. Skipping on the name alone silently
    /// discarded the second export and reported success for it.
    #[tokio::test]
    async fn a_second_mark_with_the_same_name_is_not_swallowed() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        let ask = |at: &str| ClipRequest {
            pre_secs: 5,
            post_secs: 5,
            clips: vec![ClipAsk {
                at: at.into(),
                name: "10-00-00-00 - Goal".into(),
            }],
        };

        let first = s.record_clip_requests("feed", &ask("2026-09-07T10:00:00Z")).unwrap();
        assert_eq!(first[0].name, "10-00-00-00 - Goal");

        // A different moment, same derived name.
        let second = s.record_clip_requests("feed", &ask("2026-09-07T11:30:00Z")).unwrap();
        assert_eq!(second[0].name, "10-00-00-00 - Goal (2)", "the second export was lost");
        assert_eq!(s.list_clips("feed").len(), 2);

        // The same moment again is the same clip, not a third.
        let again = s.record_clip_requests("feed", &ask("2026-09-07T10:00:00Z")).unwrap();
        assert_eq!(again[0].name, "10-00-00-00 - Goal");
        assert_eq!(s.list_clips("feed").len(), 2, "re-requesting a mark duplicated it");
    }

    /// Clips can be given back, and the space with them.
    ///
    /// They are exempt from the sweep by design, so without a delete the only
    /// way to reclaim their disk was to end the session.
    #[tokio::test]
    async fn a_clip_can_be_deleted_and_stops_being_counted() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk {
                    at: "2026-09-07T10:00:00Z".into(),
                    name: "spare".into(),
                }],
            },
        )
        .unwrap();
        s.put_clip("feed", "spare", &vec![0u8; 2048]).await.unwrap();

        let (count, bytes) = s.clip_usage("feed");
        assert_eq!((count, bytes), (1, 2048));

        assert!(s.delete_clip("feed", "spare").await);
        assert_eq!(s.clip_usage("feed"), (0, 0));
        assert!(s.read_clip("feed", "spare").await.is_none());
        assert!(!s.delete_clip("feed", "spare").await, "deleting twice must not claim success");
    }

    /// A clip name becomes a filename and arrives from a browser.
    #[test]
    fn clip_names_that_could_escape_are_refused() {
        assert!(valid_clip_name("09-06-53-05 - Goal"));
        assert!(valid_clip_name("14-35-22-11 - Try (second half)"));
        assert!(!valid_clip_name("../../etc/passwd"));
        assert!(!valid_clip_name("a/b"));
        assert!(!valid_clip_name("a\\b"));
        assert!(!valid_clip_name(".hidden"));
        assert!(!valid_clip_name(""));
        assert!(!valid_clip_name(&"x".repeat(181)));
        // A store with clips must still be recognisable as ours on upgrade.
        assert!(valid_clip_name("clip"));
    }

    /// A store written before the marker existed must still start.
    ///
    /// The marker shipped after relays were already in the field, so on the
    /// first upgrade the store the relay itself wrote looks foreign by the
    /// marker test alone. Found on the demo rig going 0.10.6 -> 0.13.0: the
    /// service refused to come up and reported what read like a
    /// misconfiguration of a path the operator had never changed.
    #[tokio::test]
    async fn a_store_predating_the_marker_is_adopted_not_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("feed-a")).unwrap();
        std::fs::write(root.join("feed-a/seg-00001.m4s"), b"xx").unwrap();
        std::fs::write(root.join("feed-a/thumb-1.jpg"), b"j").unwrap();
        assert!(!root.join(ORIGIN_MARKER).exists(), "fixture must have no marker");

        let s = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(3600),
            max_bytes_per_stream: 1 << 30,
            min_segments: 0,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .expect("an unmarked store of segment directories must be adopted");

        assert!(
            s.get("feed-a", "seg-00001.m4s").await.is_some(),
            "the window was not adopted"
        );
        assert!(
            root.join(ORIGIN_MARKER).exists(),
            "the marker must be written, so the next start needs no shape check"
        );
    }

    /// ...but shape is not a licence to adopt anything.
    ///
    /// Thumbnails are `.jpg`, so a directory of folders of pictures matches
    /// every rule except the segment one. It has to be refused: adoption
    /// enrols what it finds and the sweep then ages it out, so a false
    /// positive here deletes somebody's photographs.
    #[tokio::test]
    async fn a_library_of_pictures_is_not_mistaken_for_a_store() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Pictures");
        std::fs::create_dir_all(root.join("holiday")).unwrap();
        std::fs::write(root.join("holiday/DSC_0001.jpg"), b"photo").unwrap();

        let err = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(60),
            max_bytes_per_stream: 1 << 30,
            min_segments: 8,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .map(|_| ())
        .expect_err("folders of jpgs are not an origin store");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(root.join("holiday/DSC_0001.jpg").exists());
    }

    /// A stray file beside the segments is somebody else's directory.
    #[tokio::test]
    async fn a_loose_file_at_the_root_still_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("mixed");
        std::fs::create_dir_all(root.join("feed-a")).unwrap();
        std::fs::write(root.join("feed-a/seg-00001.m4s"), b"xx").unwrap();
        std::fs::write(root.join("notes.txt"), b"mine").unwrap();

        let err = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(60),
            max_bytes_per_stream: 1 << 30,
            min_segments: 8,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .map(|_| ())
        .expect_err("a loose file at the root means this is not our store");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(root.join("notes.txt").exists());
    }

    /// The origin root is an operator-supplied path, and every byte under
    /// it is evictable: adoption enrols what is there and the sweep, the
    /// byte cap and the free-space floor then delete it. The startup wipe
    /// this guard was written for is gone, but a directory the relay did
    /// not create must still be refused rather than taken over.
    #[tokio::test]
    async fn startup_refuses_a_directory_it_did_not_create() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("someones-data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("thesis.txt"), b"years of work").unwrap();

        let err = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(60),
            max_bytes_per_stream: 1 << 30,
            min_segments: 8,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .map(|_| ())
        .expect_err("a foreign non-empty directory must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(root.join("thesis.txt").exists(), "the directory was erased");

        // An empty directory is fine — that is a fresh install.
        let fresh = tmp.path().join("fresh");
        std::fs::create_dir_all(&fresh).unwrap();
        assert!(
            OriginStore::new(OriginConfig {
                root: fresh,
                retention: Duration::from_secs(60),
                max_bytes_per_stream: 1 << 30,
                min_segments: 8,
                min_free_bytes: 0,
                idle_grace: Duration::from_millis(80),
            })
            .map(|_| ())
            .is_ok()
        );
    }

    /// A root the relay created is adoptable by the relay's own next start.
    ///
    /// This is the other half of the guard above, and it had no test at all.
    /// The three adoption tests each write `ORIGIN_MARKER` by hand — they have
    /// to, or no store builds on a populated root — so not one of them can
    /// tell whether `new` writes one. Nothing else covered it either: on a
    /// fresh root the guard is skipped because the directory is empty, so a
    /// relay that had stopped marking its root would install, run and restart
    /// cleanly right up until it held its first segment. From then on the root
    /// is non-empty and unmarked, which is precisely the shape reserved for
    /// somebody else's directory — and the relay refuses to start, for good,
    /// and only in the field.
    ///
    /// So it is asserted as the round trip rather than as a file existing:
    /// build a store, PUT a segment, drop it, build a second store on the same
    /// root, and require the window back. Nothing is written by hand in
    /// between, so whatever the second start needs, the first has to have left
    /// there.
    #[tokio::test]
    async fn a_root_the_relay_created_is_adopted_by_its_own_next_start() {
        let tmp = tempfile::tempdir().unwrap();
        let first = store(&tmp, 8);
        let root = first.root().to_path_buf();
        put_seg(&first, "s", "seg-00001.m4s", 64).await;
        drop(first);

        assert!(
            root.join(ORIGIN_MARKER).exists(),
            "the relay did not mark the root it created, so its own next start refuses it"
        );
        // `store` builds on the same root, and this is the call that would
        // return the foreign-directory error rather than a store.
        let second = store(&tmp, 8);
        assert!(
            second.get("s", "seg-00001.m4s").await.is_some(),
            "the second start did not adopt the window the first one wrote"
        );
        assert_eq!(second.total_bytes(), 64, "adopted bytes are not accounted for");
    }

    /// The kept/evictable split still drives *how* an object is cached, but
    /// neither side may be immutable: segment numbering restarts at
    /// `seg-00000` on every flow restart and `init.mp4` is rewritten in place
    /// on reconfiguration, so no filename here is stable across runs.
    #[test]
    fn media_segments_are_distinguished_from_kept_objects() {
        for f in ["seg-00001.m4s", "seg-00001.ts", "chunk.cmfv"] {
            assert!(is_media_segment(f), "{f} should be an evictable segment");
        }
        for f in ["init.mp4", "manifest.m3u8", "manifest.mpd"] {
            assert!(!is_media_segment(f), "{f} must be a kept object");
        }
    }

    /// The body limit has to be at least as large as a realistic segment.
    /// axum's 2 MiB default rejects before the handler is reached, so this
    /// bound is what actually decides whether broadcast bitrates work.
    #[test]
    fn body_limit_admits_a_realistic_segment() {
        // 4 s of 50 Mbps video, comfortably above anything the edge emits.
        let big = 4 * 50_000_000 / 8;
        assert!(
            MAX_OBJECT_BYTES >= big,
            "MAX_OBJECT_BYTES {MAX_OBJECT_BYTES} is below a {big}-byte segment"
        );
        // And well above axum's 2 MiB default, which is the trap this guards.
        const AXUM_DEFAULT: usize = 2 * 1024 * 1024;
        const { assert!(MAX_OBJECT_BYTES > AXUM_DEFAULT) };
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type_for("a.m3u8"), "application/vnd.apple.mpegurl");
        assert_eq!(content_type_for("a.mpd"), "application/dash+xml");
        assert_eq!(content_type_for("a.m4s"), "video/mp4");
        assert_eq!(content_type_for("a.ts"), "video/mp2t");
    }

    #[test]
    fn object_name_validation() {
        assert!(valid_object_name("seg000.m4s"));
        assert!(valid_object_name("index.m3u8"));
        assert!(!valid_object_name("../secret"));
        assert!(!valid_object_name("noext"));
        assert!(!valid_object_name("a/b.m4s"));
    }
}