// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

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

mod marks;

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
    /// Serialises clip admission — see [`admit_clips`](OriginStore::admit_clips).
    /// One lock for the store, not one per stream: admission happens when an
    /// operator presses Export, so there is nothing here to contend for.
    clip_admission: std::sync::Mutex<()>,
    /// Serialises read-modify-write of a marks file — see [`marks`] and
    /// [`lock_marks`](OriginStore::lock_marks). Store-wide for the same reason
    /// as `clip_admission`: marks are made by hand.
    marks_lock: Arc<tokio::sync::Mutex<()>>,
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

/// The stream's shared marks — see [`marks`]. Kept and dropped with `clips/`,
/// and for the same reason: it belongs to the session, not to the window.
const MARKS_DIR: &str = "marks";

/// A subdirectory of a stream that belongs to the session rather than to the
/// window: `clips/` and `marks/`.
///
/// One answer for every place that must tell them from media — adoption on
/// restart, retirement, and the store-shape check — so a third such directory
/// cannot be taught to two of them and not the third. Adoption is where that
/// would hurt silently: it deletes anything that is not a segment, and today
/// it happens to use a call that refuses a directory.
fn is_session_subdir(name: &std::ffi::OsStr) -> bool {
    name == std::ffi::OsStr::new(CLIPS_DIR) || name == std::ffi::OsStr::new(MARKS_DIR)
}

/// Why a clip request was not admitted.
///
/// Every arm is something an operator can act on, and the handler turns each
/// into a sentence the player shows verbatim — which is why the store reports
/// the numbers rather than a status code.
#[derive(Debug)]
pub enum ClipRefusal {
    /// The stream is at its clip count.
    TooMany { have: usize, limit: usize },
    /// The batch would take the stream past its clip disk budget.
    OverBudget { would_use: u64, limit: u64 },
    /// Every candidate name for one mark is held by a different mark.
    NamesExhausted(String),
    Io(std::io::Error),
}

/// Where a clip request can be filed.
enum ClipSlot {
    /// Nothing holds this name; file the new record under it.
    Free(String),
    /// This exact mark is already recorded, under this name.
    Taken(String),
    /// Every candidate name is held by a *different* mark.
    Exhausted,
}

/// A name to file this request under.
///
/// Re-requesting the same mark is idempotent, so a candidate already holding
/// this mark's instant answers [`ClipSlot::Taken`]. A candidate holding a
/// different mark is a different clip and the search moves on to a suffix.
///
/// Bounded, and it **refuses** at the bound rather than reusing the base name.
/// Falling back to `wanted` handed back a name it had just proved was taken,
/// and the write that followed replaced the earlier mark's record in place —
/// while its `.mp4` stayed put, so the new record immediately read as ready
/// with the old clip's bytes: one export silently lost, and the other offered
/// to the operator under the wrong label. A refusal the caller can turn into a
/// sentence is the only honest answer at a collision ceiling.
fn free_clip_name(
    existing: &std::collections::HashMap<String, ClipRecord>,
    wanted: &str,
    at: &str,
) -> ClipSlot {
    for n in 1..=9u32 {
        let candidate = if n == 1 {
            wanted.to_string()
        } else {
            format!("{wanted} ({n})")
        };
        match existing.get(&candidate) {
            None => return ClipSlot::Free(candidate),
            Some(rec) if rec.at == at => return ClipSlot::Taken(candidate),
            Some(_) => continue,
        }
    }
    ClipSlot::Exhausted
}

/// Write a clip record, whole or not at all.
///
/// `std::fs::write` truncates first, so a crash inside it leaves a record that
/// parses as nothing: invisible to the listing, un-deletable from the portal,
/// and still holding its name against every later request for that mark.
/// Temp-then-rename is what the media path already does.
fn write_record(dir: &std::path::Path, rec: &ClipRecord) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(rec).map_err(std::io::Error::other)?;
    let tmp = dir.join(format!("{}.json{PART_SUFFIX}", rec.name));
    std::fs::write(&tmp, body)?;
    if let Err(e) = std::fs::rename(&tmp, dir.join(format!("{}.json", rec.name))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Suffix on the temporary file a clip upload is written to.
const PART_SUFFIX: &str = ".part";

/// How long a `.part` — or a clip with no record — is given before the relay
/// decides nobody is coming back for it. The edge allows a clip upload sixty
/// seconds, so an hour is generous by a wide margin and still bounded.
const PART_GRACE: Duration = Duration::from_secs(3600);

/// The longest the relay will hold a clip on its own account.
///
/// Not the retention: the manager owns that and its clock is a day past the
/// session. This is the floor under a manager that never comes back, an order
/// of magnitude above any expiry it sets, so it can only ever fire on clips
/// whose owner has forgotten them entirely.
const CLIP_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// A half-written clip that removes itself unless it is committed.
///
/// Every early return in the upload loop used to leave the temp file behind,
/// and a `.part` inside `clips/` is invisible to every bound in this file: it
/// is in no listing (which walks `*.json`), counted in no byte total, in no
/// eviction queue, skipped by the restart debris sweep, and untouched by
/// `delete_clip`. The disk still holds it, so the free-space floor pays for it
/// out of *recorded footage* — the one outcome `MAX_CLIP_BYTES_PER_STREAM`
/// exists to prevent.
///
/// The cleanup is in `Drop`, and synchronous, because the case that matters
/// most cannot be handled any other way: when the client disconnects, the
/// handler future is dropped where it stands and an `async` unlink would never
/// be polled.
///
/// The name carries a per-upload nonce so two PUTs for one clip cannot share an
/// inode. `File::create` truncates, so a retry landing on top of an upload
/// still in flight produced a file with a hole in it — which renames in,
/// lists as ready, and is never re-cut.
struct PartFile {
    path: PathBuf,
    file: tokio::fs::File,
    committed: bool,
}

impl PartFile {
    async fn create(dir: &std::path::Path, name: &str) -> std::io::Result<Self> {
        static NONCE: AtomicU64 = AtomicU64::new(0);
        let n = NONCE.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            "{name}.{}-{n}.mp4{PART_SUFFIX}",
            std::process::id()
        ));
        let file = tokio::fs::File::create(&path).await?;
        Ok(Self { path, file, committed: false })
    }

    /// Put the finished bytes where readers look for them, and disarm.
    async fn commit(mut self, dest: PathBuf) -> std::io::Result<()> {
        tokio::fs::rename(&self.path, &dest).await?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Does this directory look like a store an older relay wrote?
///
/// Used only when the marker is absent, to tell "our own store, from before
/// the marker existed" from "somebody else's directory". Everything under the
/// root becomes evictable and the idle sweep ends in `remove_dir_all`, so a
/// false positive is an operator's data deleted about two minutes after the
/// relay starts. The evidence demanded is therefore evidence a tree this relay
/// did not write is unlikely to have:
///
/// * every top-level entry is a directory (a home directory has files in it);
/// * inside those, nothing but segments, thumbnails, init segments,
///   interrupted PUTs, and the `clips/` and `marks/` subdirectories;
/// * every directory that holds files holds at least one segment named the way
///   **this system's** packager names them — `seg-00042.m4s` / `aud-00042.m4s`
///   (bilbycast-edge `engine::cmaf::manifest::segment_file_name`);
/// * and there are at least two such segments in the tree.
///
/// The naming clause is what the earlier "at least one `.m4s` anywhere" test
/// lacked. Another packager's CMAF or DASH output — `<event>/*.m4s` beside an
/// `init.mp4` — is exactly the shape of a relay store, and a media archive
/// holding a single stray `.m4s` beside folders of `.mp4` and `.jpg` passed
/// too. A window is hundreds of segments, so requiring two of them under their
/// real names costs a genuine upgrade nothing.
fn looks_like_origin_store(root: &std::path::Path) -> std::io::Result<bool> {
    let mut segments = 0usize;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == std::ffi::OsStr::new(ORIGIN_MARKER) {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Ok(false);
        }
        let mut files_here = 0usize;
        let mut segments_here = 0usize;
        for f in std::fs::read_dir(entry.path())? {
            let f = f?;
            // Exported clips and shared marks live in their own
            // subdirectories of the stream, so a directory here is expected as
            // long as it is one of those.
            if f.file_type()?.is_dir() {
                if is_session_subdir(&f.file_name()) {
                    continue;
                }
                return Ok(false);
            }
            if !f.file_type()?.is_file() {
                return Ok(false);
            }
            let name = f.file_name();
            let name = name.to_string_lossy();
            files_here += 1;
            if is_packager_segment(&name) {
                segments_here += 1;
                segments += 1;
            } else if !(name.ends_with(".m4s")
                || name.ends_with(".mp4")
                || name.ends_with(".jpg")
                || name.ends_with(PART_SUFFIX))
            {
                return Ok(false);
            }
        }
        // A directory holding files but no segments of ours is not a stream of
        // ours. One holding no files at all — a stream retired down to its
        // clips or marks — proves nothing either way and is allowed to pass.
        if files_here > 0 && segments_here == 0 {
            return Ok(false);
        }
    }
    Ok(segments >= 2)
}

/// `seg-00042.m4s` / `aud-00042.m4s` — the names bilbycast-edge's CMAF
/// packager produces, and the only ones this store is ever filled with.
fn is_packager_segment(name: &str) -> bool {
    let Some(rest) = name.strip_suffix(".m4s") else {
        return false;
    };
    let Some(digits) = rest
        .strip_prefix("seg-")
        .or_else(|| rest.strip_prefix("aud-"))
    else {
        return false;
    };
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
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
    /// `.bilbycast-origin` marker is refused rather than adopted — the root is
    /// operator-supplied and everything under it becomes evictable, so a typo
    /// naming a home directory must not enrol it into the sweep — unless it
    /// carries the shape of a store written before the marker existed, which
    /// [`looks_like_origin_store`] describes and deliberately reads narrowly.
    pub fn new(cfg: OriginConfig) -> std::io::Result<Self> {
        // Only ever adopt — and evict from — a directory this store made.
        // `origin_storage_dir` is operator-supplied and everything under it
        // becomes deletable: `remove_stream` does a `remove_dir_all` from the
        // idle sweep, and the free-space floor evicts across every stream it
        // finds. Pointed at a home directory or a mount point by a typo, the
        // store would index whatever is there and then age it out. A
        // directory that exists, is not empty, and has no marker is somebody
        // else's — unless it carries the shape of a store written before the
        // marker existed, which `looks_like_origin_store` reads narrowly.
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
            clip_admission: std::sync::Mutex::new(()),
            marks_lock: Arc::new(tokio::sync::Mutex::new(())),
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
                // Exported clips and shared marks are not segments: they must
                // survive a restart untouched, and must not enter the eviction
                // queue.
                //
                // Skipped explicitly rather than relying on what follows. The
                // debris sweep below uses `remove_file`, which refuses a
                // directory, so they would survive without this — but that is
                // an accident of the call used, not a decision, and a later
                // change to `remove_dir_all` would silently delete every
                // exported clip and every marks list on the next restart.
                // Stating the intent here costs one comparison.
                if is_session_subdir(f.file_name().as_os_str()) {
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

    /// The clips directory for a stream, or `None` if the name is not one.
    ///
    /// Gated on the same [`safe_stream_name`](Self::safe_stream_name) as `put`
    /// and `remove_stream`, not because the HTTP handlers let anything else
    /// through — they run `sanitize_stream_id` first — but because this store's
    /// methods are `pub` and the codebase already depends on the store
    /// validating its own names on a path that is not HTTP: `manager::client`
    /// forwards manager-supplied stream names straight into `drop_stream` with
    /// the comment "the origin sanitises its own stream ids; this only
    /// forwards". This branch adds a second manager verb beside that one; the
    /// clip surface has to hold the same line.
    fn clips_dir(&self, stream: &str) -> Option<PathBuf> {
        Self::safe_stream_name(stream).then(|| self.cfg.root.join(stream).join(CLIPS_DIR))
    }

    /// The same, for a method that also turns `name` into a filename.
    ///
    /// Both halves or neither: every clip method interpolates the name into
    /// `{name}.mp4` / `{name}.json`, so validating the stream and trusting the
    /// name would leave the invariant half-kept.
    fn clip_dir_for(&self, stream: &str, name: &str) -> std::io::Result<PathBuf> {
        match self.clips_dir(stream) {
            Some(dir) if valid_clip_name(name) => Ok(dir),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "origin: unsafe stream or clip name",
            )),
        }
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
    /// Check this stream's clip budget and file the request, as one operation.
    ///
    /// The two were separate calls with nothing held between them, so two
    /// viewers of one feed — a link grant and a portal login, both legitimate —
    /// each read the same count, each passed, and both wrote: a stated ceiling
    /// of a hundred clips overshot by a batch per concurrent request. One lock
    /// for the whole store is enough, because admission happens when an
    /// operator presses Export, not on any hot path.
    pub fn admit_clips(
        &self,
        stream: &str,
        req: &ClipRequest,
    ) -> Result<Vec<ClipRecord>, ClipRefusal> {
        let _admitting = self.clip_admission.lock().unwrap_or_else(|e| e.into_inner());

        let (have, _landed) = self.clip_usage(stream);
        if have + req.clips.len() > MAX_CLIPS_PER_STREAM {
            return Err(ClipRefusal::TooMany { have, limit: MAX_CLIPS_PER_STREAM });
        }
        // Projected, not landed, and tested against what this request would
        // add. `bytes >= limit` on already-stored bytes could not fire until
        // the ceiling had been crossed, and it could not see a batch in flight
        // at all — so the budget was never actually enforced.
        let used = self.clip_budget_used(stream);
        let asking = (req.clips.len() as u64)
            .saturating_mul(estimated_clip_bytes(req.pre_secs, req.post_secs));
        let would_use = used.saturating_add(asking);
        if would_use > MAX_CLIP_BYTES_PER_STREAM {
            return Err(ClipRefusal::OverBudget {
                would_use,
                limit: MAX_CLIP_BYTES_PER_STREAM,
            });
        }
        self.record_clip_requests(stream, req).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ClipRefusal::NamesExhausted(e.to_string())
            } else {
                ClipRefusal::Io(e)
            }
        })
    }

    pub fn record_clip_requests(
        &self,
        stream: &str,
        req: &ClipRequest,
    ) -> std::io::Result<Vec<ClipRecord>> {
        let Some(dir) = self.clips_dir(stream) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "origin: unsafe stream name",
            ));
        };
        if let Some(bad) = req.clips.iter().find(|a| !valid_clip_name(&a.name)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("origin: unsafe clip name '{}'", bad.name),
            ));
        }
        std::fs::create_dir_all(&dir)?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut out = Vec::new();
        // One listing for the whole request. It used to be re-read per
        // collision — a fresh `read_dir` plus a `read` and a `stat` per record,
        // inside the per-ask loop — so re-sending a batch of fifty against a
        // stream holding fifty records cost thousands of blocking file
        // operations to answer a question one scan already had.
        //
        // Doubling as the collision map also fixes the within-request case:
        // reading each candidate off disk meant fifty asks sharing one name all
        // saw the same free slot and all wrote to it, and forty-nine requested
        // exports vanished.
        let mut existing: std::collections::HashMap<String, ClipRecord> = self
            .list_clips(stream)
            .into_iter()
            .map(|c| (c.name.clone(), c))
            .collect();
        for ask in &req.clips {
            match free_clip_name(&existing, &ask.name, &ask.at) {
                ClipSlot::Taken(name) => {
                    // Same mark, already recorded. Hand back what is there so
                    // the caller sees its real state rather than a fresh
                    // pending one — and by the name it was actually filed
                    // under, which is not `ask.name` once a suffix was needed.
                    if let Some(rec) = existing.get(&name) {
                        out.push(rec.clone());
                    }
                }
                ClipSlot::Exhausted => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("too many clips already named '{}'", ask.name),
                    ));
                }
                ClipSlot::Free(name) => {
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
                    write_record(&dir, &rec)?;
                    existing.insert(rec.name.clone(), rec.clone());
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    /// Every clip this stream knows about, ready or not.
    ///
    /// `ready` and `bytes` come from the media file on disk, never from the
    /// record: a record that claimed ready without the bytes behind it would
    /// offer the portal a download that 404s.
    pub fn list_clips(&self, stream: &str) -> Vec<ClipRecord> {
        let Some(dir) = self.clips_dir(stream) else {
            return Vec::new();
        };
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

    /// A clip that is already in memory, through the same path production
    /// uses. Tests only: the buffered writer this replaced wrote a fixed
    /// `{name}.mp4.part` with no guard — the very shape [`PartFile`] exists
    /// to remove — and nothing outside the tests ever called it.
    #[cfg(test)]
    pub(crate) async fn put_clip(
        &self,
        stream: &str,
        name: &str,
        body: &[u8],
    ) -> std::io::Result<()> {
        let len = body.len() as u64;
        self.put_clip_streaming(stream, name, axum::body::Body::from(body.to_vec()), len)
            .await
            .map(|_| ())
    }

    /// The edge hands the finished media over, streamed to disk rather than
    /// buffered whole.
    ///
    /// A clip is up to 256 MiB, and holding one entirely in memory to write it
    /// out again is a quarter-gigabyte spike per concurrent upload on a service
    /// whose other objects are two-second segments. The bytes go to the `.part`
    /// file as they arrive, so the peak is a chunk rather than a clip.
    ///
    /// The ceiling is enforced *while* reading: a body that lies about its
    /// length, or sends none, would otherwise be bounded by nothing.
    ///
    /// The `.part` is **unique per upload** and removed on every way out,
    /// including an abandoned request — see [`PartFile`]. A fixed
    /// `{name}.mp4.part` opened `O_TRUNC` let a second PUT for the same clip
    /// truncate a first one's file underneath it, and the only error path that
    /// cleaned up was the size check, so a client that timed out mid-body (the
    /// edge gives a clip upload sixty seconds) left up to 256 MiB on disk that
    /// no listing, no byte total, no eviction queue and no restart could see.
    pub async fn put_clip_streaming(
        &self,
        stream: &str,
        name: &str,
        body: axum::body::Body,
        max_bytes: u64,
    ) -> std::io::Result<u64> {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;

        let dir = self.clip_dir_for(stream, name)?;
        tokio::fs::create_dir_all(&dir).await?;
        let mut part = PartFile::create(&dir, name).await?;
        let mut written: u64 = 0;
        let mut stream_body = body.into_data_stream();

        while let Some(chunk) = stream_body.next().await {
            let chunk = chunk.map_err(std::io::Error::other)?;
            written += chunk.len() as u64;
            if written > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "clip exceeds the maximum size",
                ));
            }
            part.file.write_all(&chunk).await?;
        }
        // `flush` drains tokio's userspace buffer into the kernel and stops
        // there. The rename that follows is a metadata operation a journalling
        // filesystem may well commit while the delayed-allocation data blocks
        // are still unwritten, and `list_clips` decides `ready` on the media
        // file existing — so an unclean shutdown in that window leaves a clip
        // that reads as finished, downloads as holes, and is never re-cut
        // because the exporter skips anything already ready.
        part.file.flush().await?;
        part.file.sync_all().await?;
        part.commit(dir.join(format!("{name}.mp4"))).await?;
        // And the directory entry itself, for the same reason: a synced file
        // under a rename that was never committed is a clip that vanishes.
        if let Ok(d) = tokio::fs::File::open(&dir).await {
            let _ = d.sync_all().await;
        }
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

    /// The disk this stream's clips hold **or are going to hold**.
    ///
    /// `clip_usage` reports what has landed, which is the wrong number to gate
    /// the next batch on: a pending record has no media yet and so counts as
    /// zero, so fifty cuts already commissioned were invisible to the check
    /// meant to decide whether fifty more could be. Two permitted batches
    /// therefore put 25 GiB on a stream whose stated ceiling is 4 GiB.
    ///
    /// A record that has not been cut yet is charged
    /// [`estimated_clip_bytes`] for its requested length instead.
    pub fn clip_budget_used(&self, stream: &str) -> u64 {
        self.list_clips(stream)
            .iter()
            .map(|c| {
                if c.ready {
                    c.bytes
                } else if c.failed {
                    // Nothing is coming for this one, and it holds no media.
                    0
                } else {
                    estimated_clip_bytes(c.pre_secs, c.post_secs)
                }
            })
            .sum()
    }

    /// Is there a record for this clip — i.e. did anyone ask for it?
    ///
    /// The upload is the second half of a request the origin recorded, and a
    /// `.mp4` with no `.json` beside it is an orphan: `list_clips` walks the
    /// records, so it is in no listing, counted in no byte total, deletable
    /// from no portal, and reclaimed only when the whole stream directory goes.
    /// A viewer cancelling a cut the edge has already started produced exactly
    /// that, once per cancelled clip.
    pub fn clip_record_exists(&self, stream: &str, name: &str) -> bool {
        self.clip_dir_for(stream, name)
            .is_ok_and(|dir| dir.join(format!("{name}.json")).is_file())
    }

    /// Remove one clip — its media and its record.
    ///
    /// Clips outlive the sweep, so without this the only way to reclaim the
    /// space was to end the session. Returns whether anything was there.
    pub async fn delete_clip(&self, stream: &str, name: &str) -> bool {
        let Ok(dir) = self.clip_dir_for(stream, name) else {
            return false;
        };
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
        let dir = self.clip_dir_for(stream, name)?;
        let Ok(raw) = std::fs::read(dir.join(format!("{name}.json"))) else {
            return Ok(false);
        };
        let mut rec: ClipRecord = serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
        rec.failed = true;
        rec.error = Some(reason.chars().take(300).collect());
        write_record(&dir, &rec)?;
        Ok(true)
    }

    pub async fn read_clip(&self, stream: &str, name: &str) -> Option<Vec<u8>> {
        let dir = self.clip_dir_for(stream, name).ok()?;
        tokio::fs::read(dir.join(format!("{name}.mp4"))).await.ok()
    }

    /// The clip as an open file and its length, for streaming it out.
    ///
    /// The counterpart to [`put_clip_streaming`](Self::put_clip_streaming), and
    /// for the same reason: `read_clip` buffers a whole clip — up to
    /// `MAX_CLIP_BYTES` — into a `Vec` before a byte reaches the network, and
    /// holds it until the response is fully written. That is a quarter-gigabyte
    /// of resident memory per concurrent download, on the process that is also
    /// forwarding live contribution, and the download side has far more callers
    /// than the upload side ever did.
    pub async fn open_clip(&self, stream: &str, name: &str) -> Option<(tokio::fs::File, u64)> {
        let path = self
            .clip_dir_for(stream, name)
            .ok()?
            .join(format!("{name}.mp4"));
        let file = tokio::fs::File::open(&path).await.ok()?;
        let len = file.metadata().await.ok()?.len();
        Some((file, len))
    }

    /// Take the store's marks lock.
    ///
    /// A `tokio` mutex, waited for as a future: a marks write queued behind
    /// another costs a task, not a thread. It was a `std` mutex taken on the
    /// blocking pool, where every waiter held one of the pool's threads for as
    /// long as it waited — while each write holds the lock across two fsyncs.
    /// A burst of marks writes from any viewer token could then fill the pool
    /// every `tokio::fs` call in the relay shares, segment ingest for every
    /// stream included.
    ///
    /// Owned, so the guard moves into the blocking work and is released when
    /// that work is done rather than when the request is. A client that hangs
    /// up drops its handler but not the blocking task the handler started,
    /// and a guard dropped with the handler would let the next writer in
    /// while this one was still between its read and its rename.
    async fn lock_marks(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.marks_lock.clone().lock_owned().await
    }

    pub async fn remove_stream(&self, stream: &str) {
        if !Self::safe_stream_name(stream) {
            return;
        }
        // A stream that is not tracked can still have a directory, and that is
        // the normal case for the one removal that matters most: a retired
        // stream is already out of the map, so returning early here left its
        // clips on disk for ever — neither the session being deleted nor the
        // 24-hour expiry sweep could reach them. Found by the healthcheck,
        // which noticed a stream directory serving an empty window.
        let dir = match self.streams.remove(stream) {
            Some((_, origin)) => {
                self.total_bytes
                    .fetch_sub(origin.bytes.load(Ordering::Relaxed), Ordering::Relaxed);
                origin.dir.clone()
            }
            None => self.cfg.root.join(stream),
        };
        if let Err(e) = tokio::fs::remove_dir_all(&dir).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "origin: could not remove stream directory"
            );
        }
    }

    /// The session is over, but its clips are not.
    ///
    /// Removes the media — segments, manifests, init — and keeps `clips/` and
    /// `marks/`.
    /// Clips outlive the game they came from by design: somebody exports a
    /// moment near full time and the broadcast ends minutes later, so tearing
    /// the whole directory down with the session took the export away before
    /// anyone could use it.
    ///
    /// The stream stops being served as a feed either way; what remains is a
    /// directory of finished files the portal still hands out. When the
    /// retention the manager set runs out it sends the stream to
    /// [`remove_stream`](Self::remove_stream) instead, and the lot goes.
    pub async fn retire_stream(&self, stream: &str) {
        if !Self::safe_stream_name(stream) {
            return;
        }
        let Some((_, origin)) = self.streams.remove(stream) else {
            return;
        };
        self.total_bytes
            .fetch_sub(origin.bytes.load(Ordering::Relaxed), Ordering::Relaxed);

        let mut kept: Vec<String> = Vec::new();
        match tokio::fs::read_dir(&origin.dir).await {
            Ok(mut rd) => {
                while let Ok(Some(entry)) = rd.next_entry().await {
                    // Shared marks are kept on exactly the same terms as the
                    // clips: an operator's list of moments outlives a feed drop.
                    if is_session_subdir(&entry.file_name()) {
                        // Kept only if it is holding something. Counting the
                        // directory entry itself meant a `clips/` a viewer had
                        // emptied through the portal read as "clips kept", and
                        // retirement then left exactly the empty shell the
                        // cleanup below exists to avoid.
                        let holds_anything = match tokio::fs::read_dir(entry.path()).await {
                            Ok(mut inner) => matches!(inner.next_entry().await, Ok(Some(_))),
                            Err(_) => false,
                        };
                        if holds_anything {
                            kept.push(entry.file_name().to_string_lossy().into_owned());
                        } else {
                            let _ = tokio::fs::remove_dir(entry.path()).await;
                        }
                        continue;
                    }
                    let path = entry.path();
                    let res = match entry.file_type().await {
                        Ok(t) if t.is_dir() => tokio::fs::remove_dir_all(&path).await,
                        _ => tokio::fs::remove_file(&path).await,
                    };
                    if let Err(e) = res
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(
                            path = %path.display(), error = %e,
                            "origin: could not remove a retired stream's media"
                        );
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                dir = %origin.dir.display(), error = %e,
                "origin: could not read a retired stream's directory"
            ),
        }
        // Nothing kept means nothing to keep it for: leave no empty shell
        // behind for the store-shape check to puzzle over on the next start.
        if kept.is_empty() {
            let _ = tokio::fs::remove_dir(&origin.dir).await;
        }
        // Named, not counted: an operator reading this after a feed drop goes
        // looking for whatever it says is left, and "clips remain" sent them
        // to the portal for clips a stream holding only marks never had.
        tracing::info!(
            stream = %stream, kept = %kept.join(","),
            "origin: stream retired; its media is gone"
        );
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
                // `retire_stream`, not `remove_stream`: the media has expired,
                // the exported clips have not. An ingest gap longer than
                // retention + grace — a satellite drop, an edge restart — is
                // exactly when an operator most wants the clip they cut before
                // it, and `remove_stream`'s `remove_dir_all` took `clips/`
                // with it. The hard drop stays where it belongs, on the
                // manager's expiry sweep.
                self.retire_stream(&name).await;
            }
        }

        self.reclaim_clip_debris().await;
        self.enforce_free_space().await;
    }

    /// What the relay can reclaim in `clips/` on its own.
    ///
    /// Clip retention is the manager's: it holds the expiry in Postgres and
    /// sends `drop_origin_streams` when it lapses, and that is deliberately the
    /// authority — the relay does not know what a session is or when it ended.
    /// But the bytes are here, and the manager is one database and one network
    /// away, so "the manager will say" is not a complete answer to "when does
    /// this disk come back". A manager that never returns leaves clips for
    /// ever, and nothing else in this process can see them.
    ///
    /// So this is a backstop, an order of magnitude above any retention the
    /// manager sets (a day, plus the session), never a policy:
    ///
    /// * `.part` files past the grace period — an upload nobody is making any
    ///   more. (The live ones are minutes old at most; the edge gives a clip
    ///   upload sixty seconds.)
    /// * media with no record beside it — invisible to the listing, to both
    ///   ceilings and to the portal's delete button, but not to the disk.
    /// * anything at all past [`CLIP_MAX_AGE`].
    /// * a `marks/` list nobody has changed for [`CLIP_MAX_AGE`], on a stream
    ///   nothing is ingesting — the same backstop for the same reason.
    /// * and the stream directory itself, once it holds nothing and no stream
    ///   is using it — a clips- or marks-only directory is in no eviction path
    ///   and is not re-adopted on restart, so without this it is permanent.
    async fn reclaim_clip_debris(&self) {
        let Ok(mut root) = tokio::fs::read_dir(&self.cfg.root).await else {
            return;
        };
        let now = std::time::SystemTime::now();
        while let Ok(Some(entry)) = root.next_entry().await {
            let Some(stream) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !Self::safe_stream_name(&stream) {
                continue;
            }
            // Shared marks get the clips' backstop: a list nobody has touched
            // for `CLIP_MAX_AGE`, on a stream nothing is publishing, belongs to
            // a session whose manager never came back to drop it.
            if !self.streams.contains_key(&stream) {
                let marks = entry.path().join(MARKS_DIR);
                let file = tokio::fs::metadata(marks.join(marks::MARKS_FILE)).await;
                let touched = match file {
                    Ok(m) => Ok(m),
                    Err(_) => tokio::fs::metadata(&marks).await,
                }
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| now.duration_since(m).ok());
                if touched.is_some_and(|age| age >= CLIP_MAX_AGE) {
                    tracing::info!(stream = %stream, "origin: reclaiming a forgotten marks list");
                    let _ = tokio::fs::remove_dir_all(&marks).await;
                    // Fails harmlessly while `clips/` still holds something.
                    let _ = tokio::fs::remove_dir(entry.path()).await;
                }
            }
            let dir = entry.path().join(CLIPS_DIR);
            let Ok(mut rd) = tokio::fs::read_dir(&dir).await else {
                continue;
            };

            let mut records: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut media: Vec<(String, PathBuf, std::time::Duration)> = Vec::new();
            let mut expired: Vec<PathBuf> = Vec::new();
            let mut left = 0usize;
            while let Ok(Some(f)) = rd.next_entry().await {
                let Some(name) = f.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let age = f
                    .metadata()
                    .await
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|m| now.duration_since(m).ok())
                    .unwrap_or_default();
                if name.ends_with(PART_SUFFIX) {
                    if age >= PART_GRACE {
                        expired.push(f.path());
                    } else {
                        left += 1;
                    }
                    continue;
                }
                if age >= CLIP_MAX_AGE {
                    expired.push(f.path());
                    continue;
                }
                left += 1;
                if let Some(stem) = name.strip_suffix(".json") {
                    records.insert(stem.to_string());
                } else if let Some(stem) = name.strip_suffix(".mp4") {
                    media.push((stem.to_string(), f.path(), age));
                }
            }
            // A record may legitimately arrive moments before its media, so an
            // orphan is only an orphan once it has had time to stop being one.
            for (stem, path, age) in media {
                if !records.contains(&stem) && age >= PART_GRACE {
                    tracing::info!(
                        stream = %stream, clip = %stem,
                        "origin: reclaiming clip media nothing has a record for"
                    );
                    expired.push(path);
                    left = left.saturating_sub(1);
                }
            }
            for path in &expired {
                let _ = tokio::fs::remove_file(path).await;
            }
            if !expired.is_empty() {
                tracing::info!(
                    stream = %stream, files = expired.len(),
                    "origin: reclaimed clip debris"
                );
            }
            // Nothing left, and nothing ingesting: the directory is the last
            // thing holding the stream's name on this disk.
            if left == 0 && !self.streams.contains_key(&stream) {
                let _ = tokio::fs::remove_dir(&dir).await;
                let _ = tokio::fs::remove_dir(entry.path()).await;
            }
        }
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

/// What a clip of this length is assumed to cost before anything has cut it.
///
/// The same contribution rate [`MAX_CLIP_BYTES`] is derived from, so the two
/// numbers cannot drift apart: a sixty-second clip is charged exactly the
/// per-clip ceiling, and a ten-second one a sixth of it. Used to charge
/// requested-but-not-yet-cut clips against the per-stream budget, which is the
/// only way that budget can bound anything — the bytes arrive minutes after the
/// decision to allow them.
fn estimated_clip_bytes(pre_secs: u32, post_secs: u32) -> u64 {
    let secs = u64::from(pre_secs.saturating_add(post_secs)).min(MAX_CLIP_TOTAL_SECS as u64);
    secs * 35_000_000 / 8
}

/// The longest clip anyone may export, pre-roll and post-roll together.
///
/// A review clip is a moment, not a passage of play, and the length has to be
/// bounded somewhere: the edge assembles a clip whole in memory and the relay
/// holds it whole as a request body, so an unbounded length is an unbounded
/// allocation on two machines. A minute is long enough for the thing an
/// operator marked and short enough to stay a sane object.
/// The body ceiling has to hold the longest clip the rule permits, at a
/// contribution-feed rate. This pair is the whole reason clips do not share
/// the segment limit, and it is checked at compile time because both sides are
/// constants: a change that breaks the relationship should not build, rather
/// than fail a test somebody has to run.
const _: () = {
    let sixty_secs_at_35mbit = 60usize * 35_000_000 / 8;
    assert!(
        MAX_CLIP_BYTES >= sixty_secs_at_35mbit,
        "MAX_CLIP_BYTES cannot hold a minute of 35 Mbit/s contribution feed"
    );
    assert!(
        MAX_CLIP_BYTES > MAX_OBJECT_BYTES,
        "a clip is up to thirty segments; it cannot share the segment limit"
    );
};

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

/// The largest JSON body the clip control routes will buffer.
///
/// Both of them are bounded by their own contents — fifty asks of a 180-byte
/// name, or a 300-character failure reason — so this is generous by an order of
/// magnitude and still three thousand times smaller than the media ceiling.
const MAX_CLIP_JSON_BYTES: usize = 64 * 1024;

pub fn routes() -> Router<Arc<DistributionState>> {
    // A clip is up to thirty segments of media in one object, so it cannot
    // share the segment limit. Its own route carries its own bound rather than
    // raising the limit for every PUT on the origin — a 256 MiB ceiling on
    // segment ingest would turn a runaway encoder into a memory problem.
    //
    // The 256 MiB ceiling goes on the media route ONLY. `clips_request` and
    // `clip_failed` take `axum::Json`, which collects the whole body into heap
    // before a single line of the handler runs — so a limit raised for the
    // upload became the amount of memory an unauthenticated caller could make
    // the relay buffer per connection, on a public listener, before the
    // credential check it would then fail. (It buys the media PUT nothing
    // either way: `clip_put` extracts a raw `Body`, which never consults
    // `DefaultBodyLimit`, and enforces `MAX_CLIP_BYTES` itself while streaming
    // to disk. The layer is kept there for the route's declared contract.)
    let clip_media = Router::new()
        .route(
            "/origin/{stream}/clips/{file}",
            put(clip_put).get(clip_get).delete(clip_delete),
        )
        .layer(DefaultBodyLimit::max(MAX_CLIP_BYTES));

    let clip_control = Router::new()
        // Static segments beat the `{file}` capture, so these do not shadow the
        // segment routes below.
        .route(
            "/origin/{stream}/clips",
            axum::routing::post(clips_request).get(clips_list),
        )
        .route(
            "/origin/{stream}/clips/{file}/failed",
            axum::routing::post(clip_failed),
        )
        .layer(DefaultBodyLimit::max(MAX_CLIP_JSON_BYTES));

    Router::new()
        .route("/origin/{stream}/{file}", put(origin_put).get(origin_get))
        .layer(DefaultBodyLimit::max(MAX_OBJECT_BYTES))
        .merge(clip_media)
        .merge(clip_control)
        .merge(marks::routes())
}

/// `PUT /origin/{stream}/{file}` — accept an edge CMAF/HLS upload.
/// `POST /origin/{stream}/clips` — ask for clips around marks.
///
/// Whoever may watch this feed may cut from it — but a credential is required
/// either way, not only when `require_origin_token` is on. See
/// [`require_clip_credential`]. The cut itself happens on the edge — the only
/// component with a decoder — so all this does is record the ask where the
/// portal and the edge can both see it.
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
    if let Err(resp) = require_clip_credential(&st, &stream, &headers, query.as_deref()) {
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
    // Budget check and record write happen together under one lock, on the
    // blocking pool: `admit_clips` is `read_dir` plus a `read` and a `stat` per
    // record and a write per ask, and every other method on this store reaches
    // the filesystem through `tokio::fs` for the reason this one must not run
    // on a worker — the same runtime carries the QUIC and native-UDP
    // forwarding tasks.
    let origin = st.origin.clone();
    let for_task = stream.clone();
    let admitted =
        match tokio::task::spawn_blocking(move || origin.admit_clips(&for_task, &req)).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(stream = %stream, error = %e, "origin: clip admission task failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "could not record the request")
                    .into_response();
            }
        };

    match admitted {
        Ok(recs) => {
            tracing::info!(
                stream = %stream, clips = recs.len(),
                "origin: clip export requested"
            );
            (StatusCode::ACCEPTED, axum::Json(recs)).into_response()
        }
        Err(ClipRefusal::TooMany { have, limit }) => (
            StatusCode::CONFLICT,
            format!(
                "this feed already holds {have} clips, and the limit is \
                 {limit} — delete some before exporting more"
            ),
        )
            .into_response(),
        Err(ClipRefusal::OverBudget { would_use, limit }) => (
            StatusCode::CONFLICT,
            format!(
                "this feed's clips would use {:.1} GB and the limit is {:.0} GB — \
                 delete some before exporting more",
                would_use as f64 / 1024.0 / 1024.0 / 1024.0,
                limit as f64 / 1024.0 / 1024.0 / 1024.0
            ),
        )
            .into_response(),
        // The collision ceiling. Refusing is the point — the alternative was
        // overwriting an earlier mark's record — so this needs a sentence the
        // player can show, not a 500.
        Err(ClipRefusal::NamesExhausted(what)) => (
            StatusCode::CONFLICT,
            format!(
                "{what} — rename the mark, or delete one of the clips already \
                 under that name"
            ),
        )
            .into_response(),
        Err(ClipRefusal::Io(e)) => {
            tracing::warn!(stream = %stream, error = %e, "origin: could not record clip request");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not record the request").into_response()
        }
    }
}

/// Credential check for the clip surface, independent of `require_origin_token`.
///
/// `require_origin_token` is the *read* gate for segments, and it is off by
/// default so a CDN can pull a public feed. The clip routes are a different
/// animal: `POST` commissions decode-and-encode work on the edge that cut the
/// feed, and `DELETE` destroys an operator's exported footage. Hanging either
/// off a switch designed to be open makes a default-configuration relay an
/// unauthenticated work queue and an unauthenticated delete button.
///
/// So this always demands a credential, and fails closed when there is no
/// secret to check one against — the same posture `require_clip_ingest` takes
/// on the write side. Either credential passes: the edge polls this surface
/// with its ingest token, the browser and the portal with a viewer token.
fn require_clip_credential(
    st: &Arc<DistributionState>,
    stream: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<(), Response> {
    let rt = st.control.load();
    let Some(ref secret) = rt.token_secret else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "clip access is unconfigured on this relay",
        )
            .into_response());
    };
    if super::bearer(headers)
        .and_then(|t| token::verify_ingest_token(secret, stream, &t).ok())
        .is_some()
    {
        return Ok(());
    }
    super::check_viewer_token(st, stream, headers, query)
}

/// The same posture for the two verbs only the edge may use: upload a finished
/// clip, and declare one impossible.
///
/// Deliberately **not** gated on `require_ingest_token` the way a segment PUT
/// is. That flag exists so an operator can run an origin whose ingest is
/// protected by something else — a private network, a fronting proxy — and
/// turning it off is a statement about *segments*. The clip surface is not
/// reachable at all without a token secret (`require_clip_credential` refuses
/// the request that creates the record), so demanding one here costs a
/// correctly-configured relay nothing and closes the case where an operator
/// relaxed ingest and silently opened a write surface that stores
/// operator-owned media under viewer-chosen names.
fn require_clip_ingest(
    st: &Arc<DistributionState>,
    stream: &str,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let rt = st.control.load();
    let Some(ref secret) = rt.token_secret else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "clip access is unconfigured on this relay",
        )
            .into_response());
    };
    if super::bearer(headers)
        .and_then(|t| token::verify_ingest_token(secret, stream, &t).ok())
        .is_some()
    {
        return Ok(());
    }
    Err((StatusCode::UNAUTHORIZED, "ingest token required").into_response())
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
    if let Err(resp) = require_clip_credential(&st, &stream, &headers, query.as_deref()) {
        return resp;
    }
    // `read_dir` plus a `read` and a `stat` per record, on a route the edge
    // polls every five seconds per flow and every open portal tab polls while a
    // cut is pending — so it is fan-out times poll rate of blocking file
    // operations on the runtime that also forwards live media.
    let origin = st.origin.clone();
    let listed = tokio::task::spawn_blocking(move || origin.list_clips(&stream)).await;
    match listed {
        Ok(clips) => (
            [(header::CACHE_CONTROL, "no-store")],
            axum::Json(clips),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "origin: clip listing task failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not list the clips").into_response()
        }
    }
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
    if let Err(resp) = require_clip_credential(&st, &stream, &headers, query.as_deref()) {
        return resp;
    }
    let Some((mut fh, len)) = st.origin.open_clip(&stream, name).await else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            "clip not ready",
        )
            .into_response();
    };

    // Ranges, because a 250 MB download over a contribution uplink is exactly
    // the kind that gets interrupted, and without this every retry starts again
    // from zero. The browser asks; there is no reason to make it start over.
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|raw| parse_single_range(raw, len));
    let (start, end, partial) = match range {
        // Present and satisfiable.
        Some(Some((s, e))) => (s, e, true),
        // Present and not satisfiable: say so rather than quietly serving the
        // whole file, which is how a resumed download ends up corrupt.
        Some(None) => {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [
                    (header::CONTENT_RANGE, format!("bytes */{len}")),
                    (header::CACHE_CONTROL, "no-store".to_string()),
                ],
                "that range is not in this clip",
            )
                .into_response();
        }
        None => (0, len.saturating_sub(1), false),
    };
    let count = end.saturating_sub(start).saturating_add(1).min(len);

    if start > 0 {
        use tokio::io::AsyncSeekExt;
        if fh.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "could not read the clip").into_response();
        }
    }
    // Streamed off the file, not collected: see `OriginStore::open_clip`.
    let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(
        tokio::io::AsyncReadExt::take(fh, count),
    ));

    let mut resp = Response::builder()
        .status(if partial {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(header::CONTENT_TYPE, "video/mp4")
        // The name the operator asked for, on their disk.
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{file}\""),
        )
        .header(header::CACHE_CONTROL, "private, max-age=300")
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, count);
    if partial {
        resp = resp.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
    }
    resp.body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// One byte range out of a `Range:` header, resolved against the clip's length.
///
/// `Some((first, last))` inclusive, or `None` when the header names something
/// this file cannot satisfy. Deliberately single-range only: a multipart
/// response is a lot of machinery for something no browser asks a video file
/// for, and answering the whole file to a multi-range request is the wrong
/// answer rather than a lesser one — so anything with a comma is refused.
fn parse_single_range(raw: &str, len: u64) -> Option<(u64, u64)> {
    let spec = raw.strip_prefix("bytes=")?.trim();
    if spec.contains(',') {
        return None;
    }
    let (first, last) = spec.split_once('-')?;
    let (start, end) = match (first.trim(), last.trim()) {
        // `bytes=-N`: the last N bytes.
        ("", suffix) => {
            let n: u64 = suffix.parse().ok()?;
            if n == 0 || len == 0 {
                return None;
            }
            (len.saturating_sub(n), len - 1)
        }
        (s, "") => (s.parse().ok()?, len.checked_sub(1)?),
        (s, e) => (s.parse().ok()?, e.parse::<u64>().ok()?.min(len.saturating_sub(1))),
    };
    (start <= end && start < len).then_some((start, end))
}

/// `PUT /origin/{stream}/clips/{file}` — the edge hands over a finished clip.
///
/// Ingest-gated unconditionally — see [`require_clip_ingest`]. This is a write
/// surface, and the only thing that should be writing here is the edge that cut
/// the clip.
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
    if let Err(resp) = require_clip_ingest(&st, &stream, &headers) {
        return resp;
    }
    // Nobody asked for this one — or asked and then cancelled, which is the
    // reachable case: a viewer deletes a record while the edge is mid-cut, and
    // the edge uploads it anyway from a listing it snapshotted. Storing it
    // leaves a `.mp4` with no record: invisible to the listing, to both clip
    // ceilings and to the portal's delete button, but not to the disk. The 404
    // also tells the exporter to stop, which nothing else did.
    //
    // Both this and the budget below walk the clips directory, so they share
    // one hop onto the blocking pool rather than doing it on a worker.
    let origin = st.origin.clone();
    let (for_stream, for_name) = (stream.clone(), name.to_string());
    let checked = tokio::task::spawn_blocking(move || {
        (
            origin.clip_record_exists(&for_stream, &for_name),
            origin.clip_budget_used(&for_stream),
        )
    })
    .await;
    let Ok((have_record, used)) = checked else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not store the clip").into_response();
    };
    if !have_record {
        tracing::info!(
            stream = %stream, clip = %name,
            "origin: refusing a clip upload nothing has a record for"
        );
        return (StatusCode::NOT_FOUND, "no such clip request").into_response();
    }
    // The per-stream ceiling, enforced where the bytes arrive rather than only
    // where they are asked for. The request-time check works from an estimate;
    // this one works from the scale.
    let room = MAX_CLIP_BYTES_PER_STREAM.saturating_sub(used);
    if room == 0 {
        tracing::warn!(stream = %stream, clip = %name, used, "origin: stream is over its clip budget");
        return (StatusCode::INSUFFICIENT_STORAGE, "this feed's clips are over their limit")
            .into_response();
    }
    let ceiling = (MAX_CLIP_BYTES as u64).min(room);
    match st
        .origin
        .put_clip_streaming(&stream, name, body, ceiling)
        .await
    {
        Ok(bytes) => {
            tracing::info!(stream = %stream, clip = %name, bytes, "origin: clip stored");
            (StatusCode::CREATED, "stored").into_response()
        }
        // Which limit bound it is decided by which one was smaller: saying
        // "too large" to a clip that is a normal size but does not fit the
        // feed's remaining budget sends the operator to shorten a clip when
        // what they need to do is delete one.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData && ceiling < MAX_CLIP_BYTES as u64 => {
            tracing::warn!(stream = %stream, clip = %name, used, "origin: clip would cross the stream's budget");
            (StatusCode::INSUFFICIENT_STORAGE, "this feed's clips are over their limit")
                .into_response()
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
/// Gated like the download and never left open: clips belong to the session, so
/// anyone who may watch the feed may tidy them — but a credential is always
/// required, because this is the origin's one destructive verb and it must not
/// ride a flag whose default is off. Without it the only way to reclaim clip
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
    if let Err(resp) = require_clip_credential(&st, &stream, &headers, query.as_deref()) {
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
    if let Err(resp) = require_clip_ingest(&st, &stream, &headers) {
        return resp;
    }
    let origin = st.origin.clone();
    let (for_stream, for_name, reason) = (stream.clone(), name.to_string(), body.reason.clone());
    let marked =
        tokio::task::spawn_blocking(move || origin.fail_clip(&for_stream, &for_name, &reason))
            .await;
    let Ok(marked) = marked else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not record it").into_response();
    };
    match marked {
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

    /// Backdate a file, so a test can reach a grace period measured in hours.
    fn age(path: &std::path::Path, by: Duration) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        let when = std::time::SystemTime::now() - by;
        f.set_times(std::fs::FileTimes::new().set_modified(when)).unwrap();
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

    /// And they outlive an ingest gap, which is not the same test.
    ///
    /// `clips_are_not_evicted_with_the_segments` exercises `evict`. The branch
    /// that actually deleted clips is in `sweep`: a stream idle past
    /// `retention + idle_grace` had its segment queue drained and was then
    /// handed to `remove_stream`, a `remove_dir_all` of the whole stream
    /// directory — `clips/` with it. Nothing about that requires the session to
    /// be over: an edge restart, a stopped flow or a satellite drop longer than
    /// the window is enough, and a clip write does not refresh `last_put_ms`,
    /// so exporting cannot keep the stream alive either. The operator loses the
    /// export with one `tracing::info!` and no event.
    #[tokio::test]
    async fn an_idle_sweep_retires_a_stream_without_taking_its_clips() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk {
                    at: "2026-09-07T23:06:53.200Z".into(),
                    name: "goal".into(),
                }],
            },
        )
        .unwrap();
        s.put_clip("feed", "goal", b"clip").await.unwrap();
        put_seg(&s, "feed", "seg-00000.m4s", 64).await;

        // Short enough that one sleep puts the stream past retention + grace.
        s.set_default_policy(OriginPolicy {
            retention: Duration::from_millis(5),
            max_bytes_per_stream: 1 << 30,
            min_segments: 0,
            idle_grace: Duration::from_millis(5),
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        s.sweep().await;

        assert!(
            s.read_clip("feed", "goal").await.is_some(),
            "the idle sweep deleted an exported clip"
        );
        assert_eq!(s.list_clips("feed").len(), 1, "the clip's record went with it");
        assert!(
            s.get("feed", "seg-00000.m4s").await.is_none(),
            "the media should still be reclaimed — only the clips survive"
        );
    }

    /// An abandoned upload leaves nothing behind.
    ///
    /// Only the over-size branch used to remove the temp file. A body stream
    /// that errors — which is what the edge's sixty-second client timeout looks
    /// like from here — returned through `?` and left up to 256 MiB in
    /// `clips/`, where it is in no listing (which walks `*.json`), no byte
    /// total, no eviction queue, is skipped by the restart debris sweep and
    /// untouched by `delete_clip`. The disk still holds it, so the free-space
    /// floor pays for it out of recorded footage.
    #[tokio::test]
    async fn an_abandoned_clip_upload_leaves_no_part_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        let dir = tmp.path().join("origin").join("feed").join(CLIPS_DIR);

        let failing = axum::body::Body::from_stream(futures_util::stream::once(async {
            Err::<Bytes, std::io::Error>(std::io::Error::other("the client went away"))
        }));
        let err = s
            .put_clip_streaming("feed", "goal", failing, 1 << 20)
            .await
            .expect_err("a broken body must not report success");
        assert!(err.to_string().contains("client went away"));

        let left: Vec<_> = std::fs::read_dir(&dir)
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "the abandoned upload left {left:?} behind");

        // And the size ceiling still cleans up, which is the one path that
        // always did.
        let big = axum::body::Body::from_stream(futures_util::stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from(vec![0u8; 64]))
        }));
        let _ = s.put_clip_streaming("feed", "goal", big, 8).await.unwrap_err();
        let left: Vec<_> = std::fs::read_dir(&dir)
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "the over-size upload left {left:?} behind");
    }

    /// The relay reclaims the clip debris only it can see.
    ///
    /// Three kinds, none of which anything else in this file can reach: a
    /// `.part` from an upload nobody is making any more, media with no record
    /// beside it (a viewer deleting a record mid-cut used to produce one per
    /// cancelled clip), and — as a backstop under a manager that never comes
    /// back with its `drop_origin_streams` — anything at all past
    /// `CLIP_MAX_AGE`. A live clip must survive all three passes.
    #[tokio::test]
    async fn the_relay_reclaims_clip_debris_it_alone_can_see() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk { at: "2026-09-09T10:00:00Z".into(), name: "goal".into() }],
            },
        )
        .unwrap();
        s.put_clip("feed", "goal", b"kept").await.unwrap();

        let dir = tmp.path().join("origin").join("feed").join(CLIPS_DIR);
        let stale_part = dir.join("interrupted.7-0.mp4.part");
        let orphan = dir.join("cancelled.mp4");
        let ancient = dir.join("forgotten.json");
        std::fs::write(&stale_part, b"half an upload").unwrap();
        std::fs::write(&orphan, b"nobody asked").unwrap();
        std::fs::write(&ancient, b"{}").unwrap();
        // Backdated rather than waited for: the grace is an hour and the
        // backstop a week.
        age(&stale_part, PART_GRACE * 2);
        age(&orphan, PART_GRACE * 2);
        age(&ancient, CLIP_MAX_AGE * 2);

        s.reclaim_clip_debris().await;

        assert!(!stale_part.exists(), "a stale .part was not reclaimed");
        assert!(!orphan.exists(), "clip media with no record was not reclaimed");
        assert!(!ancient.exists(), "a clip past the backstop was not reclaimed");
        assert!(
            s.read_clip("feed", "goal").await.is_some(),
            "the reclaim took a live clip with the debris"
        );
        assert_eq!(s.list_clips("feed").len(), 1);
    }

    /// Shared marks get the clips' backstop, and only where the clips do.
    ///
    /// A list goes once nobody has changed it for `CLIP_MAX_AGE` and nothing
    /// is ingesting the stream — a session whose manager never came back with
    /// its `drop_origin_streams`. It stays while the stream is live however old
    /// it is, stays while it is young, and taking it never takes a clip.
    #[tokio::test]
    async fn a_forgotten_marks_list_is_reclaimed_and_no_other() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        let root = tmp.path().join("origin");
        let list = |stream: &str| root.join(stream).join(MARKS_DIR).join(marks::MARKS_FILE);
        let write = |stream: &str| {
            std::fs::create_dir_all(list(stream).parent().unwrap()).unwrap();
            std::fs::write(list(stream), br#"{"epoch":"e","rev":1,"marks":[]}"#).unwrap();
        };

        write("gone");
        age(&list("gone"), CLIP_MAX_AGE * 2);
        write("fresh");
        put_seg(&s, "live", "seg-00001.m4s", 8).await;
        write("live");
        age(&list("live"), CLIP_MAX_AGE * 2);
        s.record_clip_requests(
            "cut",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk { at: "2026-09-09T10:00:00Z".into(), name: "goal".into() }],
            },
        )
        .unwrap();
        s.put_clip("cut", "goal", b"clip").await.unwrap();
        write("cut");
        age(&list("cut"), CLIP_MAX_AGE * 2);

        s.reclaim_clip_debris().await;

        assert!(
            !root.join("gone").exists(),
            "a forgotten marks list, and the directory it alone held, outlived the backstop"
        );
        assert!(
            list("fresh").exists(),
            "a marks list inside the backstop was reclaimed"
        );
        assert!(
            list("live").exists(),
            "the backstop took the marks of a stream that is still ingesting"
        );
        assert!(
            !root.join("cut").join(MARKS_DIR).exists(),
            "a forgotten marks list survived because a clip sat beside it"
        );
        assert!(
            s.read_clip("cut", "goal").await.is_some(),
            "reclaiming the marks took a live clip with them"
        );
    }

    /// Every place that tells session files from media asks the same
    /// question, and both answers are pinned here: adoption on restart deletes
    /// whatever the answer leaves out.
    #[test]
    fn clips_and_marks_are_the_session_subdirectories_and_nothing_else() {
        use std::ffi::OsStr;
        assert!(is_session_subdir(OsStr::new(CLIPS_DIR)));
        assert!(is_session_subdir(OsStr::new(MARKS_DIR)));
        for other in ["seg-00001.m4s", "marks.json", "clips.mp4", "Marks", ""] {
            assert!(!is_session_subdir(OsStr::new(other)), "{other}");
        }
    }

    /// A clips-only directory nobody is ingesting is not permanent.
    ///
    /// `clips_dir` never `ensure`s the stream, and both `sweep` and
    /// `enforce_free_space` iterate the tracked map, which such a directory
    /// never joins — and adoption skips it on every restart. Without a pass
    /// over the root it was the store's one unreclaimable shape.
    #[tokio::test]
    async fn an_emptied_clip_directory_is_not_left_on_disk_for_ever() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 5,
                post_secs: 5,
                clips: vec![ClipAsk { at: "2026-09-09T10:00:00Z".into(), name: "goal".into() }],
            },
        )
        .unwrap();
        assert!(s.delete_clip("feed", "goal").await);

        let stream_dir = tmp.path().join("origin").join("feed");
        assert!(stream_dir.exists(), "fixture: the directory should still be there");
        s.reclaim_clip_debris().await;
        assert!(
            !stream_dir.exists(),
            "an emptied, untracked clip directory was left behind"
        );
    }

    /// A batch in flight is charged against the budget that admits the next.
    ///
    /// The ceiling was tested as `bytes >= limit` against bytes already on
    /// disk, and `list_clips` reports a pending record as zero bytes — so a
    /// batch already commissioned was invisible to the check meant to decide
    /// whether another could be, and the comparison could not fire until the
    /// limit had already been crossed. Two permitted fifty-mark requests put
    /// 25 GiB on a stream whose stated ceiling is 4 GiB, and clips are outside
    /// the eviction queue, so the free-space floor then paid for them by
    /// deleting recorded footage across every other stream on the relay —
    /// verbatim the outcome this constant exists to prevent.
    #[tokio::test]
    async fn clips_asked_for_but_not_yet_cut_still_count_against_the_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);

        fn batch(n: usize) -> ClipRequest {
            ClipRequest {
                pre_secs: 30,
                post_secs: 30,
                clips: (0..n)
                    .map(|i| ClipAsk {
                        at: format!("2026-09-09T10:{i:02}:00Z"),
                        name: format!("mark {i}"),
                    })
                    .collect(),
            }
        }

        // A full-length clip is charged the per-clip ceiling, so the budget is
        // this many of them and no more.
        let per_clip = estimated_clip_bytes(30, 30);
        let fits = (MAX_CLIP_BYTES_PER_STREAM / per_clip) as usize;
        assert!(fits > 1 && fits < MAX_CLIPS_PER_STREAM, "fixture: {fits} is not a useful bound");

        s.admit_clips("feed", &batch(fits)).expect("a batch inside the budget must be admitted");
        // Nothing has been cut, so the *landed* total is still zero — which is
        // exactly what used to make the next request look free.
        assert_eq!(s.clip_usage("feed").1, 0, "fixture: nothing should have landed yet");
        assert!(s.clip_budget_used("feed") >= MAX_CLIP_BYTES_PER_STREAM - per_clip);

        match s.admit_clips("feed", &batch(1)) {
            Err(ClipRefusal::OverBudget { would_use, limit }) => {
                assert!(would_use > limit, "refused without being over: {would_use} vs {limit}");
            }
            Err(other) => panic!("refused for the wrong reason: {other:?}"),
            Ok(_) => panic!("a stream already at its clip budget admitted another full-length clip"),
        }
    }

    /// A name collision is refused, not resolved by overwriting.
    ///
    /// After nine suffixes the search used to fall back to the bare name — one
    /// it had just proved belonged to a different mark — and the write replaced
    /// that mark's record while its `.mp4` stayed put. The new record then read
    /// as ready with the old clip's bytes: one export silently lost, and the
    /// other offered to the operator under the wrong label, with the exporter
    /// skipping it for ever because it already read as done.
    #[tokio::test]
    async fn a_name_that_cannot_be_freed_is_refused_rather_than_reused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);

        // Ten distinct marks, one label. The first nine take `Goal` and
        // `Goal (2)`..`Goal (9)`.
        for i in 0..9 {
            s.record_clip_requests(
                "feed",
                &ClipRequest {
                    pre_secs: 5,
                    post_secs: 5,
                    clips: vec![ClipAsk {
                        at: format!("2026-09-09T1{i}:00:00Z"),
                        name: "Goal".into(),
                    }],
                },
            )
            .expect("the first nine have somewhere to go");
        }
        s.put_clip("feed", "Goal", b"the first mark's media").await.unwrap();

        let err = s
            .record_clip_requests(
                "feed",
                &ClipRequest {
                    pre_secs: 5,
                    post_secs: 5,
                    clips: vec![ClipAsk { at: "2026-09-09T23:00:00Z".into(), name: "Goal".into() }],
                },
            )
            .expect_err("a tenth mark on a full name must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        // And the first mark's record is exactly as it was.
        let first = s
            .list_clips("feed")
            .into_iter()
            .find(|c| c.name == "Goal")
            .expect("the first record must still be there");
        assert_eq!(first.at, "2026-09-09T10:00:00Z", "the first mark's record was overwritten");
        assert!(first.ready);
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
        s.put_clip("feed", "spare", &[0u8; 2048]).await.unwrap();

        let (count, bytes) = s.clip_usage("feed");
        assert_eq!((count, bytes), (1, 2048));

        assert!(s.delete_clip("feed", "spare").await);
        assert_eq!(s.clip_usage("feed"), (0, 0));
        assert!(s.read_clip("feed", "spare").await.is_none());
        assert!(!s.delete_clip("feed", "spare").await, "deleting twice must not claim success");
    }

    /// A retired stream can still be removed, clips and all.
    ///
    /// `retire_stream` takes the stream out of the tracking map and leaves its
    /// `clips/` directory behind. Every later removal — the operator deleting
    /// the session, and the 24-hour expiry sweep — therefore arrives at a
    /// stream the store no longer tracks. Returning early on that left the
    /// clips on disk for ever, which is to say the retention this feature
    /// exists to implement never actually expired anything.
    ///
    /// Found on the rig by a healthcheck noticing a stream directory that
    /// served an empty window; 38 MB of clips belonging to a session deleted
    /// half an hour earlier.
    #[tokio::test]
    async fn a_retired_stream_is_still_removable() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp, 0);

        s.put("feed", "seg-00000.m4s", axum::body::Bytes::from_static(b"media"))
            .await
            .unwrap();
        s.record_clip_requests(
            "feed",
            &ClipRequest {
                pre_secs: 3,
                post_secs: 5,
                clips: vec![ClipAsk { at: "2026-09-09T10:00:00Z".into(), name: "goal".into() }],
            },
        )
        .unwrap();
        s.put_clip("feed", "goal", &[7u8; 64]).await.unwrap();

        let dir = tmp.path().join("origin").join("feed");
        assert!(dir.exists(), "the stream should exist to begin with");

        // The game ends: media goes, clips stay, and the store stops tracking it.
        s.retire_stream("feed").await;
        assert!(dir.join("clips").exists(), "retiring took the clips with it");
        assert!(
            !dir.join("seg-00000.m4s").exists(),
            "retiring left the media behind"
        );

        // Retention runs out. This is the call that used to do nothing.
        s.remove_stream("feed").await;
        assert!(
            !dir.exists(),
            "a retired stream's directory survived removal, so its clips would              never expire"
        );
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
        // Two, because the shape check wants two: a window is hundreds of
        // segments, and "one `.m4s` somewhere" was what let another packager's
        // output through.
        std::fs::write(root.join("feed-a/seg-00001.m4s"), b"xx").unwrap();
        std::fs::write(root.join("feed-a/seg-00002.m4s"), b"yy").unwrap();
        std::fs::write(root.join("feed-a/init.mp4"), b"i").unwrap();
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

    /// Another packager's output is the shape of a store, and is not one.
    ///
    /// `/srv/www/dash/<event>/` holding `init.mp4` beside numbered `.m4s`
    /// segments passes every structural test — all directories at the top, only
    /// media extensions below — and the "at least one `.m4s`" clause it used to
    /// end on was satisfied by the first file it found. Adopting it enrols
    /// every file with its real mtime, so the first sweep evicts everything
    /// already past retention and the idle sweep `remove_dir_all`s the rest
    /// about two minutes after the relay starts.
    ///
    /// What separates the two is the file names: this store is only ever
    /// filled by bilbycast-edge's packager, which writes `seg-%05d.m4s`.
    #[tokio::test]
    async fn another_packagers_cmaf_tree_is_not_mistaken_for_a_store() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dash");
        std::fs::create_dir_all(root.join("cup-final")).unwrap();
        std::fs::write(root.join("cup-final/init.mp4"), b"init").unwrap();
        std::fs::write(root.join("cup-final/chunk-stream0-00001.m4s"), b"aa").unwrap();
        std::fs::write(root.join("cup-final/chunk-stream0-00002.m4s"), b"bb").unwrap();

        let err = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(60),
            max_bytes_per_stream: 1 << 30,
            min_segments: 8,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .map(|_| ())
        .expect_err("a foreign CMAF tree must not be adopted");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(root.join("cup-final/chunk-stream0-00001.m4s").exists());
        assert!(!root.join(ORIGIN_MARKER).exists(), "a refused directory must not be claimed");
    }

    /// A media archive with one stray segment in it is the same trap.
    ///
    /// Folders of `.mp4` and `.jpg` beside a single grab that happens to be an
    /// `.m4s`: every extension is on the permitted list and the old clause
    /// needed exactly one of them. Requiring every file-bearing directory to
    /// carry a segment of ours refuses it on the two that do not.
    #[tokio::test]
    async fn a_media_archive_with_one_stray_segment_still_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("media");
        std::fs::create_dir_all(root.join("clips-2024")).unwrap();
        std::fs::create_dir_all(root.join("stills")).unwrap();
        std::fs::create_dir_all(root.join("grabs")).unwrap();
        std::fs::write(root.join("clips-2024/wedding.mp4"), b"m").unwrap();
        std::fs::write(root.join("stills/one.jpg"), b"j").unwrap();
        std::fs::write(root.join("grabs/seg-00001.m4s"), b"s").unwrap();

        let err = OriginStore::new(OriginConfig {
            root: root.clone(),
            retention: Duration::from_secs(60),
            max_bytes_per_stream: 1 << 30,
            min_segments: 8,
            min_free_bytes: 0,
            idle_grace: Duration::from_millis(80),
        })
        .map(|_| ())
        .expect_err("a media archive must not be adopted");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(root.join("clips-2024/wedding.mp4").exists());
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