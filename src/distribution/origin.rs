// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Tier 1 — LL-HLS / CMAF HTTP origin + in-memory sliding-window cache.
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
    /// stream. Wiped on startup — see [`OriginStore::new`].
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

impl OriginStore {
    /// Build the store, creating `root` and clearing anything already there.
    ///
    /// Segments from a previous run are dead weight: the manifests that
    /// referenced them lived in memory and died with the process, so nothing
    /// can address them. Wiping on startup is what stops the directory growing
    /// without bound across restarts.
    pub fn new(cfg: OriginConfig) -> std::io::Result<Self> {
        if cfg.root.exists() {
            std::fs::remove_dir_all(&cfg.root)?;
        }
        std::fs::create_dir_all(&cfg.root)?;
        let policy = arc_swap::ArcSwap::from_pointee(cfg.policy());
        Ok(Self {
            cfg,
            policy,
            stream_policy: DashMap::new(),
            streams: DashMap::new(),
            total_bytes: AtomicU64::new(0),
            started: Instant::now(),
        })
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
        let content_type = content_type_for(file);
        let origin = self.ensure(stream);
        origin.last_put_ms.store(self.now_ms(), Ordering::Relaxed);

        if !is_media_segment(file) {
            origin
                .kept
                .insert(file.to_string(), Arc::new(KeptObject { bytes, content_type }));
            return Ok(());
        }

        let len = bytes.len() as u64;
        let path = origin.dir.join(file);
        let tmp = origin.dir.join(format!("{file}.part"));
        tokio::fs::create_dir_all(&origin.dir).await?;
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &path).await?;

        let meta = Arc::new(SegmentMeta {
            path,
            content_type,
            len,
            stored_at: Instant::now(),
        });
        // Re-PUT under the same name must not double-count the bytes.
        if let Some(prev) = origin.segments.insert(file.to_string(), meta) {
            origin.bytes.fetch_sub(prev.len, Ordering::Relaxed);
            self.total_bytes.fetch_sub(prev.len, Ordering::Relaxed);
        } else {
            origin.order.lock().await.push_back(file.to_string());
        }
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
        let origin = self.streams.get(stream)?.clone();
        if let Some(kept) = origin.kept.get(file) {
            return Some(ObjectResponse {
                bytes: kept.bytes.clone(),
                content_type: kept.content_type,
            });
        }
        let meta = origin.segments.get(file).map(|m| m.clone())?;
        match tokio::fs::read(&meta.path).await {
            Ok(b) => Some(ObjectResponse {
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

    pub async fn remove_stream(&self, stream: &str) {
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

pub fn routes() -> Router<Arc<DistributionState>> {
    Router::new()
        .route("/origin/{stream}/{file}", put(origin_put).get(origin_get))
        .layer(DefaultBodyLimit::max(MAX_OBJECT_BYTES))
}

/// `PUT /origin/{stream}/{file}` — accept an edge CMAF/HLS upload.
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
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    if !valid_object_name(&file) {
        return (StatusCode::BAD_REQUEST, "invalid object name").into_response();
    }
    // Checked before the store is touched, so a rejected request cannot be
    // used to probe which streams or segments exist.
    if st.control.load().require_origin_token
        && let Err(resp) = super::check_viewer_token(&st, &stream, &headers, query.as_deref())
    {
        return resp;
    }
    match st.origin.get(&stream, &file).await {
        Some(obj) => {
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
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, obj.content_type.to_string()),
                    (header::CACHE_CONTROL, cache.to_string()),
                ],
                obj.bytes,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
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

    #[tokio::test]
    async fn startup_wipes_a_stale_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("s")).unwrap();
        std::fs::write(root.join("s/stale.m4s"), b"old").unwrap();

        // Segments from a previous run are unaddressable — the manifests that
        // referenced them died with the process.
        let s = store(&tmp, 8);
        assert!(!root.join("s/stale.m4s").exists());
        assert!(s.get("s", "stale.m4s").await.is_none());
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