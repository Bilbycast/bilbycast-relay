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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::put;
use axum::Router;
use dashmap::DashMap;

use super::{token, DistributionState};

/// A stored HTTP object (manifest, segment, or part).
pub struct StoredObject {
    pub bytes: Bytes,
    pub content_type: &'static str,
    pub seq: u64,
    pub is_segment: bool,
}

/// Per-stream object store.
struct StreamOrigin {
    objects: DashMap<String, Arc<StoredObject>>,
}

impl StreamOrigin {
    fn new() -> Self {
        Self { objects: DashMap::new() }
    }
}

/// The origin store: a registry of per-stream object caches with a bounded
/// sliding window of media segments.
pub struct OriginStore {
    window: usize,
    streams: DashMap<String, Arc<StreamOrigin>>,
    seq: AtomicU64,
}

impl OriginStore {
    pub fn new(window_segments: usize) -> Self {
        Self {
            window: window_segments.max(1),
            streams: DashMap::new(),
            seq: AtomicU64::new(0),
        }
    }

    fn ensure(&self, stream: &str) -> Arc<StreamOrigin> {
        if let Some(s) = self.streams.get(stream) {
            return s.clone();
        }
        self.streams
            .entry(stream.to_string())
            .or_insert_with(|| Arc::new(StreamOrigin::new()))
            .clone()
    }

    /// Store an object. Manifests overwrite in place and are always kept;
    /// media segments/parts join the sliding window and evict the oldest
    /// beyond `window`.
    pub fn put(&self, stream: &str, file: &str, bytes: Bytes) {
        let ct = content_type_for(file);
        let is_segment = is_media_segment(file);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let origin = self.ensure(stream);
        origin.objects.insert(
            file.to_string(),
            Arc::new(StoredObject { bytes, content_type: ct, seq, is_segment }),
        );

        if is_segment {
            self.evict(&origin);
        }
    }

    /// Evict the oldest media segments beyond the window. Scans the map for
    /// the lowest-seq segment repeatedly (window ≤ 64, cheap) — keeps the
    /// store lock-free (no ordering queue / Mutex).
    fn evict(&self, origin: &StreamOrigin) {
        loop {
            let seg_count = origin.objects.iter().filter(|e| e.value().is_segment).count();
            if seg_count <= self.window {
                break;
            }
            // Find the oldest (min seq) segment.
            let oldest = origin
                .objects
                .iter()
                .filter(|e| e.value().is_segment)
                .min_by_key(|e| e.value().seq)
                .map(|e| e.key().clone());
            match oldest {
                Some(k) => {
                    origin.objects.remove(&k);
                }
                None => break,
            }
        }
    }

    pub fn get(&self, stream: &str, file: &str) -> Option<Arc<StoredObject>> {
        self.streams.get(stream)?.objects.get(file).map(|o| o.clone())
    }

    pub fn remove_stream(&self, stream: &str) {
        self.streams.remove(stream);
    }

    /// Total bytes currently held across all streams (telemetry).
    pub fn total_bytes(&self) -> u64 {
        self.streams
            .iter()
            .map(|s| s.objects.iter().map(|o| o.bytes.len() as u64).sum::<u64>())
            .sum()
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
    } else {
        "application/octet-stream"
    }
}

/// Is this a media segment/part (evictable), vs a manifest (kept)?
fn is_media_segment(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.ends_with(".m4s") || lower.ends_with(".ts") || lower.ends_with(".cmfv")
        || lower.ends_with(".cmfa") || lower.ends_with(".cmf")
        || (lower.ends_with(".mp4") && !lower.contains("init"))
}

/// A manifest object (never cached by intermediaries — it changes constantly).
fn is_manifest(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.ends_with(".m3u8") || lower.ends_with(".mpd")
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
pub fn routes() -> Router<Arc<DistributionState>> {
    Router::new()
        .route("/origin/{stream}/{file}", put(origin_put).get(origin_get))
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

    // Ingest is a write surface — token-gate it unless explicitly disabled.
    if st.config.require_ingest_token {
        if let Some(ref secret) = st.config.token_secret {
            let tok = bearer_or_query(&headers, None);
            match tok.and_then(|t| token::verify_ingest_token(secret, &stream, &t).ok()) {
                Some(()) => {}
                None => return (StatusCode::UNAUTHORIZED, "ingest token required").into_response(),
            }
        } else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "ingest token gate misconfigured").into_response();
        }
    }

    if body.len() > 64 * 1024 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "object too large").into_response();
    }

    st.origin.put(&stream, &file, body);
    StatusCode::CREATED.into_response()
}

/// `GET /origin/{stream}/{file}` — serve a cached object to a player/CDN.
async fn origin_get(
    State(st): State<Arc<DistributionState>>,
    Path((stream, file)): Path<(String, String)>,
) -> Response {
    let Some(stream) = super::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    if !valid_object_name(&file) {
        return (StatusCode::BAD_REQUEST, "invalid object name").into_response();
    }
    match st.origin.get(&stream, &file) {
        Some(obj) => {
            let cache = if is_manifest(&file) {
                "no-cache, no-store, must-revalidate"
            } else {
                // Segments are immutable; let CDNs/browsers cache them.
                "public, max-age=31536000, immutable"
            };
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, obj.content_type.to_string()),
                    (header::CACHE_CONTROL, cache.to_string()),
                ],
                obj.bytes.clone(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Pull a token from `Authorization: Bearer` or a `?token=` query (parsed
/// from the raw query string — the extractor path doesn't split it for us).
fn bearer_or_query(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ") {
            return Some(t.to_string());
        }
    }
    query.and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("token=").map(|t| t.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_segments_beyond_window() {
        let store = OriginStore::new(3);
        for i in 0..6 {
            store.put("s", &format!("seg{i}.m4s"), Bytes::from(vec![0u8; 10]));
        }
        // Only the last 3 segments remain.
        assert!(store.get("s", "seg0.m4s").is_none());
        assert!(store.get("s", "seg2.m4s").is_none());
        assert!(store.get("s", "seg3.m4s").is_some());
        assert!(store.get("s", "seg5.m4s").is_some());
    }

    #[test]
    fn manifests_are_kept_and_overwritten() {
        let store = OriginStore::new(2);
        store.put("s", "index.m3u8", Bytes::from_static(b"#v1"));
        for i in 0..5 {
            store.put("s", &format!("seg{i}.m4s"), Bytes::from(vec![0u8; 4]));
        }
        // Manifest survives segment eviction.
        let m = store.get("s", "index.m3u8").unwrap();
        assert_eq!(&m.bytes[..], b"#v1");
        store.put("s", "index.m3u8", Bytes::from_static(b"#v2"));
        assert_eq!(&store.get("s", "index.m3u8").unwrap().bytes[..], b"#v2");
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

    #[test]
    fn init_segment_not_evicted_as_segment() {
        // init.mp4 must be treated as a kept object, not an evictable segment.
        assert!(!is_media_segment("init.mp4"));
        assert!(is_media_segment("seg1.m4s"));
    }
}
