//! What each viewer's player is seeing.
//!
//! The DVR page already measures its own playback — buffer ahead, stalls,
//! rebuffer holds, reconnects, hls.js's bandwidth estimate, dropped frames,
//! segment timings — and until now showed it only in its own debug panel. An
//! operator asking "is the picture good for the people watching" had to ask
//! the people. This is the surface the page reports to, every twenty seconds
//! or so, and the relay carries the latest report per viewer to the manager on
//! its health tick (`stats::ViewerMetricReport`).
//!
//! **A report is a claim the player makes about itself.** The relay checks the
//! viewer token — so only somebody who may watch the feed may report on it —
//! bounds every field, and keeps the freshest report per client. It does not
//! try to verify the numbers; a page that lies about its buffer gets a wrong
//! row on an operator's screen and nothing else.
//!
//! **The client id is the page's own, not the holder and not the token.** The
//! holder is never presented to the relay by design (it is what the portal
//! compares a renewal against), and a token cannot tell two devices apart. So
//! the page mints an id per load, reports under it here, and sends the same id
//! on its portal beat; the manager joins the two. A viewer on a one-off link
//! never beats, so their report stays anonymous — which is still a row with a
//! buffer reading, where before there was nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::distribution::DistributionState;
use crate::stats::ViewerMetricReport;

/// How often the page is asked to report. Carried in every reply, as the beat
/// cadence is, so a change reaches tabs already open.
pub const REPORT_SECS: u64 = 20;

/// A report older than this is a viewer who has gone: three missed reports.
pub const REPORT_TTL: Duration = Duration::from_secs(90);

/// Most clients remembered per stream. The route is token-gated, so this is
/// a bound on good behaviour, not a defence — but it is a map that grows with
/// every page load, and a page that reloads every second must not grow it
/// without limit.
pub const MAX_CLIENTS_PER_STREAM: usize = 500;

/// Most streams with reports. Reports arrive only for streams the relay
/// holds, so this is well above anything real.
pub const MAX_STREAMS: usize = 64;

/// Most reports carried in one health message, freshest first. The manager
/// stores the whole health blob per tick, so this is a bound on that write.
pub const MAX_REPORTED: usize = 200;

/// The largest body the route will read. A report is a few hundred bytes.
const MAX_REPORT_BYTES: usize = 8 * 1024;

/// The page's report, as sent. Every field defaults so a page from another
/// build — older, or newer with fields this relay does not know — still lands.
/// Numbers come in as `f64` and are rounded and clamped in [`ViewerReport::sanitize`]:
/// a page that sends `2.5` stalls, or `-1`, gets a row rather than a 422.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ViewerReport {
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub quality: String,
    #[serde(default)]
    pub auto_low: bool,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub playing: bool,
    #[serde(default)]
    pub holdback_s: f64,
    #[serde(default)]
    pub ahead_s: f64,
    #[serde(default)]
    pub behind_live_s: f64,
    #[serde(default)]
    pub bw_kbps: f64,
    #[serde(default)]
    pub stalls: f64,
    #[serde(default)]
    pub stalls_5m: f64,
    #[serde(default)]
    pub holds: f64,
    #[serde(default)]
    pub holds_5m: f64,
    #[serde(default)]
    pub hold_ms: f64,
    #[serde(default)]
    pub reconnects: f64,
    #[serde(default)]
    pub reconnects_5m: f64,
    #[serde(default)]
    pub decoded: f64,
    #[serde(default)]
    pub dropped: f64,
    #[serde(default)]
    pub seg_ttfb_ms: f64,
    #[serde(default)]
    pub seg_load_ms: f64,
    #[serde(default)]
    pub seg_kb: f64,
    #[serde(default)]
    pub up_s: f64,
    #[serde(default)]
    pub net_type: String,
    #[serde(default)]
    pub net_down_mbps: f64,
    #[serde(default)]
    pub net_rtt_ms: f64,
    #[serde(default)]
    pub ua: String,
}

/// Why a report was refused.
#[derive(Debug, PartialEq)]
pub enum MetricRefusal {
    /// No client id, or one outside `[A-Za-z0-9_-]{1,64}`.
    BadClient,
    /// The stream already holds [`MAX_CLIENTS_PER_STREAM`] clients and this
    /// is a new one.
    TooManyClients,
    /// The relay already holds reports for [`MAX_STREAMS`] streams and this is
    /// a new one.
    TooManyStreams,
}

fn clamp_u32(v: f64, max: u32) -> u32 {
    if !v.is_finite() || v < 0.0 {
        return 0;
    }
    v.round().min(f64::from(max)) as u32
}

fn clamp_f32(v: f64, max: f32) -> f32 {
    if !v.is_finite() || v < 0.0 {
        return 0.0;
    }
    (v.min(f64::from(max)) as f32 * 10.0).round() / 10.0
}

fn bounded_word(s: &str, max: usize, allowed: &[&str], fallback: &str) -> String {
    if allowed.contains(&s) {
        return s.to_string();
    }
    if allowed.is_empty() {
        let t: String = s
            .chars()
            .filter(|c| !c.is_control())
            .take(max)
            .collect();
        return t;
    }
    fallback.to_string()
}

/// Is this a client id the store will key on?
pub fn valid_client(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl ViewerReport {
    /// Bound every field. Nothing here can refuse: an out-of-range number is
    /// clamped, an unknown word becomes the fallback, text is cut. The client
    /// id is the one field that can refuse, and [`ViewerMetrics::record`]
    /// checks it.
    pub fn sanitize(self, stream: &str) -> ViewerMetricReport {
        ViewerMetricReport {
            stream: stream.to_string(),
            client: self.client,
            age_secs: 0,
            quality: bounded_word(&self.quality, 16, &["full", "balanced", "low"], "unknown"),
            auto_low: self.auto_low,
            mode: bounded_word(&self.mode, 16, &["live", "scrub", "jog", "shuttle"], "unknown"),
            playing: self.playing,
            holdback_s: clamp_f32(self.holdback_s, 600.0),
            ahead_s: clamp_f32(self.ahead_s, 3600.0),
            behind_live_s: clamp_f32(self.behind_live_s, 86_400.0),
            bw_kbps: clamp_u32(self.bw_kbps, 10_000_000),
            stalls: clamp_u32(self.stalls, 1_000_000),
            stalls_5m: clamp_u32(self.stalls_5m, 100_000),
            holds: clamp_u32(self.holds, 1_000_000),
            holds_5m: clamp_u32(self.holds_5m, 100_000),
            hold_ms: clamp_u32(self.hold_ms, u32::MAX),
            reconnects: clamp_u32(self.reconnects, 1_000_000),
            reconnects_5m: clamp_u32(self.reconnects_5m, 100_000),
            decoded: clamp_u32(self.decoded, u32::MAX),
            dropped: clamp_u32(self.dropped, u32::MAX),
            seg_ttfb_ms: clamp_u32(self.seg_ttfb_ms, 600_000),
            seg_load_ms: clamp_u32(self.seg_load_ms, 600_000),
            seg_kb: clamp_u32(self.seg_kb, 10_000_000),
            up_s: clamp_u32(self.up_s, u32::MAX),
            net_type: bounded_word(&self.net_type, 16, &[], ""),
            net_down_mbps: clamp_f32(self.net_down_mbps, 100_000.0),
            net_rtt_ms: clamp_u32(self.net_rtt_ms, 600_000),
            ua: bounded_word(&self.ua, 120, &[], ""),
        }
    }
}

struct Entry {
    report: ViewerMetricReport,
    received: Instant,
}

/// The freshest report per client per stream.
#[derive(Default)]
pub struct ViewerMetrics {
    inner: Mutex<HashMap<String, HashMap<String, Entry>>>,
}

impl ViewerMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Keep this report, replacing the client's previous one.
    pub fn record(&self, stream: &str, report: ViewerReport) -> Result<(), MetricRefusal> {
        self.record_at(stream, report, Instant::now())
    }

    fn record_at(
        &self,
        stream: &str,
        report: ViewerReport,
        now: Instant,
    ) -> Result<(), MetricRefusal> {
        if !valid_client(&report.client) {
            return Err(MetricRefusal::BadClient);
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Expired reports leave first, so a stream full of viewers who have
        // gone does not refuse the one who has just arrived.
        prune(&mut map, now);
        if !map.contains_key(stream) && map.len() >= MAX_STREAMS {
            return Err(MetricRefusal::TooManyStreams);
        }
        let clients = map.entry(stream.to_string()).or_default();
        if !clients.contains_key(&report.client) && clients.len() >= MAX_CLIENTS_PER_STREAM {
            return Err(MetricRefusal::TooManyClients);
        }
        let report = report.sanitize(stream);
        clients.insert(
            report.client.clone(),
            Entry {
                report,
                received: now,
            },
        );
        Ok(())
    }

    /// Every live report, freshest first, at most [`MAX_REPORTED`], with
    /// `age_secs` filled in. Prunes what has expired.
    pub fn snapshot(&self) -> Vec<ViewerMetricReport> {
        self.snapshot_at(Instant::now())
    }

    fn snapshot_at(&self, now: Instant) -> Vec<ViewerMetricReport> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut map, now);
        let mut all: Vec<(Duration, &Entry)> = map
            .values()
            .flat_map(|clients| clients.values())
            .map(|e| (now.saturating_duration_since(e.received), e))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.report.client.cmp(&b.1.report.client)));
        all.into_iter()
            .take(MAX_REPORTED)
            .map(|(age, e)| {
                let mut r = e.report.clone();
                r.age_secs = age.as_secs();
                r
            })
            .collect()
    }

    /// How many clients have a live report for `stream`.
    pub fn reporting(&self, stream: &str) -> usize {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut map, Instant::now());
        map.get(stream).map(|c| c.len()).unwrap_or(0)
    }
}

fn prune(map: &mut HashMap<String, HashMap<String, Entry>>, now: Instant) {
    map.retain(|_, clients| {
        clients.retain(|_, e| now.saturating_duration_since(e.received) < REPORT_TTL);
        !clients.is_empty()
    });
}

pub(super) fn routes() -> Router<Arc<DistributionState>> {
    Router::new()
        // A static segment, so it beats the `{file}` capture as `marks` does.
        .route(
            "/origin/{stream}/metrics",
            axum::routing::post(metrics_post),
        )
        .layer(DefaultBodyLimit::max(MAX_REPORT_BYTES))
}

/// `POST /origin/{stream}/metrics` — a player's report on its own playback.
///
/// The viewer token only, as for marks: the edge has no business here. The
/// reply carries the cadence, so it is the relay's to change. The peer
/// address is not read: see `ViewerMetricReport::age_secs`.
async fn metrics_post(
    State(st): State<Arc<DistributionState>>,
    Path(stream): Path<String>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    axum::Json(report): axum::Json<ViewerReport>,
) -> Response {
    let Some(stream) = crate::distribution::sanitize_stream_id(&stream) else {
        return (StatusCode::BAD_REQUEST, "invalid stream id").into_response();
    };
    if let Err(resp) = crate::distribution::check_viewer_token(&st, &stream, &headers, query.as_deref()) {
        return resp;
    }
    let no_store = [(header::CACHE_CONTROL, "no-store")];
    match st.viewer_metrics.record(&stream, report) {
        Ok(()) => (
            StatusCode::OK,
            no_store,
            axum::Json(serde_json::json!({ "next_report_secs": REPORT_SECS })),
        )
            .into_response(),
        Err(MetricRefusal::BadClient) => (
            StatusCode::BAD_REQUEST,
            no_store,
            "a report needs a client id of up to 64 letters, digits, '-' or '_'",
        )
            .into_response(),
        Err(MetricRefusal::TooManyClients) | Err(MetricRefusal::TooManyStreams) => (
            StatusCode::TOO_MANY_REQUESTS,
            no_store,
            "the relay is holding as many playback reports as it will",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(client: &str) -> ViewerReport {
        ViewerReport {
            client: client.into(),
            quality: "low".into(),
            mode: "live".into(),
            playing: true,
            ahead_s: 4.25,
            bw_kbps: 3200.0,
            stalls: 2.0,
            stalls_5m: 1.0,
            ..Default::default()
        }
    }

    #[test]
    fn the_freshest_report_per_client_is_what_is_published_with_its_age() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        m.record_at("show", report("a"), t0).unwrap();
        m.record_at("show", report("b"), t0 + Duration::from_secs(5)).unwrap();
        let mut again = report("a");
        again.stalls = 3.0;
        m.record_at("show", again, t0 + Duration::from_secs(20)).unwrap();

        let snap = m.snapshot_at(t0 + Duration::from_secs(30));
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].client, "a", "freshest first");
        assert_eq!(snap[0].age_secs, 10);
        assert_eq!(snap[0].stalls, 3, "the later report replaced the earlier");
        assert_eq!(snap[1].client, "b");
        assert_eq!(snap[1].age_secs, 25);
        assert_eq!(snap[0].stream, "show");
        assert_eq!(snap[0].ahead_s, 4.3, "rounded to a tenth");
    }

    #[test]
    fn a_report_older_than_the_ttl_is_gone_from_the_snapshot_and_the_count() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        m.record_at("show", report("a"), t0).unwrap();
        assert_eq!(m.snapshot_at(t0 + REPORT_TTL - Duration::from_secs(1)).len(), 1);
        assert_eq!(m.snapshot_at(t0 + REPORT_TTL).len(), 0);
        assert_eq!(m.inner.lock().unwrap().len(), 0, "an empty stream is dropped too");
    }

    #[test]
    fn numbers_are_clamped_and_words_are_held_to_the_known_set() {
        let r = ViewerReport {
            client: "c".into(),
            quality: "ultra".into(),
            mode: "live".into(),
            stalls: -4.0,
            bw_kbps: f64::INFINITY,
            ahead_s: f64::NAN,
            seg_ttfb_ms: 1e12,
            net_type: "4g\u{0}\u{7}".into(),
            ua: "x".repeat(500),
            ..Default::default()
        }
        .sanitize("show");
        assert_eq!(r.quality, "unknown");
        assert_eq!(r.mode, "live");
        assert_eq!(r.stalls, 0);
        assert_eq!(r.bw_kbps, 0);
        assert_eq!(r.ahead_s, 0.0);
        assert_eq!(r.seg_ttfb_ms, 600_000);
        assert_eq!(r.net_type, "4g");
        assert_eq!(r.ua.len(), 120);
    }

    #[test]
    fn a_bad_client_id_is_refused_and_the_caps_hold() {
        let m = ViewerMetrics::default();
        for bad in ["", "a b", "x".repeat(65).as_str(), "é"] {
            assert_eq!(m.record("show", report(bad)), Err(MetricRefusal::BadClient), "{bad:?}");
        }
        for i in 0..MAX_CLIENTS_PER_STREAM {
            m.record("show", report(&format!("c{i}"))).unwrap();
        }
        assert_eq!(m.record("show", report("one-more")), Err(MetricRefusal::TooManyClients));
        // A client already held may still report.
        m.record("show", report("c0")).unwrap();
        assert_eq!(m.reporting("show"), MAX_CLIENTS_PER_STREAM);

        for i in 1..MAX_STREAMS {
            m.record(&format!("s{i}"), report("c")).unwrap();
        }
        assert_eq!(m.record("another", report("c")), Err(MetricRefusal::TooManyStreams));
    }

    #[test]
    fn the_snapshot_is_bounded() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        for i in 0..(MAX_REPORTED + 50) {
            m.record_at(&format!("s{}", i % 8), report(&format!("c{i}")), t0 + Duration::from_millis(i as u64)).unwrap();
        }
        let snap = m.snapshot_at(t0 + Duration::from_secs(1));
        assert_eq!(snap.len(), MAX_REPORTED);
        assert_eq!(snap[0].client, format!("c{}", MAX_REPORTED + 49), "the newest survive the cut");
    }
}
