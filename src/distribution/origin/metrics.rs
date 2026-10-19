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
//! the page keeps one id per tab — in `sessionStorage`, per stream, minted
//! afresh only when none is stored or when the page arrives with a new claim's
//! token — reports under it here, and sends the same id on its portal beat;
//! the manager joins the two. A reload therefore replaces the tab's report
//! rather than leaving the last one behind under an id nobody holds. A viewer
//! on a one-off link never beats, so their report stays anonymous — which is
//! still a row with a buffer reading, where before there was nothing.
//!
//! **One token is a few devices, not a stream's worth.** A token holder can
//! name any client id it likes, and the peer is loopback for everyone, so the
//! only thing that tells one viewer's reports from another's is the credential
//! presented with them: at most [`MAX_CLIENTS_PER_TOKEN`] clients per viewer
//! token per stream, counted on a hash of its [`Signature`] — the one thing a
//! token has however its text is spelled. Past that a new client is refused,
//! never swapped for one already held.
//!
//! That bounds one minted token, not the person holding it. A portal claim,
//! an operator's Watch and every visit to a manager viewing link
//! (`/watch/{stream}?k=`) each mint a token of their own, so each visitor to a
//! link reports under their own; and somebody who can mint — a link's key or a
//! portal login in hand — can have a new token every second and fill a
//! stream's table after all. What no token holder can do is push another
//! stream's reports out of health (see [`ViewerMetrics::snapshot`]), or touch
//! playback: the page ignores a refused report.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use sha2::{Digest, Sha256};

use crate::distribution::token::Signature;
use crate::distribution::DistributionState;
use crate::stats::{ViewerEvent, ViewerMetricReport, ViewerMetricStream, ViewerMetricsSnapshot};

/// How often the page is asked to report. Carried in every reply, as the beat
/// cadence is, so a change reaches tabs already open.
pub const REPORT_SECS: u64 = 20;

/// A report older than this is a viewer who has gone: three missed reports.
pub const REPORT_TTL: Duration = Duration::from_secs(90);

/// Most clients remembered per stream. The route is token-gated, so this is
/// a bound on good behaviour, not a defence — but it is a map that grows with
/// every new tab, and a page that mints an id every second must not grow it
/// without limit.
pub const MAX_CLIENTS_PER_STREAM: usize = 500;

/// Most clients one viewer token holds a report for, per stream.
///
/// A tab keeps its id across reloads and a renewal brings a new token to the
/// same id, so a token is one device, or a tokened address opened on a laptop
/// and a tablet. Eight is room for that and no room to fill a stream's table,
/// or its share of [`MAX_REPORTED`], from one token — a `…?token=` address
/// passed around, or a script holding one, however it rewrites the text. It
/// does not bound whoever can mint tokens: see the module doc. A client past
/// it is refused, never swapped for one already held: the reports a stream
/// keeps stay those of the viewers who came first.
pub const MAX_CLIENTS_PER_TOKEN: usize = 8;

/// Most streams with reports. A report is accepted only for a stream the
/// origin is serving (`OriginStore::holds_stream`), so this is well above
/// anything real.
pub const MAX_STREAMS: usize = 64;

/// Most reports carried in one health message, shared fairly across streams
/// (see [`ViewerMetrics::snapshot`]).
///
/// What it bounds is the health message. A tablet's report is about 0.9 KB of
/// JSON and one with every field at its limit under 2 KB, so the list stays
/// under 400 KB: well inside the manager's 5 MB frame cap, and small enough
/// for a manager that predates the viewer roll, which keeps a relay's whole
/// health and sends it on to every open dashboard. Each stream's entry in
/// `viewer_metrics_streams` says how many reports it had and how many made
/// the list, so a cut is never read as viewers who are not reporting.
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
    pub v: f64,
    #[serde(default)]
    pub stalls_1m: f64,
    #[serde(default)]
    pub holds_1m: f64,
    #[serde(default)]
    pub reconnects_1m: f64,
    #[serde(default)]
    pub delay_pref_s: f64,
    #[serde(default)]
    pub catching_up: bool,
    #[serde(default)]
    pub events: Vec<ReportedEvent>,
    #[serde(default)]
    pub ua: String,
}

/// One event as the page sends it; bounded like everything else.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ReportedEvent {
    #[serde(default)]
    pub ago_s: f64,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub ahead_s: f64,
    #[serde(default)]
    pub goal_s: f64,
    #[serde(default)]
    pub ms: f64,
}

/// Most events kept from one report. The page sends eight; a page that sends
/// more has the oldest dropped.
pub const MAX_EVENTS: usize = 8;

/// Why a report was refused.
#[derive(Debug, PartialEq)]
pub enum MetricRefusal {
    /// No client id, or one outside `[A-Za-z0-9_-]{1,64}`.
    BadClient,
    /// The stream already holds [`MAX_CLIENTS_PER_STREAM`] clients and this
    /// is a new one.
    TooManyClients,
    /// The credential presented already holds reports for
    /// [`MAX_CLIENTS_PER_TOKEN`] other clients on this stream.
    TooManyForToken,
    /// The relay already holds reports for [`MAX_STREAMS`] streams and this is
    /// a new one.
    TooManyStreams,
}

/// What a client's reports are counted against: a hash of the signature of
/// the token they were presented with — one per credential, however its text
/// was spelled — so the store holds neither.
type TokenKey = [u8; 16];

fn token_key(signature: &[u8]) -> TokenKey {
    let digest = Sha256::digest(signature);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
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
            v: clamp_u32(self.v, 1000),
            stalls_1m: clamp_u32(self.stalls_1m, 100_000),
            holds_1m: clamp_u32(self.holds_1m, 100_000),
            reconnects_1m: clamp_u32(self.reconnects_1m, 100_000),
            delay_pref_s: clamp_f32(self.delay_pref_s, 600.0),
            catching_up: self.catching_up,
            events: {
                let skip = self.events.len().saturating_sub(MAX_EVENTS);
                self.events
                    .into_iter()
                    .skip(skip)
                    .map(|e| ViewerEvent {
                        ago_s: clamp_u32(e.ago_s, 86_400),
                        kind: bounded_word(
                            &e.kind,
                            16,
                            &["stall", "hold", "reconnect", "downgrade"],
                            "unknown",
                        ),
                        ahead_s: clamp_f32(e.ahead_s, 3600.0),
                        goal_s: clamp_f32(e.goal_s, 3600.0),
                        ms: clamp_u32(e.ms, 3_600_000),
                    })
                    .collect()
            },
            ua: bounded_word(&self.ua, 120, &[], ""),
        }
    }
}

struct Entry {
    report: ViewerMetricReport,
    received: Instant,
    token: TokenKey,
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

    /// Keep this report, replacing the client's previous one. `credential`
    /// is the signature of the viewer token it was presented with, already
    /// verified.
    pub fn record(
        &self,
        stream: &str,
        credential: &Signature,
        report: ViewerReport,
    ) -> Result<(), MetricRefusal> {
        self.record_at(stream, token_key(credential), report, Instant::now())
    }

    fn record_at(
        &self,
        stream: &str,
        token: TokenKey,
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
        // Counted rather than indexed: a stream holds at most 500 clients,
        // and this runs once per report, every twenty seconds per viewer.
        let others = clients
            .iter()
            .filter(|(client, e)| e.token == token && **client != report.client)
            .count();
        if others >= MAX_CLIENTS_PER_TOKEN {
            return Err(MetricRefusal::TooManyForToken);
        }
        let report = report.sanitize(stream);
        clients.insert(
            report.client.clone(),
            Entry {
                report,
                received: now,
                token,
            },
        );
        Ok(())
    }

    /// The live reports to carry on health, at most [`MAX_REPORTED`], with
    /// `age_secs` filled in, and per stream how many there were. Prunes what
    /// has expired.
    ///
    /// **Shared fairly across streams.** Each stream gets an equal share of
    /// the cap, and whatever a stream with fewer reports leaves goes to the
    /// busier ones, so one stream can never push another's out — a relay
    /// carries several groups' sessions, and one feed's audience, or one
    /// link's holder, must not blank the next feed's roll. Within a stream
    /// the freshest reports are listed first, and its entry in `streams` says
    /// how many were left out.
    pub fn snapshot(&self) -> ViewerMetricsSnapshot {
        self.snapshot_at(Instant::now())
    }

    fn snapshot_at(&self, now: Instant) -> ViewerMetricsSnapshot {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut map, now);
        // In stream order, so the same reports make the cut from one tick to
        // the next when nothing has changed.
        let mut streams: Vec<(&String, Vec<(Duration, &Entry)>)> = map
            .iter()
            .map(|(stream, clients)| {
                let mut live: Vec<(Duration, &Entry)> = clients
                    .values()
                    .map(|e| (now.saturating_duration_since(e.received), e))
                    .collect();
                live.sort_by(|a, b| {
                    a.0.cmp(&b.0)
                        .then_with(|| a.1.report.client.cmp(&b.1.report.client))
                });
                (stream, live)
            })
            .collect();
        streams.sort_by(|a, b| a.0.cmp(b.0));
        let lens: Vec<usize> = streams.iter().map(|(_, live)| live.len()).collect();
        let shares = fair_shares(&lens, MAX_REPORTED);
        let mut out = ViewerMetricsSnapshot::default();
        for ((stream, live), listed) in streams.into_iter().zip(shares) {
            out.streams.push(ViewerMetricStream {
                stream: stream.clone(),
                reporting: live.len(),
                listed,
            });
            out.reports
                .extend(live.into_iter().take(listed).map(|(age, e)| {
                    let mut r = e.report.clone();
                    r.age_secs = age.as_secs();
                    r
                }));
        }
        out
    }
}

/// Split `cap` across lists of these lengths: an equal share each, and what a
/// shorter list does not use passed on to the longer ones. The shares never
/// add up to more than `cap`, nor to less than `cap` while any list is left
/// with more than its share.
fn fair_shares(lens: &[usize], cap: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..lens.len()).collect();
    order.sort_by_key(|&i| lens[i]);
    let mut shares = vec![0; lens.len()];
    let mut left = cap;
    for (k, &i) in order.iter().enumerate() {
        let share = (left / (lens.len() - k)).min(lens[i]);
        shares[i] = share;
        left -= share;
    }
    shares
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
///
/// `404` for a stream the origin is not serving, as marks answer for one with
/// no directory: a viewer token outlives the session it was minted for by
/// hours, and a tab left open on a session the manager has dropped must not
/// hold one of [`MAX_STREAMS`] report slots for it.
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
    let credential = match crate::distribution::accepted_viewer_token(
        &st,
        &stream,
        &headers,
        query.as_deref(),
    ) {
        Ok(credential) => credential,
        Err(resp) => return resp,
    };
    let no_store = [(header::CACHE_CONTROL, "no-store")];
    if !st.origin.holds_stream(&stream) {
        return (
            StatusCode::NOT_FOUND,
            no_store,
            "the relay is not serving this stream",
        )
            .into_response();
    }
    match st.viewer_metrics.record(&stream, &credential, report) {
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
        Err(MetricRefusal::TooManyForToken) => (
            StatusCode::TOO_MANY_REQUESTS,
            no_store,
            "this viewer token is already reporting for as many players as it may",
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

    /// A token of its own for every client, so the per-token bound stays out
    /// of tests about something else.
    fn own(client: &str) -> TokenKey {
        token_key(client.as_bytes())
    }

    #[test]
    fn the_freshest_report_per_client_is_what_is_published_with_its_age() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        m.record_at("show", own("a"), report("a"), t0).unwrap();
        m.record_at("show", own("b"), report("b"), t0 + Duration::from_secs(5)).unwrap();
        let mut again = report("a");
        again.stalls = 3.0;
        m.record_at("show", own("a"), again, t0 + Duration::from_secs(20)).unwrap();

        let snap = m.snapshot_at(t0 + Duration::from_secs(30)).reports;
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
        m.record_at("show", own("a"), report("a"), t0).unwrap();
        let held = m.snapshot_at(t0 + REPORT_TTL - Duration::from_secs(1));
        assert_eq!(held.reports.len(), 1);
        assert_eq!(
            held.streams,
            vec![ViewerMetricStream {
                stream: "show".into(),
                reporting: 1,
                listed: 1
            }]
        );
        let gone = m.snapshot_at(t0 + REPORT_TTL);
        assert!(gone.reports.is_empty());
        assert!(gone.streams.is_empty(), "a stream with no live report has no entry");
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
            ua: "x\u{0}\u{7}".repeat(250),
            v: 2.0,
            events: (0..20)
                .map(|i| ReportedEvent {
                    ago_s: f64::from(i),
                    kind: if i == 19 { "hold".into() } else { "<script>".into() },
                    ms: -5.0,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
        .sanitize("show");
        assert_eq!(r.quality, "unknown");
        assert_eq!(r.mode, "live");
        assert_eq!(r.stalls, 0);
        assert_eq!(r.bw_kbps, 0);
        assert_eq!(r.ahead_s, 0.0);
        assert_eq!(r.seg_ttfb_ms, 600_000);
        assert_eq!(r.ua, "x".repeat(120), "control characters dropped, then cut");
        assert_eq!(r.v, 2);
        assert_eq!(r.events.len(), MAX_EVENTS, "the newest eight of twenty");
        assert_eq!(r.events[0].ago_s, 12);
        assert_eq!(r.events[0].kind, "unknown");
        assert_eq!(r.events[7].kind, "hold");
        assert_eq!(r.events[7].ms, 0);
    }

    #[test]
    fn a_bad_client_id_is_refused_and_the_caps_hold() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        for bad in ["", "a b", "x".repeat(65).as_str(), "é"] {
            assert_eq!(
                m.record_at("show", own(bad), report(bad), t0),
                Err(MetricRefusal::BadClient),
                "{bad:?}"
            );
        }
        for i in 0..MAX_CLIENTS_PER_STREAM {
            let c = format!("c{i}");
            m.record_at("show", own(&c), report(&c), t0).unwrap();
        }
        assert_eq!(
            m.record_at("show", own("one-more"), report("one-more"), t0),
            Err(MetricRefusal::TooManyClients)
        );
        // A client already held may still report.
        m.record_at("show", own("c0"), report("c0"), t0).unwrap();
        let snap = m.snapshot_at(t0);
        assert_eq!(snap.streams[0].reporting, MAX_CLIENTS_PER_STREAM);

        for i in 1..MAX_STREAMS {
            m.record_at(&format!("s{i}"), own("c"), report("c"), t0).unwrap();
        }
        assert_eq!(
            m.record_at("another", own("c"), report("c"), t0),
            Err(MetricRefusal::TooManyStreams)
        );
    }

    /// One credential is a few devices. A link passed round, or a script
    /// holding one, could otherwise name a fresh client every report and fill
    /// a stream's table — refusing every real viewer who came after — and
    /// that stream's whole share of the health list.
    #[test]
    fn one_token_reports_for_a_few_clients_and_is_refused_past_them() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        let link = token_key(b"one token");
        for i in 0..MAX_CLIENTS_PER_TOKEN {
            m.record_at("show", link, report(&format!("tab{i}")), t0).unwrap();
        }
        assert_eq!(
            m.record_at("show", link, report("tab-extra"), t0),
            Err(MetricRefusal::TooManyForToken),
            "a ninth client under one token"
        );
        // Refused, not swapped: every client already held keeps reporting.
        m.record_at("show", link, report("tab0"), t0 + Duration::from_secs(20)).unwrap();
        let snap = m.snapshot_at(t0 + Duration::from_secs(20));
        assert_eq!(snap.streams[0].reporting, MAX_CLIENTS_PER_TOKEN);
        // Another credential is another viewer, and the bound is per stream.
        m.record_at("show", token_key(b"another token"), report("tab-extra"), t0).unwrap();
        m.record_at("other", link, report("tab-extra"), t0).unwrap();
        // A renewal brings a new token to the same tab: still that one client.
        m.record_at("show", token_key(b"its renewal"), report("tab1"), t0).unwrap();
        m.record_at("show", link, report("tab-late"), t0).unwrap();
        // A client that has gone frees its place.
        let later = t0 + REPORT_TTL;
        m.record_at("show", link, report("tab0"), later).unwrap();
        m.record_at("show", link, report("tab-after"), later).unwrap();
    }

    #[test]
    fn the_cut_is_bounded_and_shared_between_streams() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        for i in 0..(MAX_REPORTED + 50) {
            let c = format!("c{i}");
            m.record_at(
                &format!("s{}", i % 8),
                own(&c),
                report(&c),
                t0 + Duration::from_millis(i as u64),
            )
            .unwrap();
        }
        let snap = m.snapshot_at(t0 + Duration::from_secs(1));
        assert_eq!(snap.reports.len(), MAX_REPORTED);
        assert_eq!(snap.streams.len(), 8);
        for s in &snap.streams {
            assert_eq!(s.listed, MAX_REPORTED / 8, "{s:?}");
            assert_eq!(s.reporting, if s.stream.as_str() < "s2" { 32 } else { 31 }, "{s:?}");
            let listed: Vec<&ViewerMetricReport> =
                snap.reports.iter().filter(|r| r.stream == s.stream).collect();
            assert_eq!(listed.len(), s.listed);
            assert!(
                listed.windows(2).all(|w| w[0].age_secs <= w[1].age_secs),
                "freshest first within a stream"
            );
        }
    }

    /// The production shape the relay-wide freshest-first cut got wrong: a
    /// busy feed's reports, all fresher, pushed a small feed's out of the list
    /// altogether, and its operator saw nobody reporting.
    #[test]
    fn a_busy_stream_does_not_push_a_quiet_one_out_of_the_cut() {
        let m = ViewerMetrics::default();
        let t0 = Instant::now();
        for i in 0..5 {
            let c = format!("quiet{i}");
            m.record_at("quiet", own(&c), report(&c), t0).unwrap();
        }
        for i in 0..MAX_CLIENTS_PER_STREAM {
            let c = format!("busy{i}");
            m.record_at("busy", own(&c), report(&c), t0 + Duration::from_secs(10)).unwrap();
        }
        let snap = m.snapshot_at(t0 + Duration::from_secs(15));
        assert_eq!(snap.reports.len(), MAX_REPORTED);
        assert_eq!(
            snap.streams,
            vec![
                ViewerMetricStream {
                    stream: "busy".into(),
                    reporting: MAX_CLIENTS_PER_STREAM,
                    listed: MAX_REPORTED - 5,
                },
                ViewerMetricStream { stream: "quiet".into(), reporting: 5, listed: 5 },
            ]
        );
        assert_eq!(snap.reports.iter().filter(|r| r.stream == "quiet").count(), 5);
    }

    #[test]
    fn shares_are_equal_and_what_one_leaves_goes_to_the_rest() {
        assert_eq!(fair_shares(&[], 200), Vec::<usize>::new());
        assert_eq!(fair_shares(&[3, 4], 200), vec![3, 4], "under the cap, everything");
        assert_eq!(fair_shares(&[1000, 5], 200), vec![195, 5]);
        assert_eq!(fair_shares(&[100, 100, 100], 200), vec![66, 67, 67]);
        assert_eq!(fair_shares(&[10, 500, 60, 500], 200), vec![10, 65, 60, 65]);
    }

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn state(dir: &std::path::Path) -> Arc<DistributionState> {
        use crate::distribution::origin::{OriginConfig, OriginStore};
        use crate::distribution_control::{DistUpdate, DistributionControl, RuntimeDistConfig};

        let cfg = crate::config::DistributionConfig::default();
        let control = DistributionControl::new(RuntimeDistConfig::from_config(&cfg, None), vec![]);
        control.apply(DistUpdate { token_secret: Some(SECRET.into()), ..Default::default() });
        let origin = OriginStore::new(OriginConfig {
            root: dir.join("origin"),
            retention: Duration::from_secs(3600),
            max_bytes_per_stream: 1 << 30,
            min_segments: 0,
            min_free_bytes: 0,
            idle_grace: Duration::from_secs(60),
        })
        .unwrap();
        let (events, _rx) = crate::manager::events::event_channel();
        DistributionState::new(
            Arc::new(crate::distribution::hub::DistributionHub::new()),
            Arc::new(origin),
            cfg,
            control,
            tokio_util::sync::CancellationToken::new(),
            events,
        )
    }

    async fn post(
        st: &Arc<DistributionState>,
        stream: &str,
        token: &str,
        client: &str,
    ) -> StatusCode {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        metrics_post(
            State(st.clone()),
            Path(stream.to_string()),
            headers,
            axum::extract::RawQuery(None),
            axum::Json(report(client)),
        )
        .await
        .status()
    }

    /// A viewer token outlives its session by hours, so a tab left open on a
    /// session the manager has dropped would hold a report slot for a stream
    /// the relay no longer serves — and enough of them, every slot, refusing
    /// the next session's viewers. Marks refuse such a stream; so does this.
    #[tokio::test]
    async fn a_report_for_a_stream_the_origin_is_not_serving_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let exp = crate::stats::now_epoch_ms() / 1000 + 300;
        let viewer = crate::distribution::token::mint_viewer_token(SECRET, "feed", exp).unwrap();

        assert_eq!(post(&st, "feed", &viewer, "tab").await, StatusCode::NOT_FOUND);
        st.origin.put("feed", "seg-00001.m4s", bytes::Bytes::from_static(b"x")).await.unwrap();
        assert_eq!(post(&st, "feed", &viewer, "tab").await, StatusCode::OK);

        // The token the report came with is what it is counted against.
        for i in 1..MAX_CLIENTS_PER_TOKEN {
            assert_eq!(post(&st, "feed", &viewer, &format!("tab{i}")).await, StatusCode::OK);
        }
        assert_eq!(post(&st, "feed", &viewer, "tab-extra").await, StatusCode::TOO_MANY_REQUESTS);

        st.origin.retire_stream("feed").await;
        assert_eq!(post(&st, "feed", &viewer, "tab").await, StatusCode::NOT_FOUND);
    }

    /// One token can be written any number of ways — zeros or a `+` before
    /// its expiry, its hex in capitals, its one stream listed in the
    /// multi-stream form — and every spelling verifies. Counted by the text it
    /// arrived as, each spelling was a credential with eight clients of its
    /// own, and one holder filled a stream's table after all.
    #[tokio::test]
    async fn one_token_is_one_credential_however_it_is_spelled() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let exp = crate::stats::now_epoch_ms() / 1000 + 300;
        let viewer = crate::distribution::token::mint_viewer_token(SECRET, "feed", exp).unwrap();
        st.origin.put("feed", "seg-00001.m4s", bytes::Bytes::from_static(b"x")).await.unwrap();

        let (e, sig) = viewer.split_once('.').unwrap();
        let upper = sig.to_ascii_uppercase();
        let spellings = [
            viewer.clone(),
            format!("0{viewer}"),
            format!("00000{viewer}"),
            format!("+{viewer}"),
            format!("{e}.{upper}"),
            format!("{e}.{}{}", &upper[..32], &sig[32..]),
            format!("{e}.feed.{sig}"),
            format!("+0{e}.feed.{upper}"),
        ];
        assert_eq!(spellings.len(), MAX_CLIENTS_PER_TOKEN);
        for (i, token) in spellings.iter().enumerate() {
            assert_eq!(post(&st, "feed", token, &format!("tab{i}")).await, StatusCode::OK, "{token}");
        }
        assert_eq!(
            post(&st, "feed", &format!("00{e}.feed.{sig}"), "tab-extra").await,
            StatusCode::TOO_MANY_REQUESTS,
            "a ninth client under one credential, spelled anew"
        );
        // Another credential is another viewer.
        let other = crate::distribution::token::mint_viewer_token(SECRET, "feed", exp + 1).unwrap();
        assert_eq!(post(&st, "feed", &other, "tab-extra").await, StatusCode::OK);
    }
}
