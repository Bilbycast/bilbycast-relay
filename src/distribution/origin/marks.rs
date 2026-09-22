// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared marks: one list per stream, seen by everyone watching it.
//!
//! The DVR player used to keep marks in `localStorage`, which is per device.
//! Two operators watching the same session each had their own list, so "go to
//! the mark I just made" meant reading a timecode across the room. This puts
//! the list on the relay, where every viewer of the stream reads and writes the
//! same one.
//!
//! **Marks are wall-clock instants, not media times** — the same thing the
//! player already stored and the same thing a clip request sends — so a mark
//! means one moment for every viewer regardless of where each one's hls.js
//! timeline happens to start.
//!
//! **Storage is one JSON file per stream**, `{stream}/marks/marks.json`,
//! replaced whole by temp-then-rename. A session holds tens of marks, the list
//! is hundreds of bytes to a few tens of kilobytes, and every write replaces
//! it: a database would be ceremony. Lifetime follows the clips: it survives a
//! relay restart and a feed drop (`retire_stream` keeps `marks/`), goes with
//! the session when the manager drops the stream (`remove_stream`), and has
//! the same seven-day backstop under a manager that never comes back.
//!
//! **Viewers learn about each other's changes by polling** `GET`, which answers
//! `304` while the list is unchanged. At six viewers polling every few seconds
//! that is a handful of header exchanges a second, and it keeps the relay free
//! of per-viewer connection state — the same stateless posture as the rest of
//! the origin.
//!
//! **Anyone who may watch may edit.** The gate is the stream's viewer token,
//! exactly as for requesting a clip. There is no notion of who made a mark:
//! the relay's tokens name a stream, not a person.

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::{MARKS_DIR, OriginStore, PART_SUFFIX, if_none_match_matches};
use crate::distribution::DistributionState;

const MARKS_FILE: &str = "marks.json";

/// How many marks one stream may hold.
///
/// An operator marking every incident in a long match makes a few hundred at
/// most. The bound exists so a stuck client or a hostile token holder cannot
/// grow the file — which every viewer downloads on every change — without
/// limit.
pub const MAX_MARKS_PER_STREAM: usize = 500;

/// Longest name a mark may carry, in characters.
///
/// A mark's name is a label on a list row and in a tooltip, not a note.
pub const MAX_MARK_NAME_CHARS: usize = 120;

/// Largest body a marks request may send. One mark is well under 300 bytes.
const MAX_MARKS_JSON_BYTES: usize = 16 * 1024;

/// A plausible wall clock, in milliseconds: 2000-01-01 to 2100-01-01.
///
/// Not a policy about what may be marked. It catches a client that sent
/// seconds, or a media time, where the published clock was meant — either of
/// which would store a mark no player can ever place on the bar.
const MIN_AT_MS: i64 = 946_684_800_000;
const MAX_AT_MS: i64 = 4_102_444_800_000;

/// One mark.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Mark {
    /// Assigned here, never by a client, so two viewers marking at once
    /// cannot collide.
    pub id: String,
    /// The marked instant on the published clock, milliseconds since the
    /// Unix epoch.
    pub at: i64,
    #[serde(default)]
    pub name: String,
    /// `#rrggbb`, or empty for the player's default. The player narrows this
    /// further to its own closed palette before using it in a style.
    #[serde(default)]
    pub colour: String,
    /// A clip has been requested for this mark. Shared because the clips are:
    /// every viewer of the stream sees the same clip list on the portal.
    #[serde(default)]
    pub exported: bool,
}

/// A stream's whole list, as stored and as served.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MarkSet {
    /// Identifies this file's *lifetime*. Stamped when the file is first
    /// written and never changed, so a list deleted with its session and
    /// started again cannot hand a returning viewer a `304` because the new
    /// file's revision happens to equal the number the viewer last saw.
    #[serde(default)]
    pub epoch: String,
    /// Bumped on every change.
    #[serde(default)]
    pub rev: u64,
    #[serde(default)]
    pub marks: Vec<Mark>,
}

impl MarkSet {
    /// The validator a poll compares against.
    pub fn etag(&self) -> String {
        if self.epoch.is_empty() {
            "\"marks-none\"".to_string()
        } else {
            format!("\"marks-{}-{}\"", self.epoch, self.rev)
        }
    }
}

/// `POST /origin/{stream}/marks`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NewMark {
    pub at: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub colour: String,
    #[serde(default)]
    pub exported: bool,
}

/// `PATCH /origin/{stream}/marks/{id}`. Every field optional; what is absent
/// is left as it was.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct MarkEdit {
    pub name: Option<String>,
    pub colour: Option<String>,
    pub exported: Option<bool>,
}

/// Why a change to the list was refused.
#[derive(Debug)]
pub enum MarkRefusal {
    /// Something in the request is malformed. The text is shown to the
    /// operator verbatim.
    Invalid(&'static str),
    TooMany,
    NotFound,
    Io(std::io::Error),
}

impl From<std::io::Error> for MarkRefusal {
    fn from(e: std::io::Error) -> Self {
        MarkRefusal::Io(e)
    }
}

fn valid_name(name: &str) -> bool {
    name.chars().count() <= MAX_MARK_NAME_CHARS && !name.chars().any(char::is_control)
}

fn valid_colour(c: &str) -> bool {
    c.is_empty()
        || (c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|ch| ch.is_ascii_hexdigit()))
}

/// A mark id as this module mints them. Checked before it is used for
/// anything, because it arrives in a URL.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Read a stream's list. Missing is empty, not an error: a stream nobody has
/// marked yet has no file.
fn load(path: &FsPath) -> std::io::Result<MarkSet> {
    match std::fs::read(path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MarkSet::default()),
        Err(e) => Err(e),
    }
}

/// Replace the list whole or not at all — the same temp-then-rename the clip
/// records use, and for the same reason: a crash inside a truncating write
/// leaves a file that parses as nothing, and here that is every viewer's marks.
fn store(path: &FsPath, set: &MarkSet) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec(set).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!("json{PART_SUFFIX}"));
    std::fs::write(&tmp, body)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

impl OriginStore {
    fn marks_path(&self, stream: &str) -> Option<PathBuf> {
        Self::safe_stream_name(stream)
            .then(|| self.cfg.root.join(stream).join(MARKS_DIR).join(MARKS_FILE))
    }

    /// The stream's list as it stands. Blocking: call from the blocking pool.
    ///
    /// Takes no lock. Every write lands by rename, so a reader sees the whole
    /// old list or the whole new one.
    pub fn list_marks(&self, stream: &str) -> std::io::Result<MarkSet> {
        let Some(path) = self.marks_path(stream) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "origin: unsafe stream name",
            ));
        };
        load(&path)
    }

    /// Read, change and write back, under the store's marks lock.
    ///
    /// `f` returns its result and whether it changed anything; an unchanged
    /// list is not rewritten, so its revision — and every viewer's `304` —
    /// survives a no-op.
    fn mutate_marks<T>(
        &self,
        stream: &str,
        f: impl FnOnce(&mut MarkSet) -> Result<(T, bool), MarkRefusal>,
    ) -> Result<(MarkSet, T), MarkRefusal> {
        let Some(path) = self.marks_path(stream) else {
            return Err(MarkRefusal::Invalid("invalid stream id"));
        };
        // One lock for the store, as for clip admission: a mark is made when
        // an operator presses a button, so there is nothing to contend for,
        // and without it two viewers marking in the same instant would each
        // read the same list and the second write would drop the first mark.
        let _writing = self.marks_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = match load(&path) {
            Ok(s) => s,
            // Unreadable is set aside rather than overwritten: it is the one
            // copy of everyone's marks, and whoever looks at the disk later
            // deserves the chance to recover it. The list starts again empty
            // rather than refusing every write for the rest of the session.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                let aside = path.with_extension(format!(
                    "json.unreadable-{}",
                    chrono::Utc::now().format("%Y%m%dT%H%M%S")
                ));
                tracing::warn!(
                    stream = %stream, error = %e, kept_as = %aside.display(),
                    "origin: marks file would not parse; set aside and starting a new list"
                );
                let _ = std::fs::rename(&path, &aside);
                MarkSet::default()
            }
            Err(e) => return Err(MarkRefusal::Io(e)),
        };
        let (out, changed) = f(&mut set)?;
        if changed {
            if set.epoch.is_empty() {
                set.epoch = uuid::Uuid::new_v4().simple().to_string();
            }
            set.rev = set.rev.saturating_add(1);
            set.marks
                .sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.id.cmp(&b.id)));
            store(&path, &set)?;
        }
        Ok((set, out))
    }

    /// Add a mark, returning the list and the new mark's id.
    ///
    /// **Idempotent on the instant.** A mark at exactly the millisecond of one
    /// already held is that mark: its id comes back and nothing is written. A
    /// retried request — a flaky tablet connection, or a player uploading the
    /// marks it held locally before this existed — therefore cannot duplicate,
    /// and two operators pressing MARK within the same millisecond is not a
    /// distinction anybody could see on the bar.
    pub fn add_mark(&self, stream: &str, new: NewMark) -> Result<(MarkSet, String), MarkRefusal> {
        if !(MIN_AT_MS..=MAX_AT_MS).contains(&new.at) {
            return Err(MarkRefusal::Invalid(
                "a mark's time must be a wall clock in milliseconds",
            ));
        }
        if !valid_name(&new.name) {
            return Err(MarkRefusal::Invalid(
                "a mark's name must be under 120 characters of text",
            ));
        }
        if !valid_colour(&new.colour) {
            return Err(MarkRefusal::Invalid("a mark's colour must be #rrggbb"));
        }
        self.mutate_marks(stream, |set| {
            if let Some(m) = set.marks.iter().find(|m| m.at == new.at) {
                return Ok((m.id.clone(), false));
            }
            if set.marks.len() >= MAX_MARKS_PER_STREAM {
                return Err(MarkRefusal::TooMany);
            }
            let id = uuid::Uuid::new_v4().simple().to_string();
            set.marks.push(Mark {
                id: id.clone(),
                at: new.at,
                name: new.name,
                colour: new.colour,
                exported: new.exported,
            });
            Ok((id, true))
        })
    }

    pub fn edit_mark(
        &self,
        stream: &str,
        id: &str,
        edit: MarkEdit,
    ) -> Result<MarkSet, MarkRefusal> {
        if !valid_id(id) {
            return Err(MarkRefusal::NotFound);
        }
        if edit.name.as_deref().is_some_and(|n| !valid_name(n)) {
            return Err(MarkRefusal::Invalid(
                "a mark's name must be under 120 characters of text",
            ));
        }
        if edit.colour.as_deref().is_some_and(|c| !valid_colour(c)) {
            return Err(MarkRefusal::Invalid("a mark's colour must be #rrggbb"));
        }
        self.mutate_marks(stream, |set| {
            let Some(m) = set.marks.iter_mut().find(|m| m.id == id) else {
                return Err(MarkRefusal::NotFound);
            };
            let before = m.clone();
            if let Some(n) = edit.name {
                m.name = n;
            }
            if let Some(c) = edit.colour {
                m.colour = c;
            }
            if let Some(x) = edit.exported {
                m.exported = x;
            }
            let changed = *m != before;
            Ok(((), changed))
        })
        .map(|(set, ())| set)
    }

    /// Remove a mark. Removing one that is already gone succeeds: two viewers
    /// deleting the same mark want the same outcome, and the second should not
    /// be told it failed.
    pub fn delete_mark(&self, stream: &str, id: &str) -> Result<MarkSet, MarkRefusal> {
        if !valid_id(id) {
            return Err(MarkRefusal::NotFound);
        }
        self.mutate_marks(stream, |set| {
            let before = set.marks.len();
            set.marks.retain(|m| m.id != id);
            Ok(((), set.marks.len() != before))
        })
        .map(|(set, ())| set)
    }
}

pub(super) fn routes() -> Router<Arc<DistributionState>> {
    Router::new()
        // Static segments beat the `{file}` capture, as for `clips`.
        .route(
            "/origin/{stream}/marks",
            axum::routing::get(marks_list).post(marks_add),
        )
        .route(
            "/origin/{stream}/marks/{id}",
            axum::routing::patch(marks_edit).delete(marks_delete),
        )
        .layer(DefaultBodyLimit::max(MAX_MARKS_JSON_BYTES))
}

#[derive(serde::Serialize)]
struct MarksReply<'a> {
    rev: u64,
    marks: &'a [Mark],
    /// The mark a `POST` made (or found).
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

fn reply(status: StatusCode, set: &MarkSet, id: Option<String>) -> Response {
    let body = MarksReply {
        rev: set.rev,
        marks: &set.marks,
        id,
    };
    (
        status,
        [
            // Never from a cache: the list is shared state that changes under
            // the viewer, and a CDN in front of `/origin` must not pin it.
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::ETAG, set.etag()),
        ],
        axum::Json(body),
    )
        .into_response()
}

fn refusal(stream: &str, r: MarkRefusal) -> Response {
    let no_store = [(header::CACHE_CONTROL, "no-store")];
    match r {
        MarkRefusal::Invalid(why) => (StatusCode::BAD_REQUEST, no_store, why).into_response(),
        MarkRefusal::TooMany => (
            StatusCode::CONFLICT,
            no_store,
            format!(
                "this feed already holds {MAX_MARKS_PER_STREAM} marks, which is the limit \
                 — delete some before marking more"
            ),
        )
            .into_response(),
        MarkRefusal::NotFound => (StatusCode::NOT_FOUND, no_store, "no such mark").into_response(),
        MarkRefusal::Io(e) => {
            tracing::warn!(stream = %stream, error = %e, "origin: marks could not be read or written");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store,
                "could not update the marks",
            )
                .into_response()
        }
    }
}

/// Validate the stream and the credential, the two checks every verb shares.
///
/// The viewer token only. Unlike the clip surface the edge has no business
/// here, so its ingest token is not accepted. `check_viewer_token` fails closed
/// without a token secret, which is the posture the clip routes take: a relay
/// that cannot check a credential does not offer a shared write surface.
fn admit(
    st: &Arc<DistributionState>,
    stream: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<String, Response> {
    let Some(stream) = crate::distribution::sanitize_stream_id(stream) else {
        return Err((StatusCode::BAD_REQUEST, "invalid stream id").into_response());
    };
    crate::distribution::check_viewer_token(st, &stream, headers, query)?;
    Ok(stream)
}

/// Run a marks operation on the blocking pool. Every one of them is a file
/// read and perhaps a write, and this runtime also carries the forwarding
/// tasks.
async fn blocking<T: Send + 'static>(
    stream: &str,
    f: impl FnOnce() -> Result<T, MarkRefusal> + Send + 'static,
) -> Result<T, MarkRefusal> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(stream = %stream, error = %e, "origin: marks task failed");
            Err(MarkRefusal::Io(std::io::Error::other("marks task failed")))
        }
    }
}

/// `GET /origin/{stream}/marks` — the list, or `304` if the caller has it.
async fn marks_list(
    State(st): State<Arc<DistributionState>>,
    Path(stream): Path<String>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let stream = match admit(&st, &stream, &headers, query.as_deref()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let origin = st.origin.clone();
    let s = stream.clone();
    let set = match blocking(&stream, move || {
        origin.list_marks(&s).map_err(MarkRefusal::Io)
    })
    .await
    {
        Ok(set) => set,
        Err(r) => return refusal(&stream, r),
    };
    let etag = set.etag();
    if let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        && if_none_match_matches(inm, &etag)
    {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::CACHE_CONTROL, "no-store".to_string()),
                (header::ETAG, etag),
            ],
        )
            .into_response();
    }
    reply(StatusCode::OK, &set, None)
}

/// `POST /origin/{stream}/marks` — mark a moment for everyone.
async fn marks_add(
    State(st): State<Arc<DistributionState>>,
    Path(stream): Path<String>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    axum::Json(new): axum::Json<NewMark>,
) -> Response {
    let stream = match admit(&st, &stream, &headers, query.as_deref()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let origin = st.origin.clone();
    let s = stream.clone();
    match blocking(&stream, move || origin.add_mark(&s, new)).await {
        Ok((set, id)) => reply(StatusCode::CREATED, &set, Some(id)),
        Err(r) => refusal(&stream, r),
    }
}

/// `PATCH /origin/{stream}/marks/{id}` — rename, recolour, or flag exported.
async fn marks_edit(
    State(st): State<Arc<DistributionState>>,
    Path((stream, id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    axum::Json(edit): axum::Json<MarkEdit>,
) -> Response {
    let stream = match admit(&st, &stream, &headers, query.as_deref()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let origin = st.origin.clone();
    let s = stream.clone();
    match blocking(&stream, move || origin.edit_mark(&s, &id, edit)).await {
        Ok(set) => reply(StatusCode::OK, &set, None),
        Err(r) => refusal(&stream, r),
    }
}

/// `DELETE /origin/{stream}/marks/{id}`.
async fn marks_delete(
    State(st): State<Arc<DistributionState>>,
    Path((stream, id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let stream = match admit(&st, &stream, &headers, query.as_deref()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let origin = st.origin.clone();
    let s = stream.clone();
    match blocking(&stream, move || origin.delete_mark(&s, &id)).await {
        Ok(set) => reply(StatusCode::OK, &set, None),
        Err(r) => refusal(&stream, r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::origin::OriginConfig;
    use std::time::Duration;

    const T0: i64 = 1_790_000_000_000; // 2026-09-21

    fn store(tmp: &tempfile::TempDir) -> OriginStore {
        OriginStore::new(OriginConfig {
            root: tmp.path().join("origin"),
            retention: Duration::from_secs(3600),
            max_bytes_per_stream: 1 << 30,
            min_segments: 1,
            min_free_bytes: 0,
            idle_grace: Duration::from_secs(60),
        })
        .unwrap()
    }

    fn at(ms: i64) -> NewMark {
        NewMark {
            at: ms,
            name: String::new(),
            colour: String::new(),
            exported: false,
        }
    }

    #[test]
    fn a_mark_one_viewer_makes_is_the_list_every_viewer_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        assert!(s.list_marks("feed").unwrap().marks.is_empty());
        assert_eq!(s.list_marks("feed").unwrap().etag(), "\"marks-none\"");

        let (set, id) = s.add_mark("feed", at(T0 + 5_000)).unwrap();
        assert_eq!(set.rev, 1);
        let (set, _) = s.add_mark("feed", at(T0)).unwrap();
        assert_eq!(set.rev, 2);
        // Sorted by instant, not by arrival — the order the list is drawn in.
        let listed = s.list_marks("feed").unwrap();
        assert_eq!(
            listed.marks.iter().map(|m| m.at).collect::<Vec<_>>(),
            vec![T0, T0 + 5_000]
        );
        assert!(listed.marks.iter().any(|m| m.id == id));
        // Another stream's list is another list.
        assert!(s.list_marks("other").unwrap().marks.is_empty());
    }

    #[test]
    fn the_same_instant_twice_is_one_mark_and_no_new_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, first) = s.add_mark("feed", at(T0)).unwrap();
        let etag = s.list_marks("feed").unwrap().etag();
        let (set, again) = s.add_mark("feed", at(T0)).unwrap();
        assert_eq!(first, again, "a retried mark was stored twice");
        assert_eq!(set.marks.len(), 1);
        assert_eq!(
            set.etag(),
            etag,
            "a no-op changed the validator, waking every poller"
        );
    }

    #[test]
    fn edits_apply_only_what_they_name_and_a_no_op_keeps_the_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, id) = s.add_mark("feed", at(T0)).unwrap();
        let set = s
            .edit_mark(
                "feed",
                &id,
                MarkEdit {
                    name: Some("Goal".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(set.rev, 2);
        let set = s
            .edit_mark(
                "feed",
                &id,
                MarkEdit {
                    colour: Some("#4da3ff".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let m = &set.marks[0];
        assert_eq!((m.name.as_str(), m.colour.as_str()), ("Goal", "#4da3ff"));
        let rev = set.rev;
        let set = s
            .edit_mark(
                "feed",
                &id,
                MarkEdit {
                    name: Some("Goal".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            set.rev, rev,
            "an edit that changed nothing bumped the revision"
        );

        assert!(matches!(
            s.edit_mark("feed", "abc123", MarkEdit::default()),
            Err(MarkRefusal::NotFound)
        ));
    }

    #[test]
    fn deleting_twice_succeeds_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, id) = s.add_mark("feed", at(T0)).unwrap();
        assert!(s.delete_mark("feed", &id).unwrap().marks.is_empty());
        let rev = s.list_marks("feed").unwrap().rev;
        let set = s.delete_mark("feed", &id).unwrap();
        assert_eq!(set.rev, rev, "deleting nothing was recorded as a change");
    }

    #[test]
    fn malformed_marks_are_refused_before_they_are_stored() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        // Seconds where milliseconds were meant: a mark nobody could place.
        assert!(matches!(
            s.add_mark("feed", at(1_790_000_000)),
            Err(MarkRefusal::Invalid(_))
        ));
        let mut bad = at(T0);
        bad.colour = "red; background:url(x)".into();
        assert!(matches!(
            s.add_mark("feed", bad),
            Err(MarkRefusal::Invalid(_))
        ));
        let mut bad = at(T0);
        bad.name = "x".repeat(MAX_MARK_NAME_CHARS + 1);
        assert!(matches!(
            s.add_mark("feed", bad),
            Err(MarkRefusal::Invalid(_))
        ));
        let mut bad = at(T0);
        bad.name = "line\nbreak".into();
        assert!(matches!(
            s.add_mark("feed", bad),
            Err(MarkRefusal::Invalid(_))
        ));
        // A name in any script is fine: it is only ever drawn as text.
        let mut ok = at(T0);
        ok.name = "Goal — Müller's header".into();
        assert!(s.add_mark("feed", ok).is_ok());
        // An id that is not one of ours never reaches the file.
        assert!(matches!(
            s.delete_mark("feed", "../x"),
            Err(MarkRefusal::NotFound)
        ));
        // Nor does a stream name that would escape the root.
        assert!(s.list_marks("..").is_err());
    }

    #[test]
    fn a_stream_is_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        for i in 0..MAX_MARKS_PER_STREAM as i64 {
            s.add_mark("feed", at(T0 + i)).unwrap();
        }
        assert!(matches!(
            s.add_mark("feed", at(T0 - 1)),
            Err(MarkRefusal::TooMany)
        ));
    }

    #[test]
    fn a_list_started_again_does_not_answer_an_old_validator() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        s.add_mark("feed", at(T0)).unwrap();
        let old = s.list_marks("feed").unwrap().etag();
        std::fs::remove_dir_all(tmp.path().join("origin/feed")).unwrap();
        s.add_mark("feed", at(T0 + 1)).unwrap();
        let new = s.list_marks("feed").unwrap();
        assert_eq!(
            new.rev, 1,
            "the fresh list should be at the same revision number"
        );
        assert_ne!(
            new.etag(),
            old,
            "a new list at the same revision reads as unchanged"
        );
    }

    #[test]
    fn an_unreadable_list_is_set_aside_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let dir = tmp.path().join("origin/feed").join(MARKS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MARKS_FILE), b"{not json").unwrap();
        assert!(
            s.list_marks("feed").is_err(),
            "a corrupt list read as empty"
        );
        s.add_mark("feed", at(T0)).unwrap();
        assert_eq!(s.list_marks("feed").unwrap().marks.len(), 1);
        let kept = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("unreadable"));
        assert!(
            kept,
            "the unreadable list was destroyed rather than kept for recovery"
        );
    }

    #[tokio::test]
    async fn marks_survive_a_relay_restart_and_a_retirement_but_not_a_removal() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = store(&tmp);
            s.put(
                "feed",
                "seg-00001.m4s",
                axum::body::Bytes::from_static(b"x"),
            )
            .await
            .unwrap();
            s.put(
                "feed",
                "seg-00002.m4s",
                axum::body::Bytes::from_static(b"x"),
            )
            .await
            .unwrap();
            s.add_mark("feed", at(T0)).unwrap();
        }
        // Restart: adoption treats anything that is not a segment as debris.
        let s = store(&tmp);
        assert_eq!(
            s.list_marks("feed").unwrap().marks.len(),
            1,
            "a restart lost the marks"
        );

        // The feed drops for longer than retention: media goes, marks stay.
        s.retire_stream("feed").await;
        assert_eq!(
            s.list_marks("feed").unwrap().marks.len(),
            1,
            "a feed drop lost the marks"
        );

        // The session is over.
        s.remove_stream("feed").await;
        assert!(
            s.list_marks("feed").unwrap().marks.is_empty(),
            "the session's marks outlived it"
        );
    }

    #[tokio::test]
    async fn a_marks_only_directory_does_not_stop_the_store_starting() {
        // A store written before the origin marker existed is recognised by
        // its shape; a stream retired down to its marks must still pass.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin");
        std::fs::create_dir_all(root.join("live")).unwrap();
        std::fs::write(root.join("live/seg-00001.m4s"), b"x").unwrap();
        std::fs::write(root.join("live/seg-00002.m4s"), b"x").unwrap();
        std::fs::create_dir_all(root.join("gone").join(MARKS_DIR)).unwrap();
        std::fs::write(root.join("gone").join(MARKS_DIR).join(MARKS_FILE), b"{}").unwrap();
        assert!(super::super::looks_like_origin_store(&root).unwrap());
    }
}
