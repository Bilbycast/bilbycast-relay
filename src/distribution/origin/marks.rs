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
//! **A list is written only into a stream directory that already exists.**
//! Ingest makes that directory and the manager's drop removes it; a mark
//! arriving after the drop — a viewer token is stateless and outlives the
//! session — is refused with `404` rather than bringing the directory back,
//! where nothing but the backstop would ever find it again. A clip request
//! is refused on the same rule, so it cannot bring the directory back for a
//! mark to land in either, and the drop holds the marks lock: a write in
//! flight lands before the directory goes, and goes with it, or finds it
//! gone. Reading a stream with no directory is an empty list, not an error:
//! a player opened before the first segment lands must not conclude the
//! relay has no marks at all.
//!
//! **Writers queue as tasks, not threads.** The lock is a `tokio` mutex taken
//! before a write goes to the blocking pool and held until it is done there —
//! see `OriginStore::lock_marks` for why each half matters.
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

pub(super) const MARKS_FILE: &str = "marks.json";

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

/// What a refused name is told. Shown to the operator verbatim, so it says
/// both rules `valid_name` applies, and the limit as it is: 120 is allowed.
const NAME_REFUSED: &str =
    "a mark's name must be at most 120 characters of plain text — no tabs or line breaks";

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
    /// The relay holds no directory for the stream: nothing has been
    /// ingested yet, or the manager has dropped it. See the module header.
    NoStream,
    /// A read or a write failed. Answered `503`, which the player retries:
    /// `500` is kept for the one refusal it must not retry, a token gate with
    /// no secret to check against.
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

/// Read a stream's list, setting aside one that will not parse. Call only
/// under the store's marks lock: the rename must not race a writer.
///
/// Unreadable is set aside rather than overwritten: it is the one copy of
/// everyone's marks, and whoever looks at the disk later deserves the chance
/// to recover it. The list starts again empty rather than refusing every
/// request for the rest of the session.
fn load_or_set_aside(path: &FsPath, stream: &str) -> std::io::Result<MarkSet> {
    match load(path) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            let aside = path.with_extension(format!(
                "json.unreadable-{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%S")
            ));
            tracing::warn!(
                stream = %stream, error = %e, kept_as = %aside.display(),
                "origin: marks file would not parse; set aside and starting a new list"
            );
            let _ = std::fs::rename(path, &aside);
            Ok(MarkSet::default())
        }
        other => other,
    }
}

/// Replace the list whole or not at all, and durably.
///
/// The same temp-then-rename the clip records use, and for the same reason: a
/// crash inside a truncating write leaves a file that parses as nothing, and
/// here that is every viewer's marks. The rename alone covers this process
/// dying; it does not cover the host losing power, where a filesystem without
/// ext4's flush-on-replace can put the new name on data that never reached
/// the disk — exactly the empty file the rename was meant to rule out. So the
/// data is synced before the rename, and the directory after it.
///
/// `marks/` is created here; the stream directory above it never is. That one
/// is ingest's to make and the manager's to remove. `remove_stream` holds the
/// marks lock, so no write here races it. Retirement and the seven-day
/// backstop remove `marks/` and an emptied stream directory without it, and
/// can still take either from under a write; that write must then fail rather
/// than put the stream back.
fn store(path: &FsPath, set: &MarkSet) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("origin: marks path has no directory"))?;
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let body = serde_json::to_vec(set).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!("json{PART_SUFFIX}"));
    if let Err(e) = write_synced(&tmp, &body).and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Best effort: the list is already in place, and a directory that cannot
    // be opened for a sync is no reason to report the mark as lost.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn write_synced(path: &FsPath, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    f.write_all(body)?;
    f.sync_all()
}

impl OriginStore {
    fn marks_path(&self, stream: &str) -> Option<PathBuf> {
        Self::safe_stream_name(stream)
            .then(|| self.cfg.root.join(stream).join(MARKS_DIR).join(MARKS_FILE))
    }

    /// The stream's list as it stands.
    ///
    /// Reads without the lock: every write lands by rename, so a reader sees
    /// the whole old list or the whole new one. The lock is taken only to
    /// recover a file that will not parse, which is set aside here exactly as
    /// a write would set it aside. Left to the writes, a broken list stayed
    /// broken for as long as nobody marked anything — and a player that could
    /// not read the list had no way to know a write would fix it.
    ///
    /// Read again under the lock before anything is renamed: a writer may have
    /// set the file aside and stored a fresh one in the meantime, and moving
    /// that one out of the way would lose a mark.
    pub async fn list_marks(&self, stream: &str) -> Result<MarkSet, MarkRefusal> {
        let Some(path) = self.marks_path(stream) else {
            return Err(MarkRefusal::Invalid("invalid stream id"));
        };
        let unlocked = path.clone();
        match blocking(stream, move || load(&unlocked).map_err(MarkRefusal::Io)).await {
            Err(MarkRefusal::Io(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                let held = self.lock_marks().await;
                let s = stream.to_owned();
                blocking(stream, move || {
                    let _held = held;
                    load_or_set_aside(&path, &s).map_err(MarkRefusal::Io)
                })
                .await
            }
            other => other,
        }
    }

    /// Read, change and write back, under the store's marks lock.
    ///
    /// `f` returns its result and whether it changed anything; an unchanged
    /// list is not rewritten, so its revision — and every viewer's `304` —
    /// survives a no-op.
    async fn mutate_marks<T: Send + 'static>(
        &self,
        stream: &str,
        f: impl FnOnce(&mut MarkSet) -> Result<(T, bool), MarkRefusal> + Send + 'static,
    ) -> Result<(MarkSet, T), MarkRefusal> {
        let Some(path) = self.marks_path(stream) else {
            return Err(MarkRefusal::Invalid("invalid stream id"));
        };
        let stream_dir = self.cfg.root.join(stream);
        let s = stream.to_owned();
        // One lock for the store, as for clip admission: a mark is made when
        // an operator presses a button, so there is nothing to contend for,
        // and without it two viewers marking in the same instant would each
        // read the same list and the second write would drop the first mark.
        // Waited for here, as a future, and held until the blocking work is
        // done — see `lock_marks`.
        let held = self.lock_marks().await;
        blocking(stream, move || {
            let _held = held;
            // Checked under the lock, which `remove_stream` takes as well, and
            // `store` creates nothing above `marks/`: a list cannot outlive
            // the stream it belongs to. See the module header.
            if !stream_dir.is_dir() {
                return Err(MarkRefusal::NoStream);
            }
            let mut set = load_or_set_aside(&path, &s)?;
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
        })
        .await
    }

    /// Add a mark, returning the list and the new mark's id.
    ///
    /// **Idempotent on the instant.** A mark at exactly the millisecond of one
    /// already held is that mark: its id comes back and nothing is written. A
    /// retried request — a flaky tablet connection, or a player uploading the
    /// marks it held locally before this existed — therefore cannot duplicate,
    /// and two operators pressing MARK within the same millisecond is not a
    /// distinction anybody could see on the bar.
    pub async fn add_mark(
        &self,
        stream: &str,
        new: NewMark,
    ) -> Result<(MarkSet, String), MarkRefusal> {
        if !(MIN_AT_MS..=MAX_AT_MS).contains(&new.at) {
            return Err(MarkRefusal::Invalid(
                "a mark's time must be a wall clock in milliseconds",
            ));
        }
        if !valid_name(&new.name) {
            return Err(MarkRefusal::Invalid(NAME_REFUSED));
        }
        if !valid_colour(&new.colour) {
            return Err(MarkRefusal::Invalid("a mark's colour must be #rrggbb"));
        }
        self.mutate_marks(stream, move |set| {
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
        .await
    }

    pub async fn edit_mark(
        &self,
        stream: &str,
        id: &str,
        edit: MarkEdit,
    ) -> Result<MarkSet, MarkRefusal> {
        if !valid_id(id) {
            return Err(MarkRefusal::NotFound);
        }
        if edit.name.as_deref().is_some_and(|n| !valid_name(n)) {
            return Err(MarkRefusal::Invalid(NAME_REFUSED));
        }
        if edit.colour.as_deref().is_some_and(|c| !valid_colour(c)) {
            return Err(MarkRefusal::Invalid("a mark's colour must be #rrggbb"));
        }
        let id = id.to_owned();
        self.mutate_marks(stream, move |set| {
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
        .await
        .map(|(set, ())| set)
    }

    /// Remove a mark. Removing one that is already gone succeeds: two viewers
    /// deleting the same mark want the same outcome, and the second should not
    /// be told it failed.
    pub async fn delete_mark(&self, stream: &str, id: &str) -> Result<MarkSet, MarkRefusal> {
        if !valid_id(id) {
            return Err(MarkRefusal::NotFound);
        }
        let id = id.to_owned();
        self.mutate_marks(stream, move |set| {
            let before = set.marks.len();
            set.marks.retain(|m| m.id != id);
            Ok(((), set.marks.len() != before))
        })
        .await
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
        // 404 is what the player keeps a new mark pending on and tries again,
        // so a mark made in the seconds before the first segment lands is
        // posted once it has.
        MarkRefusal::NoStream => (
            StatusCode::NOT_FOUND,
            no_store,
            "the relay holds nothing for this feed to mark",
        )
            .into_response(),
        MarkRefusal::Io(e) => {
            tracing::warn!(stream = %stream, error = %e, "origin: marks could not be read or written");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [
                    (header::CACHE_CONTROL, "no-store"),
                    (header::RETRY_AFTER, "3"),
                ],
                "could not read or write the marks",
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
    let set = match st.origin.list_marks(&stream).await {
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
    match st.origin.add_mark(&stream, new).await {
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
    match st.origin.edit_mark(&stream, &id, edit).await {
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
    match st.origin.delete_mark(&stream, &id).await {
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

    /// Give `stream` the directory ingest would have made: marks are written
    /// only into one that exists.
    fn ingested(tmp: &tempfile::TempDir, stream: &str) {
        std::fs::create_dir_all(tmp.path().join("origin").join(stream)).unwrap();
    }

    fn at(ms: i64) -> NewMark {
        NewMark {
            at: ms,
            name: String::new(),
            colour: String::new(),
            exported: false,
        }
    }

    #[tokio::test]
    async fn a_mark_one_viewer_makes_is_the_list_every_viewer_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        assert!(s.list_marks("feed").await.unwrap().marks.is_empty());
        assert_eq!(s.list_marks("feed").await.unwrap().etag(), "\"marks-none\"");

        let (set, id) = s.add_mark("feed", at(T0 + 5_000)).await.unwrap();
        assert_eq!(set.rev, 1);
        let (set, _) = s.add_mark("feed", at(T0)).await.unwrap();
        assert_eq!(set.rev, 2);
        // Sorted by instant, not by arrival — the order the list is drawn in.
        let listed = s.list_marks("feed").await.unwrap();
        assert_eq!(
            listed.marks.iter().map(|m| m.at).collect::<Vec<_>>(),
            vec![T0, T0 + 5_000]
        );
        assert!(listed.marks.iter().any(|m| m.id == id));
        // Another stream's list is another list.
        assert!(s.list_marks("other").await.unwrap().marks.is_empty());
    }

    #[tokio::test]
    async fn the_same_instant_twice_is_one_mark_and_no_new_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        let (_, first) = s.add_mark("feed", at(T0)).await.unwrap();
        let etag = s.list_marks("feed").await.unwrap().etag();
        let (set, again) = s.add_mark("feed", at(T0)).await.unwrap();
        assert_eq!(first, again, "a retried mark was stored twice");
        assert_eq!(set.marks.len(), 1);
        assert_eq!(
            set.etag(),
            etag,
            "a no-op changed the validator, waking every poller"
        );
    }

    #[tokio::test]
    async fn edits_apply_only_what_they_name_and_a_no_op_keeps_the_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        let (_, id) = s.add_mark("feed", at(T0)).await.unwrap();
        let set = s
            .edit_mark(
                "feed",
                &id,
                MarkEdit {
                    name: Some("Goal".into()),
                    ..Default::default()
                },
            )
            .await
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
            .await
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
            .await
            .unwrap();
        assert_eq!(
            set.rev, rev,
            "an edit that changed nothing bumped the revision"
        );

        assert!(matches!(
            s.edit_mark("feed", "abc123", MarkEdit::default()).await,
            Err(MarkRefusal::NotFound)
        ));
    }

    #[tokio::test]
    async fn deleting_twice_succeeds_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        let (_, id) = s.add_mark("feed", at(T0)).await.unwrap();
        assert!(s.delete_mark("feed", &id).await.unwrap().marks.is_empty());
        let rev = s.list_marks("feed").await.unwrap().rev;
        let set = s.delete_mark("feed", &id).await.unwrap();
        assert_eq!(set.rev, rev, "deleting nothing was recorded as a change");
    }

    #[tokio::test]
    async fn malformed_marks_are_refused_before_they_are_stored() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        // Seconds where milliseconds were meant: a mark nobody could place.
        assert!(matches!(
            s.add_mark("feed", at(1_790_000_000)).await,
            Err(MarkRefusal::Invalid(_))
        ));
        let mut bad = at(T0);
        bad.colour = "red; background:url(x)".into();
        assert!(matches!(
            s.add_mark("feed", bad).await,
            Err(MarkRefusal::Invalid(_))
        ));
        let mut bad = at(T0);
        bad.name = "x".repeat(MAX_MARK_NAME_CHARS + 1);
        let Err(MarkRefusal::Invalid(why)) = s.add_mark("feed", bad).await else {
            panic!("a name past the limit was stored");
        };
        // The operator is shown this, so it must state the limit as it is.
        assert!(
            why.contains(&format!("at most {MAX_MARK_NAME_CHARS} characters")),
            "{why}"
        );
        let mut exactly = at(T0 + 1);
        exactly.name = "x".repeat(MAX_MARK_NAME_CHARS);
        assert!(
            s.add_mark("feed", exactly).await.is_ok(),
            "a name at the limit was refused"
        );
        let mut bad = at(T0);
        bad.name = "line\nbreak".into();
        assert!(matches!(
            s.add_mark("feed", bad).await,
            Err(MarkRefusal::Invalid(_))
        ));
        // A name in any script is fine: it is only ever drawn as text.
        let mut ok = at(T0);
        ok.name = "Goal — Müller's header".into();
        assert!(s.add_mark("feed", ok).await.is_ok());
        // An id that is not one of ours never reaches the file.
        assert!(matches!(
            s.delete_mark("feed", "../x").await,
            Err(MarkRefusal::NotFound)
        ));
        // Nor does a stream name that would escape the root.
        assert!(s.list_marks("..").await.is_err());
    }

    #[tokio::test]
    async fn a_stream_is_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        for i in 0..MAX_MARKS_PER_STREAM as i64 {
            s.add_mark("feed", at(T0 + i)).await.unwrap();
        }
        assert!(matches!(
            s.add_mark("feed", at(T0 - 1)).await,
            Err(MarkRefusal::TooMany)
        ));
    }

    #[tokio::test]
    async fn a_list_started_again_does_not_answer_an_old_validator() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        ingested(&tmp, "feed");
        s.add_mark("feed", at(T0)).await.unwrap();
        let old = s.list_marks("feed").await.unwrap().etag();
        std::fs::remove_dir_all(tmp.path().join("origin/feed")).unwrap();
        // A new session under the same name ingests, and is marked.
        ingested(&tmp, "feed");
        s.add_mark("feed", at(T0 + 1)).await.unwrap();
        let new = s.list_marks("feed").await.unwrap();
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

    /// A list that will not parse — a hand edit, or a zero-length file after
    /// a power cut — is recovered by the first request of any kind.
    ///
    /// Recovery used to happen on a write only, while a read answered an
    /// error. A player that could not read the list never wrote to it, so a
    /// feed nobody happened to mark stayed broken for every viewer.
    #[tokio::test]
    async fn an_unreadable_list_is_set_aside_by_a_read_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let dir = tmp.path().join("origin/feed").join(MARKS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MARKS_FILE), b"{not json").unwrap();
        let unreadable = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains("unreadable"))
                .count()
        };

        let listed = s
            .list_marks("feed")
            .await
            .expect("a corrupt list was an error to a read, not recovered");
        assert!(listed.marks.is_empty());
        assert_eq!(
            unreadable(),
            1,
            "the unreadable list was destroyed rather than kept for recovery"
        );
        assert!(
            !dir.join(MARKS_FILE).exists(),
            "the corrupt file is still in place"
        );

        s.add_mark("feed", at(T0)).await.unwrap();
        assert_eq!(s.list_marks("feed").await.unwrap().marks.len(), 1);
        assert_eq!(unreadable(), 1, "a healthy list was set aside as well");
    }

    /// A stream the relay holds no directory for — nothing ingested yet, or
    /// dropped by the manager — reads as an empty list and is never written.
    ///
    /// A viewer token is stateless and outlives the session, so a mark could
    /// arrive after the drop and quietly re-create the directory, where only
    /// the seven-day backstop would ever find it.
    #[tokio::test]
    async fn a_stream_the_relay_does_not_hold_is_read_as_empty_and_never_written() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let stream_dir = tmp.path().join("origin/feed");

        let listed = s.list_marks("feed").await.unwrap();
        assert!(listed.marks.is_empty());
        assert_eq!(listed.etag(), "\"marks-none\"");
        assert!(matches!(
            s.add_mark("feed", at(T0)).await,
            Err(MarkRefusal::NoStream)
        ));
        assert!(
            !stream_dir.exists(),
            "a refused mark created the stream's directory"
        );

        // The one write that can lose that race — the store itself — makes
        // `marks/` and nothing above it.
        let refused = super::store(
            &stream_dir.join(MARKS_DIR).join(MARKS_FILE),
            &MarkSet::default(),
        )
        .expect_err("a list was written for a stream with no directory");
        assert_eq!(refused.kind(), std::io::ErrorKind::NotFound);
        assert!(!stream_dir.exists(), "a write re-created a dropped stream");
    }

    /// A drop waits for a marks write in progress, so the write lands before
    /// the directory goes, and goes with it, or finds no directory. Without
    /// the lock a write that had passed its check would have the directory
    /// moved from under it halfway — or, where the drop cannot rename and
    /// deletes in place, could make `marks/` behind `remove_dir_all`'s walk,
    /// whose last rmdir then failed and left the list behind with a `201`
    /// sent for it.
    #[tokio::test]
    async fn a_drop_waits_for_a_marks_write_in_progress() {
        let tmp = tempfile::tempdir().unwrap();
        let s = std::sync::Arc::new(store(&tmp));
        ingested(&tmp, "feed");
        let stream_dir = tmp.path().join("origin/feed");

        let writing = s.lock_marks().await;
        let dropping = tokio::spawn({
            let s = s.clone();
            async move { s.remove_stream("feed").await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            stream_dir.exists(),
            "the drop went ahead under a marks write in progress"
        );
        drop(writing);
        dropping.await.unwrap();
        assert!(!stream_dir.exists(), "the drop did not happen once free");
        assert!(matches!(
            s.add_mark("feed", at(T0)).await,
            Err(MarkRefusal::NoStream)
        ));
    }

    /// Marks writers waiting for the lock wait as tasks, not on threads of
    /// the blocking pool — the pool every `tokio::fs` call in the relay
    /// shares, segment ingest for every stream included. Each write holds the
    /// lock across two fsyncs, so writers queued there on threads could fill
    /// the pool and stall everything behind them.
    #[test]
    fn marks_writers_queue_without_holding_blocking_threads() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let tmp = tempfile::tempdir().unwrap();
            let s = std::sync::Arc::new(store(&tmp));
            ingested(&tmp, "feed");

            // A write in progress, and more than the pool's worth queued
            // behind it.
            let writing = s.lock_marks().await;
            let writers: Vec<_> = (0..4)
                .map(|i| {
                    let s = s.clone();
                    tokio::spawn(async move { s.add_mark("feed", at(T0 + i)).await })
                })
                .collect();
            tokio::time::sleep(Duration::from_millis(100)).await;

            let io =
                tokio::time::timeout(Duration::from_secs(2), tokio::fs::metadata(tmp.path())).await;
            assert!(
                io.is_ok(),
                "queued marks writers held the blocking pool, and file I/O waited behind them"
            );

            drop(writing);
            for w in writers {
                w.await.unwrap().unwrap();
            }
            assert_eq!(s.list_marks("feed").await.unwrap().marks.len(), 4);
        });
    }

    /// A write's lock is released when the write is done, not when its
    /// request is. A client that hangs up drops the handler, and the blocking
    /// work the handler started goes on; a guard dropped with the handler let
    /// the next writer read the list while this one was still between its
    /// read and its rename, and one of the two marks was lost.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_write_whose_request_is_dropped_holds_the_lock_until_it_is_done() {
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().unwrap();
        let s = std::sync::Arc::new(store(&tmp));
        ingested(&tmp, "feed");
        // A list whose read waits until the test lets it through: a FIFO.
        let dir = tmp.path().join("origin/feed").join(MARKS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join(MARKS_FILE);
        let c = std::ffi::CString::new(list.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let writer = tokio::spawn({
            let s = s.clone();
            async move { s.add_mark("feed", at(T0)).await }
        });
        // The lock is taken, and the write is on the blocking pool with it.
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.marks_lock.try_lock().is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fixture: the write never took the lock");

        // The client hangs up.
        writer.abort();
        let _ = writer.await;
        let released_early = s.marks_lock.try_lock().is_ok();

        // Let the read through before asserting anything: a blocking task
        // still waiting on the FIFO would hold the runtime open, and the test
        // would hang rather than fail.
        std::fs::write(&list, br#"{"epoch":"e","rev":1,"marks":[]}"#).unwrap();
        assert!(
            !released_early,
            "the lock went with the request while the write it guards was still running"
        );
        let freed = tokio::time::timeout(Duration::from_secs(5), s.lock_marks()).await;
        assert!(freed.is_ok(), "the write never gave the lock back");
        drop(freed);
        assert_eq!(s.list_marks("feed").await.unwrap().marks.len(), 1);
    }

    /// `500` is the token gate's alone, the one refusal the player takes as
    /// "this relay has no shared marks" for good. A disk that failed once
    /// must read as worth trying again.
    #[test]
    fn a_failed_read_or_write_is_retryable_and_not_the_gates_500() {
        let r = refusal("feed", MarkRefusal::Io(std::io::Error::other("disk")));
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            r.headers().get(header::RETRY_AFTER).map(|v| v.as_bytes()),
            Some(&b"3"[..])
        );
        assert_eq!(
            r.headers().get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
            Some(&b"no-store"[..])
        );
        // What the player keeps a new mark pending on.
        assert_eq!(
            refusal("feed", MarkRefusal::NoStream).status(),
            StatusCode::NOT_FOUND
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
            s.add_mark("feed", at(T0)).await.unwrap();
        }
        // Restart: adoption treats anything that is not a segment as debris.
        // What keeps `marks/` out of that is `is_session_subdir`, pinned by
        // its own test in `origin.rs`; this checks the outcome.
        let s = store(&tmp);
        assert_eq!(
            s.list_marks("feed").await.unwrap().marks.len(),
            1,
            "a restart lost the marks"
        );

        // The feed drops for longer than retention: media goes, marks stay.
        s.retire_stream("feed").await;
        assert_eq!(
            s.list_marks("feed").await.unwrap().marks.len(),
            1,
            "a feed drop lost the marks"
        );

        // The session is over.
        s.remove_stream("feed").await;
        assert!(
            s.list_marks("feed").await.unwrap().marks.is_empty(),
            "the session's marks outlived it"
        );
        // And a viewer still holding a token cannot bring them back.
        assert!(matches!(
            s.add_mark("feed", at(T0 + 1)).await,
            Err(MarkRefusal::NoStream)
        ));
        assert!(
            !tmp.path().join("origin/feed").exists(),
            "a mark after the drop re-created the stream's directory"
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
