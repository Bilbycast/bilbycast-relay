// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-viewer WHEP session: SDP answer + the send loop that fans one
//! stream's elementary frames out to one browser over DTLS/SRTP.
//!
//! The relay is **not** a true encrypt-once SFU — like the edge, each viewer
//! owns an independent str0m PeerConnection with its own SRTP context. But
//! unlike the edge it does the expensive demux/transcode work **zero** times
//! (the edge already shipped browser-ready H.264+Opus), so the per-viewer
//! cost collapses to RTP-packetize + SRTP-encrypt — and, decisively, the
//! fan-out lives on the public relay instead of the NAT'd, uplink-capped edge.
//!
//! The RTP packetizing is str0m's: each H.264 access unit goes to str0m's
//! writer once, whole, as Annex B. The hub has already put the stream's SPS /
//! PPS back ahead of any IDR that lacked them (`DistributionHub::publish`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use str0m::media::{Frequency, MediaTime};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use super::es::{EsFrame, EsKind};
use super::hub::{DistributionHub, StreamSubscription};
use super::webrtc::session::{SessionConfig, SessionEnd, WebrtcSession};
use super::webrtc::{SETUP_DEADLINE, Setup, await_connected};
use crate::manager::events::{category, EventSender, EventSeverity};

/// How often a viewer's session is driven when no frame has arrived to drive
/// it: answering the browser's STUN consent checks and running str0m's
/// timeouts, ICE giving up on a departed viewer among them. A browser checks
/// consent every few seconds, so a second's delay costs nothing.
const IDLE_DRIVE_INTERVAL: Duration = Duration::from_secs(1);

/// Handle returned to the HTTP signaling layer once a viewer's SDP offer has
/// been accepted. The send loop is already running in a detached task.
pub struct ViewerHandle {
    pub session_id: String,
    pub answer_sdp: String,
    /// Cancels exactly this viewer (DELETE /whep/{session_id}).
    pub cancel: CancellationToken,
}

/// Create a WHEP viewer session from an SDP offer, answer it, and spawn the
/// per-viewer send loop. Returns the answer SDP + a session id + a cancel
/// token scoped to this one viewer.
pub async fn create_and_spawn_viewer(
    hub: Arc<DistributionHub>,
    stream_id: String,
    offer_sdp: &str,
    public_ip: Option<IpAddr>,
    parent_cancel: CancellationToken,
    events: EventSender,
) -> Result<ViewerHandle> {
    // ICE-Lite server role. Bind to the public IP if pinned so the per-packet
    // destination matches the advertised host candidate; else 0.0.0.0:0.
    let bind_addr = match public_ip {
        Some(ip) => std::net::SocketAddr::new(ip, 0),
        None => "0.0.0.0:0".parse().unwrap(),
    };
    let session_config = SessionConfig { bind_addr, public_ip, ice_lite: true };

    let mut session = WebrtcSession::new(&session_config)
        .await
        .context("failed to create WebRTC session")?;

    let answer_sdp = session
        .accept_offer(offer_sdp)
        .context("failed to accept SDP offer")?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let cancel = parent_cancel.child_token();

    let subscription = hub.subscribe(&stream_id);

    let loop_cancel = cancel.clone();
    let loop_stream = stream_id.clone();
    let loop_sid = session_id.clone();
    tokio::spawn(async move {
        // Cancel our own token however this task ends — natural exit (viewer
        // disconnect / ingest gone) or a panic unwinding out of str0m — so any
        // lifecycle watcher (the per-IP reaper, the session registry cleanup)
        // fires on explicit DELETE, natural end and a crash alike. A plain
        // `cancel()` after the loop is skipped by a panic, and the viewer's
        // per-IP slot leaked with it.
        let _cancel_on_exit = loop_cancel.clone().drop_guard();
        viewer_loop(
            session,
            subscription,
            Tokens {
                viewer: loop_cancel,
                service: parent_cancel,
            },
            &loop_stream,
            &loop_sid,
            &events,
        )
        .await;
    });

    Ok(ViewerHandle { session_id, answer_sdp, cancel })
}

/// A viewer's cancellation token, and the distribution service's it is a
/// child of — which of the two fired is what tells a client's `DELETE` from
/// the relay stopping.
struct Tokens {
    viewer: CancellationToken,
    service: CancellationToken,
}

/// Why a WHEP viewer ended: what its last log line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewerEnd {
    /// `DELETE /whep/{stream}/{session}`.
    Deleted,
    /// The distribution service stopped.
    Stopped,
    /// ICE + DTLS did not complete within [`SETUP_DEADLINE`].
    SetupTimedOut,
    /// The viewer negotiated no video, or no H.264 PT on it.
    NoVideo,
    /// The stream's broadcast closed: its ingest is gone.
    StreamClosed,
    /// The session itself ended.
    Session(SessionEnd),
}

impl std::fmt::Display for ViewerEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewerEnd::Deleted => f.write_str("deleted by the client"),
            ViewerEnd::Stopped => f.write_str("the distribution service stopped"),
            ViewerEnd::SetupTimedOut => {
                write!(f, "ICE + DTLS not complete within {SETUP_DEADLINE:?}")
            }
            ViewerEnd::NoVideo => f.write_str("no H.264 video negotiated"),
            ViewerEnd::StreamClosed => f.write_str("stream closed"),
            ViewerEnd::Session(end) => write!(f, "{end}"),
        }
    }
}

impl ViewerEnd {
    /// Why a viewer ended that was not cut short by its stream or its setup:
    /// a cancel — the client's `DELETE`, or the service stopping — or the
    /// session's own end. A session that has not ended by
    /// [`WebrtcSession::end`]'s measure was ended by ICE going `Disconnected`
    /// during setup, which `await_connected` takes at once.
    fn of(session: &WebrtcSession, tokens: &Tokens) -> Self {
        if tokens.service.is_cancelled() {
            ViewerEnd::Stopped
        } else if tokens.viewer.is_cancelled() {
            ViewerEnd::Deleted
        } else {
            ViewerEnd::Session(session.end().unwrap_or(SessionEnd::IceDisconnected))
        }
    }
}

/// The per-viewer send loop. Every way out of it ends the viewer: the task's
/// drop guard cancels the session's token, and the reaper in
/// `distribution::whep_offer` then drops the session record and the per-IP
/// slot. Its last log line says why it ended.
async fn viewer_loop(
    mut session: WebrtcSession,
    sub: StreamSubscription,
    tokens: Tokens,
    stream_id: &str,
    session_id: &str,
    events: &EventSender,
) {
    let end = send_to_viewer(&mut session, sub, &tokens, stream_id, session_id, events).await;
    tracing::info!("WHEP viewer '{session_id}' closed (stream '{stream_id}'): {end}");
}

/// Connect the viewer, then send it the stream until something ends it;
/// returns what did.
async fn send_to_viewer(
    session: &mut WebrtcSession,
    mut sub: StreamSubscription,
    tokens: &Tokens,
    stream_id: &str,
    session_id: &str,
    events: &EventSender,
) -> ViewerEnd {
    let cancel = &tokens.viewer;
    // 1. Wait for ICE + DTLS to complete — for `SETUP_DEADLINE` at most.
    match await_connected(session, cancel, SETUP_DEADLINE).await {
        Setup::Connected => {
            tracing::info!("WHEP viewer '{session_id}' connected on stream '{stream_id}'");
        }
        Setup::Disconnected => return ViewerEnd::of(session, tokens),
        Setup::TimedOut => {
            tracing::warn!(
                "WHEP viewer '{session_id}' did not complete ICE + DTLS within {SETUP_DEADLINE:?} \
                 (stream '{stream_id}'); closing it"
            );
            return ViewerEnd::SetupTimedOut;
        }
    }

    // str0m may emit MediaAdded after Connected — flush so the MIDs are set.
    session.drain_pending_events();

    let Some(video_mid) = session.video_mid else {
        tracing::warn!("WHEP viewer '{session_id}': no video MID negotiated");
        return ViewerEnd::NoVideo;
    };
    let Some(video_pt) = session.get_pt(video_mid) else {
        tracing::warn!("WHEP viewer '{session_id}': no video PT negotiated");
        return ViewerEnd::NoVideo;
    };
    let audio = session
        .audio_mid
        .and_then(|mid| session.get_pt(mid).map(|pt| (mid, pt)));

    // 2. Prime the decoder with the cached keyframe so a late joiner starts
    //    immediately instead of waiting for the source's next IDR.
    if let Some(kf) = sub.keyframe.take() {
        write_video(session, video_mid, video_pt, &kf.frame, &sub).await;
    }

    // 3. Main fan-out loop. A viewer that leaves without a DELETE — a closed
    //    tab, a lost network — surfaces only as str0m's ICE agent giving up,
    //    reported from whichever drain ran its timeouts, and it ends the
    //    session once ICE has stayed down for `ICE_DISCONNECT_GRACE`. So the
    //    session is driven when no frame comes too (a stalled stream, or one
    //    whose ingest is gone) — which is also what lets the grace lapse — and
    //    `is_disconnected` is checked after every write and every drive.
    //    Before, the event was dropped and nothing drove an idle session: the
    //    departed viewer was sent the stream, and held its per-IP slot, for as
    //    long as the stream lived.
    let mut idle = tokio::time::interval(IDLE_DRIVE_INTERVAL);
    idle.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let end = loop {
        if session.is_disconnected() {
            break ViewerEnd::of(session, tokens);
        }
        tokio::select! {
            _ = cancel.cancelled() => break ViewerEnd::of(session, tokens),
            recv = sub.rx.recv() => match recv {
                Ok(frame) => {
                    match frame.kind {
                        EsKind::VideoH264 => {
                            write_video(session, video_mid, video_pt, &frame, &sub).await;
                        }
                        EsKind::AudioOpus => {
                            if let Some((amid, apt)) = audio {
                                write_audio(session, amid, apt, &frame, &sub).await;
                            }
                        }
                    }
                    // Keep ICE/DTLS/RTCP alive between media writes.
                    session.drive_udp_io().await;
                    report_offpath(session, events, stream_id, session_id, &sub);
                }
                Err(RecvError::Lagged(_)) => {
                    // Viewer fell behind — resync happens naturally on the
                    // next keyframe. Keep going.
                }
                Err(RecvError::Closed) => break ViewerEnd::StreamClosed, // ingest gone
            },
            _ = idle.tick() => {
                session.drive_udp_io().await;
                report_offpath(session, events, stream_id, session_id, &sub);
            }
        }
    };

    // A session can be torn down by the pin's own consequence (its pairs get
    // pruned), so check once more on the way out — otherwise the very sessions
    // the control kills are the ones that never report why.
    report_offpath(session, events, stream_id, session_id, &sub);
    end
}

/// Surface the WebRTC ingress source pin's first drop for this session: one
/// Warning event to the manager plus one telemetry increment. Both are
/// one-shot — `take_offpath_alert` clears the latch, so a reflection flood
/// (which is a flood by construction) cannot turn the alarm into its own
/// amplifier.
///
/// This exists because the control WILL fire on a legitimate viewer whose
/// public IP changes mid-session (Wi-Fi → cellular, CGNAT pool rotation).
/// Without it the viewer just goes black and the only evidence is one `warn!`
/// line on a headless relay.
fn report_offpath(
    session: &mut WebrtcSession,
    events: &EventSender,
    stream_id: &str,
    session_id: &str,
    sub: &StreamSubscription,
) {
    let Some((pinned, offender)) = session.take_offpath_alert() else {
        return;
    };
    sub.state.add_offpath_session();
    events.emit_with_id_and_details(
        EventSeverity::Warning,
        category::DISTRIBUTION,
        "WHEP viewer: off-path datagram dropped by the media source pin",
        session_id,
        serde_json::json!({
            "error_code": "webrtc_offpath_source",
            "stream": stream_id,
            "session_id": session_id,
            "pinned_ip": pinned.to_string(),
            "source_addr": offender.to_string(),
            "source_ip": offender.ip().to_string(),
        }),
    );
}

/// Hand one video access unit to str0m (see [`write_video_au_on`]) and count
/// it on the stream's bytes-out.
async fn write_video(
    session: &mut WebrtcSession,
    mid: str0m::media::Mid,
    pt: str0m::media::Pt,
    frame: &EsFrame,
    sub: &StreamSubscription,
) {
    let bytes = write_video_au_on(session, mid, pt, frame.pts_90k, &frame.data).await;
    sub.state.add_bytes_out(bytes as u64);
}

/// Send one H.264 access unit on a known (mid, pt) as **one** str0m frame,
/// Annex B. Returns the number of access-unit bytes written.
///
/// str0m's writer packetizes a frame itself (RFC 6184): the SPS / PPS go out
/// as one STAP-A ahead of the next slice, a NAL past its MTU as FU-A, every
/// packet carries the frame's RTP timestamp and only the frame's last one
/// the marker bit. Each NAL used to be packetized here first and every RTP
/// payload written as a frame of its own, so str0m packetized the packets.
/// It fragmented each 1200-byte FU-A again at its own, smaller payload size,
/// so a receiver reassembled type-28 "NAL units" out of every IDR and large
/// slice, decoded no picture from them, and got every fragment as a
/// marker-bit frame of its own. A browser received video, decoded none of it
/// and asked for a keyframe forever. bilbycast-edge fixed the same fault in
/// its WebRTC output (e927368).
async fn write_video_au_on(
    session: &mut WebrtcSession,
    mid: str0m::media::Mid,
    pt: str0m::media::Pt,
    pts_90k: u64,
    au: &[u8],
) -> usize {
    let media_time = MediaTime::new(pts_90k, Frequency::NINETY_KHZ);
    if let Err(e) = session.write_media(mid, pt, Instant::now(), media_time, au) {
        tracing::trace!("video write error: {e}");
    }
    // str0m queues up to 512 writes (`MAX_PENDING_PAYLOADS`) and packetizes
    // them only from a timeout; drain now so the unit's packets go out at once
    // and the queue never nears that cap.
    session.drain_outputs().await;
    au.len()
}

/// Send one H.264 access unit over a session, resolving the video (mid, pt)
/// from the session's negotiated tracks. Used by a WHIP *client* (the edge,
/// or an integration test) to push media. No-op until video is negotiated.
pub async fn write_video_au(session: &mut WebrtcSession, pts_90k: u64, au: &[u8]) -> usize {
    let Some(mid) = session.video_mid else { return 0 };
    let Some(pt) = session.get_pt(mid) else { return 0 };
    write_video_au_on(session, mid, pt, pts_90k, au).await
}

/// Write one Opus frame to str0m at the 48 kHz audio clock.
async fn write_audio(
    session: &mut WebrtcSession,
    mid: str0m::media::Mid,
    pt: str0m::media::Pt,
    frame: &EsFrame,
    sub: &StreamSubscription,
) {
    // Source PTS is 90 kHz; Opus RTP runs at 48 kHz.
    let media_time = MediaTime::new(frame.pts_90k * 48_000 / 90_000, Frequency::FORTY_EIGHT_KHZ);
    if let Err(e) = session.write_media(mid, pt, Instant::now(), media_time, &frame.data) {
        tracing::trace!("WHEP audio write error: {e}");
    }
    session.drain_outputs().await;
    sub.state.add_bytes_out(frame.data.len() as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A viewer's last log line says why it ended: a client's `DELETE` (its
    /// own token cancelled) apart from the relay stopping (the service's,
    /// which cancels the viewer's with it), and either apart from the
    /// session's own end.
    #[tokio::test]
    async fn a_viewers_last_line_names_what_ended_it() {
        let service = CancellationToken::new();
        let tokens = Tokens {
            viewer: service.child_token(),
            service: service.clone(),
        };
        let mut session = WebrtcSession::new(&SessionConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_ip: None,
            ice_lite: true,
        })
        .await
        .unwrap();

        // What `await_connected` ends on before the session has ended by its
        // own measure: ICE's first disconnect.
        assert_eq!(
            ViewerEnd::of(&session, &tokens),
            ViewerEnd::Session(SessionEnd::IceDisconnected)
        );
        session.close();
        assert_eq!(
            ViewerEnd::of(&session, &tokens),
            ViewerEnd::Session(SessionEnd::Closed)
        );
        tokens.viewer.cancel();
        assert_eq!(ViewerEnd::of(&session, &tokens), ViewerEnd::Deleted);
        service.cancel();
        assert_eq!(ViewerEnd::of(&session, &tokens), ViewerEnd::Stopped);

        for (end, line) in [
            (ViewerEnd::Deleted, "deleted by the client"),
            (ViewerEnd::Stopped, "the distribution service stopped"),
            (
                ViewerEnd::SetupTimedOut,
                "ICE + DTLS not complete within 30s",
            ),
            (ViewerEnd::NoVideo, "no H.264 video negotiated"),
            (ViewerEnd::StreamClosed, "stream closed"),
            (
                ViewerEnd::Session(SessionEnd::IceDisconnected),
                "ICE disconnected",
            ),
            (ViewerEnd::Session(SessionEnd::Closed), "DTLS closed"),
        ] {
            assert_eq!(end.to_string(), line);
        }
    }
}
