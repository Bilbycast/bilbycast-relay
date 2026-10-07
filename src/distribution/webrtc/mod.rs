// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebRTC (str0m) plumbing for the relay's viewer-distribution SFU.
//!
//! Vendored from bilbycast-edge — the relay runs the ICE-Lite **server**
//! role only (per-viewer WHEP sessions). See the module docs in each file.
//!
//! There is no RTP packetizer here: str0m's writer packetizes each H.264
//! access unit it is handed (see `whep::write_video_au_on`). The relay's own
//! RFC 6184 packetizer (`rtp_h264`, vendored from the edge) was removed with
//! the edge's own copy — feeding its packets to str0m packetized them twice.

pub mod session;

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use self::session::{SessionEvent, WebrtcSession};

/// How long a session may take, from the SDP exchange, to complete ICE and
/// DTLS. Ample for any peer that is going to connect at all: ICE-Lite has
/// nothing to gather, and a browser connects in well under a second.
///
/// Without a bound a session waited for `Connected` for ever. An ICE-Lite
/// agent with no remote candidate never fails (`is` counts "no remote
/// candidates yet" as still possible), so an offer without `a=candidate`
/// lines whose sender never sends STUN — a trickle-ICE client that gave up,
/// or anyone at all on the public WHEP endpoint — held its session, UDP
/// socket, task and per-IP viewer slot until a DELETE that need never come.
pub const SETUP_DEADLINE: Duration = Duration::from_secs(30);

/// How a session's setup ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Setup {
    /// ICE and DTLS completed.
    Connected,
    /// str0m gave up, or `cancel` fired, first.
    Disconnected,
    /// Neither within the deadline. The caller drops the session.
    TimedOut,
}

/// Drive `session` until ICE and DTLS complete, for `within` at most.
///
/// The WHEP viewer, WHIP ingest and cascade pull all wait for `Connected` this
/// way, each with [`SETUP_DEADLINE`]; every one ends its session on anything
/// but [`Setup::Connected`], and dropping it is what gives back the socket and,
/// for a viewer, the per-IP slot.
pub async fn await_connected(
    session: &mut WebrtcSession,
    cancel: &CancellationToken,
    within: Duration,
) -> Setup {
    let setup = async {
        loop {
            match session.poll_event(cancel).await {
                SessionEvent::Connected => return Setup::Connected,
                SessionEvent::Disconnected => return Setup::Disconnected,
                _ => {}
            }
        }
    };
    tokio::time::timeout(within, setup)
        .await
        .unwrap_or(Setup::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::webrtc::session::SessionConfig;

    async fn session(ice_lite: bool) -> WebrtcSession {
        WebrtcSession::new(&SessionConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_ip: Some("127.0.0.1".parse().unwrap()),
            ice_lite,
        })
        .await
        .unwrap()
    }

    /// An offer without candidates whose sender never sends STUN: the
    /// ICE-Lite side stays in Checking for ever, so the wait ends at the
    /// deadline. Unbounded, it did not end at all.
    #[tokio::test]
    async fn a_peer_that_never_connects_times_out() {
        let mut client = session(false).await;
        let (offer, _pending) = client.create_offer(true, true, false).unwrap();
        let offer: String = offer
            .split_inclusive('\n')
            .filter(|l| !l.starts_with("a=candidate"))
            .collect();
        let mut server = session(true).await;
        server.accept_offer(&offer).unwrap();
        drop(client);

        let started = std::time::Instant::now();
        let cancel = CancellationToken::new();
        let setup = tokio::time::timeout(
            Duration::from_secs(10),
            await_connected(&mut server, &cancel, Duration::from_millis(300)),
        )
        .await
        .expect("the wait must end at its own deadline");
        assert_eq!(setup, Setup::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    /// A peer that does connect is reported connected, and a cancel ends the
    /// wait as a disconnect.
    #[tokio::test]
    async fn a_connecting_peer_connects_and_a_cancel_ends_the_wait() {
        let mut client = session(false).await;
        let (offer, pending) = client.create_offer(true, true, false).unwrap();
        let mut server = session(true).await;
        let answer = server.accept_offer(&offer).unwrap();
        client.apply_answer(&answer, pending).unwrap();

        let cancel = CancellationToken::new();
        let (a, b) = tokio::join!(
            await_connected(&mut client, &cancel, SETUP_DEADLINE),
            await_connected(&mut server, &cancel, SETUP_DEADLINE),
        );
        assert_eq!((a, b), (Setup::Connected, Setup::Connected));

        let mut idle = session(true).await;
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            await_connected(&mut idle, &cancelled, SETUP_DEADLINE).await,
            Setup::Disconnected
        );
    }
}
