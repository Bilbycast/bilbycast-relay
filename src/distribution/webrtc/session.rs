// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebRTC session wrapper around str0m.
//!
//! VENDORED from `bilbycast-edge::engine::webrtc::session`. Depends only on
//! str0m + tokio + anyhow — zero edge-internal types — so it lifts cleanly.
//! The relay uses it in the ICE-Lite **server** role only (per-viewer WHEP).
//! Keep in sync with the edge; the SDP-normalise / `is`-ICE-priority
//! interop workarounds and the codec set ([`H264_LEVEL_5_1`]) must not diverge
//! across the two str0m deployments — the edge's WHIP output negotiates with
//! this file's WHIP ingest.
//!
//! **KNOWN, DELIBERATE DIVERGENCE — do not "resync" it away.** This copy
//! carries a security control the edge copy does not: [`PeerPin`], an ingress
//! source filter closing an ICE-Lite peer-reflexive UDP reflector (a spoofed
//! STUN Binding Request from a credentialed client repoints the whole SRTP
//! stream at the spoofed address). The edge runs the same vendored state
//! machine in the same ICE-Lite server role from `engine::input_webrtc`
//! (WHIP ingest) and `engine::output_webrtc` (WHEP output) on the same str0m
//! release (see either Cargo.toml — deliberately not a numeral here, since the
//! two crates move in lockstep and a number goes stale on every bump while the
//! claim it supports does not), and therefore still has the reflector. That is
//! recorded as accepted residual risk, not as fixed: the edge's WHIP/WHEP
//! routes sit behind `auth_middleware`, so exploiting it costs one valid edge
//! API credential — which any legitimate WHEP viewer of that edge holds.
//! Porting `PeerPin` across is the fix; until then, a sync in either direction
//! must carry this control forward, never delete it.
//!
//! The disconnect latch ([`WebrtcSession::is_disconnected`], with
//! [`ICE_DISCONNECT_GRACE`] and [`SessionEnd`]) is relay-only too: the WHEP
//! send loop reaps a departed viewer by it. Carry it forward in a sync as
//! well, and the handling of `Event::Closed` with it.
//!
//! Manages the lifecycle of a single WebRTC PeerConnection: ICE, DTLS,
//! SRTP, and media I/O. Integrates str0m's sans-I/O model with tokio
//! by driving the UDP socket and str0m poll loop in a select! loop.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use str0m::change::SdpOffer;
use str0m::format::{Codec, PayloadParams};
use str0m::media::{Direction, MediaKind, MediaTime, Mid, Pt};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use str0m::net::Protocol;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// The H.264 entries every session registers, as `(pt, rtx_pt,
/// packetization_mode_1, profile_level_id)`: str0m 0.24.1's own seven
/// built-in entries (`CodecConfig::enable_h264`) with the same payload type,
/// RTX payload type, packetization mode and profile, and only the level byte
/// raised from 3.1 (`0x1f`) to 5.1 (`0x33`). With Opus they are the whole
/// codec set — see [`rtc_config`].
///
/// **Why level 5.1.** str0m answers with its own `profile-level-id` and never
/// narrows or raises an H.264 level to the peer's (see the KNOWN LIMITATION
/// note in str0m's `PayloadParams::update_param`). With the built-in 3.1, the
/// answer to a 1080p or 4K publisher would declare that the relay receives
/// nothing above level 3.1.
///
/// **Why exactly one entry per (packetization mode, profile).** This used to be
/// str0m's whole default set *plus* four extra level-5.1 entries. Since str0m
/// 0.22 (#1016) an H.264 level mismatch only lowers the match score, so an
/// offered Baseline mode-1 PT matched both the built-in 3.1 entry and the
/// extra 5.1 one. When the remote dictates the PTs — a browser's `recvonly`
/// WHEP offer, or a `recvonly` answer to our `sendonly` offer — both entries
/// lock that one PT and str0m panics, "Pt locked multiple times: 102". Every
/// Chrome WHEP viewer hit it. With one entry per pair, an offered PT can match
/// at most one local entry.
///
/// **Why only H.264 and Opus.** They are all this pipeline carries
/// (`EsKind::{VideoH264, AudioOpus}`). Every other codec in str0m's default set
/// is one the relay cannot depacketize on ingest or produce for a viewer, and
/// [`WebrtcSession::get_pt`] used to take the first negotiated entry, which in
/// the default set is VP8 (PT 96): H.264 went out labelled as VP8.
///
/// **Why str0m's own numbers.** They are proven-valid RTX slots (an arbitrary
/// free PT can break str0m's SDP generation), none collides with Opus's 111,
/// and they are what bilbycast-edge registers too: the edge's WHIP output
/// talks to this crate's WHIP ingest, so the two sets must stay identical.
/// `codec_set_is_str0ms_h264_defaults_at_level_5_1_plus_opus` fails if a str0m
/// bump moves the built-in entries.
const H264_LEVEL_5_1: [(u8, u8, bool, u32); 7] = [
    (127, 121, true, 0x42_00_33),  // Baseline, packetization-mode=1
    (125, 107, false, 0x42_00_33), // Baseline, packetization-mode=0
    (108, 109, true, 0x42_e0_33),  // Constrained Baseline, mode 1
    (124, 120, false, 0x42_e0_33), // Constrained Baseline, mode 0
    (123, 119, true, 0x4d_00_33),  // Main, mode 1
    (35, 36, false, 0x4d_00_33),   // Main, mode 0
    (114, 115, true, 0x64_00_33),  // High, mode 1
];

/// The str0m configuration every session is built from: Opus without RED, the
/// [`H264_LEVEL_5_1`] entries, and no other codec.
///
/// str0m 0.24 also added a receive-reorder deadline (2 s video, 1 s audio) that
/// holds every later frame behind an incomplete one until it expires. Without
/// retransmission, one lost packet then stalls video about twice as long as
/// 0.23 did. `None` restores 0.23's release by frame count, which is what this
/// pipeline was tuned against.
fn rtc_config(ice_lite: bool) -> RtcConfig {
    let mut config = Rtc::builder()
        .set_ice_lite(ice_lite)
        .set_reordering_timeout_video(None)
        .set_reordering_timeout_audio(None)
        .clear_codecs()
        .enable_opus(true, false);
    let codecs = config.codec_config();
    for (pt, rtx, packetization_mode_1, profile_level_id) in H264_LEVEL_5_1 {
        codecs.add_h264(
            Pt::new_with_value(pt),
            Some(Pt::new_with_value(rtx)),
            packetization_mode_1,
            profile_level_id,
        );
    }
    config
}

/// A panic str0m raised while negotiating with one peer, caught so that it
/// fails that peer alone (see [`isolate_negotiation`]). Same shape as
/// bilbycast-edge's; the HTTP handlers in `distribution/mod.rs` turn it into
/// the `webrtc_negotiation_panic` Warning event.
#[derive(Debug)]
pub struct NegotiationPanic {
    /// The step that panicked: `"session setup"`, `"SDP offer"`, `"SDP offer
    /// creation"` or `"SDP answer"`.
    pub step: &'static str,
    /// The panic message.
    pub message: String,
}

impl std::fmt::Display for NegotiationPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "str0m panicked during {}: {}", self.step, self.message)
    }
}

impl std::error::Error for NegotiationPanic {}

/// Run one synchronous str0m negotiation step, turning a panic inside it into
/// a [`NegotiationPanic`] error.
///
/// str0m still asserts its way through some SDP it cannot reconcile — an offer
/// whose one RTX PT repairs two H.264 PTs makes 0.24.1 panic "Pt locked
/// multiple times" whatever codecs are registered — and the input is whatever
/// a WHEP viewer, a WHIP publisher or a cascade upstream sent. Unchecked, the
/// panic unwinds through the HTTP handler: the client gets a dropped
/// connection, and before `ViewerSlot` existed the per-IP slot leaked with it.
/// Contained here, it is an error for that one request. Each step wraps
/// everything str0m does with the peer's SDP — parsing it and writing ours
/// included — as bilbycast-edge's `isolate_negotiation` does.
///
/// `AssertUnwindSafe` is sound because nothing observes the `Rtc` afterwards:
/// every caller discards the whole session when one of these steps returns
/// `Err`, which is the contract documented on each.
fn isolate_negotiation<T>(step: &'static str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "(no message)".to_string());
            let panic = NegotiationPanic { step, message };
            tracing::warn!("WebRTC: {panic}; failing this peer only");
            Err(panic.into())
        }
    }
}

/// The payload type a track is written on, from the payload params its
/// m-line negotiated: H.264 on video, Opus on audio, `None` when the peer
/// accepted neither. Ported from bilbycast-edge's `send_pt`; keep the two
/// identical.
///
/// `Writer::payload_params` lists every negotiated param in codec-config
/// order, and its first entry used to be taken — whatever its packetization
/// mode. On video, packetization-mode 1 is preferred: str0m packetizes into
/// STAP-A / FU-A, which a mode-0 PT forbids, so a mode-0 PT is taken only
/// when the peer accepted no other. [`H264_LEVEL_5_1`] is ordered by profile,
/// so a peer offering Baseline only in mode 0 and another profile in mode 1
/// used to get its mode-0 PT.
fn send_pt<'a>(kind: MediaKind, params: impl Iterator<Item = &'a PayloadParams>) -> Option<Pt> {
    let mut mode_0 = None;
    for p in params {
        let spec = p.spec();
        match kind {
            MediaKind::Audio if spec.codec == Codec::Opus => return Some(p.pt()),
            MediaKind::Video if spec.codec == Codec::H264 => {
                if spec.format.packetization_mode == Some(1) {
                    return Some(p.pt());
                }
                mode_0.get_or_insert(p.pt());
            }
            _ => {}
        }
    }
    mode_0
}

/// How long ICE may stay disconnected before the session is over
/// ([`WebrtcSession::is_disconnected`]).
///
/// `is` reports an ICE-Lite agent `Disconnected` 15 s after the peer's last
/// Binding Request (`RECENT_BINDING_REQUEST`), but that agent comes back: the
/// peer's next request re-creates the pair it pruned and, carrying
/// USE-CANDIDATE as a controlling agent's checks on its nominated pair do,
/// nominates it, and ICE is `Completed` again. A viewer whose checks paused —
/// a Wi-Fi or cellular hiccup, a suspended laptop, a backgrounded mobile
/// browser — resumes. A browser gives up only when it has heard nothing for
/// RFC 7675's 30 s, so 15 s of grace on top of `is`'s 15 s ends the relay's
/// side no sooner than the browser would end its own.
///
/// The grace is not free: str0m keeps sending to the last nominated address
/// until the session ends, so a viewer that really left is sent about 30 s of
/// its stream rather than 15.
pub const ICE_DISCONNECT_GRACE: Duration = Duration::from_secs(15);

/// Why a session is over. See [`WebrtcSession::end`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// ICE stayed disconnected for [`ICE_DISCONNECT_GRACE`]: the peer stopped
    /// answering — a closed tab, a lost network.
    IceDisconnected,
    /// The connection was closed: the peer sent a DTLS close_notify
    /// (`RTCPeerConnection.close()`, a str0m peer's `Rtc::close`) or its SCTP
    /// association went, or this side closed the `Rtc`.
    Closed,
    /// The UDP socket failed.
    SocketError,
    /// str0m returned an error.
    Str0mError,
}

impl std::fmt::Display for SessionEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SessionEnd::IceDisconnected => "ICE disconnected",
            SessionEnd::Closed => "DTLS closed",
            SessionEnd::SocketError => "UDP socket error",
            SessionEnd::Str0mError => "str0m error",
        })
    }
}

/// Events produced by the WebRTC session for the caller to handle.
///
/// Some fields are retained for future use (audio support, timing, diagnostics)
/// even though they are not yet consumed by callers.
#[allow(dead_code)]
pub enum SessionEvent {
    /// Received depayloaded media data on a track.
    MediaData {
        mid: Mid,
        pt: Pt,
        /// str0m 0.20 changed `MediaData.data` from `Vec<u8>` to `Arc<[u8]>`.
        /// Carried through as-is rather than `.to_vec()`'d, matching
        /// bilbycast-edge's `engine::webrtc::session`. The ingest path never
        /// needs its own copy: video borrows it into the AU assembler, and
        /// audio hands the `Arc` itself to `Bytes::from_owner`.
        data: Arc<[u8]>,
        rtp_time: MediaTime,
        network_time: Instant,
        contiguous: bool,
    },
    /// ICE connection state changed.
    IceStateChange(IceConnectionState),
    /// The peer is connected (ICE + DTLS complete).
    Connected,
    /// A new media track was added.
    MediaAdded { mid: Mid, kind: MediaKind },
    /// Incoming keyframe request from the remote peer.
    KeyframeRequest { mid: Mid },
    /// The session ended — see [`SessionEnd`] — or `poll_event`'s cancel
    /// fired. Also reported the moment ICE goes `Disconnected`, which an
    /// ICE-Lite session can come back from: [`poll_event`]'s callers (setup,
    /// WHIP ingest, the cascade pull) end on it at once, as they always have,
    /// while the WHEP send loop reads [`WebrtcSession::is_disconnected`],
    /// which gives ICE [`ICE_DISCONNECT_GRACE`] to return.
    ///
    /// [`poll_event`]: WebrtcSession::poll_event
    Disconnected,
}

/// Configuration for creating a WebRTC session.
pub struct SessionConfig {
    /// Local UDP socket address to bind. Use "0.0.0.0:0" for auto-assign.
    pub bind_addr: SocketAddr,
    /// Public IP to advertise in ICE candidates (optional).
    pub public_ip: Option<std::net::IpAddr>,
    /// Whether this session should behave as an ICE-Lite agent. Set this to
    /// `true` for server-side roles (WHIP input, WHEP output) and `false` for
    /// client-side roles (WHIP output, WHEP input) — str0m rejects the
    /// handshake when both peers advertise `a=ice-lite`.
    pub ice_lite: bool,
}

/// Ingress source pin — the anti-reflection control on the media socket.
///
/// **Why this exists.** ICE-Lite mints a *peer-reflexive* remote candidate from
/// any STUN Binding Request that carries a correct MESSAGE-INTEGRITY, and — in
/// lite mode — marks the resulting pair nominated the instant the request sets
/// USE-CANDIDATE (`is-0.11.1/src/agent.rs`: `pair.nominate(self.ice_lite)`
/// forces `NominationState::Success`, then `evaluate_nomination` picks the
/// highest-**PRIORITY** nominated pair — and PRIORITY is an attribute the
/// sender chooses). str0m then routes every DTLS/SRTP transmit to that pair's
/// address (`str0m-0.24.1/src/lib.rs`, the `send_addr` branch of
/// `poll_output`).
///
/// The relay hands its ICE ufrag/pwd to whoever POSTs a WHEP offer, in the 201
/// answer. So a client that has completed one legitimate session already holds
/// every credential needed to forge such a request from a **spoofed** source
/// address. One ~100-byte spoofed datagram repoints the whole SRTP stream at
/// the spoofed address, and one more every few seconds keeps it there: a UDP
/// reflector with a four-to-five-order-of-magnitude amplification ratio.
///
/// There is no upstream switch for this. `is` 0.11 implements no consent
/// freshness (RFC 7675) — the word "consent" appears in that crate exactly
/// once, in a doc comment about RTT measurement.
///
/// **The control.** Filter on **ingress**, before `Rtc::handle_input`, so the
/// spoofed datagram never reaches the ICE agent: no peer-reflexive candidate is
/// minted, no pair is nominated, and — decisively — no STUN reply is generated.
/// An egress-only guard would still bounce the reply off the victim.
///
/// **When it arms.** Only once DTLS completes, and it pins the address str0m
/// was sending DTLS records to at that moment. That address is provably the
/// peer that answered the handshake: DTLS only ever leaves via `send_addr`, so
/// a spoofer who moved the nomination *before* the handshake finished would
/// have sent our DTLS to the victim, which cannot answer, and `Connected` would
/// never fire. Everything before `Connected` stays wide open, because ICE and
/// DTLS must run from an address nobody has learned yet.
///
/// **What it costs.** The pin is on the IP only, so a NAT *port* rebind — the
/// common case — still passes. A viewer whose **IP** changes mid-stream
/// (Wi-Fi → cellular) is dropped and must re-POST the WHEP offer. That is a
/// small incremental cost, because mid-session IP migration barely works here
/// today either: `evaluate_nomination` ranks nominated pairs purely by
/// priority with no liveness filter, so a roaming viewer's new pair only wins
/// if it happens to outrank the dead one. Making migration *safe* rather than
/// merely absent needs a return-routability check (RFC 7675 consent, or a full
/// non-lite agent) that neither str0m nor `is` offers today.
///
/// It costs one more thing, in the **client** (non-ICE-Lite) role that
/// `cascade.rs` uses: there the relay is the controlling agent and
/// `is::handle_timeout` keeps issuing binding requests to *every* candidate
/// pair, not only the nominated one. A legitimately multi-homed remote peer —
/// and `select_local_candidate_ips` advertises loopback *and* the
/// route-discovered LAN IP, so a same-host cascade peer is exactly that —
/// answers from more than one source IP. After arming, replies from the
/// non-nominated IP are dropped, those pairs fail `is_still_possible` and get
/// pruned. The session survives on its nominated pair but silently loses its
/// ICE failover redundancy.
///
/// **Divergence from the edge.** This file is vendored from
/// `bilbycast-edge::engine::webrtc::session` and the two are meant to be kept
/// in sync. `PeerPin` is a deliberate, recorded divergence: the relay copy
/// carries it, the edge copy does not (see the module header). Do not delete
/// it as "drift" when next syncing the two.
#[derive(Default)]
struct PeerPin {
    /// Remote IP the DTLS handshake completed with. `None` until `Connected`.
    pinned: Option<IpAddr>,
    /// Destination of the most recent DTLS record we transmitted. This is the
    /// nominated peer; STUN replies (which go to whatever address asked, and
    /// so can be steered by a spoofer) deliberately do NOT update it.
    last_dtls_dest: Option<IpAddr>,
    /// Source of the most recent datagram we accepted **and demuxed** — the
    /// arming fallback if somehow no DTLS record was transmitted before
    /// `Connected`. Recorded only after the `DatagramRecv` demux succeeds (see
    /// [`WebrtcSession::ingest`]), so this is never arbitrary unvalidated
    /// bytes' source.
    last_recv_src: Option<IpAddr>,
    /// Off-path datagrams dropped since arming. Exposed for diagnostics.
    dropped: u64,
    /// The first off-path source of this session, latched for exactly one read
    /// by the owning transport (see [`WebrtcSession::take_offpath_alert`]) so
    /// the drop reaches the manager's Events page once — never per datagram,
    /// which under a reflection flood would make the alarm its own amplifier.
    alert: Option<SocketAddr>,
}

impl PeerPin {
    /// Does this UDP payload demultiplex as a DTLS record? RFC 9443 §3: STUN
    /// is 0..=3, DTLS 20..=63, RTP/RTCP 128..=191.
    fn is_dtls(payload: &[u8]) -> bool {
        matches!(payload.first(), Some(20..=63))
    }

    /// Observe an outbound datagram. Only DTLS records move `last_dtls_dest`.
    fn note_transmit(&mut self, dest: SocketAddr, payload: &[u8]) {
        if Self::is_dtls(payload) {
            self.last_dtls_dest = Some(dest.ip());
        }
    }

    /// Observe an inbound datagram we are about to hand to str0m.
    fn note_receive(&mut self, source: SocketAddr) {
        self.last_recv_src = Some(source.ip());
    }

    /// Arm the pin on the DTLS peer. Idempotent — `Connected` fires once, but
    /// re-arming later would be exactly the hole this closes.
    fn arm(&mut self) {
        if self.pinned.is_some() {
            return;
        }
        match self.last_dtls_dest.or(self.last_recv_src) {
            Some(ip) => {
                self.pinned = Some(ip);
                tracing::debug!("WebRTC: pinned media peer to {ip} (DTLS complete)");
            }
            // Unreachable in practice: `Connected` means a DTLS handshake ran,
            // which means records went out. Fail open rather than wedge a live
            // session on a state we did not anticipate — but say so loudly.
            None => tracing::warn!(
                "WebRTC: connected without an observed DTLS peer — source pin NOT armed"
            ),
        }
    }

    /// Should this inbound datagram be handed to str0m?
    fn accept(&mut self, source: SocketAddr) -> bool {
        match self.pinned {
            None => true,
            Some(ip) if ip == source.ip() => true,
            Some(ip) => {
                self.dropped += 1;
                // Loud once, then quiet: a reflection attempt is a flood by
                // construction and must not become its own log amplifier.
                if self.dropped == 1 {
                    self.alert = Some(source);
                    tracing::warn!(
                        "WebRTC: dropped an off-path datagram from {source} — this session is \
                         pinned to {ip}. Either a source-spoofed ICE reflection attempt, or a \
                         viewer whose IP changed (which must re-POST the WHEP offer)."
                    );
                } else {
                    tracing::trace!("WebRTC: dropped off-path datagram from {source}");
                }
                false
            }
        }
    }
}

/// A WebRTC session wrapping str0m's `Rtc` state machine.
pub struct WebrtcSession {
    rtc: Rtc,
    socket: UdpSocket,
    local_addr: SocketAddr,
    /// ICE host candidate IPs we advertised. Used to map incoming packets
    /// to the correct `destination` field for str0m when the socket is
    /// bound to an unspecified address (`0.0.0.0`).
    candidate_ips: Vec<std::net::IpAddr>,
    /// Video track MID (if any).
    pub video_mid: Option<Mid>,
    /// Audio track MID (if any).
    pub audio_mid: Option<Mid>,
    /// Anti-reflection ingress filter. See [`PeerPin`].
    pin: PeerPin,
    /// Latched by the first fatal end — a closed connection, a socket or
    /// str0m error — on whichever path drained it. See [`Self::end`].
    ended: Option<SessionEnd>,
    /// When ICE last went `Disconnected`, until it is `Connected` or
    /// `Completed` again. See [`ICE_DISCONNECT_GRACE`].
    ice_disconnected_since: Option<Instant>,
    buf: Vec<u8>,
}

impl WebrtcSession {
    /// Create a new session with ICE-lite and bind a UDP socket.
    pub async fn new(config: &SessionConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        let local_addr = socket.local_addr()?;

        // Build the host-candidate set the answer SDP will advertise.
        //
        // When the operator pinned a `public_ip` we honour it verbatim —
        // they know the deployment topology better than we do (NAT 1:1
        // mappings, behind-LB deployments). The caller has *also* bound
        // the UDP socket to that exact IP so the destination address on
        // every incoming packet matches the local candidate (see
        // `engine::input_webrtc::whip_input_loop` for the matching bind
        // logic — without it, the `is` ICE state machine discards every
        // STUN binding request as `unknown interface`).
        //
        // When the bind is unspecified (`0.0.0.0`) we advertise both
        // loopback **and** the route-discovered LAN IP, so same-host
        // peers (loopback / dev / WHIP smoke tests) and real LAN peers
        // both have a candidate they can reach. The previous
        // implementation only advertised the LAN IP and silently broke
        // loopback testing on macOS.
        let port = local_addr.port();
        let route_discovered_lan_ip = || -> Option<std::net::IpAddr> {
            std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
                .ok()
                .map(|a| a.ip())
                .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        };
        let candidate_ips = select_local_candidate_ips(
            local_addr.ip(),
            config.public_ip,
            route_discovered_lan_ip,
        );

        // Opus + str0m's H.264 entries at level 5.1, nothing else. The reasons,
        // and the panic the previous set caused, are on `H264_LEVEL_5_1`.
        let rtc = isolate_negotiation("session setup", || {
            let mut rtc = rtc_config(config.ice_lite).build(Instant::now());
            for ip in &candidate_ips {
                let cand_addr = SocketAddr::new(*ip, port);
                let cand = Candidate::host(cand_addr, Protocol::Udp)
                    .map_err(|e| anyhow::anyhow!("ICE candidate error: {}", e))?;
                rtc.add_local_candidate(cand);
                tracing::debug!("WebRTC: added local ICE host candidate {cand_addr}");
            }
            Ok(rtc)
        })?;

        Ok(Self {
            rtc,
            socket,
            local_addr,
            candidate_ips: candidate_ips.clone(),
            video_mid: None,
            audio_mid: None,
            pin: PeerPin::default(),
            ended: None,
            ice_disconnected_since: None,
            buf: vec![0u8; 2048],
        })
    }

    /// The remote IP this session's media is pinned to, once DTLS has
    /// completed. `None` while the handshake is still open. See [`PeerPin`].
    pub fn pinned_peer_ip(&self) -> Option<IpAddr> {
        self.pin.pinned
    }

    /// Datagrams dropped by the ingress source pin — spoofed ICE reflection
    /// attempts, or a viewer whose IP changed. Non-zero on a healthy session
    /// only under attack.
    pub fn offpath_datagrams_dropped(&self) -> u64 {
        self.pin.dropped
    }

    /// Take the one-shot off-path alert: `(pinned_ip, offending_source)`, set
    /// the first time this session drops a datagram from an unpinned address
    /// and cleared by this read.
    ///
    /// The transport layer polls this (see `whep::viewer_loop`) and turns it
    /// into one Warning event + one telemetry increment per session. Kept as a
    /// pull rather than a callback so this vendored file takes on no
    /// dependency on the relay's event channel — the edge's copy has none.
    pub fn take_offpath_alert(&mut self) -> Option<(IpAddr, SocketAddr)> {
        let source = self.pin.alert.take()?;
        Some((self.pin.pinned?, source))
    }

    /// Accept an SDP offer (server mode) and return the SDP answer string.
    ///
    /// On `Err` the session must be discarded: a panic inside str0m comes back
    /// as a [`NegotiationPanic`] error (see [`isolate_negotiation`]), and the
    /// `Rtc` it unwound out of is in no state to be driven further.
    pub fn accept_offer(&mut self, offer_sdp: &str) -> Result<String> {
        // str0m 0.18's SDP parser accepted only `s=-` as the session name,
        // and ffmpeg and other WHIP publishers send a real one (e.g.
        // `s=FFmpegPublishSession`, which RFC 8866 allows). str0m 0.24.1
        // accepts any non-empty name, so that rewrite now matters only for an
        // empty `s=`, which str0m still rejects. The BUNDLE rewrite is a
        // separate workaround; see `normalise_sdp_offer_for_str0m`.
        let normalised = normalise_sdp_offer_for_str0m(offer_sdp);

        let answer_sdp = isolate_negotiation("SDP offer", || {
            let offer = SdpOffer::from_sdp_string(&normalised)
                .map_err(|e| anyhow::anyhow!("SDP parse error: {}", e))?;

            tracing::info!("SDP offer (normalised):\n{}", normalised);

            let answer = self
                .rtc
                .sdp_api()
                .accept_offer(offer)
                .map_err(|e| anyhow::anyhow!("SDP accept error: {}", e))?;
            Ok(answer.to_sdp_string())
        })?;
        tracing::info!("SDP answer:\n{}", answer_sdp);

        // MIDs will be discovered via MediaAdded events
        Ok(answer_sdp)
    }

    /// Create an SDP offer (client mode). Returns the SDP offer string.
    /// The pending offer must be kept and passed to `apply_answer()`.
    ///
    /// A panic inside str0m comes back as a [`NegotiationPanic`] error.
    pub fn create_offer(&mut self, video: bool, audio: bool, send_only: bool) -> Result<(String, str0m::change::SdpPendingOffer)> {
        let direction = if send_only { Direction::SendOnly } else { Direction::RecvOnly };

        let (offer_sdp, pending) = isolate_negotiation("SDP offer creation", || {
            let mut api = self.rtc.sdp_api();

            if video {
                let mid = api.add_media(MediaKind::Video, direction, None, None, None);
                self.video_mid = Some(mid);
            }
            if audio {
                let mid = api.add_media(MediaKind::Audio, direction, None, None, None);
                self.audio_mid = Some(mid);
            }

            let (offer, pending) = api
                .apply()
                .ok_or_else(|| anyhow::anyhow!("No SDP changes to apply"))?;
            Ok((offer.to_sdp_string(), pending))
        })?;

        tracing::info!("SDP offer (created):\n{}", offer_sdp);
        Ok((offer_sdp, pending))
    }

    /// Apply an SDP answer received from the remote peer (client mode).
    /// Requires the pending offer from `create_offer()`.
    ///
    /// On `Err` the session must be discarded, as for [`Self::accept_offer`].
    pub fn apply_answer(&mut self, answer_sdp: &str, pending: str0m::change::SdpPendingOffer) -> Result<()> {
        isolate_negotiation("SDP answer", || {
            let answer = str0m::change::SdpAnswer::from_sdp_string(answer_sdp)
                .map_err(|e| anyhow::anyhow!("SDP answer parse error: {}", e))?;

            self.rtc
                .sdp_api()
                .accept_answer(pending, answer)
                .map_err(|e| anyhow::anyhow!("SDP answer accept error: {}", e))?;

            // Kickstart the ICE agent. After accept_answer the agent has
            // remote candidates and credentials, but str0m's first
            // `poll_output()` may return a `Timeout` with a deadline ~100
            // years in the future ("nothing to do") because the sans-IO
            // state machine hasn't been told to advance time. Without this
            // call, our `poll_event` loop on the sender side sleeps until
            // doomsday and ICE never starts. One zero-cost time injection
            // wakes the agent and the next `poll_output` produces the first
            // STUN binding request immediately.
            let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));

            Ok(())
        })
    }

    /// Get the local socket address.
    /// Retained for diagnostics and future ICE candidate reporting.
    #[allow(dead_code)]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Write media data to a track.
    pub fn write_media(
        &mut self,
        mid: Mid,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<()> {
        if let Some(writer) = self.rtc.writer(mid) {
            // str0m 0.20+ takes `impl Into<Arc<[u8]>>`. Building the `Arc`
            // straight from the slice costs one allocation + one copy;
            // going via `to_vec()` would pay for both twice, on every
            // egress RTP payload, per viewer.
            writer
                .write(pt, wallclock, rtp_time, Arc::<[u8]>::from(data))
                .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
        }
        Ok(())
    }

    /// Drain str0m's pending output queue, sending any queued UDP transmits
    /// to the wire.
    ///
    /// str0m holds up to 512 pending writes per track (`MAX_PENDING_PAYLOADS`
    /// in its `media/mod.rs`; 100 before 0.24) and packetizes them only from
    /// `handle_timeout`; past the cap `write_media` returns
    /// `WriteWithoutPoll`. Draining after each write sends an access unit's
    /// packets at once and keeps that queue at one entry. We feed an
    /// `Input::Timeout` so the write is packetized eagerly. Cheap when there's
    /// nothing pending (one no-op timeout + one no-op poll).
    ///
    /// Events drained here are not returned, but what they say about the
    /// session's end is kept (see [`Self::is_disconnected`]): str0m reports
    /// ICE giving up from inside the very `handle_timeout` this runs, so for a
    /// viewer that left without a DELETE this is where it usually surfaces.
    pub async fn drain_outputs(&mut self) {
        // Feed a current-time timeout so str0m runs `do_payload` and turns
        // the just-written sample into RTP packets ready for `poll_output`.
        let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(transmit)) => {
                    self.pin.note_transmit(transmit.destination, &transmit.contents);
                    let _ = self.socket.send_to(&transmit.contents, transmit.destination).await;
                }
                Ok(Output::Event(event)) => {
                    let _ = self.handle_event(event);
                }
                Ok(Output::Timeout(_)) | Err(_) => break,
            }
        }
    }

    /// The negotiated payload type to write `mid`'s media on: H.264 on a
    /// video m-line — a packetization-mode=1 PT whenever the peer accepted
    /// one — and Opus on an audio one (see [`send_pt`]). `None` when the peer
    /// accepted neither, rather than another codec's PT.
    ///
    /// Under str0m's default set the first negotiated entry was taken, and it
    /// was VP8, so between two `WebrtcSession`s — the edge's WHIP output and
    /// this crate's ingest, or an upstream WHEP viewer and a cascade pull —
    /// this returned PT 96 and H.264 went out labelled VP8.
    pub fn get_pt(&mut self, mid: Mid) -> Option<Pt> {
        let kind = self.rtc.media(mid)?.kind();
        let writer = self.rtc.writer(mid)?;
        send_pt(kind, writer.payload_params())
    }

    /// Drain all pending str0m events without blocking, populating
    /// `self.video_mid` / `self.audio_mid` from any queued
    /// `MediaAdded` events.
    ///
    /// str0m may emit `Event::Connected` *before* the queued
    /// `MediaAdded` events. Callers that wait only for Connected
    /// can race past the track discovery and end up with
    /// `video_mid == None` (the WHEP viewer "no video MID
    /// negotiated" bug). Call this after Connected to flush any
    /// pending events.
    pub fn drain_pending_events(&mut self) {
        // Anything that is not a pending Event (a Transmit, a Timeout, or an
        // error) ends the drain, exactly as the previous `match … => break`
        // arm did — the non-Event value is discarded either way.
        while let Ok(Output::Event(event)) = self.rtc.poll_output() {
            let _ = self.handle_event(event);
        }
    }

    /// Check if the session is still alive.
    /// Retained for future session health monitoring.
    #[allow(dead_code)]
    pub fn is_alive(&self) -> bool {
        self.rtc.is_alive()
    }

    /// The session is over ([`Self::end`] says why).
    ///
    /// Callers that drive the session with [`Self::drain_outputs`] and
    /// [`Self::drive_udp_io`] — the WHEP send loop — must check this after
    /// each call, and drive the session even when they have nothing to send,
    /// so that an ICE grace lapses. `drain_outputs` returns no event at all and
    /// `drive_udp_io` only the first of a batch, so a disconnect used to be
    /// dropped there: a viewer that left without a DELETE was sent the stream,
    /// and held its per-IP slot, for as long as the stream lived.
    pub fn is_disconnected(&self) -> bool {
        self.end().is_some()
    }

    /// Why the session is over, or `None` while it is not.
    ///
    /// - A fatal end is final from the moment any drain sees it: the peer
    ///   closed the connection (`Event::Closed`, which str0m follows by going
    ///   inert — no timeout and no ICE event ever comes after it), the socket
    ///   failed, or str0m did. A closed `Rtc` counts too, however it closed.
    /// - ICE going `Disconnected` is not, on its own: an ICE-Lite agent comes
    ///   back on the peer's next nomination. It ends the session only once it
    ///   has lasted [`ICE_DISCONNECT_GRACE`]. Before, the first `Disconnected`
    ///   ended it, so a viewer whose consent checks paused for 15 s was closed
    ///   although str0m and the browser would both have resumed, and the
    ///   `/watch` player, which does not reconnect, stayed black.
    pub fn end(&self) -> Option<SessionEnd> {
        if let Some(end) = self.ended {
            return Some(end);
        }
        if !self.rtc.is_alive() {
            return Some(SessionEnd::Closed);
        }
        self.ice_disconnected_since
            .filter(|since| since.elapsed() >= ICE_DISCONNECT_GRACE)
            .map(|_| SessionEnd::IceDisconnected)
    }

    /// Keep the first fatal end; see [`Self::end`].
    fn latch(&mut self, end: SessionEnd) {
        self.ended.get_or_insert(end);
    }

    /// Close the connection from this side: str0m sends an RTCP BYE and a
    /// DTLS close_notify on the next drain ([`Self::drain_outputs`],
    /// [`Self::drive_udp_io`]), and the peer's session ends on it
    /// ([`SessionEnd::Closed`]). This session is over at once.
    pub fn close(&mut self) {
        // `start_close` fails only on an SCTP or DTLS error, and then the
        // `Rtc` is unusable anyway: the session is over either way.
        let _ = self.rtc.close();
        self.latch(SessionEnd::Closed);
    }

    /// Drive the session event loop. Blocks until a meaningful event occurs.
    pub async fn poll_event(&mut self, cancel: &CancellationToken) -> SessionEvent {
        loop {
            // Drain all pending str0m outputs
            match self.rtc.poll_output() {
                Ok(Output::Transmit(transmit)) => {
                    tracing::trace!("poll_event: Transmit {} bytes -> {}", transmit.contents.len(), transmit.destination);
                    self.pin.note_transmit(transmit.destination, &transmit.contents);
                    let _ = self.socket.send_to(&transmit.contents, transmit.destination).await;
                    continue;
                }
                Ok(Output::Event(event)) => {
                    tracing::trace!("poll_event: Event {:?}", std::any::type_name_of_val(&event));
                    if let Some(se) = self.handle_event(event) {
                        return se;
                    }
                    continue;
                }
                Ok(Output::Timeout(deadline)) => {
                    // Everything is drained. A session that is over has
                    // nothing to wait for — least of all a closed `Rtc`, which
                    // is inert: its deadline is years away and no input wakes
                    // it, so a `Closed` this loop did not see itself (one a
                    // drain took) used to park it for good.
                    if self.is_disconnected() {
                        return SessionEvent::Disconnected;
                    }
                    // Wait for input — and for an ICE grace to lapse, so that
                    // it is noticed when it does.
                    let wake = match self.ice_disconnected_since {
                        Some(since) => deadline.min(since + ICE_DISCONNECT_GRACE),
                        None => deadline,
                    };
                    let sleep_dur = wake.saturating_duration_since(Instant::now());
                    tracing::trace!("poll_event: Timeout, sleeping {:?}", sleep_dur);
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            return SessionEvent::Disconnected;
                        }
                        _ = tokio::time::sleep(sleep_dur) => {
                            let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));
                            continue;
                        }
                        result = self.socket.recv_from(&mut self.buf) => {
                            match result {
                                Ok((len, source)) => {
                                    // The ONE ingress path — filter included.
                                    // See `WebrtcSession::ingest`.
                                    self.ingest(len, source);
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("UDP recv error: {}", e);
                                    self.latch(SessionEnd::SocketError);
                                    return SessionEvent::Disconnected;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("str0m error: {}", e);
                    self.latch(SessionEnd::Str0mError);
                    return SessionEvent::Disconnected;
                }
            }
        }
    }

    /// The **one** path from the UDP socket into str0m.
    ///
    /// Both receive loops — `poll_event`'s blocking `recv_from` arm and
    /// `drive_udp_io`'s non-blocking drain — call exactly this and nothing
    /// else. That is deliberate and load-bearing: when the anti-reflection
    /// filter lived inline in both loops it could be (and, in review, was)
    /// deleted from both with the whole test suite still green, because the
    /// guard had two copies and neither was reachable from a test. There is
    /// now one copy, on the only route in, so a third receive path cannot be
    /// added without it either.
    ///
    /// Returns whether the datagram reached str0m. Ordering inside matters:
    ///
    /// 1. [`PeerPin::accept`] runs **before** `Rtc::handle_input`, so a
    ///    spoofed STUN Binding Request mints no peer-reflexive candidate and —
    ///    decisively — draws no reply. An egress-only guard would still bounce
    ///    the reply off the victim.
    /// 2. [`PeerPin::note_receive`] runs **after** the `DatagramRecv` demux
    ///    succeeds, so the arming fallback can only ever pin on a source whose
    ///    payload was at least recognisable as STUN/DTLS/RTP/RTCP — never on
    ///    arbitrary unvalidated bytes.
    fn ingest(&mut self, len: usize, source: SocketAddr) -> bool {
        if !self.pin.accept(source) {
            return false;
        }
        let now = Instant::now();
        // str0m's DatagramRecv try_into rejects datagrams that aren't
        // STUN/DTLS/RTP/RTCP. Hostile or stray packets must NOT crash the
        // WebRTC session task — drop them and keep going.
        let contents = match (&self.buf[..len]).try_into() {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("WebRTC: dropped {len}-byte datagram from {source}: {e}");
                return false;
            }
        };
        self.pin.note_receive(source);
        let destination = self.destination_for_source(source);
        let receive = str0m::net::Receive {
            proto: Protocol::Udp,
            source,
            destination,
            contents,
        };
        let _ = self.rtc.handle_input(Input::Receive(now, receive));
        true
    }

    /// Map an incoming packet's source address to the correct local
    /// destination address that str0m expects.
    ///
    /// When the socket is bound to an unspecified address (`0.0.0.0`),
    /// `self.local_addr` is `0.0.0.0:<port>` — which doesn't match any
    /// ICE host candidate. str0m's ICE agent routes packets by matching
    /// `(source, destination)` to a candidate pair; if the destination
    /// doesn't match a local candidate, the packet is silently discarded.
    ///
    /// This method picks the correct candidate IP based on the source:
    /// - Source is loopback → prefer loopback candidate
    /// - Source is non-loopback → prefer non-loopback candidate
    /// - Fallback → first candidate
    ///
    /// When `local_addr` is already a specific IP (operator set
    /// `public_ip`, or bound to a specific interface), it matches the
    /// candidate directly, so we return it as-is.
    fn destination_for_source(&self, source: SocketAddr) -> SocketAddr {
        resolve_destination(self.local_addr, &self.candidate_ips, source)
    }

    /// Non-blocking: receive any pending UDP packets and feed them to
    /// str0m, then drain all pending transmits. Returns the first
    /// meaningful session event (if any) discovered while processing; a
    /// disconnect behind it is not returned but is kept, so check
    /// [`Self::is_disconnected`] rather than the return value.
    ///
    /// Designed for the WHIP client output and WHEP viewer send loops,
    /// which need to keep str0m alive (RTCP, STUN keepalives) while
    /// they are primarily driven by the broadcast channel. Call this
    /// after writing media and after each broadcast packet batch.
    pub async fn drive_udp_io(&mut self) -> Option<SessionEvent> {
        let mut event_out: Option<SessionEvent> = None;

        // Non-blocking receive loop: drain all pending UDP packets.
        loop {
            match self.socket.try_recv_from(&mut self.buf) {
                Ok((len, source)) => {
                    // The ONE ingress path — filter included. See
                    // `WebrtcSession::ingest`.
                    self.ingest(len, source);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // Process any pending timeouts.
        let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));

        // Drain all pending str0m outputs (transmits + events).
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(transmit)) => {
                    self.pin.note_transmit(transmit.destination, &transmit.contents);
                    let _ = self.socket.send_to(&transmit.contents, transmit.destination).await;
                }
                Ok(Output::Event(ev)) => {
                    if event_out.is_none() {
                        event_out = self.handle_event(ev);
                    }
                    // Continue draining even if we got an event.
                }
                Ok(Output::Timeout(_)) | Err(_) => break,
            }
        }

        event_out
    }

    fn handle_event(&mut self, event: Event) -> Option<SessionEvent> {
        match event {
            Event::Connected => {
                tracing::info!("WebRTC connected (ICE + DTLS complete)");
                // Arm the anti-reflection pin on the peer that just answered
                // the DTLS handshake. See `PeerPin`.
                self.pin.arm();
                Some(SessionEvent::Connected)
            }
            Event::IceConnectionStateChange(state) => {
                tracing::debug!("ICE state: {:?}", state);
                // Kept here, the one place every drain path goes through, so
                // it holds whether or not the caller sees the event (see
                // `end`). A disconnect starts the grace; only a nomination —
                // `Connected` or `Completed` — ends it. `Checking` does not:
                // a pair re-created without one is no recovery, so the clock
                // runs on.
                match state {
                    IceConnectionState::Disconnected => {
                        self.ice_disconnected_since.get_or_insert_with(Instant::now);
                        Some(SessionEvent::Disconnected)
                    }
                    IceConnectionState::Connected | IceConnectionState::Completed => {
                        if let Some(since) = self.ice_disconnected_since.take() {
                            tracing::info!(
                                "WebRTC: ICE back ({state:?}) after {:.1?} disconnected",
                                since.elapsed()
                            );
                        }
                        Some(SessionEvent::IceStateChange(state))
                    }
                    _ => Some(SessionEvent::IceStateChange(state)),
                }
            }
            Event::Closed => {
                // The peer's DTLS close_notify (or its SCTP association
                // going). str0m drains its own close output and then goes
                // inert: nothing — no ICE event, no timeout — follows. It
                // used to fall through to `_ => None`, so a WHIP ingest or a
                // cascade pull whose peer closed without a DELETE parked in
                // `poll_event` for good, its stream still registered.
                tracing::debug!("WebRTC: the peer closed the connection");
                self.latch(SessionEnd::Closed);
                Some(SessionEvent::Disconnected)
            }
            Event::MediaAdded(added) => {
                let kind = {
                    let media = self.rtc.media(added.mid)?;
                    media.kind()
                };
                match kind {
                    MediaKind::Video => self.video_mid = Some(added.mid),
                    MediaKind::Audio => self.audio_mid = Some(added.mid),
                }
                tracing::info!(
                    "Media track added: {:?} mid={:?} (direction={:?})",
                    kind,
                    added.mid,
                    self.rtc.media(added.mid).map(|m| m.direction()),
                );
                Some(SessionEvent::MediaAdded { mid: added.mid, kind })
            }
            Event::MediaData(data) => {
                tracing::trace!(
                    "MediaData: mid={:?} pt={} len={} contiguous={}",
                    data.mid,
                    data.pt,
                    data.data.len(),
                    data.contiguous,
                );
                Some(SessionEvent::MediaData {
                    mid: data.mid,
                    pt: data.pt,
                    data: data.data,
                    rtp_time: data.time,
                    network_time: data.network_time,
                    contiguous: data.contiguous,
                })
            }
            Event::KeyframeRequest(kf) => {
                Some(SessionEvent::KeyframeRequest { mid: kf.mid })
            }
            _ => None,
        }
    }
}

/// Pick the set of local IPs to advertise as ICE host candidates.
///
/// This is the pure-data half of `WebrtcSession::new`'s candidate-selection
/// logic, broken out so it can be unit-tested without binding real
/// sockets. The interesting cases are:
///
/// - **Operator pinned `public_ip`** — return exactly that IP. The operator
///   knows the deployment topology better than we do (e.g. NAT 1:1
///   mappings, behind-LB deployments), so honour it verbatim. The caller
///   is expected to bind the UDP socket to that same IP so per-packet
///   destination matches the local candidate.
/// - **Bound to an unspecified address** (`0.0.0.0` / `::`) — advertise
///   loopback **and** the route-discovered LAN IP, so both same-host
///   peers (loopback / unit tests / WHIP smoke tests on a developer
///   laptop) and real LAN peers can reach us. The previous implementation
///   only advertised the LAN IP and silently broke loopback testing on
///   macOS — see the 2026-04-09 Bug A fix in QUALITY_REPORT.md.
/// - **Bound to a specific interface** — advertise that interface's IP.
fn select_local_candidate_ips(
    bound_ip: std::net::IpAddr,
    pinned: Option<std::net::IpAddr>,
    route_discovered_lan_ip: impl FnOnce() -> Option<std::net::IpAddr>,
) -> Vec<std::net::IpAddr> {
    if let Some(p) = pinned {
        return vec![p];
    }
    if !bound_ip.is_unspecified() {
        return vec![bound_ip];
    }
    let mut out: Vec<std::net::IpAddr> =
        vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
    if let Some(lan) = route_discovered_lan_ip()
        && !out.contains(&lan) {
            out.push(lan);
        }
    out
}

/// Map an incoming packet's source address to the correct local destination
/// address for str0m's `Receive` struct.
///
/// When the socket is bound to `0.0.0.0`, `local_addr` is `0.0.0.0:<port>`
/// which doesn't match any ICE host candidate. str0m routes packets by
/// matching `(source, destination)` to a candidate pair; mismatched
/// destination causes silent packet drops — the root cause of Scenario K
/// (no `Event::MediaData` after ICE+DTLS complete) and Scenario L (ICE
/// stuck in Checking on the server side).
///
/// Logic:
/// - If `local_addr` is a specific IP → use it (matches the candidate).
/// - If single candidate → use that candidate.
/// - If multiple candidates → match source locality (loopback ↔ loopback,
///   LAN ↔ LAN).
/// - Fallback → first candidate.
fn resolve_destination(
    local_addr: SocketAddr,
    candidate_ips: &[std::net::IpAddr],
    source: SocketAddr,
) -> SocketAddr {
    if !local_addr.ip().is_unspecified() {
        return local_addr;
    }

    let port = local_addr.port();

    if candidate_ips.len() == 1 {
        let dest = SocketAddr::new(candidate_ips[0], port);
        tracing::trace!(
            "WebRTC destination mapped: source={source} → dest={dest} (single candidate)"
        );
        return dest;
    }

    let src_is_loopback = source.ip().is_loopback();

    // Try to match: loopback source → loopback candidate, LAN → LAN.
    for &ip in candidate_ips {
        if src_is_loopback == ip.is_loopback() {
            let dest = SocketAddr::new(ip, port);
            tracing::trace!(
                "WebRTC destination mapped: source={source} → dest={dest}"
            );
            return dest;
        }
    }

    // Fallback to first candidate.
    if let Some(&ip) = candidate_ips.first() {
        let dest = SocketAddr::new(ip, port);
        tracing::trace!(
            "WebRTC destination fallback: source={source} → dest={dest}"
        );
        dest
    } else {
        local_addr
    }
}

/// Normalise an incoming SDP offer so str0m's overly strict parser will
/// accept it.
///
/// Workarounds applied (all safe — affect only descriptive/grouping
/// metadata, never ICE, DTLS, crypto, or codec semantics):
///
/// 1. **Session name** (`s=`): rewritten to `s=-`. str0m 0.18 accepted
///    nothing else, and ffmpeg sends `s=FFmpegPublishSession`. str0m 0.24.1
///    accepts any non-empty name (RFC 8866 §5.3), so this now only rescues
///    an empty `s=`, which it still rejects.
///
/// 2. **BUNDLE group** (`a=group:BUNDLE`): ffmpeg 8.x WHIP muxer emits
///    `a=group:BUNDLE 0 1` but only includes one m-section with
///    `a=mid:1` — mid 0 doesn't exist. str0m tries to reconcile the
///    group with the actual m-sections and silently drops the codec
///    payload parameters, producing an answer with an empty
///    `m=video 0 UDP/TLS/RTP/SAVPF ` line. We rewrite the BUNDLE group
///    to only list MIDs that have a corresponding `a=mid:X` attribute.
fn normalise_sdp_offer_for_str0m(offer: &str) -> String {
    // First pass: collect all MIDs declared in the SDP via `a=mid:X`.
    let mut declared_mids: Vec<String> = Vec::new();
    for line in offer.lines() {
        let trimmed = line.trim();
        if let Some(mid) = trimmed.strip_prefix("a=mid:") {
            declared_mids.push(mid.to_string());
        }
    }

    // Second pass: rewrite.
    let mut out = String::with_capacity(offer.len());
    let mut session_name_rewritten = false;
    let mut bundle_rewritten = false;

    for raw_line in offer.split_inclusive('\n') {
        let line_no_eol = raw_line.trim_end_matches(['\r', '\n']);
        let eol = &raw_line[line_no_eol.len()..];

        // Workaround 1: session name
        if !session_name_rewritten && line_no_eol.starts_with("s=") && line_no_eol != "s=-" {
            out.push_str("s=-");
            out.push_str(eol);
            session_name_rewritten = true;
            continue;
        }

        // Workaround 2: BUNDLE group with phantom MIDs.
        if !bundle_rewritten && line_no_eol.starts_with("a=group:BUNDLE ") {
            let bundle_mids: Vec<&str> = line_no_eol
                .strip_prefix("a=group:BUNDLE ")
                .unwrap_or("")
                .split_whitespace()
                .filter(|mid| declared_mids.iter().any(|d| d == mid))
                .collect();
            if !bundle_mids.is_empty() {
                out.push_str("a=group:BUNDLE ");
                out.push_str(&bundle_mids.join(" "));
                out.push_str(eol);
            }
            // If no valid MIDs remain, drop the BUNDLE line entirely.
            bundle_rewritten = true;
            continue;
        }

        out.push_str(raw_line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_replaces_real_session_name_with_dash() {
        let offer = "v=0\r\n\
                     o=- 123 2 IN IP4 127.0.0.1\r\n\
                     s=FFmpegPublishSession\r\n\
                     t=0 0\r\n";
        let out = normalise_sdp_offer_for_str0m(offer);
        assert!(out.contains("\r\ns=-\r\n"));
        assert!(!out.contains("FFmpegPublishSession"));
    }

    #[test]
    fn normalise_leaves_dash_session_name_alone() {
        let offer = "v=0\r\ns=-\r\nt=0 0\r\n";
        assert_eq!(normalise_sdp_offer_for_str0m(offer), offer);
    }

    #[test]
    fn normalise_only_rewrites_first_session_name() {
        // Per RFC 4566 there is exactly one s= line per SDP, but a media
        // description in some pathological inputs might contain a literal
        // `s=` substring. Make sure we don't accidentally touch m=/a= lines
        // that happen to start with `s` later in the document.
        let offer = "v=0\r\n\
                     s=Foo\r\n\
                     t=0 0\r\n\
                     m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                     a=sendonly\r\n";
        let out = normalise_sdp_offer_for_str0m(offer);
        assert!(out.contains("\r\ns=-\r\n"));
        assert!(out.contains("a=sendonly"));
    }

    #[test]
    fn normalise_preserves_lf_only_line_endings() {
        let offer = "v=0\ns=Whatever\nt=0 0\n";
        let out = normalise_sdp_offer_for_str0m(offer);
        assert_eq!(out, "v=0\ns=-\nt=0 0\n");
    }

    /// ffmpeg 8.x WHIP muxer emits `a=group:BUNDLE 0 1` but only has one
    /// m-section with `a=mid:1`. The phantom mid=0 reference confuses
    /// str0m into generating an answer with empty payload types. Our
    /// normaliser must strip the phantom MID from the BUNDLE group.
    #[test]
    fn normalise_strips_phantom_mids_from_bundle() {
        let offer = "v=0\r\n\
                     o=FFmpeg 123 2 IN IP4 127.0.0.1\r\n\
                     s=-\r\n\
                     t=0 0\r\n\
                     a=group:BUNDLE 0 1\r\n\
                     m=video 9 UDP/TLS/RTP/SAVPF 106\r\n\
                     a=mid:1\r\n\
                     a=rtpmap:106 H264/90000\r\n";
        let out = normalise_sdp_offer_for_str0m(offer);
        assert!(out.contains("a=group:BUNDLE 1\r\n"), "BUNDLE should only list mid=1, got: {}", out);
        assert!(out.contains("a=mid:1"));
        assert!(out.contains("a=rtpmap:106 H264/90000"));
    }

    /// When the BUNDLE group is valid (all MIDs exist), leave it alone.
    #[test]
    fn normalise_preserves_valid_bundle() {
        let offer = "v=0\r\ns=-\r\nt=0 0\r\n\
                     a=group:BUNDLE 0 1\r\n\
                     m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
                     a=mid:0\r\n\
                     m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                     a=mid:1\r\n";
        let out = normalise_sdp_offer_for_str0m(offer);
        assert!(out.contains("a=group:BUNDLE 0 1\r\n"));
    }

    /// Bug A regression (2026-04-09): when the WebRTC socket is bound to
    /// `0.0.0.0` and the operator did not pin a `public_ip`, we MUST
    /// advertise loopback in addition to the LAN IP so same-host peers
    /// (notably ffmpeg WHIP on a developer laptop) can reach us. The
    /// previous implementation only advertised the LAN IP, which silently
    /// broke loopback ICE/DTLS on macOS.
    #[test]
    fn select_candidate_ips_unspecified_bind_advertises_loopback_and_lan() {
        let lan: std::net::IpAddr = "192.168.7.42".parse().unwrap();
        let ips = select_local_candidate_ips(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            None,
            || Some(lan),
        );
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(ips[1], lan);
    }

    #[test]
    fn select_candidate_ips_unspecified_bind_falls_back_to_loopback_only() {
        // No discoverable LAN IP (e.g. host has no default route).
        let ips = select_local_candidate_ips(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            None,
            || None,
        );
        assert_eq!(ips, vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn select_candidate_ips_pinned_public_ip_wins() {
        let pinned: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let ips = select_local_candidate_ips(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            Some(pinned),
            || panic!("must not call route discovery when public_ip is pinned"),
        );
        assert_eq!(ips, vec![pinned]);
    }

    #[test]
    fn select_candidate_ips_specific_bind_uses_bound_ip() {
        let bound: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let ips = select_local_candidate_ips(
            bound,
            None,
            || panic!("must not call route discovery when bind is specific"),
        );
        assert_eq!(ips, vec![bound]);
    }

    #[test]
    fn select_candidate_ips_dedupes_loopback_lan() {
        // Pathological: route discovery returns loopback. Don't list twice.
        let lo: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ips = select_local_candidate_ips(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            None,
            || Some(lo),
        );
        // Route-discovery filter inside `WebrtcSession::new` rejects
        // loopback before passing it in, so this would normally be `None`,
        // but the dedupe logic should still hold defensively.
        assert_eq!(ips, vec![lo]);
    }

    // ── resolve_destination tests ──────────────────────────────────────

    #[test]
    fn resolve_dest_specific_bind_returns_local_addr() {
        let local: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        let candidates = vec!["10.0.0.5".parse().unwrap()];
        let source: SocketAddr = "192.168.1.100:9999".parse().unwrap();
        assert_eq!(resolve_destination(local, &candidates, source), local);
    }

    #[test]
    fn resolve_dest_single_candidate() {
        let local: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        let candidates = vec!["127.0.0.1".parse().unwrap()];
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let expected: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert_eq!(resolve_destination(local, &candidates, source), expected);
    }

    #[test]
    fn resolve_dest_loopback_source_picks_loopback_candidate() {
        let local: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let lan: std::net::IpAddr = "192.168.7.42".parse().unwrap();
        let candidates = vec![lo, lan];
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_eq!(
            resolve_destination(local, &candidates, source),
            SocketAddr::new(lo, 5000),
        );
    }

    #[test]
    fn resolve_dest_lan_source_picks_lan_candidate() {
        let local: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let lan: std::net::IpAddr = "192.168.7.42".parse().unwrap();
        let candidates = vec![lo, lan];
        let source: SocketAddr = "192.168.7.100:9999".parse().unwrap();
        assert_eq!(
            resolve_destination(local, &candidates, source),
            SocketAddr::new(lan, 5000),
        );
    }

    #[test]
    fn resolve_dest_empty_candidates_falls_back_to_local() {
        let local: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        let source: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        assert_eq!(resolve_destination(local, &[], source), local);
    }

    // ── PeerPin: the anti-reflection ingress filter ────────────────────
    //
    // These drive the exact object `WebrtcSession` drives — the session's
    // recv paths call `pin.accept`, its transmit paths call
    // `pin.note_transmit`, and `Event::Connected` calls `pin.arm`.

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A DTLS record (first byte 20..=63) — the payload shape that identifies
    /// the nominated peer. RFC 9443 §3.
    const DTLS: &[u8] = &[22, 0xfe, 0xfd];
    /// A STUN message (first byte 0..=3) — steerable by a spoofer, so it must
    /// never move the pin.
    const STUN: &[u8] = &[0x01, 0x01, 0x00, 0x00];
    /// An SRTP packet (first byte 128..=191).
    const SRTP: &[u8] = &[0x80, 0x60, 0x00, 0x01];
    /// A well-formed 20-byte STUN Binding Request — type `0x0001`, zero
    /// length, RFC 5389 magic cookie `0x2112A442`, 12-byte transaction id.
    /// This is the reflector's opening move, and it is what the ingress-path
    /// tests spoof.
    ///
    /// Note it does NOT survive str0m's `DatagramRecv` demux on its own
    /// (`"No message integrity in incoming STUN binding request"` — str0m
    /// requires MESSAGE-INTEGRITY, which is why the finding's premise needs a
    /// client holding the relay's ufrag/pwd). That is irrelevant to what these
    /// tests assert: [`PeerPin::accept`] runs *before* the demux, so a drop
    /// counted on `offpath_datagrams_dropped()` is unambiguously the pin's
    /// doing and never the demux's.
    const STUN_BINDING_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, // Binding Request, length 0
        0x21, 0x12, 0xa4, 0x42, // magic cookie
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, // txid
    ];
    /// A 16-byte RTP packet — a full 12-byte header plus payload. Unlike the
    /// STUN request above this *does* demux, so it is what the tests use when
    /// they need `ingest` to return `true` for an admitted source.
    const RTP_PACKET: &[u8] = &[
        0x80, 0x60, 0x00, 0x01, // V=2, PT=96, seq=1
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // SSRC
        0xaa, 0xbb, 0xcc, 0xdd, // payload
    ];

    #[test]
    fn dtls_record_types_are_classified_per_rfc9443() {
        assert!(PeerPin::is_dtls(DTLS));
        assert!(PeerPin::is_dtls(&[20]));
        assert!(PeerPin::is_dtls(&[63]));
        assert!(!PeerPin::is_dtls(STUN));
        assert!(!PeerPin::is_dtls(SRTP));
        assert!(!PeerPin::is_dtls(&[19]));
        assert!(!PeerPin::is_dtls(&[64]));
        assert!(!PeerPin::is_dtls(&[]));
    }

    /// Before DTLS completes the filter must be fully open: ICE and DTLS run
    /// from an address nobody has learned yet, so anything stricter would stop
    /// every session from ever connecting.
    #[test]
    fn unarmed_pin_accepts_every_source() {
        let mut pin = PeerPin::default();
        assert!(pin.accept(sa("203.0.113.7:40000")));
        assert!(pin.accept(sa("198.51.100.10:40000")));
        assert!(pin.accept(sa("[2001:db8::1]:40000")));
        assert_eq!(pin.dropped, 0);
        assert_eq!(pin.pinned, None);
    }

    /// THE REFLECTOR. An attacker completes ICE + DTLS from its own address,
    /// then sends ONE spoofed STUN Binding Request carrying USE-CANDIDATE, a
    /// max PRIORITY and a valid MESSAGE-INTEGRITY (it has the relay's ice-pwd
    /// from the 201 answer). str0m's ICE-Lite agent would mint a
    /// peer-reflexive candidate, nominate it on priority alone, and redirect
    /// the whole SRTP stream at the spoofed victim.
    ///
    /// The datagram must be dropped BEFORE str0m sees it — that is what stops
    /// both the redirect and the STUN reply that an egress-only guard would
    /// still have bounced off the victim.
    #[test]
    fn spoofed_ice_reflection_datagram_is_dropped_before_str0m_sees_it() {
        let attacker = sa("203.0.113.7:40000");
        let victim = sa("198.51.100.10:53"); // a DNS resolver, say

        let mut pin = PeerPin::default();
        // ICE + DTLS from the attacker's real address.
        assert!(pin.accept(attacker));
        pin.note_receive(attacker);
        pin.note_transmit(attacker, DTLS);
        pin.arm();
        assert_eq!(pin.pinned, Some(attacker.ip()));

        // The one spoofed packet that used to move the media.
        assert!(!pin.accept(victim), "spoofed source must not reach str0m");
        assert_eq!(pin.dropped, 1);
        // Repeats stay dropped and stay counted (the attack is sustained by
        // one packet per keepalive interval).
        assert!(!pin.accept(victim));
        assert!(!pin.accept(sa("198.51.100.10:19")));
        assert_eq!(pin.dropped, 3);

        // ...and the legitimate peer is untouched throughout.
        assert!(pin.accept(attacker));
    }

    /// The pin follows the DTLS peer, not whatever spoke last. A spoofer that
    /// injects a Binding Request during setup draws a STUN *reply* to the
    /// spoofed address — if that reply were allowed to set the pin, the fix
    /// would arm on the victim and the attacker would then be the one
    /// filtered, leaving the reflector intact.
    #[test]
    fn a_spoofed_stun_reply_target_never_becomes_the_pin() {
        let real = sa("198.51.100.10:40000");
        let spoofed = sa("203.0.113.9:1900");

        let mut pin = PeerPin::default();
        pin.note_receive(real);
        pin.note_transmit(real, DTLS);
        // Attacker injects a spoofed Binding Request mid-handshake; str0m
        // answers it, so we transmit STUN to the spoofed address.
        pin.note_transmit(spoofed, STUN);
        // Media/SRTP to the real peer must not be needed to keep it either.
        pin.arm();

        assert_eq!(pin.pinned, Some(real.ip()), "pin must follow DTLS, not STUN");
        assert!(!pin.accept(spoofed));
    }

    /// A NAT *port* rebind keeps the IP and is routine — the pin is on the IP
    /// alone so it must sail through. Breaking this would drop real viewers
    /// behind ordinary consumer NAT.
    #[test]
    fn same_ip_port_rebind_is_still_accepted() {
        let mut pin = PeerPin::default();
        pin.note_transmit(sa("198.51.100.10:40000"), DTLS);
        pin.arm();

        assert!(pin.accept(sa("198.51.100.10:41234")));
        assert!(pin.accept(sa("198.51.100.10:9")));
        assert_eq!(pin.dropped, 0);
    }

    /// Arming is one-shot. Re-arming on a later `Connected` would let an
    /// attacker who got one datagram through re-point the pin — exactly the
    /// hole being closed.
    #[test]
    fn arming_is_idempotent() {
        let mut pin = PeerPin::default();
        pin.note_transmit(sa("198.51.100.10:40000"), DTLS);
        pin.arm();
        pin.note_transmit(sa("203.0.113.7:40000"), DTLS);
        pin.arm();
        assert_eq!(pin.pinned, Some("198.51.100.10".parse::<IpAddr>().unwrap()));
    }

    /// Defensive fallback: `Connected` implies a DTLS handshake ran, so
    /// `last_dtls_dest` is always set in practice. If it somehow isn't, arm on
    /// the last **demuxed** source rather than leaving the session unpinned.
    ///
    /// The narrowing matters: `note_receive` is now called only after the
    /// `DatagramRecv` demux succeeds (see [`WebrtcSession::ingest`]), so the
    /// least-trustworthy signal in the struct can no longer be set by a
    /// pre-arm attacker sending arbitrary bytes that are not STUN, DTLS, RTP
    /// or RTCP at all. It was previously recorded before the demux, which made
    /// "pin on whatever garbage last arrived" the documented behaviour.
    #[test]
    fn arm_falls_back_to_the_last_demuxed_source() {
        let mut pin = PeerPin::default();
        pin.note_receive(sa("198.51.100.10:40000"));
        pin.arm();
        assert_eq!(pin.pinned, Some("198.51.100.10".parse::<IpAddr>().unwrap()));
        assert!(!pin.accept(sa("203.0.113.7:40000")));
    }

    /// The narrowing above, asserted through the real ingress path rather than
    /// on the bare struct: bytes that do not demux as STUN/DTLS/RTP/RTCP must
    /// leave no trace the pin could later arm on.
    #[tokio::test]
    async fn undemuxable_bytes_never_become_the_arming_fallback() {
        let mut s = test_session().await;
        let junk: &[u8] = &[0x77, 0x77, 0x77, 0x77]; // 119: not STUN/DTLS/RTP/RTCP
        s.buf[..junk.len()].copy_from_slice(junk);
        assert!(
            !s.ingest(junk.len(), sa("203.0.113.7:40000")),
            "undemuxable bytes must not reach str0m"
        );
        s.pin.arm();
        assert_eq!(s.pinned_peer_ip(), None, "must not pin on unvalidated bytes");
    }

    // ── The WIRING: both receive paths run through `ingest` ─────────────
    //
    // The tests above drive `PeerPin` directly, which proves the predicate is
    // right and proves NOTHING about whether it is connected to the socket.
    // Review demonstrated exactly that gap: deleting the guard from both
    // receive loops left the suite green. These tests exercise the real
    // `WebrtcSession` ingress path instead.

    async fn test_session() -> WebrtcSession {
        WebrtcSession::new(&SessionConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_ip: None,
            ice_lite: true,
        })
        .await
        .expect("bind test session")
    }

    /// Arm a session's pin on `peer`, exactly as `Event::Connected` does.
    fn arm_on(s: &mut WebrtcSession, peer: SocketAddr) {
        s.pin.note_transmit(peer, DTLS);
        s.pin.arm();
        assert_eq!(s.pinned_peer_ip(), Some(peer.ip()), "test setup: pin must arm");
    }

    /// `ingest` — the single ingress path both receive loops call — must
    /// refuse an off-path source and admit the pinned one.
    #[tokio::test]
    async fn ingest_refuses_off_path_sources_and_admits_the_pinned_peer() {
        let mut s = test_session().await;
        let peer = sa("198.51.100.10:40000");
        arm_on(&mut s, peer);

        s.buf[..STUN_BINDING_REQUEST.len()].copy_from_slice(STUN_BINDING_REQUEST);
        let spoofed = sa("203.0.113.7:40000");
        assert!(
            !s.ingest(STUN_BINDING_REQUEST.len(), spoofed),
            "off-path datagram must not reach str0m"
        );
        assert_eq!(s.offpath_datagrams_dropped(), 1, "the pin, not the demux, dropped it");

        // A NAT *port* rebind on the pinned IP still passes — the common case.
        s.buf[..RTP_PACKET.len()].copy_from_slice(RTP_PACKET);
        assert!(
            s.ingest(RTP_PACKET.len(), sa("198.51.100.10:41234")),
            "the pinned peer's media must reach str0m across a port rebind"
        );
        assert_eq!(s.offpath_datagrams_dropped(), 1, "the pinned peer is never dropped");
    }

    /// `drive_udp_io` — the non-blocking receive loop used by the WHEP viewer
    /// send loop — must run its datagrams through the filter. This one goes
    /// over a real socket: a genuinely different source IP (127.0.0.2, a
    /// second loopback address) sends to the session's real bound port.
    ///
    /// Deleting the `self.ingest(len, source)` call from `drive_udp_io` (or
    /// the `pin.accept` guard inside `ingest`) turns this red.
    #[tokio::test]
    async fn drive_udp_io_filters_off_path_datagrams_over_a_real_socket() {
        let mut s = test_session().await;
        let bound = s.local_addr;
        arm_on(&mut s, sa("127.0.0.1:40000"));

        // Off-path: same host, different source IP.
        let attacker = tokio::net::UdpSocket::bind("127.0.0.2:0").await.expect("bind 127.0.0.2");
        attacker.send_to(STUN_BINDING_REQUEST, bound).await.expect("send spoofed");
        // On-path: the pinned IP, sending something that genuinely demuxes.
        let real = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind 127.0.0.1");
        real.send_to(RTP_PACKET, bound).await.expect("send real");

        // Give the kernel a moment to deliver both, then drain.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        s.drive_udp_io().await;

        assert_eq!(
            s.offpath_datagrams_dropped(),
            1,
            "drive_udp_io must run received datagrams through the source pin"
        );
        let (pinned, offender) = s.take_offpath_alert().expect("first drop raises one alert");
        assert_eq!(pinned, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(offender.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
        assert!(s.take_offpath_alert().is_none(), "the alert is one-shot");
    }

    /// `poll_event` — the blocking receive loop used during setup and by the
    /// WHIP/cascade paths — must run its datagrams through the same filter.
    /// Same real-socket shape; `poll_event` blocks for events, so it is driven
    /// under a timeout and the assertion is made on what it consumed.
    ///
    /// Deleting the `self.ingest(len, source)` call from `poll_event` (or the
    /// `pin.accept` guard inside `ingest`) turns this red.
    #[tokio::test]
    async fn poll_event_filters_off_path_datagrams_over_a_real_socket() {
        let mut s = test_session().await;
        let bound = s.local_addr;
        arm_on(&mut s, sa("127.0.0.1:40000"));

        let attacker = tokio::net::UdpSocket::bind("127.0.0.2:0").await.expect("bind 127.0.0.2");
        attacker.send_to(STUN_BINDING_REQUEST, bound).await.expect("send spoofed");

        let cancel = CancellationToken::new();
        // poll_event only returns on a session event; there is none here, so
        // let it spin over the datagram and then time out.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(300), s.poll_event(&cancel))
            .await;

        assert_eq!(
            s.offpath_datagrams_dropped(),
            1,
            "poll_event must run received datagrams through the source pin"
        );
    }

    /// With nothing observed at all, fail OPEN rather than wedge a live
    /// session on an unanticipated state (the warning in `arm` is the alarm).
    #[test]
    fn arm_with_nothing_observed_leaves_the_filter_open() {
        let mut pin = PeerPin::default();
        pin.arm();
        assert_eq!(pin.pinned, None);
        assert!(pin.accept(sa("203.0.113.7:40000")));
    }

    /// IPv6 sessions get the same treatment — the pin compares `IpAddr`, so
    /// v6 peers pin and v6 spoofs drop.
    #[test]
    fn pin_applies_to_ipv6_peers() {
        let mut pin = PeerPin::default();
        pin.note_transmit(sa("[2001:db8::10]:40000"), DTLS);
        pin.arm();
        assert!(pin.accept(sa("[2001:db8::10]:41111")));
        assert!(!pin.accept(sa("[2001:db8::999]:40000")));
        assert_eq!(pin.dropped, 1);
    }

    // ── The codec set ──────────────────────────────────────────────────

    /// `H264_LEVEL_5_1` is str0m's own built-in H.264 set with only the level
    /// raised, and Opus (without RED) is the only other codec. A str0m bump
    /// that renumbers, reorders or adds to its built-in H.264 entries turns
    /// this red: move the table with it, and bilbycast-edge's copy in the same
    /// change.
    #[test]
    fn codec_set_is_str0ms_h264_defaults_at_level_5_1_plus_opus() {
        use str0m::format::{Codec, PayloadParams};

        // (pt, rtx pt, packetization mode, profile-level-id)
        type Entry = (u8, Option<u8>, Option<u8>, u32);
        fn h264(params: &[PayloadParams]) -> Vec<Entry> {
            params
                .iter()
                .filter(|p| p.spec().codec == Codec::H264)
                .map(|p| {
                    let format = p.spec().format;
                    (
                        *p.pt(),
                        p.resend().map(|rtx| *rtx),
                        format.packetization_mode,
                        format
                            .profile_level_id
                            .expect("H.264 entries carry a profile-level-id"),
                    )
                })
                .collect()
        }

        let builtin = h264(Rtc::builder().codec_config().params());
        let ours = rtc_config(true).codec_config().params().to_vec();
        let registered = h264(&ours);

        assert_eq!(
            registered.len(),
            builtin.len(),
            "{registered:x?} vs {builtin:x?}"
        );
        for (o, b) in registered.iter().zip(&builtin) {
            assert_eq!(
                (o.0, o.1, o.2),
                (b.0, b.1, b.2),
                "PT, RTX PT and packetization mode"
            );
            assert_eq!(o.3 >> 8, b.3 >> 8, "profile of PT {}", o.0);
            assert_eq!(
                b.3 & 0xff,
                0x1f,
                "str0m's built-in PT {} is no longer level 3.1",
                b.0
            );
            assert_eq!(o.3 & 0xff, 0x33, "PT {} is not level 5.1", o.0);
        }

        let others: Vec<(Codec, u8)> = ours
            .iter()
            .filter(|p| p.spec().codec != Codec::H264)
            .map(|p| (p.spec().codec, *p.pt()))
            .collect();
        assert_eq!(
            others,
            vec![(Codec::Opus, 111)],
            "anything besides H.264 and Opus"
        );
        assert!(ours.iter().all(|p| p.red().is_none()), "RED is off");
    }

    /// A panic inside a negotiation step comes back as a typed
    /// [`NegotiationPanic`] carrying the step and the panic message — both
    /// payload shapes `panic!` produces — and a step that does not panic
    /// passes its own result through untouched, an error included.
    #[test]
    fn isolate_negotiation_turns_a_panic_into_a_typed_error() {
        let pt = 102;
        let err =
            isolate_negotiation::<()>("SDP offer", || panic!("Pt locked multiple times: {pt}"))
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "str0m panicked during SDP offer: Pt locked multiple times: 102"
        );
        let panic = err.downcast_ref::<NegotiationPanic>().expect("typed");
        assert_eq!(
            (panic.step, panic.message.as_str()),
            ("SDP offer", "Pt locked multiple times: 102")
        );
        let err =
            isolate_negotiation::<()>("SDP answer", || panic!("a static message")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "str0m panicked during SDP answer: a static message"
        );

        assert_eq!(isolate_negotiation("SDP offer", || Ok(7)).unwrap(), 7);
        let err =
            isolate_negotiation::<()>("SDP offer", || Err(anyhow::anyhow!("SDP accept error")))
                .unwrap_err();
        assert_eq!(err.to_string(), "SDP accept error");
        assert!(
            err.downcast_ref::<NegotiationPanic>().is_none(),
            "not a panic"
        );
    }

    /// An offer that str0m cannot negotiate fails as a [`NegotiationPanic`]
    /// of the step it reached, and one that does not even parse fails as a
    /// plain error — the parse now runs inside the isolated step too.
    #[tokio::test]
    async fn accept_offer_reports_which_step_panicked() {
        // Baseline in packetization mode 1 and 0, one RTX PT repairing both:
        // str0m 0.24.1 locks that RTX PT twice and panics.
        let hostile = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n\
             m=video 9 UDP/TLS/RTP/SAVPF 102 104 103\r\nc=IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:hstl\r\na=ice-pwd:hostilepasswordhostile\r\n\
             a=fingerprint:sha-256 5B:7E:0A:26:41:91:C4:7F:33:D8:12:6E:A0:5C:B9:E4:08:71:2D:9F:C6:3A:55:EB:10:84:7D:F2:69:0C:A3:1E\r\n\
             a=setup:actpass\r\na=mid:0\r\na=recvonly\r\na=rtcp-mux\r\n\
             a=rtpmap:102 H264/90000\r\n\
             a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n\
             a=rtpmap:104 H264/90000\r\n\
             a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n\
             a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\na=fmtp:103 apt=104\r\n";
        let err = test_session().await.accept_offer(hostile).unwrap_err();
        let panic = err
            .downcast_ref::<NegotiationPanic>()
            .expect("a str0m panic");
        assert_eq!(panic.step, "SDP offer");
        assert!(
            panic.message.contains("Pt locked multiple times"),
            "{panic}"
        );

        let err = test_session()
            .await
            .accept_offer("v=0\r\nnot an offer\r\n")
            .unwrap_err();
        assert!(err.downcast_ref::<NegotiationPanic>().is_none(), "{err}");
    }

    // ── The send payload type ─────────────────────────────────────────

    /// Negotiated params, in codec-config order, for the m-line that offered
    /// `offered` as `(pt, codec name, fmtp)` — what `Writer::payload_params`
    /// hands `send_pt`.
    fn negotiated(kind: MediaKind, offered: &[(u8, &str, &str)]) -> Vec<PayloadParams> {
        let (m, clock) = match kind {
            MediaKind::Video => ("video", "90000"),
            MediaKind::Audio => ("audio", "48000/2"),
        };
        let mut sdp = format!(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n\
             m={m} 9 UDP/TLS/RTP/SAVPF {}\r\nc=IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:pptu\r\na=ice-pwd:payloadtypepasswordpw\r\n\
             a=fingerprint:sha-256 5B:7E:0A:26:41:91:C4:7F:33:D8:12:6E:A0:5C:B9:E4:08:71:2D:9F:C6:3A:55:EB:10:84:7D:F2:69:0C:A3:1E\r\n\
             a=setup:actpass\r\na=mid:0\r\na=recvonly\r\na=rtcp-mux\r\n",
            offered
                .iter()
                .map(|o| o.0.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        for (pt, codec, fmtp) in offered {
            sdp.push_str(&format!("a=rtpmap:{pt} {codec}/{clock}\r\n"));
            if !fmtp.is_empty() {
                sdp.push_str(&format!("a=fmtp:{pt} {fmtp}\r\n"));
            }
        }
        let mut rtc = rtc_config(true).build(Instant::now());
        rtc.sdp_api()
            .accept_offer(SdpOffer::from_sdp_string(&sdp).unwrap())
            .unwrap();
        let mid = Mid::from("0");
        rtc.writer(mid).unwrap().payload_params().cloned().collect()
    }

    /// Video goes out on an H.264 packetization-mode=1 PT whenever the peer
    /// accepted one, even when a mode-0 PT comes first in codec-config order;
    /// a peer that accepted only mode 0 still gets video, on that PT. Audio
    /// goes out on Opus.
    ///
    /// Before, the first negotiated entry was taken. This offer — Baseline in
    /// mode 0 (PT 104), Constrained Baseline in mode 1 (PT 106) — lists
    /// Baseline first in [`H264_LEVEL_5_1`], so video went out on 104 and
    /// str0m sent STAP-A and FU-A on a PT that forbids them. bilbycast-edge's
    /// `send_pt` returns 106 here.
    #[test]
    fn video_is_written_on_a_packetization_mode_1_pt_when_the_peer_took_one() {
        const MODE_0: &str =
            "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f";
        const MODE_1: &str =
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";
        let params = negotiated(
            MediaKind::Video,
            &[(104, "H264", MODE_0), (106, "H264", MODE_1)],
        );
        assert_eq!(
            params.iter().map(|p| *p.pt()).collect::<Vec<_>>(),
            vec![104, 106],
            "mode 0 first in codec-config order"
        );
        assert_eq!(
            send_pt(MediaKind::Video, params.iter()),
            Some(Pt::new_with_value(106))
        );

        let params = negotiated(MediaKind::Video, &[(104, "H264", MODE_0)]);
        assert_eq!(
            send_pt(MediaKind::Video, params.iter()),
            Some(Pt::new_with_value(104))
        );

        let params = negotiated(
            MediaKind::Audio,
            &[(111, "opus", "minptime=10;useinbandfec=1")],
        );
        assert_eq!(
            send_pt(MediaKind::Audio, params.iter()),
            Some(Pt::new_with_value(111))
        );
        assert_eq!(
            send_pt(MediaKind::Video, params.iter()),
            None,
            "no H.264 on an audio line"
        );
    }

    // ── The disconnect latch ──────────────────────────────────────────

    /// What the drains do with every event: hand it to `handle_event` and
    /// drop the result.
    fn ice(s: &mut WebrtcSession, state: IceConnectionState) {
        let _ = s.handle_event(Event::IceConnectionStateChange(state));
    }

    /// Backdate the start of an ICE disconnect by `ago`.
    fn disconnected_for(s: &mut WebrtcSession, ago: Duration) {
        s.ice_disconnected_since = Some(Instant::now().checked_sub(ago).unwrap());
    }

    /// An ICE disconnect str0m reports while a caller is not looking at
    /// events — in `drain_outputs`, or behind another event in `drive_udp_io`
    /// — is kept, and ends the session once it has lasted
    /// `ICE_DISCONNECT_GRACE`; a nomination in the meantime (`Connected` or
    /// `Completed`) cancels it, and a re-created pair without one (`Checking`)
    /// does not restart the clock.
    ///
    /// Before, the first `Disconnected` ended the session, though an ICE-Lite
    /// agent comes back from it on the peer's next nomination: the "brief"
    /// half of this test failed on it.
    #[tokio::test]
    async fn an_ice_disconnect_ends_the_session_only_once_it_has_lasted_the_grace() {
        let mut s = test_session().await;
        assert_eq!(s.end(), None);
        ice(&mut s, IceConnectionState::Checking);
        assert_eq!(s.end(), None, "not every state change is the end");

        // A brief disconnect is not the end, and a nomination cancels it.
        ice(&mut s, IceConnectionState::Disconnected);
        assert_eq!(s.end(), None, "a fresh disconnect may yet come back");
        ice(&mut s, IceConnectionState::Completed);
        assert_eq!(s.ice_disconnected_since, None, "Completed cancels it");
        disconnected_for(&mut s, Duration::ZERO);
        ice(&mut s, IceConnectionState::Connected);
        assert_eq!(s.ice_disconnected_since, None, "Connected cancels it too");

        // One that lasts the grace is.
        ice(&mut s, IceConnectionState::Disconnected);
        disconnected_for(&mut s, ICE_DISCONNECT_GRACE - Duration::from_secs(1));
        assert_eq!(s.end(), None);
        disconnected_for(&mut s, ICE_DISCONNECT_GRACE);
        assert_eq!(s.end(), Some(SessionEnd::IceDisconnected));
        assert!(s.is_disconnected());

        // A later `Disconnected` keeps the first one's start, and `Checking`
        // in between neither cancels nor restarts it.
        ice(&mut s, IceConnectionState::Checking);
        ice(&mut s, IceConnectionState::Disconnected);
        assert_eq!(s.end(), Some(SessionEnd::IceDisconnected));
    }

    /// A fatal end is final from the first drain that sees it: the peer
    /// closing the connection (`Event::Closed`, which used to be dropped), a
    /// closed `Rtc`, or a local `close`.
    #[tokio::test]
    async fn a_closed_connection_ends_the_session_at_once() {
        let mut s = test_session().await;
        assert!(matches!(
            s.handle_event(Event::Closed),
            Some(SessionEvent::Disconnected)
        ));
        assert_eq!(s.end(), Some(SessionEnd::Closed));
        ice(&mut s, IceConnectionState::Completed);
        assert_eq!(s.end(), Some(SessionEnd::Closed), "and nothing revives it");

        let mut s = test_session().await;
        s.rtc.disconnect();
        assert_eq!(s.end(), Some(SessionEnd::Closed), "a closed Rtc is over");

        let mut s = test_session().await;
        s.close();
        assert_eq!(s.end(), Some(SessionEnd::Closed));
    }

    /// Two connected sessions; `close` on one sends its DTLS close_notify, and
    /// the other's `poll_event` returns `Disconnected` on it within a few
    /// seconds, its end `Closed`.
    ///
    /// Before, `Event::Closed` was dropped and str0m then went inert, so
    /// `poll_event` slept on a deadline years away: a WHIP ingest or cascade
    /// pull whose peer closed without a DELETE never ended.
    #[tokio::test]
    async fn poll_event_ends_when_the_peer_closes_the_connection() {
        let session = |ice_lite| async move {
            WebrtcSession::new(&SessionConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                public_ip: Some("127.0.0.1".parse().unwrap()),
                ice_lite,
            })
            .await
            .unwrap()
        };
        let mut client = session(false).await;
        let mut server = session(true).await;
        let (offer, pending) = client.create_offer(true, false, true).unwrap();
        let answer = server.accept_offer(&offer).unwrap();
        client.apply_answer(&answer, pending).unwrap();
        async fn connected(s: &mut WebrtcSession, cancel: &CancellationToken) -> bool {
            loop {
                match s.poll_event(cancel).await {
                    SessionEvent::Connected => return true,
                    SessionEvent::Disconnected => return false,
                    _ => {}
                }
            }
        }
        let cancel = CancellationToken::new();
        let both = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                connected(&mut client, &cancel),
                connected(&mut server, &cancel)
            )
        })
        .await
        .expect("the two sessions connect");
        assert_eq!(both, (true, true));

        client.close();
        client.drain_outputs().await;
        assert!(client.is_disconnected());

        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SessionEvent::Disconnected = server.poll_event(&cancel).await {
                    return;
                }
            }
        })
        .await;
        assert!(
            ended.is_ok(),
            "poll_event did not end after the peer closed"
        );
        assert_eq!(server.end(), Some(SessionEnd::Closed));
    }
}
