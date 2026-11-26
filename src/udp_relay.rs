// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Plain-UDP relay data plane — native SRT/RIST over relay without QUIC.
//!
//! This is the additive sibling of the QUIC relay ([`crate::server`] +
//! [`crate::session`]). It binds a plain UDP socket and pairs two edges by a
//! shared tunnel UUID via **source-address rendezvous**: each edge connects
//! *outbound* (firewall traversal), periodically sends an authenticated
//! [`UdpRelayControl::Register`] control datagram (nil-UUID-prefixed), and the
//! relay latches that edge's post-NAT source address into the tunnel's
//! ingress/egress slot. Media datagrams (`[16-byte real UUID][AEAD payload]`,
//! identical framing to the QUIC datagram path) are then forwarded **verbatim**
//! to the paired slot's latched address — the relay stays end-to-end opaque
//! (the AEAD layer lives on the edges; the relay holds no media key).
//!
//! Why no QUIC: SRT/RIST run their own ARQ + congestion control; carrying them
//! inside QUIC adds per-packet AEAD/header overhead and a second congestion
//! controller that fights theirs. Plain UDP forwarding removes both.
//!
//! The existing QUIC tunnel path is untouched; this runs as a parallel task.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use serde::Serialize;
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::config::RelayConfig;
use crate::manager::events::{category, EventSeverity};
use crate::protocol::{
    decode_udp_datagram, encode_udp_control, try_decode_udp_control, TunnelDirection,
    UdpRelayControl, TUNNEL_PROTOCOL_VERSION,
};
use crate::session::SessionContext;
use crate::stats::{Counted, DepartedTunnels, TunnelStats, TunnelTotals};
use crate::tunnel_router::TokenDigest;
use crate::util::IpCounts;

/// Session is reaped after this long with no register/keepalive or data, and a
/// slot of a session that stays is cleared after this long with nothing from
/// its own address ([`UdpSessionRouter::reap_idle`]).
/// Edges re-register every ~5 s (see the edge `udp_relay_client`), so a 30 s
/// idle window tolerates a few missed keepalives (cellular/satellite handover)
/// without tearing a live session down.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the idle reaper runs.
const REAPER_INTERVAL: Duration = Duration::from_secs(10);

/// Per-datagram receive buffer. SRT default payload 1316 + AEAD(28) + UUID(16)
/// ≈ 1360; 2048 covers larger payloads + jumbo-ish without truncation.
const RECV_BUF: usize = 2048;

/// 32 MB socket buffers — broadcast contribution at tens of Mbps overruns the
/// default ~200 KB kernel buffer (testbed quality gate #11).
pub(crate) const SOCK_BUF_BYTES: usize = 32 * 1024 * 1024;

// ── Lock-free atomic SocketAddr (mirrors the edge udp_forwarder pattern) ──

/// A `SocketAddr` stored in atomics so the forwarding hot path reads/updates a
/// latched peer address without locking.
struct AtomicAddr {
    /// 0 = unset, 4 = IPv4, 6 = IPv6.
    family: AtomicU8,
    hi: AtomicU64,
    lo: AtomicU64,
    port: AtomicU16,
}

impl AtomicAddr {
    fn new() -> Self {
        Self {
            family: AtomicU8::new(0),
            hi: AtomicU64::new(0),
            lo: AtomicU64::new(0),
            port: AtomicU16::new(0),
        }
    }

    fn store(&self, addr: SocketAddr) {
        match addr.ip() {
            IpAddr::V4(v4) => {
                self.lo.store(u32::from(v4) as u64, Ordering::Relaxed);
                self.hi.store(0, Ordering::Relaxed);
                self.port.store(addr.port(), Ordering::Relaxed);
                self.family.store(4, Ordering::Release);
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                self.hi
                    .store(u64::from_be_bytes(o[..8].try_into().unwrap()), Ordering::Relaxed);
                self.lo
                    .store(u64::from_be_bytes(o[8..].try_into().unwrap()), Ordering::Relaxed);
                self.port.store(addr.port(), Ordering::Relaxed);
                self.family.store(6, Ordering::Release);
            }
        }
    }

    fn load(&self) -> Option<SocketAddr> {
        let fam = self.family.load(Ordering::Acquire);
        if fam == 0 {
            return None;
        }
        let port = self.port.load(Ordering::Relaxed);
        let ip = if fam == 4 {
            IpAddr::V4(Ipv4Addr::from(self.lo.load(Ordering::Relaxed) as u32))
        } else {
            let mut o = [0u8; 16];
            o[..8].copy_from_slice(&self.hi.load(Ordering::Relaxed).to_be_bytes());
            o[8..].copy_from_slice(&self.lo.load(Ordering::Relaxed).to_be_bytes());
            IpAddr::V6(Ipv6Addr::from(o))
        };
        Some(SocketAddr::new(ip, port))
    }

    fn is_set(&self) -> bool {
        self.family.load(Ordering::Acquire) != 0
    }

    /// Unset the address. The data path reads the family first (`Acquire`),
    /// so it sees either the whole old address or none.
    fn clear(&self) {
        self.family.store(0, Ordering::Release);
    }
}

/// Now in epoch-millis (saturating).
fn now_ms() -> u64 {
    crate::stats::now_epoch_ms()
}

/// Monotonic milliseconds since process start.
///
/// The slot hold-down below MUST NOT use wall time: an NTP/PTP step (routine
/// on a broadcast host — `chrony` settling, `phc2sys` starting) would either
/// expire every hold-down at once or freeze them for the length of the step.
fn mono_ms() -> u64 {
    // `+ 1` so this NEVER returns 0, because 0 is the "slot has never carried
    // media" sentinel on `ingress_media_ms` / `egress_media_ms`. Without the
    // offset, media forwarded in the process's first millisecond stamps a slot
    // with 0 and the hold-down reads it as unprotected — a real (if narrow)
    // hole, and one that made the hijack test pass an attacker through.
    crate::observability::monotonic_us() / 1_000 + 1
}

/// Is a slot protected from being moved to a different source IP?
///
/// Pure so the boundary is unit-testable without a 12 s sleep or a clock seam.
/// `last_media_ms == 0` means the slot has never carried media, and such a
/// slot is deliberately unprotected — see the hold-down comment in `latch`.
fn slot_is_protected(last_media_ms: u64, now_ms: u64) -> bool {
    last_media_ms != 0 && now_ms.saturating_sub(last_media_ms) < SLOT_TAKEOVER_GRACE_MS
}

/// Has a slot been *heard* in the last [`PEER_LIVE_MS`]: a `Register` accepted
/// from it at `seen_ms`, or media forwarded from its latched address at
/// `media_ms`? `0` is never, for either stamp.
///
/// Pure, like [`slot_is_protected`], so its boundary is tested without a 16 s
/// sleep. A stamp in the future saturates to "just heard".
fn slot_heard(seen_ms: u64, media_ms: u64, now_ms: u64) -> bool {
    let last = seen_ms.max(media_ms);
    last != 0 && now_ms.saturating_sub(last) < PEER_LIVE_MS
}

/// Has a latched slot been silent long enough to be cleared: nothing from it,
/// `Register` or media, for longer than [`SESSION_IDLE_TIMEOUT`]?
fn slot_departed(seen_ms: u64, media_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(seen_ms.max(media_ms)) > SESSION_IDLE_TIMEOUT.as_millis() as u64
}

/// Is `src` an address a real edge could have reached us from, and that we can
/// therefore safely latch into a tunnel slot?
///
/// The latch turns a source address into a *send* target: whatever ends up in a
/// slot is where the paired side's media is forwarded. So the slot must never
/// hold an address that no host owns — an unspecified IP, a multicast or
/// broadcast group, or port 0. None of them can be the genuine post-NAT source
/// of an edge that dialed out to us, so refusing them costs nothing.
///
/// **This is defence in depth, not the reflection mitigation.** On Linux — the
/// only platform this relay ships on — most of these sources never reach
/// `recv_from` at all: `ip_route_input_slow()` routes an IPv4 datagram whose
/// *source* is multicast, limited-broadcast or zeronet to `martian_source` and
/// drops it, and `ip6_rcv_core()` drops an IPv6 packet with a multicast source
/// outright. So the check earns its keep only on a kernel that does not filter
/// martians, or a future non-Linux port. Treat the "free multicast fan-out"
/// reading as theoretical.
///
/// It does **not** address unicast reflection: an attacker who spoofs a
/// *plausible* unicast source passes this check by construction. The mitigation
/// for that is `require_bind_auth: true` (plus the [`SLOT_TAKEOVER_GRACE_MS`]
/// hold-down for a slot already carrying media). The one unicast class that is
/// genuinely catastrophic — an address that routes back to the relay itself,
/// turning a session into an unbounded forward loop — is handled by the
/// dest-equals-source drop in [`UdpSessionRouter::forward_target`] and the
/// degenerate-latch refusal in [`UdpSessionRouter::latch`], not here.
///
/// Those two close the **single-address** loop (one relay-local address in both
/// slots). They do not close a **two-address** variant, where the slots hold two
/// *different* addresses that both route back to this relay (its v4 and v6
/// listeners, say): each hop then matches the opposite slot and bounces back.
/// Closing that would need the relay's own bound-address set threaded onto this
/// type, and it is deliberately not done, because the precondition is already
/// unreachable on a stock Linux host: a datagram arriving on any interface with
/// a source address the host itself owns is dropped as a martian source by
/// `__fib_validate_source` (a local source's route type is `RTN_LOCAL`, not
/// `RTN_UNICAST`, and `net.ipv4.conf.*.accept_local` defaults to 0) — which is
/// the same reason the two guards above are defence in depth rather than the
/// mitigation. Record it here so nobody reads them as a total closure; if this
/// relay is ever ported to a kernel without that filter, thread the bound
/// addresses in.
///
/// Deliberately permissive about **loopback and private ranges**: the testbed
/// runs the relay and both edges on `127.0.0.1`, and real deployments relay
/// between RFC1918 / ULA addresses inside an operator network. Rejecting either
/// would break working configurations, which is a worse bug than the one this
/// closes.
fn is_latchable_source(src: SocketAddr) -> bool {
    if src.port() == 0 {
        return false;
    }
    match src.ip() {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    }
}

/// A latched slot may only move to a DIFFERENT source IP once it has been
/// silent this long.
///
/// Edges re-register every ~5 s and live media refreshes the slot continuously,
/// so 12 s is two missed keepalives: a flowing session cannot be stolen, while
/// a genuine WAN-IP change (carrier handover, DHCP move) still recovers well
/// inside the 30 s `SESSION_IDLE_TIMEOUT`.
/// Invariant: register cadence (5 s) < this < `SESSION_IDLE_TIMEOUT` (30 s).
const SLOT_TAKEOVER_GRACE_MS: u64 = 12_000;

/// How long a slot stays *heard* after its last accepted `Register` or the
/// last media forwarded from its address ([`slot_heard`]). The `Ack`'s
/// `peer_live` says whether the opposite slot is heard, and a session's status
/// and [`UdpSessionRouter::active_count`] count heard slots.
///
/// Three register intervals, so two lost `Register`s in a row do not make a
/// peer look gone, and well inside the 30 s idle reap, so an edge learns its
/// peer has gone before the relay clears the slot. The edge mirrors this value
/// (`RELAY_PEER_LIVE_MS` in `bilbycast-edge/src/tunnel/native_meet.rs`) to
/// time its own decisions: change both.
pub(crate) const PEER_LIVE_MS: u64 = 16_000;

/// How often an edge re-registers: the edge's `KEEPALIVE_INTERVAL`.
const EDGE_REGISTER_INTERVAL_MS: u64 = 5_000;

const _: () = assert!(PEER_LIVE_MS >= 3 * EDGE_REGISTER_INTERVAL_MS);
const _: () = assert!(PEER_LIVE_MS < SESSION_IDLE_TIMEOUT.as_millis() as u64);

/// A native-UDP relay session: two latched edge addresses paired by tunnel UUID.
pub struct UdpSession {
    pub tunnel_id: Uuid,
    /// Manager "egress node" / destination side (receives from the tunnel).
    ingress: AtomicAddr,
    /// Manager "ingress node" / source side (sends INTO the tunnel).
    egress: AtomicAddr,
    /// Index (into the relay's bound-socket set) that each side last
    /// registered / sent on. The reply to a side MUST egress from the SAME
    /// relay socket it dialed, or its NAT/conntrack (and any per-port firewall
    /// forward) drops the unexpected source — the multi-listen-port bug that
    /// pinned all forwarding onto `sockets[0]`. `usize::MAX` = unset.
    ingress_sock: AtomicUsize,
    egress_sock: AtomicUsize,
    /// Monotonic ms at which each slot last carried MEDIA from its latched
    /// address. `0` = never. Deliberately NOT refreshed by `Register`: a slot
    /// earns protection by carrying traffic, so an attacker cannot pre-claim
    /// an idle slot and then hide behind the hold-down. Distinct from
    /// `last_seen_ms`, which either side refreshes.
    ingress_media_ms: AtomicU64,
    egress_media_ms: AtomicU64,
    /// Monotonic ms of the last `Register` accepted on each slot. `0` = never.
    /// With `*_media_ms` it says whether the slot is heard ([`slot_heard`]):
    /// what the `Ack`'s `peer_live`, the session's status and the reaper's
    /// slot clearing go by. Written under the session's entry lock.
    ingress_seen_ms: AtomicU64,
    egress_seen_ms: AtomicU64,
    /// The `standby` flag of the `Register` that last latched each slot: that
    /// edge's media goes through the tunnel's other relay, and it registers
    /// here only to be found. Written under the session's entry lock.
    ingress_standby: AtomicBool,
    egress_standby: AtomicBool,
    /// Monotonic ms since which both slots have been heard without a break, as
    /// `Register`s observe it; `0` = not both heard. The `Ack`'s `live_ms`.
    /// Read and written under the session's entry lock.
    live_since_ms: AtomicU64,
    /// The token shown by the `Register` that latched each slot, the right one
    /// or not: with none registered for the tunnel, any is taken. Read and
    /// written under the session's entry lock.
    ingress_shown: Option<TokenDigest>,
    egress_shown: Option<TokenDigest>,
    /// Source IP that created the session (for per-IP DoS accounting).
    creator_ip: IpAddr,
    pub stats: Arc<TunnelStats>,
    last_seen_ms: AtomicU64,
    created_at: Instant,
}

impl UdpSession {
    fn new(tunnel_id: Uuid, creator_ip: IpAddr) -> Self {
        Self {
            tunnel_id,
            ingress: AtomicAddr::new(),
            egress: AtomicAddr::new(),
            ingress_sock: AtomicUsize::new(usize::MAX),
            egress_sock: AtomicUsize::new(usize::MAX),
            ingress_media_ms: AtomicU64::new(0),
            egress_media_ms: AtomicU64::new(0),
            ingress_seen_ms: AtomicU64::new(0),
            egress_seen_ms: AtomicU64::new(0),
            ingress_standby: AtomicBool::new(false),
            egress_standby: AtomicBool::new(false),
            live_since_ms: AtomicU64::new(0),
            ingress_shown: None,
            egress_shown: None,
            creator_ip,
            stats: Arc::new(TunnelStats::new()),
            last_seen_ms: AtomicU64::new(now_ms()),
            created_at: Instant::now(),
        }
    }

    /// Both slots hold an address: the `Ack`'s `ready`, whose meaning edges up
    /// to v0.117.0 depend on. A slot that has gone quiet still counts until
    /// the reaper clears it.
    fn both_latched(&self) -> bool {
        self.ingress.is_set() && self.egress.is_set()
    }

    /// One slot's address, its stamps and its standby flag.
    fn side(&self, direction: TunnelDirection) -> (&AtomicAddr, &AtomicU64, &AtomicU64, &AtomicBool) {
        match direction {
            TunnelDirection::Ingress => {
                (&self.ingress, &self.ingress_seen_ms, &self.ingress_media_ms, &self.ingress_standby)
            }
            TunnelDirection::Egress => {
                (&self.egress, &self.egress_seen_ms, &self.egress_media_ms, &self.egress_standby)
            }
        }
    }

    /// The slot holds an address and has been heard in the last [`PEER_LIVE_MS`].
    fn heard(&self, direction: TunnelDirection, now: u64) -> bool {
        let (addr, seen, media, _) = self.side(direction);
        addr.is_set() && slot_heard(seen.load(Ordering::Relaxed), media.load(Ordering::Relaxed), now)
    }

    /// The slot holds an address that nothing has come from for longer than
    /// [`SESSION_IDLE_TIMEOUT`].
    fn departed(&self, direction: TunnelDirection, now: u64) -> bool {
        let (addr, seen, media, _) = self.side(direction);
        addr.is_set() && slot_departed(seen.load(Ordering::Relaxed), media.load(Ordering::Relaxed), now)
    }

    /// Empty a slot, as if no edge had ever latched it: no address, socket,
    /// stamps, token or standby flag. The two slots are no longer both heard.
    /// Taken with `&mut`, so under the session's entry lock.
    fn clear_slot(&mut self, direction: TunnelDirection) {
        let (addr, seen, media, standby) = self.side(direction);
        addr.clear();
        seen.store(0, Ordering::Relaxed);
        media.store(0, Ordering::Relaxed);
        standby.store(false, Ordering::Relaxed);
        let (sock, shown) = match direction {
            TunnelDirection::Ingress => (&self.ingress_sock, &mut self.ingress_shown),
            TunnelDirection::Egress => (&self.egress_sock, &mut self.egress_shown),
        };
        sock.store(usize::MAX, Ordering::Relaxed);
        *shown = None;
        self.live_since_ms.store(0, Ordering::Relaxed);
    }

    /// The session as `/api/v1/udp-sessions` lists it, by which slots are heard
    /// rather than which are latched: a slot whose edge has moved to the other
    /// relay stays latched for up to 30 s, and `"active"` would have said media
    /// was flowing here. `"active"`: both heard, and not both edges standing by
    /// here, so media may be flowing through this relay.
    fn status_str(&self, now: u64) -> &'static str {
        let standby = |direction| self.side(direction).3.load(Ordering::Relaxed);
        match (self.heard(TunnelDirection::Ingress, now), self.heard(TunnelDirection::Egress, now)) {
            (true, true) if standby(TunnelDirection::Ingress) && standby(TunnelDirection::Egress) => "standby",
            (true, true) => "active",
            (true, false) => "waiting_egress",
            (false, true) => "waiting_ingress",
            (false, false) => "empty",
        }
    }
}

/// The opposite slot of a tunnel.
fn opposite(direction: TunnelDirection) -> TunnelDirection {
    match direction {
        TunnelDirection::Ingress => TunnelDirection::Egress,
        TunnelDirection::Egress => TunnelDirection::Ingress,
    }
}

impl Counted for UdpSession {
    fn stats(&self) -> &Arc<TunnelStats> {
        &self.stats
    }
}

/// Serializable native-UDP session info for the REST API.
#[derive(Debug, Serialize)]
pub struct UdpSessionInfo {
    pub tunnel_id: Uuid,
    pub transport: &'static str,
    pub status: String,
    pub ingress_addr: Option<String>,
    pub egress_addr: Option<String>,
    pub bytes_ingress: u64,
    pub bytes_egress: u64,
    pub datagrams: u64,
    pub uptime_secs: u64,
}

/// Pairs native-UDP edges by tunnel UUID via source-address rendezvous.
///
/// Auth reuses the QUIC path's [`crate::tunnel_router::TunnelRouter`] bind-token
/// registry (the manager already pushes per-tunnel HMAC tokens via
/// `authorize_tunnel`), so no new manager machinery is needed.
pub struct UdpSessionRouter {
    /// A session leaves the map through `departed`, which keeps what it
    /// counted.
    sessions: DashMap<Uuid, UdpSession>,
    departed: DepartedTunnels,
    /// Per-source-IP session-creation counter (DoS mitigation).
    sessions_by_ip: IpCounts,
    max_sessions_per_ip: u32,
    /// This process's `relay_id` on every `Ack`: 32 lowercase hex characters,
    /// new at each start, so an edge can tell one relay at two addresses from
    /// two relays, and a restarted relay from the one before.
    relay_id: String,
}

/// What an `Ack` reports of the tunnel, as the `Register` it answers left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readiness {
    /// Both slots hold an address: the `Ack`'s `ready`.
    pub latched: bool,
    /// The opposite slot was heard in the last [`PEER_LIVE_MS`]: `peer_live`.
    pub peer_live: bool,
    /// How long both slots have been heard without a break, as `Register`s
    /// observed it; `0` when `peer_live` is false: `live_ms`.
    pub live_ms: u64,
}

/// Outcome of latching a registration.
pub enum LatchResult {
    /// Session updated; what the `Ack` reports.
    Ok(Readiness),
    /// As [`Self::Ok`], and the slot was taken from the address that held it:
    /// one that is carrying media, and has not shown the registered token as
    /// this `Register` did.
    TookOver { readiness: Readiness, held_by: SocketAddr },
    /// Per-IP session cap exceeded — registration dropped.
    RejectedDosCap,
    /// The slot is latched to a different IP that is currently carrying media.
    /// A `Register` cannot move a live session; see [`SLOT_TAKEOVER_GRACE_MS`].
    RejectedSlotHeld,
    /// The source address can never be a legitimate slot occupant — either it
    /// is an address no host can own (see [`is_latchable_source`]) or the
    /// *opposite* slot of this tunnel already holds exactly it, which would
    /// build a session whose forwarding target is its own source.
    RejectedInvalidSource,
}

impl UdpSessionRouter {
    pub fn new(max_sessions_per_ip: u32) -> Self {
        Self {
            sessions: DashMap::new(),
            departed: DepartedTunnels::default(),
            sessions_by_ip: IpCounts::default(),
            max_sessions_per_ip,
            relay_id: Uuid::new_v4().simple().to_string(),
        }
    }

    /// The `relay_id` this process puts on every `Ack`.
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Latch (or refresh) an edge's source address into its tunnel slot.
    ///
    /// `standby` is the `Register`'s own flag: this edge's media goes through
    /// the tunnel's other relay. `shown` is the token its `Register` showed,
    /// and `registered` the one the manager has registered for the slot, if it
    /// has.
    ///
    /// The per-IP creation cap + counter bump + insert happen atomically under
    /// the DashMap shard entry lock, so they're counted exactly once per session
    /// (and freed once in [`Self::remove_if`]). Lock order is always
    /// `sessions` → `sessions_by_ip`, matching [`Self::remove_if`] — no
    /// deadlock. The entry stays locked to the end, so a session is not removed
    /// between being found here and being marked as seen, and the slot's
    /// stamps, its standby flag and the session's `live_since_ms` change
    /// together.
    ///
    /// What is returned is what the `Ack` reports ([`Readiness`]): whether both
    /// slots are latched, whether the opposite one is heard, and for how long
    /// both have been.
    // One parameter per thing a `Register` carries or the caller knows about
    // it; a struct to hold them would be built at the one production call.
    #[allow(clippy::too_many_arguments)]
    pub fn latch(
        &self,
        tunnel_id: Uuid,
        direction: TunnelDirection,
        src: SocketAddr,
        sock_idx: usize,
        standby: bool,
        shown: Option<TokenDigest>,
        registered: Option<TokenDigest>,
    ) -> LatchResult {
        self.latch_at(tunnel_id, direction, src, sock_idx, standby, shown, registered, mono_ms())
    }

    /// [`Self::latch`] at the monotonic millisecond `now`, the clock every
    /// stamp it reads and writes is on — so a test can age a slot without
    /// sleeping. The session's wall-clock `last_seen_ms` stays on the wall
    /// clock, as the whole-session reap reads it.
    #[allow(clippy::too_many_arguments)]
    fn latch_at(
        &self,
        tunnel_id: Uuid,
        direction: TunnelDirection,
        src: SocketAddr,
        sock_idx: usize,
        standby: bool,
        shown: Option<TokenDigest>,
        registered: Option<TokenDigest>,
        now: u64,
    ) -> LatchResult {
        use dashmap::mapref::entry::Entry;

        // Source-address sanity lives HERE, at the router's own choke point,
        // not only at the (currently single) call site. `latch` is `pub` on a
        // `pub struct` in a library crate: the invariant "a slot only ever
        // holds an address a real edge could have reached us from" belongs to
        // the type that owns the slot, or the next caller silently reopens it.
        //
        // Checked before the session entry so an implausible source can never
        // create a session — and so cannot burn a legitimate host's per-IP
        // quota on the way to being rejected.
        if !is_latchable_source(src) {
            return LatchResult::RejectedInvalidSource;
        }

        let ip = src.ip();
        let mut session = match self.sessions.entry(tunnel_id) {
            Entry::Occupied(o) => o.into_ref(),
            Entry::Vacant(v) => {
                if self.sessions_by_ip.add(ip, self.max_sessions_per_ip).is_err() {
                    return LatchResult::RejectedDosCap;
                }
                v.insert(UdpSession::new(tunnel_id, ip))
            }
        };
        // A tunnel's two ends are two distinct edge sockets, so the two slots
        // can never legitimately hold the same address. Letting them build a
        // session whose forwarding target IS its own source: if that address
        // routes back to the relay (its own advertised `public_udp_addr`, say)
        // one spoofed media datagram is delivered back to our own listening
        // socket and re-forwarded, forever, at kernel line rate — on a recv
        // loop shared by every session on that port. `forward_target` drops
        // dest == src as well; this refuses to reach the state at all.
        let other = match direction {
            TunnelDirection::Ingress => &session.egress,
            TunnelDirection::Egress => &session.ingress,
        };
        if other.load() == Some(src) {
            return LatchResult::RejectedInvalidSource;
        }

        // Hold-down: refuse to move a slot that is currently carrying media to
        // a different source IP.
        //
        // `latch` was unconditional last-writer-wins, so any party who could
        // send one `Register` for a known tunnel id — trivially harvested from
        // the open-by-default `/api/v1/udp-sessions`, or replayed off the wire
        // — could point a live tunnel's egress at themselves: the contribution
        // feed stops reaching the real receiver and is delivered to them.
        //
        // Same-IP moves are always allowed: a NAT port rebind, a relay socket
        // rotation and an edge restart on the same host are all legitimate and
        // all keep the IP. A slot that has never carried media stays
        // last-writer-wins, so first contact is byte-identical to before.
        let session = &mut *session;
        // Asked before anything below changes the slot: a slot never latched,
        // cleared by the reaper or silent for `PEER_LIVE_MS` starts a new
        // stretch of being heard.
        let was_heard = session.heard(direction, now);
        let (cur_slot, cur_sock, media_ms, seen_ms, cur_standby, cur_shown) = match direction {
            TunnelDirection::Ingress => (
                &session.ingress,
                &session.ingress_sock,
                &session.ingress_media_ms,
                &session.ingress_seen_ms,
                &session.ingress_standby,
                &mut session.ingress_shown,
            ),
            TunnelDirection::Egress => (
                &session.egress,
                &session.egress_sock,
                &session.egress_media_ms,
                &session.egress_seen_ms,
                &session.egress_standby,
                &mut session.egress_shown,
            ),
        };
        let mut held_by = None;
        if let Some(cur) = cur_slot.load()
            && cur.ip() != src.ip()
            && slot_is_protected(media_ms.load(Ordering::Relaxed), now)
        {
            // Unless this edge shows the slot's token and the holder has not:
            // it got the slot while there was none to show. Its `Register`s are
            // refused now, and its media alone would hold the slot for as long
            // as it goes on. A holder that has shown the token keeps the slot,
            // and so does any holder until an edge comes that shows it.
            let shows_registered = |token: Option<TokenDigest>| {
                token.zip(registered).is_some_and(|(token, registered)| token.matches(&registered))
            };
            if shows_registered(*cur_shown) || !shows_registered(shown) {
                return LatchResult::RejectedSlotHeld;
            }
            // The media that protected the slot was not this edge's.
            media_ms.store(0, Ordering::Relaxed);
            held_by = Some(cur);
        }

        cur_slot.store(src);
        cur_sock.store(sock_idx, Ordering::Relaxed);
        *cur_shown = shown;
        seen_ms.store(now, Ordering::Relaxed);
        cur_standby.store(standby, Ordering::Relaxed);
        session.last_seen_ms.store(now_ms(), Ordering::Relaxed);

        // Both slots have been heard without a break since `live_since_ms`. The
        // stretch ends when the other slot is not heard now, and starts again
        // when this one had a break: it was not heard, or it was just taken
        // from another edge, which is not the one that was heard.
        let peer_live = session.heard(opposite(direction), now);
        let live_since = match session.live_since_ms.load(Ordering::Relaxed) {
            _ if !peer_live => 0,
            0 => now,
            _ if !was_heard || held_by.is_some() => now,
            since => since,
        };
        session.live_since_ms.store(live_since, Ordering::Relaxed);
        let readiness = Readiness {
            latched: session.both_latched(),
            peer_live,
            live_ms: if peer_live { now.saturating_sub(live_since) } else { 0 },
        };
        match held_by {
            Some(held_by) => LatchResult::TookOver { readiness, held_by },
            None => LatchResult::Ok(readiness),
        }
    }

    /// Resolve the forwarding target for a media datagram arriving from `src`
    /// on tunnel `tunnel_id`: the *opposite* latched slot, plus the index of
    /// the relay socket that target dialed (so the reply egresses from the SAME
    /// port the peer expects — required when the relay binds multiple UDP ports,
    /// e.g. one per uplink). Also accounts bytes. `None` if the session/peer
    /// isn't known (dropped).
    pub fn forward_target(
        &self,
        tunnel_id: Uuid,
        src: SocketAddr,
        bytes: u64,
    ) -> Option<(SocketAddr, usize)> {
        let session = self.sessions.get(&tunnel_id)?;
        let ingress = session.ingress.load();
        let egress = session.egress.load();
        // Resolve the direction and the paired target BEFORE touching any
        // counter: a datagram we are about to drop as a self-loop must not
        // refresh liveness. Refreshing first is what let a loop hold its own
        // hold-down open (protecting the attacker on BOTH slots) and outrun the
        // 30 s idle reaper indefinitely.
        //
        // Note the target is kept as an `Option` rather than `?`-unwrapped
        // here: a datagram from a latched slot whose PEER has not registered
        // yet is still evidence that this slot is live, and must go on
        // refreshing its hold-down exactly as it did before this guard existed
        // (see below). Only the self-loop skips the accounting.
        let (target, target_sock, bytes_ctr, media_ms) = if Some(src) == ingress {
            // From the destination side → forward to the source side.
            (
                egress,
                session.egress_sock.load(Ordering::Relaxed),
                &session.stats.bytes_ingress,
                &session.ingress_media_ms,
            )
        } else if Some(src) == egress {
            // From the source side → forward to the destination side.
            (
                ingress,
                session.ingress_sock.load(Ordering::Relaxed),
                &session.stats.bytes_egress,
                &session.egress_media_ms,
            )
        } else {
            // Source addr matches neither latched slot (unregistered or a NAT
            // rebind not yet re-latched by a keepalive). Drop.
            return None;
        };

        // Never forward a datagram back to where it came from. `latch` refuses
        // to put one address in both slots, but this is the data path's own
        // choke point: if the address is relay-local, `send_to(data, src)`
        // delivers straight back to our own listening socket, which forwards it
        // again — an unbounded loop at kernel line rate starving every other
        // session sharing this recv loop. One comparison on values already in
        // registers; the function does two more of the same kind above.
        if target == Some(src) {
            return None;
        }

        // The datagram arrived from a latched slot, so that slot is carrying
        // media — record it BEFORE the "peer not latched yet" drop below, as
        // this function always has. A contribution edge that registers and
        // starts sending while its receiver is still down would otherwise leave
        // `*_media_ms` at zero, and `slot_is_protected` would then let one
        // unauthenticated `Register` move its slot: the hold-down would cover
        // only tunnels that are already flowing end to end.
        bytes_ctr.fetch_add(bytes, Ordering::Relaxed);
        media_ms.store(mono_ms(), Ordering::Relaxed);

        // The paired slot is not latched yet: nothing to forward to.
        let target = target?;
        session.stats.udp_datagrams_total.fetch_add(1, Ordering::Relaxed);
        session.last_seen_ms.store(now_ms(), Ordering::Relaxed);
        Some((target, target_sock))
    }

    /// Remove sessions idle longer than [`SESSION_IDLE_TIMEOUT`], then clear
    /// each slot of the sessions that stay which has been silent that long.
    /// Returns the count of sessions reaped.
    pub fn reap_idle(&self) -> usize {
        self.reap_idle_at(mono_ms())
    }

    /// [`Self::reap_idle`] with slots judged at the monotonic millisecond
    /// `now`; whole sessions are judged on the wall clock, as before.
    fn reap_idle_at(&self, now: u64) -> usize {
        let reaped = self.reap_idle_sessions();
        self.clear_departed_slots(now);
        reaped
    }

    /// Clear each slot that holds an address nothing has come from, `Register`
    /// or media, for longer than [`SESSION_IDLE_TIMEOUT`], in a session the
    /// other slot keeps alive.
    ///
    /// Without this, an edge that moved to the tunnel's other relay left its
    /// slot here latched for as long as its peer kept registering, and `ready`
    /// went on saying both sides were present. A cleared slot is empty again:
    /// any `Register` latches it, as at first contact, and the slot's next
    /// edge starts with no media stamp, token or standby flag of the last one.
    fn clear_departed_slots(&self, now: u64) {
        use TunnelDirection::{Egress, Ingress};
        let departed = |s: &UdpSession| s.departed(Ingress, now) || s.departed(Egress, now);
        // Collected first, and the iterator dropped: `get_mut` below takes
        // the shard's write lock, which a live iterator's read guard would
        // hold up for ever.
        let ids: Vec<Uuid> =
            self.sessions.iter().filter(|e| departed(e.value())).map(|e| *e.key()).collect();
        for id in ids {
            // Asked again under the entry's lock: a slot that registered since
            // is kept.
            let Some(mut session) = self.sessions.get_mut(&id) else {
                continue;
            };
            for direction in [Ingress, Egress] {
                if session.departed(direction, now) {
                    session.clear_slot(direction);
                    tracing::debug!(
                        "native-UDP tunnel {id}: {direction:?} slot cleared, nothing from it for {}s",
                        SESSION_IDLE_TIMEOUT.as_secs()
                    );
                }
            }
        }
    }

    /// Remove whole sessions idle longer than [`SESSION_IDLE_TIMEOUT`] on the
    /// wall clock. Returns the count reaped.
    fn reap_idle_sessions(&self) -> usize {
        let now = now_ms();
        let cutoff = SESSION_IDLE_TIMEOUT.as_millis() as u64;
        let is_stale = |session: &UdpSession| {
            now.saturating_sub(session.last_seen_ms.load(Ordering::Relaxed)) > cutoff
        };
        let stale: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|e| is_stale(e.value()))
            .map(|e| *e.key())
            .collect();
        // Asked again as each is removed: one that has registered since stays.
        stale.iter().filter(|id| self.remove_if(id, is_stale)).count()
    }

    /// Force-remove a session (REST escape hatch or manager command).
    pub fn remove(&self, tunnel_id: &Uuid) -> bool {
        self.remove_if(tunnel_id, |_| true)
    }

    /// Remove a session if it is `gone`, and give back what it counts on its
    /// creator's address. Asked and given back under the session's entry lock,
    /// like the rest of [`Self::latch`]'s bookkeeping: an address never counts
    /// a session that is not in the map.
    fn remove_if(&self, tunnel_id: &Uuid, gone: impl FnOnce(&UdpSession) -> bool) -> bool {
        let removed = self.departed.remove_if(&self.sessions, tunnel_id, |session| {
            let gone = gone(session);
            if gone {
                self.sessions_by_ip.remove(session.creator_ip);
            }
            gone
        });
        removed.is_some()
    }

    /// What every native-UDP session has counted since the relay started, the
    /// ones that have gone included.
    pub fn totals(&self) -> TunnelTotals {
        self.departed.totals(&self.sessions)
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Sessions whose two slots are both heard and whose two edges are not both
    /// standing by: those media may be flowing through. A tunnel whose edges
    /// went to its other relay, or that stands by here while it runs there, is
    /// not counted.
    pub fn active_count(&self) -> usize {
        let now = mono_ms();
        self.sessions.iter().filter(|e| e.value().status_str(now) == "active").count()
    }

    pub fn list(&self) -> Vec<UdpSessionInfo> {
        let now = mono_ms();
        self.sessions
            .iter()
            .map(|e| {
                let s = e.value();
                UdpSessionInfo {
                    tunnel_id: s.tunnel_id,
                    transport: "udp",
                    status: s.status_str(now).to_string(),
                    ingress_addr: s.ingress.load().map(|a| a.to_string()),
                    egress_addr: s.egress.load().map(|a| a.to_string()),
                    bytes_ingress: s.stats.bytes_ingress.load(Ordering::Relaxed),
                    bytes_egress: s.stats.bytes_egress.load(Ordering::Relaxed),
                    datagrams: s.stats.udp_datagrams_total.load(Ordering::Relaxed),
                    uptime_secs: s.created_at.elapsed().as_secs(),
                }
            })
            .collect()
    }
}

/// Build a UDP socket for the relay's native plane: dual-stack contract
/// (`IPV6_V6ONLY=1` on v6), `SO_REUSEADDR`, 32 MB send/recv buffers,
/// non-blocking, then wrapped for tokio.
fn build_relay_udp_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match addr.ip() {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if matches!(addr.ip(), IpAddr::V6(_)) {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    // Best-effort large buffers; the OS may clamp to net.core.rmem_max.
    let _ = socket.set_recv_buffer_size(SOCK_BUF_BYTES);
    let _ = socket.set_send_buffer_size(SOCK_BUF_BYTES);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// Pick the bound socket whose address family matches `dest` (falls back to the
/// first socket — covers single-family deployments and IPv4-mapped sends).
fn socket_for(sockets: &[Arc<UdpSocket>], dest: SocketAddr) -> &Arc<UdpSocket> {
    let want_v6 = dest.is_ipv6();
    sockets
        .iter()
        .find(|s| s.local_addr().map(|a| a.is_ipv6() == want_v6).unwrap_or(false))
        .unwrap_or(&sockets[0])
}

/// Run the plain-UDP relay data plane: [`bind_udp_relay`] then
/// [`serve_udp_relay`]. `main` goes through `supervise::supervise_udp_relay`
/// instead, which retries the bind.
pub async fn run_udp_relay(config: &RelayConfig, ctx: Arc<SessionContext>) -> Result<()> {
    serve_udp_relay(bind_udp_relay(config)?, ctx).await
}

/// Bind one socket per [`RelayConfig::effective_udp_relay_addrs`] entry.
///
/// Bind failures are **non-fatal**: a socket that can't bind is logged and
/// skipped (so an upgrade never bricks a relay over a busy `:4434`). If *no*
/// socket binds this returns an error, the relay continues QUIC-only, and the
/// supervisor tries the bind again later (relay#15).
pub fn bind_udp_relay(config: &RelayConfig) -> Result<Vec<Arc<UdpSocket>>> {
    let entries = config.effective_udp_relay_addrs();
    let mut sockets: Vec<Arc<UdpSocket>> = Vec::with_capacity(entries.len());
    for raw in &entries {
        let addr: SocketAddr = match raw.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("native-UDP relay: invalid bind address '{raw}': {e}");
                continue;
            }
        };
        match build_relay_udp_socket(addr) {
            Ok(sock) => {
                tracing::info!("native-UDP relay listening on {addr}");
                sockets.push(Arc::new(sock));
            }
            Err(e) => {
                tracing::warn!("native-UDP relay: failed to bind {addr}: {e} (skipping)");
            }
        }
    }

    if sockets.is_empty() {
        anyhow::bail!("native-UDP relay: no listener could be bound");
    }
    Ok(sockets)
}

/// Forward on the bound sockets forever. Returns only if a receive loop
/// ends, which none does short of a panic.
pub async fn serve_udp_relay(sockets: Vec<Arc<UdpSocket>>, ctx: Arc<SessionContext>) -> Result<()> {
    let sockets: Arc<Vec<Arc<UdpSocket>>> = Arc::new(sockets);

    // Idle-session reaper (UDP has no connection-close signal).
    {
        let router = ctx.udp_sessions.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REAPER_INTERVAL);
            loop {
                tick.tick().await;
                let n = router.reap_idle();
                if n > 0 {
                    tracing::debug!("native-UDP relay reaped {n} idle session(s)");
                }
            }
        });
    }

    // One recv loop per bound socket; all share the session router + socket set.
    // Each loop carries its own index so a session records which port each side
    // dialed and the reply egresses from that same socket.
    let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    for (idx, sock) in sockets.iter().cloned().enumerate() {
        let ctx = ctx.clone();
        let sockets = sockets.clone();
        set.spawn(async move {
            recv_loop(idx, sock, sockets, ctx).await;
        });
    }
    // First loop to exit collapses the task; dropping the JoinSet aborts the rest.
    match set.join_next().await {
        Some(Err(join)) => Err(anyhow::anyhow!("native-UDP receive loop failed: {join}")),
        _ => Err(anyhow::anyhow!("native-UDP receive loop stopped")),
    }
}

async fn recv_loop(
    idx: usize,
    sock: Arc<UdpSocket>,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    ctx: Arc<SessionContext>,
) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("native-UDP relay recv error: {e}");
                continue;
            }
        };
        let data = &buf[..n];

        // Control plane (nil-UUID prefix) → registration/keepalive.
        if let Some(ctrl) = try_decode_udp_control(data) {
            handle_control(&ctx, &sock, idx, src, ctrl).await;
            continue;
        }

        // Data plane → forward verbatim to the paired slot, egressing from the
        // socket the target dialed (falls back to family-match for a target
        // whose dialed socket is somehow unknown / out of range).
        let Some((tunnel_id, _payload)) = decode_udp_datagram(data) else {
            continue; // too short
        };
        if let Some((dest, dest_sock)) = ctx.udp_sessions.forward_target(tunnel_id, src, n as u64) {
            let out = sockets.get(dest_sock).unwrap_or_else(|| socket_for(&sockets, dest));
            if let Err(e) = out.send_to(data, dest).await {
                tracing::trace!("native-UDP relay forward to {dest} failed: {e}");
            }
        }
    }
}

async fn handle_control(
    ctx: &Arc<SessionContext>,
    sock: &Arc<UdpSocket>,
    sock_idx: usize,
    src: SocketAddr,
    ctrl: UdpRelayControl,
) {
    match ctrl {
        // `seq` and `standby` are typed (`u32`, `bool`) and serde has already
        // refused any other value, so there is nothing further to validate:
        // `seq` is only echoed back to the address it came from, and `standby`
        // only says how this session is counted.
        UdpRelayControl::Register {
            tunnel_id,
            direction,
            bind_token,
            protocol_version,
            seq,
            standby,
        } => {
            if protocol_version != 0 && protocol_version != TUNNEL_PROTOCOL_VERSION {
                tracing::debug!(
                    "native-UDP register for {tunnel_id} proto v{protocol_version} (relay v{TUNNEL_PROTOCOL_VERSION})"
                );
            }

            // Source-address sanity, before anything else touches state: a
            // slot is a send target, so it must never hold an address no host
            // can own. See `is_latchable_source`.
            if !is_latchable_source(src) {
                tracing::warn!(
                    "native-UDP register rejected for tunnel {tunnel_id} from {src}: \
                     source address is not latchable"
                );
                ctx.event_sender.emit_with_id_and_details(
                    EventSeverity::Warning,
                    category::TUNNEL,
                    "Native-UDP register rejected: implausible source address",
                    &tunnel_id.to_string(),
                    serde_json::json!({
                        "error_code": "relay_invalid_source_addr",
                        "reason": "unroutable_source",
                        "remote_addr": src.to_string(),
                        "remote_ip": src.ip().to_string(),
                        "transport": "udp",
                    }),
                );
                return;
            }

            // Reuse the QUIC path's bind-token authorization registry.
            let shown = bind_token.as_deref().map(TokenDigest::of);
            if !ctx.router.verify_bind_token(&tunnel_id, direction, shown.as_ref()) {
                tracing::warn!(
                    "native-UDP register rejected for tunnel {tunnel_id} from {src}: invalid bind_token"
                );
                ctx.event_sender.emit_with_id_and_details(
                    EventSeverity::Warning,
                    category::TUNNEL,
                    "Native-UDP register rejected: invalid token",
                    &tunnel_id.to_string(),
                    serde_json::json!({ "remote_addr": src.to_string(), "transport": "udp" }),
                );
                return;
            }

            let registered = ctx.router.registered_token(&tunnel_id, direction);
            let latched = ctx.udp_sessions.latch(
                tunnel_id,
                direction,
                src,
                sock_idx,
                standby.unwrap_or(false),
                shown,
                registered,
            );
            if let LatchResult::TookOver { held_by, .. } = latched {
                tracing::warn!(
                    "native-UDP tunnel {tunnel_id}: {src} showed the {direction:?} slot's token, \
                     which {held_by} held without"
                );
                ctx.event_sender.emit_with_id_and_details(
                    EventSeverity::Warning,
                    category::TUNNEL,
                    "Native-UDP slot taken over by the edge that showed its token",
                    &tunnel_id.to_string(),
                    serde_json::json!({
                        "error_code": "relay_unproven_holder_replaced",
                        "transport": "udp",
                        "direction": format!("{direction:?}"),
                        "remote_addr": src.to_string(),
                        "held_by": held_by.to_string(),
                    }),
                );
            }
            match latched {
                LatchResult::Ok(readiness) | LatchResult::TookOver { readiness, .. } => {
                    // Ack so the edge confirms the relay is alive (failover),
                    // learns when both sides are present, and — an edge after
                    // v0.117.0 — whether its peer is heard here, to meet it on
                    // whichever relay both reach.
                    let ack = UdpRelayControl::Ack {
                        tunnel_id,
                        ready: readiness.latched,
                        peer_live: Some(readiness.peer_live),
                        live_ms: Some(readiness.live_ms),
                        relay_id: Some(ctx.udp_sessions.relay_id().to_owned()),
                        seq,
                    };
                    if let Ok(bytes) = encode_udp_control(&ack) {
                        let _ = sock.send_to(&bytes, src).await;
                    }
                    if readiness.latched {
                        tracing::debug!(
                            "native-UDP tunnel {tunnel_id}: both slots latched, peer {} ({} ms live)",
                            if readiness.peer_live { "heard" } else { "not heard in the last 16 s" },
                            readiness.live_ms
                        );
                    }
                }
                LatchResult::RejectedSlotHeld => {
                    // Deliberately no Ack: the caller is either an attacker
                    // trying to move a live tunnel, or a stale/duplicate edge.
                    // Acking would tell an attacker the tunnel id is real.
                    tracing::warn!(
                        "native-UDP register rejected for {tunnel_id} from {src}: \
                         slot is carrying media from a different address"
                    );
                    ctx.event_sender.emit_with_id_and_details(
                        EventSeverity::Warning,
                        category::TUNNEL,
                        "Native-UDP register refused: slot held by a live peer",
                        &tunnel_id.to_string(),
                        serde_json::json!({
                            "error_code": "relay_slot_takeover_refused",
                            "remote_addr": src.to_string(),
                            "remote_ip": src.ip().to_string(),
                            "transport": "udp",
                        }),
                    );
                }
                LatchResult::RejectedInvalidSource => {
                    // The `is_latchable_source` half is already handled by the
                    // early return above, so reaching here means the DEGENERATE
                    // latch: the opposite slot of this tunnel already holds
                    // exactly this address, which would make the session
                    // forward to its own source. No Ack, same as a held slot.
                    tracing::warn!(
                        "native-UDP register rejected for {tunnel_id} from {src}: \
                         the opposite slot already holds this address (self-loop)"
                    );
                    ctx.event_sender.emit_with_id_and_details(
                        EventSeverity::Warning,
                        category::TUNNEL,
                        "Native-UDP register rejected: implausible source address",
                        &tunnel_id.to_string(),
                        serde_json::json!({
                            "error_code": "relay_invalid_source_addr",
                            "reason": "both_slots_same_address",
                            "remote_addr": src.to_string(),
                            "remote_ip": src.ip().to_string(),
                            "transport": "udp",
                        }),
                    );
                }
                LatchResult::RejectedDosCap => {
                    tracing::warn!(
                        "native-UDP register rejected for {tunnel_id} from {src}: per-IP session cap"
                    );
                    ctx.event_sender.emit_with_id_and_details(
                        EventSeverity::Warning,
                        category::TUNNEL,
                        "Native-UDP register rejected: per-IP session cap exceeded",
                        &tunnel_id.to_string(),
                        serde_json::json!({
                            "error_code": "relay_dos_suspect",
                            "remote_addr": src.to_string(),
                            "remote_ip": src.ip().to_string(),
                            "transport": "udp",
                        }),
                    );
                }
            }
        }
        // Edges don't send Ack to the relay; ignore defensively.
        UdpRelayControl::Ack { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn latch_pairs_and_forwards_both_directions() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let src = v4(5000); // egress / source side
        let dst = v4(6000); // ingress / destination side

        // Only one side latched → not ready, no forwarding target. Egress
        // dialed relay socket 0, ingress dialed socket 1 (multi-port relay).
        assert!(matches!(r.latch(t, TunnelDirection::Egress, src, 0, false, None, None), LatchResult::Ok(Readiness { latched: false, .. })));
        assert!(r.forward_target(t, src, 100).is_none());

        // Both latched → ready.
        assert!(matches!(r.latch(t, TunnelDirection::Ingress, dst, 1, false, None, None), LatchResult::Ok(Readiness { latched: true, .. })));

        // Source-side datagram forwards to the destination side via the socket
        // the destination dialed (1), and vice versa via socket 0.
        assert_eq!(r.forward_target(t, src, 100), Some((dst, 1)));
        assert_eq!(r.forward_target(t, dst, 100), Some((src, 0)));

        // Unknown source addr is dropped.
        assert!(r.forward_target(t, v4(9999), 100).is_none());
    }

    #[test]
    fn forwards_egress_from_the_socket_the_target_dialed() {
        // Regression for the multi-listen-port bug: replies must leave the SAME
        // relay socket the peer dialed, not always sockets[0].
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let src = v4(5000); // source/egress side, dialed relay socket 2
        let dst = v4(6000); // destination/ingress side, dialed relay socket 0
        r.latch(t, TunnelDirection::Egress, src, 2, false, None, None);
        r.latch(t, TunnelDirection::Ingress, dst, 0, false, None, None);
        // src→dst egresses from the socket dst dialed (0)…
        assert_eq!(r.forward_target(t, src, 1), Some((dst, 0)));
        // …and dst→src egresses from the socket src dialed (2).
        assert_eq!(r.forward_target(t, dst, 1), Some((src, 2)));
    }

    #[test]
    fn unknown_tunnel_has_no_target() {
        let r = UdpSessionRouter::new(64);
        assert!(r.forward_target(Uuid::new_v4(), v4(1), 1).is_none());
    }

    #[test]
    fn nat_rebind_relatches_source_addr() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let dst = v4(6000);
        r.latch(t, TunnelDirection::Ingress, dst, 0, false, None, None);
        r.latch(t, TunnelDirection::Egress, v4(5000), 0, false, None, None);
        assert_eq!(r.forward_target(t, v4(5000), 1), Some((dst, 0)));
        // Egress edge's NAT rebinds to a new port; re-register relatches it.
        r.latch(t, TunnelDirection::Egress, v4(5001), 0, false, None, None);
        assert!(r.forward_target(t, v4(5000), 1).is_none());
        assert_eq!(r.forward_target(t, v4(5001), 1), Some((dst, 0)));
    }

    #[test]
    fn per_ip_session_cap_enforced() {
        let r = UdpSessionRouter::new(2);
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        // Three distinct tunnels from the same IP: third is rejected.
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 1), 0, false, None, None),
            LatchResult::Ok(_)
        ));
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 2), 0, false, None, None),
            LatchResult::Ok(_)
        ));
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 3), 0, false, None, None),
            LatchResult::RejectedDosCap
        ));
    }

    #[test]
    fn reap_removes_idle_sessions_and_frees_ip_quota() {
        let r = UdpSessionRouter::new(1);
        let t = Uuid::new_v4();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        r.latch(t, TunnelDirection::Egress, SocketAddr::new(ip.into(), 1), 0, false, None, None);
        // Force it stale.
        r.sessions
            .get(&t)
            .unwrap()
            .last_seen_ms
            .store(0, Ordering::Relaxed);
        assert_eq!(r.reap_idle(), 1);
        assert_eq!(r.count(), 0);
        // IP quota was freed → a new session from the same IP succeeds.
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 2), 0, false, None, None),
            LatchResult::Ok(_)
        ));
    }
}

#[cfg(test)]
mod slot_holddown_tests {
    use super::*;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse::<IpAddr>().unwrap(), port)
    }

    /// Mark a slot as having just carried media, as `forward_target` would.
    fn mark_media(r: &UdpSessionRouter, t: Uuid, dir: TunnelDirection) {
        let s = r.sessions.get(&t).expect("session exists");
        let stamp = match dir {
            TunnelDirection::Ingress => &s.ingress_media_ms,
            TunnelDirection::Egress => &s.egress_media_ms,
        };
        stamp.store(mono_ms(), Ordering::Relaxed);
    }

    fn slot_addr(r: &UdpSessionRouter, t: Uuid, dir: TunnelDirection) -> Option<SocketAddr> {
        let s = r.sessions.get(&t)?;
        match dir {
            TunnelDirection::Ingress => s.ingress.load(),
            TunnelDirection::Egress => s.egress.load(),
        }
    }

    /// THE HIJACK. A live tunnel's slot must not move to a different IP on the
    /// strength of one unauthenticated `Register` — that redirects the
    /// contribution feed away from the real receiver and to the attacker.
    #[test]
    fn live_slot_cannot_be_stolen_by_a_different_ip() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let real = addr("198.51.100.10", 5000);
        let attacker = addr("203.0.113.7", 5000);

        assert!(matches!(r.latch(t, TunnelDirection::Egress, real, 0, false, None, None), LatchResult::Ok(_)));
        mark_media(&r, t, TunnelDirection::Egress);

        assert!(matches!(
            r.latch(t, TunnelDirection::Egress, attacker, 0, false, None, None),
            LatchResult::RejectedSlotHeld
        ));
        assert_eq!(
            slot_addr(&r, t, TunnelDirection::Egress),
            Some(real),
            "the live peer must keep the slot"
        );
    }

    /// A NAT port rebind keeps the IP and must still re-latch — this is normal
    /// and frequent, and refusing it would drop real sessions.
    #[test]
    fn same_ip_port_rebind_still_relatches() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let before = addr("198.51.100.10", 5000);
        let after = addr("198.51.100.10", 41234);

        r.latch(t, TunnelDirection::Egress, before, 0, false, None, None);
        mark_media(&r, t, TunnelDirection::Egress);

        assert!(matches!(r.latch(t, TunnelDirection::Egress, after, 0, false, None, None), LatchResult::Ok(_)));
        assert_eq!(slot_addr(&r, t, TunnelDirection::Egress), Some(after));
    }

    /// A slot that has never carried media stays last-writer-wins, so first
    /// contact and re-provisioning behave exactly as before the hold-down —
    /// and pre-claiming an idle slot buys an attacker no protection.
    #[test]
    fn idle_slot_is_still_last_writer_wins() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let first = addr("198.51.100.10", 5000);
        let second = addr("203.0.113.7", 5000);

        r.latch(t, TunnelDirection::Egress, first, 0, false, None, None);
        // No media ever forwarded on this slot.
        assert!(matches!(r.latch(t, TunnelDirection::Egress, second, 0, false, None, None), LatchResult::Ok(_)));
        assert_eq!(slot_addr(&r, t, TunnelDirection::Egress), Some(second));
    }

    /// A genuine WAN-IP change (carrier handover) must recover once the old
    /// peer has gone quiet for the grace period — well inside the 30 s idle
    /// timeout, so the session is never stranded. Exercised on the pure
    /// predicate: faking an "old" stamp is impossible a millisecond into the
    /// process, and a 12 s sleep has no place in a unit test.
    #[test]
    fn takeover_allowed_once_the_incumbent_goes_quiet() {
        let now = 1_000_000u64;
        assert!(slot_is_protected(now, now), "just carried media");
        assert!(
            slot_is_protected(now - (SLOT_TAKEOVER_GRACE_MS - 1), now),
            "still inside the grace window"
        );
        assert!(
            !slot_is_protected(now - SLOT_TAKEOVER_GRACE_MS, now),
            "grace elapsed — a real carrier handover must be able to take over"
        );
        assert!(!slot_is_protected(0, now), "never carried media = unprotected");
        // A stamp in the future (a clock oddity we cannot rule out) saturates
        // the subtraction to 0 and therefore protects the slot. That is the
        // safe direction — it expires as the monotonic clock advances past it,
        // rather than leaving a live slot stealable.
        assert!(slot_is_protected(now + 5_000, now));
    }

    /// The hold-down is per-slot: protecting a live egress must not prevent
    /// the ingress side from latching or moving.
    #[test]
    fn holddown_is_per_slot_not_per_session() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        r.latch(t, TunnelDirection::Egress, addr("198.51.100.10", 5000), 0, false, None, None);
        mark_media(&r, t, TunnelDirection::Egress);

        assert!(matches!(
            r.latch(t, TunnelDirection::Ingress, addr("203.0.113.9", 6000), 0, false, None, None),
            LatchResult::Ok(_)
        ));
    }

    /// A slot is a *send* target. Latching an address no host can own turns the
    /// relay into a black hole (unspecified / port 0) or, worse, a free
    /// multicast/broadcast fan-out of somebody else's contribution feed.
    #[test]
    fn implausible_source_addresses_are_not_latchable() {
        for bad in [
            "0.0.0.0:5000",           // unspecified v4
            "224.0.0.1:5000",         // multicast v4
            "239.255.1.2:5000",       // admin-scoped multicast v4
            "255.255.255.255:5000",   // limited broadcast
            "[::]:5000",              // unspecified v6
            "[ff02::1]:5000",         // link-local all-nodes multicast v6
            "198.51.100.10:0",        // port 0
            "[2001:db8::1]:0",        // port 0, v6
        ] {
            assert!(
                !is_latchable_source(bad.parse().unwrap()),
                "{bad} must not be latchable"
            );
        }
    }

    /// The check must NOT reject loopback or private ranges — the testbed runs
    /// relay + both edges on 127.0.0.1, and real deployments relay between
    /// RFC1918 / ULA addresses. Rejecting these would break working configs.
    #[test]
    fn loopback_and_private_sources_stay_latchable() {
        for good in [
            "127.0.0.1:5000",
            "10.0.0.9:5000",
            "172.16.4.1:41234",
            "192.168.1.50:4434",
            "100.64.0.7:5000",  // CGNAT — a very common real post-NAT source
            "198.51.100.10:5000",
            "[::1]:5000",
            "[fd00::1]:5000",   // ULA
            "[2001:db8::1]:5000",
        ] {
            assert!(
                is_latchable_source(good.parse().unwrap()),
                "{good} must stay latchable"
            );
        }
    }

    /// `latch` — not just the free predicate — must refuse an unlatchable
    /// source, and must leave no trace when it does.
    ///
    /// This is the wiring test: the predicate having the right opinion is
    /// worthless if the router never asks it. Deleting the
    /// `is_latchable_source` guard from `latch` turns this red.
    #[test]
    fn latch_refuses_an_unlatchable_source_address() {
        let r = UdpSessionRouter::new(64);
        for bad in ["0.0.0.0:5000", "224.0.0.1:5000", "255.255.255.255:5000", "10.0.0.9:0"] {
            let t = Uuid::new_v4();
            let src: SocketAddr = bad.parse().unwrap();
            assert!(
                matches!(r.latch(t, TunnelDirection::Egress, src, 0, false, None, None), LatchResult::RejectedInvalidSource),
                "{bad} must be refused by latch, not merely by the predicate"
            );
            assert_eq!(
                slot_addr(&r, t, TunnelDirection::Egress),
                None,
                "{bad} must leave the slot unset"
            );
            // And it must not have created a session at all — otherwise a
            // rejected register still burns the source IP's per-IP quota.
            assert_eq!(r.count(), 0, "{bad} must not create a session");
        }
    }

    /// The two ends of a tunnel are two distinct edge sockets. Letting both
    /// slots hold ONE address builds a session that forwards to its own source
    /// — an unbounded loop when that address routes back to the relay.
    #[test]
    fn both_slots_cannot_hold_the_same_address() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        // The relay's own advertised dial address, as an attacker would spoof it.
        let relay_self = addr("111.118.193.172", 7400);

        assert!(matches!(r.latch(t, TunnelDirection::Ingress, relay_self, 0, false, None, None), LatchResult::Ok(_)));
        assert!(
            matches!(
                r.latch(t, TunnelDirection::Egress, relay_self, 0, false, None, None),
                LatchResult::RejectedInvalidSource
            ),
            "the opposite slot must refuse an address the other slot already holds"
        );
        assert_eq!(slot_addr(&r, t, TunnelDirection::Egress), None);
        // Not "active", so nothing is forwarded on it either.
        assert!(r.forward_target(t, relay_self, 100).is_none());
    }

    /// The data path's own guard: whatever state a session reached, a datagram
    /// is never forwarded back to where it came from.
    #[test]
    fn forward_target_never_returns_its_own_source() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let relay_self = addr("111.118.193.172", 7400);

        // Drive the router into the degenerate state directly, bypassing
        // `latch`'s refusal — this asserts the drop holds regardless of HOW
        // both slots came to hold one address.
        r.latch(t, TunnelDirection::Ingress, addr("198.51.100.10", 5000), 0, false, None, None);
        let s = r.sessions.get(&t).expect("session exists");
        s.ingress.store(relay_self);
        s.egress.store(relay_self);
        drop(s);

        assert_eq!(
            r.forward_target(t, relay_self, 100),
            None,
            "dest == src is an unbounded forward loop and must be dropped"
        );
        // …and the dropped datagram must not refresh liveness, or the loop
        // would hold its own hold-down open and outrun the idle reaper.
        let s = r.sessions.get(&t).expect("session exists");
        assert_eq!(s.ingress_media_ms.load(Ordering::Relaxed), 0, "no media stamp on a drop");
        assert_eq!(s.egress_media_ms.load(Ordering::Relaxed), 0, "no media stamp on a drop");
        assert_eq!(s.stats.udp_datagrams_total.load(Ordering::Relaxed), 0);
    }

    /// The self-loop drop must be the ONLY case that skips accounting. A
    /// contribution edge that registers and starts sending while its receiver
    /// is still down is a half-latched session carrying real media: that media
    /// must keep stamping `*_media_ms`, or `slot_is_protected` stays false and
    /// one unauthenticated `Register` can move the live contributor's slot —
    /// the hold-down would then cover only tunnels already flowing end to end.
    #[test]
    fn media_from_a_latched_slot_holds_it_down_before_the_peer_arrives() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let contributor = addr("198.51.100.10", 5000);

        assert!(matches!(
            r.latch(t, TunnelDirection::Ingress, contributor, 0, false, None, None),
            LatchResult::Ok(Readiness { latched: false, .. }) // peer not latched: session is "waiting"
        ));
        // Media arrives with no egress peer yet — nothing to forward to…
        assert_eq!(r.forward_target(t, contributor, 1316), None);

        // …but the slot is demonstrably live, so it is accounted and held down.
        let s = r.sessions.get(&t).expect("session exists");
        assert_eq!(s.stats.bytes_ingress.load(Ordering::Relaxed), 1316);
        assert!(
            slot_is_protected(s.ingress_media_ms.load(Ordering::Relaxed), mono_ms()),
            "a waiting contributor's slot must be held down while it sends"
        );
        drop(s);

        // And the hold-down actually refuses the spoofed move.
        assert!(matches!(
            r.latch(t, TunnelDirection::Ingress, addr("203.0.113.7", 5000), 0, false, None, None),
            LatchResult::RejectedSlotHeld
        ));
        assert_eq!(slot_addr(&r, t, TunnelDirection::Ingress), Some(contributor));
    }

    /// The grace must sit between the register cadence and the idle timeout,
    /// or the hold-down either blocks live keepalives or outlives the session.
    #[test]
    fn grace_window_is_bounded_by_the_register_cadence_and_idle_timeout() {
        let grace = SLOT_TAKEOVER_GRACE_MS;
        assert!(grace > EDGE_REGISTER_INTERVAL_MS, "must exceed the ~5 s register cadence");
        assert!(
            grace < SESSION_IDLE_TIMEOUT.as_millis() as u64,
            "must expire before the session is reaped"
        );
    }
}

#[cfg(test)]
mod shown_token_tests {
    //! Tokens that come after the registers they are for.
    use super::*;
    use crate::manager::events::Event;
    use crate::session::test_relay::start_relay_capped;
    use TunnelDirection::{Egress, Ingress};

    fn addr(host: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, host], port))
    }

    fn token(text: &str) -> Option<TokenDigest> {
        Some(TokenDigest::of(text))
    }

    /// A router in which `src` registered on `direction`, showing `shown` with
    /// nothing registered, and is sending.
    fn held(t: Uuid, direction: TunnelDirection, src: SocketAddr, shown: Option<TokenDigest>) -> UdpSessionRouter {
        let r = UdpSessionRouter::new(64);
        assert!(matches!(r.latch(t, direction, src, 0, false, shown, None), LatchResult::Ok(Readiness { latched: false, .. })));
        assert!(r.forward_target(t, src, 1316).is_none());
        r
    }

    fn slot(r: &UdpSessionRouter, t: Uuid, direction: TunnelDirection) -> (Option<SocketAddr>, u64, usize) {
        let s = r.sessions.get(&t).unwrap();
        let (slot, media_ms, sock) = match direction {
            Ingress => (&s.ingress, &s.ingress_media_ms, &s.ingress_sock),
            Egress => (&s.egress, &s.egress_media_ms, &s.egress_sock),
        };
        (slot.load(), media_ms.load(Ordering::Relaxed), sock.load(Ordering::Relaxed))
    }

    /// The edge that shows the registered token has the slot from a holder that
    /// is sending and has not shown it, at once, and what the holder still
    /// sends goes nowhere. The edge earns its protection for itself.
    #[test]
    fn the_token_takes_the_slot_from_a_holder_that_has_not_shown_it() {
        for direction in [Ingress, Egress] {
            let other = if direction == Ingress { Egress } else { Ingress };
            for shown in [None, token("wrong")] {
                let t = Uuid::new_v4();
                let (stranger, real, peer) = (addr(1, 5000), addr(2, 6000), addr(3, 7000));
                let r = held(t, direction, stranger, shown);
                assert!(matches!(r.latch(t, other, peer, 1, false, None, None), LatchResult::Ok(Readiness { latched: true, .. })));
                assert_eq!(r.forward_target(t, peer, 1), Some((stranger, 0)));

                // Not while no token is registered, nor to one that shows none.
                for (shown, registered) in
                    [(token("right"), None), (None, token("right")), (token("wrong"), token("right"))]
                {
                    let latched = r.latch(t, direction, real, 2, false, shown, registered);
                    assert!(matches!(latched, LatchResult::RejectedSlotHeld));
                    assert_eq!(r.forward_target(t, peer, 1), Some((stranger, 0)));
                }
                let latched = r.latch(t, direction, real, 2, false, token("right"), token("right"));
                assert!(matches!(
                    latched,
                    LatchResult::TookOver { readiness: Readiness { latched: true, .. }, held_by } if held_by == stranger
                ));
                assert_eq!(slot(&r, t, direction), (Some(real), 0, 2));
                assert_eq!(r.forward_target(t, stranger, 1316), None);
                assert_eq!(r.forward_target(t, peer, 1), Some((real, 2)));
                assert_eq!(r.forward_target(t, real, 1), Some((peer, 1)));
                let third = addr(4, 8000);
                let latched = r.latch(t, direction, third, 3, false, token("right"), token("right"));
                assert!(matches!(latched, LatchResult::RejectedSlotHeld));
            }
        }
    }

    /// With nobody on the other side the tunnel is not ready, whoever has the
    /// slot.
    #[test]
    fn a_slot_taken_over_is_ready_when_the_other_side_is_there() {
        let t = Uuid::new_v4();
        let r = held(t, Ingress, addr(1, 5000), None);
        let latched = r.latch(t, Ingress, addr(2, 6000), 0, false, token("right"), token("right"));
        assert!(matches!(latched, LatchResult::TookOver { readiness: Readiness { latched: false, .. }, .. }));
    }

    /// A holder that has shown the token keeps its slot while it sends, whoever
    /// else shows it, and whether it did before or after the token came.
    #[test]
    fn a_holder_that_has_shown_the_token_keeps_the_slot() {
        let (real, replayed) = (addr(1, 5000), addr(2, 6000));
        for registered_at_first in [None, token("right")] {
            let t = Uuid::new_v4();
            let r = UdpSessionRouter::new(64);
            r.latch(t, Egress, real, 0, false, token("right"), registered_at_first);
            r.forward_target(t, real, 1);
            for _ in 0..3 {
                let latched = r.latch(t, Egress, replayed, 0, false, token("right"), token("right"));
                assert!(matches!(latched, LatchResult::RejectedSlotHeld));
                assert_eq!(slot(&r, t, Egress).0, Some(real));
                assert!(matches!(
                    r.latch(t, Egress, real, 0, false, token("right"), token("right")),
                    LatchResult::Ok(Readiness { latched: false, .. })
                ));
            }
        }
        // Shown by a later register of its own, with none at first.
        let t = Uuid::new_v4();
        let r = held(t, Egress, real, None);
        r.latch(t, Egress, real, 0, false, token("right"), None);
        let latched = r.latch(t, Egress, replayed, 0, false, token("right"), token("right"));
        assert!(matches!(latched, LatchResult::RejectedSlotHeld));
    }

    /// What counts as shown is what the register that holds the slot showed for
    /// it: not one for the other slot, nor one that was refused.
    #[test]
    fn a_token_shown_for_another_slot_or_refused_does_not_count() {
        let t = Uuid::new_v4();
        let (stranger, real) = (addr(1, 5000), addr(2, 6000));
        let r = held(t, Egress, stranger, None);
        assert!(matches!(
            r.latch(t, Ingress, addr(1, 5001), 0, false, token("right"), None),
            LatchResult::Ok(Readiness { latched: true, .. })
        ));
        let refused = r.latch(t, Egress, addr(3, 7000), 0, false, token("right"), None);
        assert!(matches!(refused, LatchResult::RejectedSlotHeld));
        let latched = r.latch(t, Egress, real, 0, false, token("right"), token("right"));
        assert!(matches!(latched, LatchResult::TookOver { .. }));

        // Nor one shown by whoever had the slot before.
        let t = Uuid::new_v4();
        r.latch(t, Egress, real, 0, false, token("right"), None);
        r.latch(t, Egress, stranger, 0, false, None, None);
        r.forward_target(t, stranger, 1);
        let latched = r.latch(t, Egress, real, 0, false, token("right"), token("right"));
        assert!(matches!(latched, LatchResult::TookOver { .. }));
    }

    /// The token registered now is the one that counts: the holder of the one
    /// before a rotation is not cut off until an edge comes with the new one.
    #[test]
    fn the_token_that_counts_is_the_one_registered_now() {
        let t = Uuid::new_v4();
        let (old, new) = (addr(1, 5000), addr(2, 6000));
        let r = held(t, Egress, old, token("before"));
        let refused = r.latch(t, Egress, new, 0, false, token("before"), token("before"));
        assert!(matches!(refused, LatchResult::RejectedSlotHeld));
        r.forward_target(t, old, 1);
        assert_eq!(slot(&r, t, Egress).0, Some(old));
        let latched = r.latch(t, Egress, new, 0, false, token("after"), token("after"));
        assert!(matches!(latched, LatchResult::TookOver { .. }));
    }

    /// A datagram of the native plane, sent from its own address.
    pub(super) async fn socket(host: u8) -> UdpSocket {
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, host], 0))).await.unwrap()
    }

    async fn register(sock: &UdpSocket, relay: SocketAddr, t: Uuid, direction: TunnelDirection, token: Option<&str>) -> Option<bool> {
        let register = UdpRelayControl::Register {
            tunnel_id: t,
            direction,
            bind_token: token.map(str::to_owned),
            protocol_version: TUNNEL_PROTOCOL_VERSION,
            seq: None,
            standby: None,
        };
        match ack(sock, relay, &register).await? {
            UdpRelayControl::Ack { ready, .. } => Some(ready),
            other => panic!("{other:?} is not an ack"),
        }
    }

    /// Send `register` from `sock` and wait for the control datagram that
    /// answers it, if one comes within 300 ms: an `Ack` for its tunnel.
    pub(super) async fn ack(sock: &UdpSocket, relay: SocketAddr, register: &UdpRelayControl) -> Option<UdpRelayControl> {
        let UdpRelayControl::Register { tunnel_id: t, .. } = register else {
            panic!("{register:?} is not a register");
        };
        sock.send_to(&encode_udp_control(register).unwrap(), relay).await.unwrap();
        let mut buf = [0; 2048];
        loop {
            let read = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf));
            let n = read.await.ok()?.unwrap();
            if let Some(ack) = try_decode_udp_control(&buf[..n]) {
                assert!(matches!(ack, UdpRelayControl::Ack { tunnel_id, .. } if tunnel_id == *t), "{ack:?}");
                return Some(ack);
            }
        }
    }

    async fn send(sock: &UdpSocket, relay: SocketAddr, t: Uuid, payload: &str) {
        let datagram = crate::protocol::encode_udp_datagram(&t, payload.as_bytes());
        sock.send_to(&datagram, relay).await.unwrap();
    }

    /// The payloads of the media that reaches `sock`.
    async fn read(sock: &UdpSocket) -> Vec<String> {
        let mut buf = [0; 2048];
        let mut all = Vec::new();
        while let Ok(n) = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
            let data = &buf[..n.unwrap()];
            if try_decode_udp_control(data).is_none() {
                let (_, payload) = decode_udp_datagram(data).unwrap();
                all.push(String::from_utf8(payload.to_vec()).unwrap());
            }
        }
        all
    }

    /// Over sockets and the plane's own receive loop: a stranger has a side
    /// while no token is registered and goes on sending, and the edge's
    /// registers are refused. When the token comes its next register has the
    /// side, and is acked; the stranger's are refused.
    #[tokio::test]
    async fn an_edge_kept_out_by_a_stranger_gets_in_when_its_token_comes() {
        let (_, _, ctx, mut events) = start_relay_capped(false, 64, 100);
        let config = RelayConfig {
            udp_relay_addrs: Some(vec!["127.0.0.1:0".into()]),
            ..RelayConfig::default()
        };
        let sockets = bind_udp_relay(&config).unwrap();
        let relay = sockets[0].local_addr().unwrap();
        tokio::spawn(serve_udp_relay(sockets, ctx.clone()));

        let t = Uuid::new_v4();
        let (stranger, real, peer) = (socket(3).await, socket(2).await, socket(4).await);
        assert_eq!(register(&peer, relay, t, Egress, Some("egress")).await, Some(false));
        assert_eq!(register(&stranger, relay, t, Ingress, None).await, Some(true));
        send(&stranger, relay, t, "from the stranger").await;
        assert_eq!(read(&peer).await, ["from the stranger"]);
        assert_eq!(register(&real, relay, t, Ingress, Some("ingress")).await, None);
        send(&peer, relay, t, "to whom").await;
        assert_eq!(read(&stranger).await, ["to whom"]);
        assert_eq!(read(&real).await, [""; 0]);

        ctx.router.authorize_tunnel(t, "ingress", "egress");
        send(&stranger, relay, t, "still there").await;
        assert_eq!(read(&peer).await, ["still there"]);
        assert_eq!(register(&stranger, relay, t, Ingress, None).await, None);
        assert_eq!(register(&real, relay, t, Ingress, Some("ingress")).await, Some(true));
        send(&stranger, relay, t, "refused").await;
        send(&real, relay, t, "from the edge").await;
        assert_eq!(read(&peer).await, ["from the edge"]);
        send(&peer, relay, t, "to the edge").await;
        assert_eq!(read(&real).await, ["to the edge"]);
        assert_eq!(read(&stranger).await, [""; 0]);
        assert_eq!(register(&stranger, relay, t, Ingress, None).await, None);
        assert_eq!(register(&real, relay, t, Ingress, Some("ingress")).await, Some(true));
        assert_eq!(register(&peer, relay, t, Egress, Some("egress")).await, Some(true));

        let raised: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok())
            .filter(|event| event.message.starts_with("Native-UDP slot taken over"))
            .collect();
        assert_eq!(raised.len(), 1);
        assert_eq!((raised[0].severity, raised[0].category.as_str()), (EventSeverity::Warning, category::TUNNEL));
        assert_eq!(raised[0].flow_id, Some(t.to_string()));
        assert_eq!(
            raised[0].details,
            Some(serde_json::json!({
                "error_code": "relay_unproven_holder_replaced",
                "transport": "udp",
                "direction": "Ingress",
                "remote_addr": real.local_addr().unwrap().to_string(),
                "held_by": stranger.local_addr().unwrap().to_string(),
            }))
        );
    }
}

#[cfg(test)]
mod liveness_tests {
    //! Which slots are heard, which edges stand by, and slots whose edge has
    //! gone: what lets a pair of edges after v0.117.0 meet on whichever relay
    //! both reach, and fail back together.
    use super::shown_token_tests::{ack, socket};
    use super::*;
    use crate::session::test_relay::start_relay_capped;
    use TunnelDirection::{Egress, Ingress};

    /// A monotonic millisecond for `latch_at`, far from the process's own
    /// clock, so no stamp written here is mistaken for one written by the
    /// data path, which runs on that clock.
    const T: u64 = 10_000_000;

    /// The source edge, which registers `Egress`.
    fn source() -> SocketAddr {
        "198.51.100.10:5000".parse().unwrap()
    }

    /// The destination edge, which registers `Ingress`.
    fn destination() -> SocketAddr {
        "203.0.113.7:6000".parse().unwrap()
    }

    fn token(text: &str) -> Option<TokenDigest> {
        Some(TokenDigest::of(text))
    }

    fn readiness(latched: bool, peer_live: bool, live_ms: u64) -> Readiness {
        Readiness { latched, peer_live, live_ms }
    }

    /// A `Register` from the edge that has `direction`, at `now`.
    fn register(r: &UdpSessionRouter, t: Uuid, direction: TunnelDirection, standby: bool, now: u64) -> Readiness {
        let src = if direction == Ingress { destination() } else { source() };
        let LatchResult::Ok(readiness) = r.latch_at(t, direction, src, 0, standby, None, None, now) else {
            panic!("the {direction:?} register at {now} was refused");
        };
        readiness
    }

    fn status(r: &UdpSessionRouter, t: Uuid, now: u64) -> &'static str {
        r.sessions.get(&t).unwrap().status_str(now)
    }

    /// Parity with the edge's `RELAY_PEER_LIVE_MS`, which times its moves by it.
    #[test]
    fn the_peer_live_window_is_16_s() {
        assert_eq!(PEER_LIVE_MS, 16_000);
    }

    #[test]
    fn a_slot_is_heard_for_16_s_after_its_last_register_or_media() {
        assert!(slot_heard(T - 15_999, 0, T), "15 999 ms ago is heard");
        assert!(!slot_heard(T - 16_000, 0, T), "16 000 ms ago is not");
        assert!(!slot_heard(0, 0, T), "0 is never");
        assert!(slot_heard(0, T - 15_999, T), "media alone counts");
        assert!(slot_heard(T - 60_000, T - 1, T), "the later stamp counts");
        assert!(slot_heard(T + 5_000, 0, T), "a stamp in the future is just heard");

        assert!(!slot_departed(T - 30_000, 0, T), "30 s is not yet gone");
        assert!(slot_departed(T - 30_001, 0, T), "past 30 s is");
        assert!(!slot_departed(T - 60_000, T - 30_000, T), "media keeps a slot");
    }

    /// `ready` keeps its meaning — both slots latched — while `peer_live` says
    /// whether the other one is still heard, by its `Register`s or its media.
    #[test]
    fn an_ack_reports_the_peer_live_only_while_it_is_heard() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        assert_eq!(register(&r, t, Egress, false, T), readiness(false, false, 0));
        assert_eq!(register(&r, t, Ingress, false, T), readiness(true, true, 0));
        assert_eq!(register(&r, t, Ingress, false, T + 10_000), readiness(true, true, 10_000));
        // The egress side's last `Register` is 17 s old: latched, not heard.
        assert_eq!(register(&r, t, Ingress, false, T + 17_000), readiness(true, false, 0));
        // Media from its address is hearing it.
        r.sessions.get(&t).unwrap().egress_media_ms.store(T + 16_500, Ordering::Relaxed);
        assert_eq!(register(&r, t, Ingress, false, T + 18_000), readiness(true, true, 0));
        assert_eq!(register(&r, t, Egress, false, T + 18_500), readiness(true, true, 500));
    }

    #[test]
    fn live_ms_grows_and_restarts_after_a_gap_of_either_side() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        register(&r, t, Egress, false, T);
        assert_eq!(register(&r, t, Ingress, false, T).live_ms, 0);
        assert_eq!(register(&r, t, Egress, false, T + 5_000).live_ms, 5_000);
        assert_eq!(register(&r, t, Ingress, false, T + 10_000).live_ms, 10_000);

        // The ingress side goes quiet, and the egress side's next `Register`
        // finds it unheard…
        assert_eq!(register(&r, t, Egress, false, T + 26_000), readiness(true, false, 0));
        // …so the stretch starts again from its return.
        assert_eq!(register(&r, t, Ingress, false, T + 27_000), readiness(true, true, 0));
        assert_eq!(register(&r, t, Egress, false, T + 31_000).live_ms, 4_000);
        assert_eq!(register(&r, t, Ingress, false, T + 36_000).live_ms, 9_000);

        // The egress side goes quiet for longer than 16 s while the other's
        // `Register`s still find it heard: its own return restarts the stretch.
        assert_eq!(register(&r, t, Ingress, false, T + 46_000).live_ms, 19_000);
        assert_eq!(register(&r, t, Egress, false, T + 47_001), readiness(true, true, 0));
        assert_eq!(register(&r, t, Ingress, false, T + 48_001).live_ms, 1_000);
    }

    /// A slot taken from a stranger by the edge that shows its token is a new
    /// edge on that side, whose stretch has only begun.
    #[test]
    fn a_slot_taken_over_starts_the_stretch_again() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let stranger: SocketAddr = "192.0.2.9:7000".parse().unwrap();
        assert!(matches!(r.latch_at(t, Ingress, stranger, 0, false, None, None, T), LatchResult::Ok(_)));
        r.sessions.get(&t).unwrap().ingress_media_ms.store(T + 4_000, Ordering::Relaxed);
        assert_eq!(register(&r, t, Egress, false, T + 1_000), readiness(true, true, 0));
        assert_eq!(register(&r, t, Egress, false, T + 5_000).live_ms, 4_000);
        let taken = r.latch_at(t, Ingress, destination(), 0, false, token("right"), token("right"), T + 6_000);
        assert!(matches!(
            taken,
            LatchResult::TookOver { readiness: Readiness { latched: true, peer_live: true, live_ms: 0 }, held_by }
                if held_by == stranger
        ));
        assert_eq!(register(&r, t, Egress, false, T + 7_000).live_ms, 1_000);
    }

    /// The status goes by which slots are heard: a pair whose `Register`s
    /// stopped reads `empty` while both slots are still latched.
    #[test]
    fn the_status_counts_heard_slots_not_latched_ones() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        register(&r, t, Egress, false, T);
        assert_eq!(status(&r, t, T), "waiting_ingress");
        register(&r, t, Ingress, false, T + 10_000);
        assert_eq!(status(&r, t, T + 10_000), "active");
        assert_eq!(status(&r, t, T + 16_000), "waiting_egress");
        assert_eq!(status(&r, t, T + 26_000), "empty");
        assert!(r.sessions.get(&t).unwrap().both_latched());
    }

    /// Both edges registering here only to be found, their media going
    /// through the tunnel's other relay: listed `standby`, not counted active.
    /// One edge sending here is enough to count.
    #[test]
    fn a_standby_pair_reads_standby_and_is_not_counted_active() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let listed = |r: &UdpSessionRouter| (r.list()[0].status.clone(), r.active_count(), r.count());
        r.latch(t, Egress, source(), 0, true, None, None);
        assert_eq!(listed(&r), ("waiting_ingress".into(), 0, 1));
        r.latch(t, Ingress, destination(), 0, true, None, None);
        assert_eq!(listed(&r), ("standby".into(), 0, 1));
        r.latch(t, Ingress, destination(), 0, false, None, None);
        assert_eq!(listed(&r), ("active".into(), 1, 1));
        r.latch(t, Egress, source(), 0, false, None, None);
        assert_eq!(listed(&r), ("active".into(), 1, 1));
        r.latch(t, Ingress, destination(), 0, true, None, None);
        r.latch(t, Egress, source(), 0, true, None, None);
        assert_eq!(listed(&r), ("standby".into(), 0, 1));
    }

    /// Over the plane's own receive loop: every `Ack` names this relay process
    /// and echoes the `Register`'s `seq`, and the `standby` flag reaches the
    /// session. An edge up to v0.117.0 sends neither and is answered as before,
    /// with the new fields beside `ready`.
    #[tokio::test]
    async fn the_ack_names_the_relay_and_echoes_seq() {
        let (_, _, ctx, _events) = start_relay_capped(false, 64, 100);
        let config = RelayConfig {
            udp_relay_addrs: Some(vec!["127.0.0.1:0".into()]),
            ..RelayConfig::default()
        };
        let sockets = bind_udp_relay(&config).unwrap();
        let relay = sockets[0].local_addr().unwrap();
        tokio::spawn(serve_udp_relay(sockets, ctx.clone()));

        let relay_id = ctx.udp_sessions.relay_id().to_owned();
        assert_eq!(relay_id.len(), 32);
        assert!(relay_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{relay_id}");
        assert_ne!(UdpSessionRouter::new(64).relay_id(), relay_id, "one per process");

        let t = Uuid::new_v4();
        let register = |direction, seq, standby| UdpRelayControl::Register {
            tunnel_id: t,
            direction,
            bind_token: None,
            protocol_version: TUNNEL_PROTOCOL_VERSION,
            seq,
            standby,
        };
        let (source, destination) = (socket(1).await, socket(1).await);
        assert_eq!(
            ack(&source, relay, &register(Egress, Some(u32::MAX), Some(false))).await,
            Some(UdpRelayControl::Ack {
                tunnel_id: t,
                ready: false,
                peer_live: Some(false),
                live_ms: Some(0),
                relay_id: Some(relay_id.clone()),
                seq: Some(u32::MAX),
            })
        );
        assert_eq!(
            ack(&destination, relay, &register(Ingress, None, None)).await,
            Some(UdpRelayControl::Ack {
                tunnel_id: t,
                ready: true,
                peer_live: Some(true),
                live_ms: Some(0),
                relay_id: Some(relay_id.clone()),
                seq: None,
            })
        );
        assert_eq!(ctx.udp_sessions.list()[0].status, "active");

        for (sock, direction, seq) in [(&source, Egress, 7), (&destination, Ingress, 8)] {
            let answer = ack(sock, relay, &register(direction, Some(seq), Some(true))).await;
            assert!(matches!(
                answer,
                Some(UdpRelayControl::Ack { ready: true, peer_live: Some(true), seq: Some(s), relay_id: Some(ref id), .. })
                    if s == seq && *id == relay_id
            ));
        }
        assert_eq!(ctx.udp_sessions.list()[0].status, "standby");
        assert_eq!(ctx.udp_sessions.active_count(), 0);
    }

    /// The reaper clears a slot whose edge has gone — nothing from it for
    /// 30 s — in a session its peer keeps alive, and the peer's next `Ack`
    /// says the tunnel is no longer ready. Up to v0.20.0 only whole sessions
    /// were reaped, so an edge that moved to the other relay stayed latched
    /// here for as long as its peer registered.
    #[test]
    fn a_stale_slot_is_cleared_and_the_session_kept() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let LatchResult::Ok(_) = r.latch_at(t, Ingress, destination(), 2, true, token("right"), None, T) else {
            panic!("refused");
        };
        register(&r, t, Egress, false, T + 25_000);

        r.reap_idle_at(T + 30_000);
        assert_eq!(r.sessions.get(&t).unwrap().ingress.load(), Some(destination()), "30 s is not yet gone");

        assert_eq!(r.reap_idle_at(T + 30_001), 0, "the session stays");
        assert_eq!(r.count(), 1);
        {
            let s = r.sessions.get(&t).unwrap();
            assert_eq!(s.ingress.load(), None);
            assert_eq!(
                (
                    s.ingress_seen_ms.load(Ordering::Relaxed),
                    s.ingress_media_ms.load(Ordering::Relaxed),
                    s.ingress_sock.load(Ordering::Relaxed),
                    s.ingress_standby.load(Ordering::Relaxed),
                    s.ingress_shown.is_none(),
                    s.live_since_ms.load(Ordering::Relaxed),
                ),
                (0, 0, usize::MAX, false, true, 0)
            );
            assert_eq!(s.egress.load(), Some(source()), "the peer's slot is kept");
        }
        assert_eq!(register(&r, t, Egress, false, T + 31_000), readiness(false, false, 0));
        assert_eq!(r.forward_target(t, source(), 100), None, "nothing to forward to");

        // Media keeps a slot whose `Register`s have stopped.
        r.sessions.get(&t).unwrap().egress_media_ms.store(T + 56_000, Ordering::Relaxed);
        r.reap_idle_at(T + 62_000);
        assert_eq!(r.sessions.get(&t).unwrap().egress.load(), Some(source()));
        r.reap_idle_at(T + 86_001);
        assert_eq!(status(&r, t, T + 86_001), "empty");
        assert_eq!(r.count(), 1, "whole sessions still go by the wall clock");
    }

    /// A cleared slot is empty again: the next `Register` has it, whoever
    /// sends it, as at first contact, though a live edge had it with the token.
    #[test]
    fn a_cleared_slot_is_latched_by_any_register() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        let stranger: SocketAddr = "192.0.2.9:7000".parse().unwrap();
        let held = r.latch_at(t, Ingress, destination(), 1, false, token("right"), None, T);
        assert!(matches!(held, LatchResult::Ok(_)));
        r.sessions.get(&t).unwrap().ingress_media_ms.store(T, Ordering::Relaxed);
        let refused = r.latch_at(t, Ingress, stranger, 0, false, None, None, T + 1_000);
        assert!(matches!(refused, LatchResult::RejectedSlotHeld), "held while it carries media");

        register(&r, t, Egress, false, T + 20_000);
        r.reap_idle_at(T + 30_001);
        assert_eq!(r.sessions.get(&t).unwrap().ingress.load(), None);

        let latched = r.latch_at(t, Ingress, stranger, 3, false, None, None, T + 30_500);
        assert!(matches!(latched, LatchResult::Ok(Readiness { latched: true, peer_live: true, live_ms: 0 })));
        let s = r.sessions.get(&t).unwrap();
        assert_eq!((s.ingress.load(), s.ingress_sock.load(Ordering::Relaxed)), (Some(stranger), 3));
    }
}

#[cfg(test)]
mod totals_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn source(host: u8) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, host], 5000))
    }

    fn destination(host: u8) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, host], 6000))
    }

    /// Register both sides from hosts of their own, the source first.
    fn register(r: &UdpSessionRouter, t: Uuid, host: u8) {
        r.latch(t, TunnelDirection::Egress, source(host), 0, false, None, None);
        r.latch(t, TunnelDirection::Ingress, destination(host), 0, false, None, None);
    }

    /// Make a session idle for longer than the reaper lets it be.
    fn make_stale(r: &UdpSessionRouter, t: Uuid) {
        if let Some(s) = r.sessions.get(&t) {
            s.last_seen_ms.store(0, Ordering::Relaxed);
        }
    }

    fn totals(bytes_ingress: u64, bytes_egress: u64, udp_datagrams_total: u64) -> TunnelTotals {
        TunnelTotals { bytes_ingress, bytes_egress, tcp_streams_total: 0, udp_datagrams_total }
    }

    /// A gap between one forward, or one read of the totals, and the next. The
    /// map's lock and the totals' are unfair: without it the removers starve.
    fn pause() {
        std::thread::sleep(std::time::Duration::from_micros(1));
    }

    /// Neither the reaper nor the REST delete moves the totals, and a session
    /// registered again under its id counts on from them while its own figures
    /// start again.
    #[test]
    fn a_session_that_goes_leaves_the_totals() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        assert_eq!(r.totals(), totals(0, 0, 0));
        register(&r, t, 1);
        assert!(r.forward_target(t, source(1), 1000).is_some());
        assert!(r.forward_target(t, destination(1), 50).is_some());
        assert_eq!(r.totals(), totals(50, 1000, 2));

        make_stale(&r, t);
        assert_eq!(r.reap_idle(), 1);
        assert_eq!(r.count(), 0);
        assert_eq!(r.totals(), totals(50, 1000, 2), "reaped");

        register(&r, t, 1);
        assert_eq!(r.totals(), totals(50, 1000, 2), "registered again");
        assert!(r.forward_target(t, source(1), 7).is_some());
        let own = r.list().remove(0);
        assert_eq!((own.bytes_ingress, own.bytes_egress, own.datagrams), (0, 7, 1));
        assert_eq!(r.totals(), totals(50, 1007, 3));

        assert!(r.remove(&t));
        assert!(!r.remove(&t));
        assert_eq!(r.count(), 0);
        assert_eq!(r.totals(), totals(50, 1007, 3), "deleted");
    }

    /// Four threads forward on two sessions that are deleted, or reaped, and
    /// registered again under them as fast as they can be, while another reads
    /// the totals: no figure falls, and at the end each is what was counted.
    #[test]
    fn the_totals_never_fall_under_concurrent_removal() {
        let r = &UdpSessionRouter::new(64);
        // One is only ever deleted and the other only ever reaped: a reap
        // takes every stale session there is.
        let deleted = (Uuid::new_v4(), 1);
        let reaped = (Uuid::new_v4(), 2);
        let stop = &AtomicBool::new(false);
        let (datagrams, reads) = std::thread::scope(|s| {
            let writers: Vec<_> = [deleted, reaped, deleted, reaped]
                .into_iter()
                .map(|(t, host)| {
                    s.spawn(move || {
                        // The side that registers last, so a datagram is
                        // counted and forwarded, or neither.
                        let from = destination(host);
                        let mut counted = 0;
                        while !stop.load(Ordering::Relaxed) {
                            counted += u64::from(r.forward_target(t, from, 1316).is_some());
                            pause();
                        }
                        counted
                    })
                })
                .collect();
            let removers = [
                s.spawn(move || {
                    for _ in 0..20_000 {
                        register(r, deleted.0, deleted.1);
                        r.remove(&deleted.0);
                    }
                }),
                s.spawn(move || {
                    for _ in 0..20_000 {
                        register(r, reaped.0, reaped.1);
                        make_stale(r, reaped.0);
                        r.reap_idle();
                    }
                }),
            ];
            let reader = s.spawn(move || {
                let (mut last, mut reads) = (TunnelTotals::default(), 0);
                while !stop.load(Ordering::Relaxed) {
                    let now = r.totals();
                    assert!(now.bytes_ingress >= last.bytes_ingress, "{now:?} after {last:?}");
                    assert!(
                        now.udp_datagrams_total >= last.udp_datagrams_total,
                        "{now:?} after {last:?}"
                    );
                    (last, reads) = (now, reads + 1);
                    pause();
                }
                reads
            });
            let removed: Vec<_> = removers.into_iter().map(|r| r.join()).collect();
            stop.store(true, Ordering::Relaxed);
            removed.into_iter().for_each(|r| r.unwrap());
            let datagrams: u64 = writers.into_iter().map(|w| w.join().unwrap()).sum();
            (datagrams, reader.join().unwrap())
        });
        assert!(datagrams > 0 && reads > 0, "{datagrams} datagrams, {reads} reads");
        assert_eq!(r.totals(), totals(datagrams * 1316, 0, datagrams));
    }
}

#[cfg(test)]
mod removal_race_tests {
    //! Sessions that are removed while others, or the same one, register.
    use super::*;
    use std::sync::atomic::AtomicBool;

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));

    fn latch(r: &UdpSessionRouter, t: Uuid, port: u16) -> bool {
        let src = SocketAddr::new(HOST, port);
        matches!(r.latch(t, TunnelDirection::Egress, src, 0, false, None, None), LatchResult::Ok(_))
    }

    fn make_stale(r: &UdpSessionRouter, t: Uuid) {
        if let Some(s) = r.sessions.get(&t) {
            s.last_seen_ms.store(0, Ordering::Relaxed);
        }
    }

    /// The sessions of one address are created and removed on several threads
    /// at once. Each thread holds one at a time, so a cap of one each refuses
    /// nobody, and then the cap holds as if nothing had happened.
    #[test]
    fn the_per_ip_count_survives_sessions_coming_and_going() {
        std::thread::scope(|s| {
            // Routers side by side, for more of the rare interleavings.
            for threads in [3, 3, 3, 4, 4, 4] {
                s.spawn(move || {
                    let r = &UdpSessionRouter::new(u32::from(threads));
                    std::thread::scope(|s| {
                        for port in 1..=threads {
                            s.spawn(move || {
                                let t = Uuid::new_v4();
                                for _ in 0..150_000 {
                                    assert!(latch(r, t, port), "refused below the cap");
                                    assert!(r.remove(&t));
                                }
                            });
                        }
                    });
                    assert_eq!((r.count(), r.sessions_by_ip.held(HOST)), (0, None));

                    let held: Vec<Uuid> = (0..threads).map(|_| Uuid::new_v4()).collect();
                    for (t, port) in held.iter().zip(1..) {
                        assert!(latch(r, *t, port), "refused below the cap");
                    }
                    assert!(!latch(r, Uuid::new_v4(), 100), "past the cap");
                    assert_eq!(r.sessions_by_ip.held(HOST), Some(u32::from(threads)));
                    assert!(r.remove(&held[0]));
                    assert!(latch(r, Uuid::new_v4(), 100), "a full cap frees up");
                });
            }
        });
    }

    /// The reaper finds a session idle, and a datagram is forwarded on it
    /// before the reaper comes to remove it.
    #[test]
    fn a_session_seen_again_before_it_is_reaped_stays() {
        let r = UdpSessionRouter::new(64);
        let t = Uuid::new_v4();
        assert!(latch(&r, t, 5000));
        make_stale(&r, t);
        let reaped = std::thread::scope(|s| {
            // As `forward_target` holds it: the reaper finds the session, and
            // waits to remove it.
            let session = r.sessions.get(&t).unwrap();
            let reaper = s.spawn(|| r.reap_idle());
            std::thread::sleep(Duration::from_millis(100));
            session.last_seen_ms.store(now_ms(), Ordering::Relaxed);
            drop(session);
            reaper.join().unwrap()
        });
        assert_eq!((reaped, r.count()), (0, 1));
        assert_eq!(r.sessions_by_ip.held(HOST), Some(1));

        make_stale(&r, t);
        assert_eq!((r.reap_idle(), r.count()), (1, 0));
        assert_eq!(r.sessions_by_ip.held(HOST), None);
    }

    /// An idle session registers again as fast as it can while the reaper
    /// runs: no register is refused, though the cap is one, and each leaves a
    /// session behind.
    #[test]
    fn a_session_that_registers_again_is_never_reaped() {
        let r = &UdpSessionRouter::new(1);
        let t = Uuid::new_v4();
        let stop = &AtomicBool::new(false);
        let (refused, lost) = std::thread::scope(|s| {
            s.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    r.reap_idle();
                }
            });
            let (mut refused, mut lost) = (0, 0);
            for _ in 0..1_000_000 {
                make_stale(r, t);
                refused += u32::from(!latch(r, t, 5000));
                lost += u32::from(!r.sessions.contains_key(&t));
            }
            stop.store(true, Ordering::Relaxed);
            (refused, lost)
        });
        assert_eq!((refused, lost), (0, 0));
        assert_eq!(r.sessions_by_ip.held(HOST), Some(1));
    }
}
