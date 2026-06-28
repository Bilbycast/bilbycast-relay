// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

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
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
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
use crate::stats::TunnelStats;

/// Session is reaped after this long with no register/keepalive or data.
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
const SOCK_BUF_BYTES: usize = 32 * 1024 * 1024;

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
}

/// Now in epoch-millis (saturating).
fn now_ms() -> u64 {
    crate::stats::now_epoch_ms()
}

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
            creator_ip,
            stats: Arc::new(TunnelStats::new()),
            last_seen_ms: AtomicU64::new(now_ms()),
            created_at: Instant::now(),
        }
    }

    fn both_latched(&self) -> bool {
        self.ingress.is_set() && self.egress.is_set()
    }

    fn status_str(&self) -> &'static str {
        match (self.ingress.is_set(), self.egress.is_set()) {
            (true, true) => "active",
            (true, false) => "waiting_egress",
            (false, true) => "waiting_ingress",
            (false, false) => "empty",
        }
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
    sessions: DashMap<Uuid, Arc<UdpSession>>,
    /// Per-source-IP session-creation counter (DoS mitigation).
    sessions_by_ip: DashMap<IpAddr, Arc<AtomicU32>>,
    max_sessions_per_ip: u32,
}

/// Outcome of latching a registration.
pub enum LatchResult {
    /// Session updated; `bool` = both slots now latched (media may flow).
    Ok(bool),
    /// Per-IP session cap exceeded — registration dropped.
    RejectedDosCap,
}

impl UdpSessionRouter {
    pub fn new(max_sessions_per_ip: u32) -> Self {
        Self {
            sessions: DashMap::new(),
            sessions_by_ip: DashMap::new(),
            max_sessions_per_ip,
        }
    }

    /// Latch (or refresh) an edge's source address into its tunnel slot.
    ///
    /// The per-IP creation cap + counter bump + insert happen atomically under
    /// the DashMap shard entry lock, so they're counted exactly once per session
    /// (and freed once in [`Self::remove`]). Lock order is always
    /// `sessions` → `sessions_by_ip`, matching [`Self::remove`] — no deadlock.
    pub fn latch(
        &self,
        tunnel_id: Uuid,
        direction: TunnelDirection,
        src: SocketAddr,
        sock_idx: usize,
    ) -> LatchResult {
        use dashmap::mapref::entry::Entry;
        let ip = src.ip();
        let session = match self.sessions.entry(tunnel_id) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => {
                let counter = self
                    .sessions_by_ip
                    .entry(ip)
                    .or_insert_with(|| Arc::new(AtomicU32::new(0)))
                    .clone();
                let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if n > self.max_sessions_per_ip {
                    counter.fetch_sub(1, Ordering::Relaxed);
                    return LatchResult::RejectedDosCap;
                }
                v.insert(Arc::new(UdpSession::new(tunnel_id, ip))).clone()
            }
        };
        match direction {
            TunnelDirection::Ingress => {
                session.ingress.store(src);
                session.ingress_sock.store(sock_idx, Ordering::Relaxed);
            }
            TunnelDirection::Egress => {
                session.egress.store(src);
                session.egress_sock.store(sock_idx, Ordering::Relaxed);
            }
        }
        session.last_seen_ms.store(now_ms(), Ordering::Relaxed);
        LatchResult::Ok(session.both_latched())
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
        let (target, target_sock) = if Some(src) == ingress {
            // From the destination side → forward to the source side.
            session.stats.bytes_ingress.fetch_add(bytes, Ordering::Relaxed);
            (egress?, session.egress_sock.load(Ordering::Relaxed))
        } else if Some(src) == egress {
            // From the source side → forward to the destination side.
            session.stats.bytes_egress.fetch_add(bytes, Ordering::Relaxed);
            (ingress?, session.ingress_sock.load(Ordering::Relaxed))
        } else {
            // Source addr matches neither latched slot (unregistered or a NAT
            // rebind not yet re-latched by a keepalive). Drop.
            return None;
        };
        session.stats.udp_datagrams_total.fetch_add(1, Ordering::Relaxed);
        session.last_seen_ms.store(now_ms(), Ordering::Relaxed);
        Some((target, target_sock))
    }

    /// Remove sessions idle longer than [`SESSION_IDLE_TIMEOUT`]. Returns the
    /// count reaped.
    pub fn reap_idle(&self) -> usize {
        let now = now_ms();
        let cutoff = SESSION_IDLE_TIMEOUT.as_millis() as u64;
        let stale: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|e| now.saturating_sub(e.value().last_seen_ms.load(Ordering::Relaxed)) > cutoff)
            .map(|e| *e.key())
            .collect();
        for id in &stale {
            self.remove(id);
        }
        stale.len()
    }

    /// Force-remove a session (idle reap or REST escape hatch).
    pub fn remove(&self, tunnel_id: &Uuid) -> bool {
        if let Some((_, session)) = self.sessions.remove(tunnel_id) {
            if let Some(c) = self.sessions_by_ip.get(&session.creator_ip) {
                let prev = c.fetch_sub(1, Ordering::Relaxed);
                if prev == 1 {
                    drop(c);
                    self.sessions_by_ip
                        .remove_if(&session.creator_ip, |_, v| v.load(Ordering::Relaxed) == 0);
                }
            }
            true
        } else {
            false
        }
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn active_count(&self) -> usize {
        self.sessions.iter().filter(|e| e.value().both_latched()).count()
    }

    pub fn list(&self) -> Vec<UdpSessionInfo> {
        self.sessions
            .iter()
            .map(|e| {
                let s = e.value();
                UdpSessionInfo {
                    tunnel_id: s.tunnel_id,
                    transport: "udp",
                    status: s.status_str().to_string(),
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
fn socket_for<'a>(sockets: &'a [Arc<UdpSocket>], dest: SocketAddr) -> &'a Arc<UdpSocket> {
    let want_v6 = dest.is_ipv6();
    sockets
        .iter()
        .find(|s| s.local_addr().map(|a| a.is_ipv6() == want_v6).unwrap_or(false))
        .unwrap_or(&sockets[0])
}

/// Run the plain-UDP relay data plane. Binds one socket per
/// [`RelayConfig::effective_udp_relay_addrs`] entry and forwards forever.
///
/// Bind failures are **non-fatal**: a socket that can't bind is logged and
/// skipped (so an upgrade never bricks a relay over a busy `:4434`). If *no*
/// socket binds the task exits and the relay continues QUIC-only.
pub async fn run_udp_relay(config: &RelayConfig, ctx: Arc<SessionContext>) -> Result<()> {
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
    let _ = set.join_next().await;
    Ok(())
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
        UdpRelayControl::Register {
            tunnel_id,
            direction,
            bind_token,
            protocol_version,
        } => {
            if protocol_version != 0 && protocol_version != TUNNEL_PROTOCOL_VERSION {
                tracing::debug!(
                    "native-UDP register for {tunnel_id} proto v{protocol_version} (relay v{TUNNEL_PROTOCOL_VERSION})"
                );
            }

            // Reuse the QUIC path's bind-token authorization registry.
            if !ctx
                .router
                .verify_bind_token(&tunnel_id, direction, bind_token.as_deref())
            {
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

            match ctx.udp_sessions.latch(tunnel_id, direction, src, sock_idx) {
                LatchResult::Ok(ready) => {
                    // Ack so the edge confirms the relay is alive (failover) and
                    // learns when both sides are present.
                    if let Ok(bytes) =
                        encode_udp_control(&UdpRelayControl::Ack { tunnel_id, ready })
                    {
                        let _ = sock.send_to(&bytes, src).await;
                    }
                    if ready {
                        tracing::debug!("native-UDP tunnel {tunnel_id} active (both sides latched)");
                    }
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
        assert!(matches!(r.latch(t, TunnelDirection::Egress, src, 0), LatchResult::Ok(false)));
        assert!(r.forward_target(t, src, 100).is_none());

        // Both latched → ready.
        assert!(matches!(r.latch(t, TunnelDirection::Ingress, dst, 1), LatchResult::Ok(true)));

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
        r.latch(t, TunnelDirection::Egress, src, 2);
        r.latch(t, TunnelDirection::Ingress, dst, 0);
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
        r.latch(t, TunnelDirection::Ingress, dst, 0);
        r.latch(t, TunnelDirection::Egress, v4(5000), 0);
        assert_eq!(r.forward_target(t, v4(5000), 1), Some((dst, 0)));
        // Egress edge's NAT rebinds to a new port; re-register relatches it.
        r.latch(t, TunnelDirection::Egress, v4(5001), 0);
        assert!(r.forward_target(t, v4(5000), 1).is_none());
        assert_eq!(r.forward_target(t, v4(5001), 1), Some((dst, 0)));
    }

    #[test]
    fn per_ip_session_cap_enforced() {
        let r = UdpSessionRouter::new(2);
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        // Three distinct tunnels from the same IP: third is rejected.
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 1), 0),
            LatchResult::Ok(_)
        ));
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 2), 0),
            LatchResult::Ok(_)
        ));
        assert!(matches!(
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 3), 0),
            LatchResult::RejectedDosCap
        ));
    }

    #[test]
    fn reap_removes_idle_sessions_and_frees_ip_quota() {
        let r = UdpSessionRouter::new(1);
        let t = Uuid::new_v4();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        r.latch(t, TunnelDirection::Egress, SocketAddr::new(ip.into(), 1), 0);
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
            r.latch(Uuid::new_v4(), TunnelDirection::Egress, SocketAddr::new(ip.into(), 2), 0),
            LatchResult::Ok(_)
        ));
    }
}
