// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tunnel routing: pairs ingress and egress edges by tunnel ID and forwards data.

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use dashmap::mapref::one::Ref;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::protocol::{TunnelDirection, TunnelProtocol};
use crate::stats::{Counted, DepartedTunnels, TunnelStats, TunnelStatsSnapshot, TunnelTotals};

/// The SHA-256 of a bind token. What a holder showed is remembered as this:
/// 32 bytes, however long the token it sent.
#[derive(Clone, Copy)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    pub fn of(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    /// In constant time, as the tokens themselves would be compared.
    pub fn matches(&self, other: &Self) -> bool {
        crate::util::constant_time_eq(&self.0, &other.0)
    }
}

/// A registered tunnel endpoint (one side — ingress or egress).
pub struct TunnelEndpoint {
    /// Identity for reporting (manager node_id if identified, else connection_id).
    pub edge_id: String,
    /// Internal key for edge_connections DashMap lookups (always connection_id).
    pub connection_id: String,
    pub direction: TunnelDirection,
    pub connection: quinn::Connection,
    /// The token its bind showed, the right one or not: with none registered
    /// for the tunnel, any bind may be taken.
    pub shown: Option<TokenDigest>,
}

/// State of a tunnel as tracked by the router.
pub struct TunnelState {
    pub tunnel_id: Uuid,
    pub protocol: TunnelProtocol,
    pub ingress: Option<TunnelEndpoint>,
    pub egress: Option<TunnelEndpoint>,
    /// The endpoints a later bind took their side over from, the one taken
    /// over last at the end. Each is connected and has not unbound since, and
    /// is told nothing: [`Self::give_back`] can make it the holder again.
    displaced: Vec<TunnelEndpoint>,
    pub stats: Arc<TunnelStats>,
}

impl TunnelState {
    fn new(tunnel_id: Uuid, protocol: TunnelProtocol) -> Self {
        Self {
            tunnel_id,
            protocol,
            ingress: None,
            egress: None,
            displaced: Vec::new(),
            stats: Arc::new(TunnelStats::new()),
        }
    }

    pub fn side(&self, direction: TunnelDirection) -> Option<&TunnelEndpoint> {
        match direction {
            TunnelDirection::Ingress => self.ingress.as_ref(),
            TunnelDirection::Egress => self.egress.as_ref(),
        }
    }

    fn side_mut(&mut self, direction: TunnelDirection) -> &mut Option<TunnelEndpoint> {
        match direction {
            TunnelDirection::Ingress => &mut self.ingress,
            TunnelDirection::Egress => &mut self.egress,
        }
    }

    /// Make `endpoint` its side's holder.
    fn hold(&mut self, endpoint: TunnelEndpoint) {
        let direction = endpoint.direction;
        let same = |e: &TunnelEndpoint| {
            e.direction == direction && e.connection_id == endpoint.connection_id
        };
        self.displaced.retain(|e| !same(e));
        // A connection that binds its side again takes it from nobody.
        if let Some(older) = self.side_mut(direction).take_if(|e| !same(e)) {
            self.displaced.push(older);
        }
        *self.side_mut(direction) = Some(endpoint);
    }

    /// Make the last connection displaced from this side to have shown `token`
    /// its holder again, unless the holder has shown it too.
    fn give_back(&mut self, direction: TunnelDirection, token: &TokenDigest) -> Option<GivenBack> {
        let shows = |e: &TunnelEndpoint| e.shown.is_some_and(|shown| shown.matches(token));
        let holder = self.side(direction);
        if holder.is_some_and(shows) {
            return None;
        }
        let from = holder.map(|e| e.connection.remote_address());
        let last = self.displaced.iter().rposition(|e| e.direction == direction && shows(e))?;
        let endpoint = self.displaced.remove(last);
        let given = GivenBack {
            direction,
            connection_id: endpoint.connection_id.clone(),
            to: endpoint.connection.remote_address(),
            from,
        };
        self.hold(endpoint);
        Some(given)
    }

    pub fn is_active(&self) -> bool {
        self.ingress.is_some() && self.egress.is_some()
    }

    fn is_empty(&self) -> bool {
        self.ingress.is_none() && self.egress.is_none()
    }

    pub fn status_str(&self) -> &'static str {
        match (&self.ingress, &self.egress) {
            (Some(_), Some(_)) => "active",
            (Some(_), None) => "waiting_egress",
            (None, Some(_)) => "waiting_ingress",
            (None, None) => "empty",
        }
    }
}

impl Counted for TunnelState {
    fn stats(&self) -> &Arc<TunnelStats> {
        &self.stats
    }
}

/// Serializable tunnel info for the REST API.
#[derive(Debug, Serialize)]
pub struct TunnelInfo {
    pub tunnel_id: Uuid,
    pub protocol: String,
    pub status: String,
    pub ingress_edge_id: Option<String>,
    pub egress_edge_id: Option<String>,
    /// Post-NAT remote address of each QUIC endpoint's connection (the public
    /// `host:port` each edge dialed in from, as seen by the relay). Distinct
    /// field names from the native-UDP plane's `ingress_addr`/`egress_addr`
    /// so the manager UI's native-UDP-vs-QUIC detection (which keys on the
    /// presence of `ingress_addr`) is unaffected. `None` until that side binds.
    pub ingress_remote_addr: Option<String>,
    pub egress_remote_addr: Option<String>,
    pub stats: TunnelStatsSnapshot,
}

/// A side that went back to the connection that had shown its token.
pub struct GivenBack {
    pub direction: TunnelDirection,
    pub connection_id: String,
    pub to: SocketAddr,
    /// Who held it. Nobody, if whoever took it over has left.
    pub from: Option<SocketAddr>,
}

/// Where data that a connection sends on a tunnel goes.
pub struct Route {
    /// The side the sender bound.
    pub from: TunnelDirection,
    /// The connection bound to the other side.
    pub peer: quinn::Connection,
    pub stats: Arc<TunnelStats>,
}

/// Why data that a connection sends on a tunnel goes nowhere.
#[derive(Debug, PartialEq, Eq)]
pub enum NoRoute {
    /// The sender holds neither side of the tunnel, or there is no such
    /// tunnel. One answer for both: a sender cannot tell which ids are in use.
    NotBound,
    /// The sender holds one side and nobody holds the other.
    NoPeer,
}

/// Pre-authorized bind tokens for a tunnel (set by manager via authorize_tunnel command).
struct AuthorizedTunnel {
    ingress_token: TokenDigest,
    egress_token: TokenDigest,
}

/// The tunnel router manages all active and pending tunnels.
pub struct TunnelRouter {
    /// A tunnel leaves the map through `departed`, which keeps what it counted.
    tunnels: DashMap<Uuid, TunnelState>,
    departed: DepartedTunnels,
    /// Pre-authorized bind tokens keyed by tunnel UUID.
    /// If a tunnel has an entry here, bind requests must include a valid bind_token.
    authorized_tokens: DashMap<Uuid, AuthorizedTunnel>,
    /// When `true`, binds for tunnels without a pre-registered `authorize_tunnel`
    /// entry are rejected (fail-closed). When `false`, they are allowed
    /// (backwards-compatible permissive mode). Driven by
    /// `RelayConfig::require_bind_auth`.
    require_bind_auth: bool,
}

impl TunnelRouter {
    /// Construct a router with an explicit auth policy.
    /// `require_bind_auth = false` is the permissive backwards-compatible mode.
    pub fn with_auth_policy(require_bind_auth: bool) -> Self {
        Self {
            tunnels: DashMap::new(),
            departed: DepartedTunnels::default(),
            authorized_tokens: DashMap::new(),
            require_bind_auth,
        }
    }

    /// Register expected bind tokens for a tunnel (called by manager authorize_tunnel command).
    ///
    /// A side bound before they came is not given up for want of its token
    /// alone. An edge that the manager cannot reach still shows the token it
    /// had, and one without a bind secret shows none; neither could bind again.
    /// The holder loses its side to a bind that shows the token, and here to a
    /// connection it took the side from that had shown it: that one is
    /// connected, and no bind of its own will come. Returns those sides.
    pub fn authorize_tunnel(
        &self,
        tunnel_id: Uuid,
        ingress_token: &str,
        egress_token: &str,
    ) -> Vec<GivenBack> {
        let ingress_token = TokenDigest::of(ingress_token);
        let egress_token = TokenDigest::of(egress_token);
        self.authorized_tokens.insert(tunnel_id, AuthorizedTunnel { ingress_token, egress_token });
        // After the tokens are in. `bind` asks for them under the tunnel's
        // lock, so one that got by without is in the tunnel by now.
        let Some(mut state) = self.tunnels.get_mut(&tunnel_id) else {
            return Vec::new();
        };
        [(TunnelDirection::Ingress, ingress_token), (TunnelDirection::Egress, egress_token)]
            .into_iter()
            .filter_map(|(direction, token)| state.give_back(direction, &token))
            .collect()
    }

    /// Remove authorization for a tunnel.
    pub fn revoke_tunnel(&self, tunnel_id: &Uuid) {
        self.authorized_tokens.remove(tunnel_id);
    }

    /// The token registered for a tunnel+direction, if there is one.
    pub fn registered_token(
        &self,
        tunnel_id: &Uuid,
        direction: TunnelDirection,
    ) -> Option<TokenDigest> {
        self.authorized_tokens.get(tunnel_id).map(|auth| match direction {
            TunnelDirection::Ingress => auth.ingress_token,
            TunnelDirection::Egress => auth.egress_token,
        })
    }

    /// Verify a bind token for a tunnel+direction.
    ///
    /// Returns `true` if the token shown is the expected one for the given
    /// direction. When no authorization is registered for this tunnel:
    /// permissive mode (`require_bind_auth = false`, default) returns `true`
    /// for backwards compatibility; strict mode returns `false`.
    pub fn verify_bind_token(
        &self,
        tunnel_id: &Uuid,
        direction: TunnelDirection,
        shown: Option<&TokenDigest>,
    ) -> bool {
        match self.registered_token(tunnel_id, direction) {
            Some(expected) => shown.is_some_and(|shown| shown.matches(&expected)),
            None => !self.require_bind_auth,
        }
    }

    /// Bind a tunnel endpoint, if the token it shows is verified. Nothing
    /// changes if it is not.
    ///
    /// If both sides are now bound, the tunnel becomes active.
    pub fn bind(
        &self,
        tunnel_id: Uuid,
        protocol: TunnelProtocol,
        endpoint: TunnelEndpoint,
    ) -> BindResult {
        let entry = self.tunnels.entry(tunnel_id);
        // Under the tunnel's lock: see `authorize_tunnel`.
        if !self.verify_bind_token(&tunnel_id, endpoint.direction, endpoint.shown.as_ref()) {
            return BindResult::Refused;
        }
        let mut state = match entry {
            Entry::Occupied(held) => held.into_ref(),
            Entry::Vacant(free) => free.insert(TunnelState::new(tunnel_id, protocol)),
        };
        state.hold(endpoint);

        if state.is_active() {
            BindResult::Active
        } else {
            BindResult::Waiting
        }
    }

    /// Unbind a tunnel endpoint (edge disconnected or explicitly unbound).
    /// Uses `connection_id` for matching. Returns the peer's `connection_id` for notification.
    pub fn unbind(&self, tunnel_id: &Uuid, connection_id: &str) -> Option<String> {
        self.release(tunnel_id, connection_id).flatten()
    }

    /// [`Self::unbind`]. `None` if the connection held no side, else the
    /// connection that holds the other, if one does.
    fn release(&self, tunnel_id: &Uuid, connection_id: &str) -> Option<Option<String>> {
        let mut released = None;

        if let Some(mut entry) = self.tunnels.get_mut(tunnel_id) {
            let state = entry.value_mut();
            state.displaced.retain(|e| e.connection_id != connection_id);

            if let Some(ref ingress) = state.ingress
                && ingress.connection_id == connection_id {
                    state.ingress = None;
                    released = Some(state.egress.as_ref().map(|e| e.connection_id.clone()));
                }
            if let Some(ref egress) = state.egress
                && egress.connection_id == connection_id {
                    state.egress = None;
                    released = Some(state.ingress.as_ref().map(|e| e.connection_id.clone()));
                }

            // If both sides are gone, remove the tunnel entirely, unless one
            // is bound again before it is removed.
            if state.is_empty() {
                drop(entry);
                self.departed
                    .remove_if(&self.tunnels, tunnel_id, TunnelState::is_empty);
            }
        }

        released
    }

    /// Forcibly and authoritatively remove a tunnel by its tunnel id.
    ///
    /// Unlike [`Self::unbind`], which removes a *single* endpoint matched by
    /// `connection_id`, this drops the entire tunnel entry in one shot
    /// regardless of how many sides are currently bound. Returns `None` if no
    /// such tunnel exists, or `Some(connection_ids)` listing every endpoint
    /// that was still bound when it was removed — so the caller can notify those
    /// peers with `TunnelDown` (matching connection-loss cleanup semantics).
    ///
    /// This is the teardown primitive shared by the manager WS `close_tunnel`
    /// command and the REST `DELETE /api/v1/tunnels/{id}` escape hatch. It
    /// exists because the previous `close_tunnel` path called [`Self::unbind`]
    /// with the *edge_id* (the manager node_id for an identified edge), which
    /// never matches the `connection_id` that `unbind` compares against — so
    /// teardown silently no-opped for any edge that had sent an `Identify`
    /// message.
    pub fn force_remove_tunnel(&self, tunnel_id: &Uuid) -> Option<Vec<String>> {
        self.departed.remove(&self.tunnels, tunnel_id).map(|state| {
            let mut affected = Vec::new();
            if let Some(ingress) = state.ingress {
                affected.push(ingress.connection_id);
            }
            if let Some(egress) = state.egress {
                affected.push(egress.connection_id);
            }
            affected
        })
    }

    /// Remove all tunnel endpoints for a given edge (edge disconnected).
    /// Uses `connection_id` for matching. Returns the tunnels it held a side
    /// of, as a list of (tunnel_id, peer_connection_id).
    pub fn remove_edge(&self, connection_id: &str) -> Vec<(Uuid, Option<String>)> {
        let mut affected = Vec::new();

        // Collect the tunnels this edge has bound
        let tunnel_ids: Vec<Uuid> = self
            .tunnels
            .iter()
            .filter(|entry| {
                let s = entry.value();
                let its = |e: &TunnelEndpoint| e.connection_id == connection_id;
                s.ingress.as_ref().is_some_and(its)
                    || s.egress.as_ref().is_some_and(its)
                    || s.displaced.iter().any(its)
            })
            .map(|entry| *entry.key())
            .collect();

        for tid in tunnel_ids {
            if let Some(peer) = self.release(&tid, connection_id) {
                affected.push((tid, peer));
            }
        }

        affected
    }

    /// Whether `connection_id` has bound this side and not unbound it: it holds
    /// the side, or it is remembered as the one the side was taken over from.
    pub fn has_bound(
        &self,
        tunnel_id: &Uuid,
        direction: TunnelDirection,
        connection_id: &str,
    ) -> bool {
        self.tunnels.get(tunnel_id).is_some_and(|state| {
            state
                .side(direction)
                .into_iter()
                .chain(&state.displaced)
                .any(|e| e.direction == direction && e.connection_id == connection_id)
        })
    }

    /// Where data from `connection_id` on this tunnel goes. Only a connection
    /// that holds a side of the tunnel may send on it, and it sends as that
    /// side, as ingress if it holds both. One that has bound nothing, and so
    /// shown no token, sends nothing; nor does one whose side a newer
    /// connection has taken over.
    ///
    /// Asked for every datagram, so it looks the tunnel up once.
    pub fn route(&self, tunnel_id: &Uuid, connection_id: &str) -> Result<Route, NoRoute> {
        let state = self.tunnels.get(tunnel_id).ok_or(NoRoute::NotBound)?;
        let holds = |side: &Option<TunnelEndpoint>| {
            side.as_ref().is_some_and(|e| e.connection_id == connection_id)
        };
        let (from, other) = if holds(&state.ingress) {
            (TunnelDirection::Ingress, &state.egress)
        } else if holds(&state.egress) {
            (TunnelDirection::Egress, &state.ingress)
        } else {
            return Err(NoRoute::NotBound);
        };
        let other = other.as_ref().ok_or(NoRoute::NoPeer)?;
        Ok(Route {
            from,
            peer: other.connection.clone(),
            stats: state.stats.clone(),
        })
    }

    /// Get info for all tunnels (for REST API).
    pub fn list_tunnels(&self) -> Vec<TunnelInfo> {
        self.tunnels
            .iter()
            .map(|entry| {
                let s = entry.value();
                TunnelInfo {
                    tunnel_id: s.tunnel_id,
                    protocol: format!("{:?}", s.protocol).to_lowercase(),
                    status: s.status_str().to_string(),
                    ingress_edge_id: s.ingress.as_ref().map(|e| e.edge_id.clone()),
                    egress_edge_id: s.egress.as_ref().map(|e| e.edge_id.clone()),
                    ingress_remote_addr: s
                        .ingress
                        .as_ref()
                        .map(|e| e.connection.remote_address().to_string()),
                    egress_remote_addr: s
                        .egress
                        .as_ref()
                        .map(|e| e.connection.remote_address().to_string()),
                    stats: s.stats.snapshot(),
                }
            })
            .collect()
    }

    /// Look one tunnel up. The map itself stays private, so nothing takes a
    /// tunnel out of it past `departed`.
    pub fn tunnel(&self, tunnel_id: &Uuid) -> Option<Ref<'_, Uuid, TunnelState>> {
        self.tunnels.get(tunnel_id)
    }

    /// What every QUIC tunnel has counted since the relay started, the ones
    /// that have gone included.
    pub fn totals(&self) -> TunnelTotals {
        self.departed.totals(&self.tunnels)
    }

    /// Count of tunnels in each state.
    pub fn counts(&self) -> (usize, usize) {
        let total = self.tunnels.len();
        let active = self
            .tunnels
            .iter()
            .filter(|e| e.value().is_active())
            .count();
        (total, active)
    }
}

/// Result of binding a tunnel endpoint.
pub enum BindResult {
    /// The token shown is not the side's.
    Refused,
    /// Tunnel is now active (both sides bound).
    Active,
    /// Waiting for the peer to bind.
    Waiting,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> Uuid {
        Uuid::new_v4()
    }

    fn verify(router: &TunnelRouter, t: &Uuid, direction: TunnelDirection, token: Option<&str>) -> bool {
        router.verify_bind_token(t, direction, token.map(TokenDigest::of).as_ref())
    }

    #[test]
    fn permissive_mode_allows_unauthorized_tunnel() {
        let router = TunnelRouter::with_auth_policy(false);
        assert!(verify(&router, &tid(), TunnelDirection::Ingress, None));
        assert!(verify(&router, &tid(), TunnelDirection::Egress, Some("anything")));
    }

    #[test]
    fn strict_mode_rejects_unauthorized_tunnel() {
        let router = TunnelRouter::with_auth_policy(true);
        assert!(!verify(&router, &tid(), TunnelDirection::Ingress, None));
        assert!(!verify(&router, &tid(), TunnelDirection::Egress, Some("anything")));
    }

    #[test]
    fn authorized_tunnel_requires_matching_token_in_both_modes() {
        for strict in [false, true] {
            let router = TunnelRouter::with_auth_policy(strict);
            let t = tid();
            router.authorize_tunnel(t, "ingress-tok", "egress-tok");

            // Correct tokens accepted.
            assert!(verify(&router, &t, TunnelDirection::Ingress, Some("ingress-tok")));
            assert!(verify(&router, &t, TunnelDirection::Egress, Some("egress-tok")));

            // Wrong direction, wrong value, and missing token all rejected.
            assert!(!verify(&router, &t, TunnelDirection::Ingress, Some("egress-tok")));
            assert!(!verify(&router, &t, TunnelDirection::Ingress, Some("nope")));
            assert!(!verify(&router, &t, TunnelDirection::Ingress, None));
        }
    }

    #[test]
    fn revoke_restores_policy_default() {
        let t = tid();

        let strict = TunnelRouter::with_auth_policy(true);
        strict.authorize_tunnel(t, "a", "b");
        strict.revoke_tunnel(&t);
        assert!(!verify(&strict, &t, TunnelDirection::Ingress, Some("a")));

        let permissive = TunnelRouter::with_auth_policy(false);
        permissive.authorize_tunnel(t, "a", "b");
        permissive.revoke_tunnel(&t);
        assert!(verify(&permissive, &t, TunnelDirection::Ingress, None));
    }
}

#[cfg(test)]
mod displaced_tests {
    use super::*;
    use crate::session::test_relay::{edge, start_relay};

    /// Two connections take a side from each other, and bind it again while
    /// they have it, as often as they like: the router remembers each of them
    /// once, and the one that has the side not as one it was taken from.
    #[tokio::test]
    async fn a_connection_is_remembered_once() {
        let (relay, cert, _ctx) = start_relay();
        let (_endpoint, connection, _send, _recv) = edge(relay, &cert, 100).await;
        let router = TunnelRouter::with_auth_policy(false);
        let id = Uuid::new_v4();
        let bind = |name: &str, direction| {
            router.bind(id, TunnelProtocol::Udp, TunnelEndpoint {
                edge_id: name.into(),
                connection_id: name.into(),
                direction,
                connection: connection.clone(),
                shown: None,
            });
        };
        let displaced = || -> Vec<(String, TunnelDirection)> {
            let state = router.tunnel(&id).unwrap();
            state.displaced.iter().map(|e| (e.connection_id.clone(), e.direction)).collect()
        };
        let (ingress, egress) = (TunnelDirection::Ingress, TunnelDirection::Egress);
        for _ in 0..3 {
            bind("a", ingress);
            assert_eq!(displaced(), []);
        }
        for _ in 0..50 {
            bind("b", ingress);
            assert_eq!(displaced(), [("a".into(), ingress)]);
            bind("b", ingress);
            assert_eq!(displaced(), [("a".into(), ingress)]);
            bind("a", ingress);
            assert_eq!(displaced(), [("b".into(), ingress)]);
        }
        // On the other side, as well as on this.
        bind("b", egress);
        bind("a", egress);
        assert_eq!(displaced(), [("b".into(), ingress), ("b".into(), egress)]);
        bind("b", egress);
        assert_eq!(displaced(), [("b".into(), ingress), ("a".into(), egress)]);
        router.unbind(&id, "b");
        assert_eq!(displaced(), [("a".into(), egress)]);
        assert!(router.remove_edge("a").len() == 1);
        assert_eq!(router.counts(), (0, 0));
    }
}

#[cfg(test)]
mod totals_tests {
    use super::*;
    use crate::session::test_relay::{edge, start_relay};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, mpsc};
    use std::time::{Duration, Instant};

    fn bind(router: &TunnelRouter, id: Uuid, name: &str, connection: &quinn::Connection) {
        for direction in [TunnelDirection::Ingress, TunnelDirection::Egress] {
            router.bind(id, TunnelProtocol::Udp, TunnelEndpoint {
                edge_id: name.into(),
                connection_id: format!("{name}-{direction:?}"),
                direction,
                connection: connection.clone(),
                shown: None,
            });
        }
    }

    /// Count one datagram of `bytes` as the session of the ingress that `name`
    /// bound would: look the tunnel up, send, count. The tunnel may be removed
    /// in between.
    fn forward(router: &TunnelRouter, id: &Uuid, name: &str, bytes: u64) -> bool {
        let Ok(Route { stats, .. }) = router.route(id, &format!("{name}-Ingress")) else {
            return false;
        };
        pause();
        stats.udp_datagrams_total.fetch_add(1, Ordering::Relaxed);
        stats.bytes_ingress.fetch_add(bytes, Ordering::Relaxed);
        true
    }

    fn totals(bytes_ingress: u64, udp_datagrams_total: u64) -> TunnelTotals {
        TunnelTotals { bytes_ingress, udp_datagrams_total, ..Default::default() }
    }

    /// The time a send takes, and the gap between one forward, or one read of
    /// the totals, and the next. The map's lock and the totals' are unfair:
    /// without the gaps the removers starve.
    fn pause() {
        std::thread::sleep(Duration::from_micros(1));
    }

    /// An entry that keeps a read of the totals waiting, with their lock held,
    /// until it is opened.
    struct Gate<'a> {
        reached: mpsc::Sender<()>,
        open: &'a Mutex<()>,
        stats: Arc<TunnelStats>,
    }

    impl Counted for Gate<'_> {
        fn stats(&self) -> &Arc<TunnelStats> {
            self.reached.send(()).unwrap();
            drop(self.open.lock());
            &self.stats
        }
    }

    /// The unbind of the last side finds the tunnel empty, then waits for a
    /// read of the totals to end before it removes it. A side bound meanwhile
    /// keeps the tunnel, and its figures.
    #[tokio::test]
    async fn a_side_bound_before_the_empty_tunnel_is_removed_keeps_it() {
        let (relay, cert, _ctx) = start_relay();
        let (_endpoint, connection, _send, _recv) = edge(relay, &cert, 100).await;
        let router = TunnelRouter::with_auth_policy(false);
        let id = Uuid::new_v4();
        bind(&router, id, "a", &connection);
        assert!(forward(&router, &id, "a", 10));
        router.unbind(&id, "a-Ingress");

        let wait = Duration::from_secs(10);
        let open = Mutex::new(());
        let (reached, reading) = mpsc::channel();
        let read = DashMap::new();
        read.insert(id, Gate { reached, open: &open, stats: Arc::new(TunnelStats::new()) });
        std::thread::scope(|s| {
            let shut = open.lock().unwrap();
            s.spawn(|| router.departed.totals(&read));
            reading.recv_timeout(wait).unwrap();
            let unbind = s.spawn(|| router.unbind(&id, "a-Egress"));
            let until = Instant::now() + wait;
            while !router.tunnel(&id).unwrap().is_empty() {
                assert!(Instant::now() < until, "the last side was not unbound");
                pause();
            }
            bind(&router, id, "b", &connection);
            drop(shut);
            unbind.join().unwrap();
        });
        assert_eq!(router.counts(), (1, 1));
        assert!(forward(&router, &id, "b", 5));
        assert_eq!(router.list_tunnels()[0].stats.bytes_ingress, 15);
        assert_eq!(router.totals(), totals(15, 2));
    }

    /// Every way a tunnel leaves the router, and an edge that takes its side
    /// over from another: none moves the totals.
    #[tokio::test]
    async fn every_way_out_of_the_router_keeps_the_totals() {
        let (relay, cert, _ctx) = start_relay();
        let (_endpoint, connection, _send, _recv) = edge(relay, &cert, 100).await;
        let router = TunnelRouter::with_auth_policy(false);
        let id = Uuid::new_v4();
        assert_eq!(router.totals(), totals(0, 0));

        bind(&router, id, "a", &connection);
        assert!(forward(&router, &id, "a", 10));
        assert_eq!(router.totals(), totals(10, 1));
        bind(&router, id, "b", &connection);
        assert!(forward(&router, &id, "b", 5));
        assert_eq!(router.totals(), totals(15, 2), "another edge took both sides over");
        assert_eq!(router.list_tunnels()[0].stats.bytes_ingress, 15, "of the one tunnel");
        assert!(router.remove_edge("a-Ingress").is_empty(), "the edges taken over from");

        router.unbind(&id, "b-Ingress");
        assert_eq!(router.counts(), (1, 0));
        assert_eq!(router.totals(), totals(15, 2), "one side unbound");
        router.unbind(&id, "b-Egress");
        assert_eq!(router.counts(), (0, 0));
        assert_eq!(router.totals(), totals(15, 2), "unbound");

        bind(&router, id, "c", &connection);
        assert!(forward(&router, &id, "c", 100));
        assert_eq!(router.list_tunnels()[0].stats.bytes_ingress, 100, "its own, from nothing");
        assert!(router.force_remove_tunnel(&id).is_some());
        assert_eq!(router.totals(), totals(115, 3), "removed by force");
        assert!(router.force_remove_tunnel(&id).is_none());
        assert_eq!(router.totals(), totals(115, 3));

        bind(&router, id, "d", &connection);
        assert!(forward(&router, &id, "d", 1000));
        router.remove_edge("d-Ingress");
        router.remove_edge("d-Egress");
        assert_eq!(router.counts(), (0, 0));
        assert_eq!(router.totals(), totals(1115, 4), "both edges disconnected");
    }

    /// Four threads forward through two tunnels that are removed and bound
    /// again under them as fast as they can be, while another reads the totals:
    /// no figure falls, and at the end each is what was counted.
    #[tokio::test]
    async fn the_totals_never_fall_under_concurrent_removal() {
        let (relay, cert, _ctx) = start_relay();
        let (_endpoint, connection, _send, _recv) = edge(relay, &cert, 100).await;
        let router = TunnelRouter::with_auth_policy(false);
        let ids: Vec<Uuid> = (0..2).map(|_| Uuid::new_v4()).collect();
        let stop = AtomicBool::new(false);
        let (datagrams, reads) = std::thread::scope(|s| {
            let writers: Vec<_> = (0..4)
                .map(|i| {
                    let (router, stop, id) = (&router, &stop, ids[i % 2]);
                    s.spawn(move || {
                        let mut counted = 0;
                        while !stop.load(Ordering::Relaxed) {
                            counted += u64::from(forward(router, &id, "e", 1316));
                            pause();
                        }
                        counted
                    })
                })
                .collect();
            let removers: Vec<_> = ids
                .iter()
                .map(|&id| {
                    let (router, connection) = (&router, &connection);
                    s.spawn(move || {
                        for round in 0..20_000 {
                            bind(router, id, "e", connection);
                            if round % 2 == 0 {
                                router.force_remove_tunnel(&id);
                            } else {
                                router.remove_edge("e-Ingress");
                                router.unbind(&id, "e-Egress");
                            }
                        }
                    })
                })
                .collect();
            let reader = s.spawn(|| {
                let (mut last, mut reads) = (TunnelTotals::default(), 0);
                while !stop.load(Ordering::Relaxed) {
                    let now = router.totals();
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
        assert_eq!(router.totals(), totals(datagrams * 1316, datagrams));
    }
}
