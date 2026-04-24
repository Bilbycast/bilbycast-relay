// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Tunnel routing: pairs ingress and egress edges by tunnel ID and forwards data.

use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;
use uuid::Uuid;

use crate::protocol::{TunnelDirection, TunnelProtocol};
use crate::stats::{TunnelStats, TunnelStatsSnapshot};

/// A registered tunnel endpoint (one side — ingress or egress).
pub struct TunnelEndpoint {
    /// Identity for reporting (manager node_id if identified, else connection_id).
    pub edge_id: String,
    /// Internal key for edge_connections DashMap lookups (always connection_id).
    pub connection_id: String,
    pub direction: TunnelDirection,
    pub connection: quinn::Connection,
}

/// State of a tunnel as tracked by the router.
pub struct TunnelState {
    pub tunnel_id: Uuid,
    pub protocol: TunnelProtocol,
    pub ingress: Option<TunnelEndpoint>,
    pub egress: Option<TunnelEndpoint>,
    pub stats: Arc<TunnelStats>,
}

impl TunnelState {
    pub fn is_active(&self) -> bool {
        self.ingress.is_some() && self.egress.is_some()
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

/// Serializable tunnel info for the REST API.
#[derive(Debug, Serialize)]
pub struct TunnelInfo {
    pub tunnel_id: Uuid,
    pub protocol: String,
    pub status: String,
    pub ingress_edge_id: Option<String>,
    pub egress_edge_id: Option<String>,
    pub stats: TunnelStatsSnapshot,
}

/// Pre-authorized bind tokens for a tunnel (set by manager via authorize_tunnel command).
pub struct AuthorizedTunnel {
    pub ingress_token: String,
    pub egress_token: String,
}

/// The tunnel router manages all active and pending tunnels.
pub struct TunnelRouter {
    tunnels: DashMap<Uuid, TunnelState>,
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
            authorized_tokens: DashMap::new(),
            require_bind_auth,
        }
    }

    /// Register expected bind tokens for a tunnel (called by manager authorize_tunnel command).
    pub fn authorize_tunnel(&self, tunnel_id: Uuid, ingress_token: String, egress_token: String) {
        self.authorized_tokens.insert(
            tunnel_id,
            AuthorizedTunnel {
                ingress_token,
                egress_token,
            },
        );
    }

    /// Remove authorization for a tunnel.
    pub fn revoke_tunnel(&self, tunnel_id: &Uuid) {
        self.authorized_tokens.remove(tunnel_id);
    }

    /// Verify a bind token for a tunnel+direction.
    ///
    /// Returns `true` if the provided bind_token matches the expected token
    /// for the given direction. When no authorization is registered for this
    /// tunnel: permissive mode (`require_bind_auth = false`, default) returns
    /// `true` for backwards compatibility; strict mode returns `false`.
    pub fn verify_bind_token(
        &self,
        tunnel_id: &Uuid,
        direction: TunnelDirection,
        bind_token: Option<&str>,
    ) -> bool {
        let Some(auth) = self.authorized_tokens.get(tunnel_id) else {
            // No authorization registered: fail-closed in strict mode,
            // fail-open in permissive (backwards-compatible) mode.
            return !self.require_bind_auth;
        };

        let expected = match direction {
            TunnelDirection::Ingress => &auth.ingress_token,
            TunnelDirection::Egress => &auth.egress_token,
        };

        let Some(provided) = bind_token else {
            // Authorization exists but no token provided
            return false;
        };

        // Constant-time comparison to prevent timing attacks
        constant_time_eq(expected.as_bytes(), provided.as_bytes())
    }

    /// Bind a tunnel endpoint. Returns (was_newly_activated, peer_connection_if_active).
    ///
    /// If both sides are now bound, the tunnel becomes active.
    pub fn bind(
        &self,
        tunnel_id: Uuid,
        protocol: TunnelProtocol,
        endpoint: TunnelEndpoint,
    ) -> BindResult {
        let direction = endpoint.direction;

        let mut entry = self.tunnels.entry(tunnel_id).or_insert_with(|| TunnelState {
            tunnel_id,
            protocol,
            ingress: None,
            egress: None,
            stats: Arc::new(TunnelStats::new()),
        });

        let state = entry.value_mut();

        match direction {
            TunnelDirection::Ingress => {
                state.ingress = Some(endpoint);
            }
            TunnelDirection::Egress => {
                state.egress = Some(endpoint);
            }
        }

        if state.is_active() {
            BindResult::Active
        } else {
            BindResult::Waiting
        }
    }

    /// Unbind a tunnel endpoint (edge disconnected or explicitly unbound).
    /// Uses `connection_id` for matching. Returns the peer's `connection_id` for notification.
    pub fn unbind(&self, tunnel_id: &Uuid, connection_id: &str) -> Option<String> {
        let mut peer_connection_id = None;

        if let Some(mut entry) = self.tunnels.get_mut(tunnel_id) {
            let state = entry.value_mut();

            if let Some(ref ingress) = state.ingress {
                if ingress.connection_id == connection_id {
                    state.ingress = None;
                    peer_connection_id =
                        state.egress.as_ref().map(|e| e.connection_id.clone());
                }
            }
            if let Some(ref egress) = state.egress {
                if egress.connection_id == connection_id {
                    state.egress = None;
                    peer_connection_id =
                        state.ingress.as_ref().map(|e| e.connection_id.clone());
                }
            }

            // If both sides are gone, remove the tunnel entirely
            if state.ingress.is_none() && state.egress.is_none() {
                drop(entry);
                self.tunnels.remove(tunnel_id);
            }
        }

        peer_connection_id
    }

    /// Remove all tunnel endpoints for a given edge (edge disconnected).
    /// Uses `connection_id` for matching. Returns list of (tunnel_id, peer_connection_id).
    pub fn remove_edge(&self, connection_id: &str) -> Vec<(Uuid, Option<String>)> {
        let mut affected = Vec::new();

        // Collect tunnel IDs that this edge participates in
        let tunnel_ids: Vec<Uuid> = self
            .tunnels
            .iter()
            .filter(|entry| {
                let s = entry.value();
                s.ingress
                    .as_ref()
                    .is_some_and(|e| e.connection_id == connection_id)
                    || s.egress
                        .as_ref()
                        .is_some_and(|e| e.connection_id == connection_id)
            })
            .map(|entry| *entry.key())
            .collect();

        for tid in tunnel_ids {
            let peer = self.unbind(&tid, connection_id);
            affected.push((tid, peer));
        }

        affected
    }

    /// Look up a tunnel to find the peer connection for forwarding.
    pub fn get_peer_connection(
        &self,
        tunnel_id: &Uuid,
        from_direction: TunnelDirection,
    ) -> Option<(quinn::Connection, Arc<TunnelStats>)> {
        self.tunnels.get(tunnel_id).and_then(|entry| {
            let state = entry.value();
            let peer = match from_direction {
                TunnelDirection::Ingress => state.egress.as_ref(),
                TunnelDirection::Egress => state.ingress.as_ref(),
            };
            peer.map(|p| (p.connection.clone(), state.stats.clone()))
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
                    stats: s.stats.snapshot(),
                }
            })
            .collect()
    }

    /// Direct access to the tunnels map (for session lookups).
    pub fn tunnels_ref(&self) -> &DashMap<Uuid, TunnelState> {
        &self.tunnels
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
    /// Tunnel is now active (both sides bound).
    Active,
    /// Waiting for the peer to bind.
    Waiting,
}

/// Constant-time byte comparison to prevent timing attacks on token verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn permissive_mode_allows_unauthorized_tunnel() {
        let router = TunnelRouter::with_auth_policy(false);
        assert!(router.verify_bind_token(&tid(), TunnelDirection::Ingress, None));
        assert!(router.verify_bind_token(&tid(), TunnelDirection::Egress, Some("anything")));
    }

    #[test]
    fn strict_mode_rejects_unauthorized_tunnel() {
        let router = TunnelRouter::with_auth_policy(true);
        assert!(!router.verify_bind_token(&tid(), TunnelDirection::Ingress, None));
        assert!(!router.verify_bind_token(&tid(), TunnelDirection::Egress, Some("anything")));
    }

    #[test]
    fn authorized_tunnel_requires_matching_token_in_both_modes() {
        for strict in [false, true] {
            let router = TunnelRouter::with_auth_policy(strict);
            let t = tid();
            router.authorize_tunnel(t, "ingress-tok".into(), "egress-tok".into());

            // Correct tokens accepted.
            assert!(router.verify_bind_token(&t, TunnelDirection::Ingress, Some("ingress-tok")));
            assert!(router.verify_bind_token(&t, TunnelDirection::Egress, Some("egress-tok")));

            // Wrong direction, wrong value, and missing token all rejected.
            assert!(!router.verify_bind_token(&t, TunnelDirection::Ingress, Some("egress-tok")));
            assert!(!router.verify_bind_token(&t, TunnelDirection::Ingress, Some("nope")));
            assert!(!router.verify_bind_token(&t, TunnelDirection::Ingress, None));
        }
    }

    #[test]
    fn revoke_restores_policy_default() {
        let t = tid();

        let strict = TunnelRouter::with_auth_policy(true);
        strict.authorize_tunnel(t, "a".into(), "b".into());
        strict.revoke_tunnel(&t);
        assert!(!strict.verify_bind_token(&t, TunnelDirection::Ingress, Some("a")));

        let permissive = TunnelRouter::with_auth_policy(false);
        permissive.authorize_tunnel(t, "a".into(), "b".into());
        permissive.revoke_tunnel(&t);
        assert!(permissive.verify_bind_token(&t, TunnelDirection::Ingress, None));
    }
}
