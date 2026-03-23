// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
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
    pub edge_id: String,
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

/// The tunnel router manages all active and pending tunnels.
pub struct TunnelRouter {
    tunnels: DashMap<Uuid, TunnelState>,
}

impl TunnelRouter {
    pub fn new() -> Self {
        Self {
            tunnels: DashMap::new(),
        }
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
    /// Returns the peer's edge_id if there was a peer (for notification).
    pub fn unbind(&self, tunnel_id: &Uuid, edge_id: &str) -> Option<String> {
        let mut peer_edge_id = None;

        if let Some(mut entry) = self.tunnels.get_mut(tunnel_id) {
            let state = entry.value_mut();

            if let Some(ref ingress) = state.ingress {
                if ingress.edge_id == edge_id {
                    state.ingress = None;
                    peer_edge_id = state.egress.as_ref().map(|e| e.edge_id.clone());
                }
            }
            if let Some(ref egress) = state.egress {
                if egress.edge_id == edge_id {
                    state.egress = None;
                    peer_edge_id = state.ingress.as_ref().map(|e| e.edge_id.clone());
                }
            }

            // If both sides are gone, remove the tunnel entirely
            if state.ingress.is_none() && state.egress.is_none() {
                drop(entry);
                self.tunnels.remove(tunnel_id);
            }
        }

        peer_edge_id
    }

    /// Remove all tunnel endpoints for a given edge (edge disconnected).
    /// Returns list of (tunnel_id, peer_edge_id) for notification.
    pub fn remove_edge(&self, edge_id: &str) -> Vec<(Uuid, Option<String>)> {
        let mut affected = Vec::new();

        // Collect tunnel IDs that this edge participates in
        let tunnel_ids: Vec<Uuid> = self
            .tunnels
            .iter()
            .filter(|entry| {
                let s = entry.value();
                s.ingress.as_ref().is_some_and(|e| e.edge_id == edge_id)
                    || s.egress.as_ref().is_some_and(|e| e.edge_id == edge_id)
            })
            .map(|entry| *entry.key())
            .collect();

        for tid in tunnel_ids {
            let peer = self.unbind(&tid, edge_id);
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
