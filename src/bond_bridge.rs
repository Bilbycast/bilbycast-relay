// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Relay-hosted **bond bridge** — bonding via relay.
//!
//! A bond bridge terminates an INGRESS bond arriving from edge A (its 5G /
//! Starlink / … legs), recovers the original stream with the bond's full
//! cross-leg ARQ + FEC + reorder, then re-originates a fresh EGRESS bond (or
//! single path) toward edge B. It runs **in-process** in the relay using the
//! pure-Rust `bonding-transport` `BondSocket::{receiver,sender}` — no new C
//! deps, so binary purity holds.
//!
//! This is the one place the relay is NOT a payload-opaque byte-forwarder: a
//! bridged bond must be terminated to be recovered. That is inherent to
//! "bonding via relay" (the bond is proprietary `0xBC` at both ends and must be
//! reassembled to aggregate the legs). The QUIC tunnel relay + the native-UDP
//! relay stay fully opaque; only explicitly-configured bridges terminate a bond.
//! Inner media can still be end-to-end encrypted above the bond.
//!
//! Legs here can be **UDP or QUIC** (the firewall-traversal aggregation case:
//! edge A's cellular/satellite uplinks dial the relay's public ingress ports
//! over either carrier). The QUIC leg role is auto-derived from the side: an
//! ingress (receiver) leg is the QUIC **server** (listens on its `bind`); an
//! egress (sender) leg is the QUIC **client** (dials its `remote`). RIST is
//! excluded as an aggregation leg by design (unidirectional at the bond layer).
//!
//! QUIC transport TLS defaults to self-signed — the bond's `encryption_key`
//! (ChaCha20-Poly1305 AEAD, shared end-to-end with the peer edge) is the real
//! confidentiality + integrity layer, exactly as for the UDP leg which carries
//! no transport TLS at all. PEM certs are supported for production transport TLS.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use bonding_transport::{
    BondSocket, BondSocketConfig, EqualizationMode, PacketHints, PathConfig, PathTransport,
    QuicRole, QuicTlsMode, RoundRobinScheduler, WeightedRttScheduler,
};

/// Default per-leg equalization budget (ms) when equalization measures but no
/// explicit `max_bonding_latency_ms` / `hold_max_ms` is given. Matches the
/// edge's `DEFAULT_EQUALIZATION_BUDGET_MS` (1 s) so the sender's demote budget
/// and the receiver's alignment ceiling agree by default.
const DEFAULT_EQUALIZATION_BUDGET_MS: u64 = 1000;

/// Which side of the bridge a `BridgeSide` is — decides the QUIC leg role
/// (receiver legs are QUIC servers, sender legs are QUIC clients).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BridgeSocketRole {
    Receiver,
    Sender,
}

// ── Config (manager-pushed or static in RelayConfig) ──

/// One relay-hosted bond bridge: ingress bond (from edge A) → egress bond (to edge B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondBridgeConfig {
    /// Stable bridge id (UUID string recommended).
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Ingress side — terminate edge A's bond here (receiver).
    pub ingress: BridgeSide,
    /// Egress side — re-originate toward edge B (sender).
    pub egress: BridgeSide,
}

/// One side of a bridge (a complete bond definition).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSide {
    /// Bond flow id. The ingress and egress sides MUST use different flow ids.
    pub flow_id: u32,
    #[serde(default)]
    pub scheduler: SchedulerKind,
    /// Bond legs (UDP). Ingress legs `bind` local ports; egress legs `remote`
    /// the destination. Path `id`s + `flow_id` must match the peer edge.
    pub paths: Vec<LegSpec>,
    #[serde(default)]
    pub tuning: BridgeTuning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerKind {
    #[default]
    WeightedRtt,
    RoundRobin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegSpec {
    pub id: u8,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_weight")]
    pub weight_hint: u32,
    /// Carrier for this leg. Defaults to UDP — absent `transport` on legacy
    /// configs deserialises to `Udp`, so existing UDP bridges are unaffected.
    #[serde(default)]
    pub transport: BridgeLegTransport,
    /// Receiver (ingress) leg: set `bind` (UDP: local bind / QUIC: listen addr).
    /// Sender (egress) leg: set `remote` (the dial target). On a QUIC egress
    /// leg `bind` is the optional local source bind for NIC pinning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

fn default_weight() -> u32 {
    1
}

/// Per-leg carrier. `Udp` (default) or `Quic`. RIST is excluded by design.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BridgeLegTransport {
    #[default]
    Udp,
    Quic {
        /// Client (egress) SNI / server name. Ignored on the ingress server.
        /// Must match the peer edge's QUIC leg server name; with self-signed
        /// TLS it is not verified, but it still rides ALPN/SNI.
        #[serde(default = "default_quic_server_name")]
        server_name: String,
        /// Transport TLS mode. Default self-signed (bond AEAD is the real
        /// confidentiality layer end-to-end).
        #[serde(default)]
        tls: BridgeQuicTls,
    },
}

fn default_quic_server_name() -> String {
    "bilbycast-bond".to_string()
}

/// QUIC transport TLS for a bridge leg.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BridgeQuicTls {
    /// Self-signed in-process. The client skips cert verification; the bond
    /// `encryption_key` AEAD secures the payload end-to-end. Matches the edge's
    /// bond-leg default and the relay's own QUIC-server fallback.
    #[default]
    SelfSigned,
    /// PEM cert chain + private key on disk (production transport TLS), with an
    /// optional client trust root for mutual verification.
    Pem {
        cert_chain_path: String,
        private_key_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_trust_root_path: Option<String>,
    },
}

impl BridgeQuicTls {
    fn to_quic_tls_mode(&self) -> Result<QuicTlsMode> {
        Ok(match self {
            BridgeQuicTls::SelfSigned => QuicTlsMode::SelfSigned,
            BridgeQuicTls::Pem {
                cert_chain_path,
                private_key_path,
                client_trust_root_path,
            } => {
                let cert_chain = std::fs::read(cert_chain_path)
                    .with_context(|| format!("read cert chain '{cert_chain_path}'"))?;
                let private_key = std::fs::read(private_key_path)
                    .with_context(|| format!("read private key '{private_key_path}'"))?;
                let client_trust_root = match client_trust_root_path {
                    Some(p) => Some(
                        std::fs::read(p).with_context(|| format!("read trust root '{p}'"))?,
                    ),
                    None => None,
                };
                QuicTlsMode::Pem { cert_chain, private_key, client_trust_root }
            }
        })
    }
}

impl LegSpec {
    /// Build the bonding-transport `PathTransport` for this leg, given which
    /// side of the bridge it lives on (decides the QUIC role).
    fn to_path_transport(&self, role: BridgeSocketRole) -> Result<PathTransport> {
        let bind = match &self.bind {
            Some(s) => Some(s.parse::<SocketAddr>().with_context(|| format!("leg {} bind '{s}'", self.id))?),
            None => None,
        };
        let remote = match &self.remote {
            Some(s) => Some(s.parse::<SocketAddr>().with_context(|| format!("leg {} remote '{s}'", self.id))?),
            None => None,
        };
        match &self.transport {
            BridgeLegTransport::Udp => Ok(PathTransport::Udp { bind, remote, interface: self.interface.clone() }),
            BridgeLegTransport::Quic { server_name, tls } => {
                let tls = tls.to_quic_tls_mode()?;
                match role {
                    // Ingress (receiver) → QUIC server: listen on `bind`.
                    BridgeSocketRole::Receiver => {
                        let addr = bind.ok_or_else(|| {
                            anyhow!("leg {} (quic ingress) requires 'bind' (the listen address)", self.id)
                        })?;
                        Ok(PathTransport::Quic {
                            role: QuicRole::Server,
                            addr,
                            server_name: server_name.clone(),
                            tls,
                            bind: None,
                            interface: self.interface.clone(),
                        })
                    }
                    // Egress (sender) → QUIC client: dial `remote`, optional source `bind`.
                    BridgeSocketRole::Sender => {
                        let addr = remote.ok_or_else(|| {
                            anyhow!("leg {} (quic egress) requires 'remote' (the dial target)", self.id)
                        })?;
                        Ok(PathTransport::Quic {
                            role: QuicRole::Client,
                            addr,
                            server_name: server_name.clone(),
                            tls,
                            bind,
                            interface: self.interface.clone(),
                        })
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeTuning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nack_delay_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nack_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmit_capacity: Option<usize>,
    /// Per-leg latency/jitter **equalization** mode — `"off"` (default; plain
    /// cross-leg ARQ/FEC recovery, full throughput, lowest added latency),
    /// `"auto"` (time-align heterogeneous legs — best for *symmetric*
    /// high-latency legs; live testing showed it thrashes on an extreme
    /// dominant-leg + protection-leg split like 95% Starlink / 5% 5G), or
    /// `"on"` (force-align). On the ingress side this is the receiver that
    /// aligns; the matching peer edge's bonded output must be stamping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equalization: Option<String>,
    /// Single bonding-latency budget (ms) — the receiver's alignment ceiling +
    /// loss-recovery deadline when equalization measures. Set this **equal** to
    /// the peer edge's `max_bonding_latency_ms`. Falls back to `hold_max_ms`,
    /// else the 1 s default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bonding_latency_ms: Option<u32>,
    /// Legacy adaptive hold-time ceiling (ms). When equalization is `off` this
    /// is the servo ceiling above `hold_ms`; superseded by
    /// `max_bonding_latency_ms` when equalization measures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_max_ms: Option<u32>,
    /// Optional 32-byte AEAD key (hex, 64 chars). Both peer edges must share it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
}

/// Map the tri-state equalization string to the bonding layer's
/// [`EqualizationMode`]. **Absent → `Off`** (plain cross-leg ARQ/FEC recovery):
/// the conservative, predictable bridge default. Live 5G+Starlink testing showed
/// `Auto` alignment thrashes on an extreme-asymmetric leg split (e.g. 95% on a
/// low-RTT leg, 5% on a high-jitter leg), so it is opt-in — best for symmetric
/// high-latency legs, not a dominant-leg + protection-leg aggregate.
fn parse_equalization(s: Option<&str>) -> Result<EqualizationMode> {
    Ok(match s.map(|x| x.trim().to_ascii_lowercase()).as_deref() {
        None | Some("off") => EqualizationMode::Off,
        Some("auto") => EqualizationMode::Auto,
        Some("on") => EqualizationMode::On,
        Some(other) => anyhow::bail!("unknown equalization '{other}' (want auto|off|on)"),
    })
}

impl BridgeSide {
    fn to_socket_config(&self, role: BridgeSocketRole) -> Result<BondSocketConfig> {
        let mut cfg = BondSocketConfig {
            flow_id: self.flow_id,
            paths: Vec::with_capacity(self.paths.len()),
            ..Default::default()
        };
        if let Some(ms) = self.tuning.hold_ms {
            cfg.hold_time = Duration::from_millis(ms as u64);
        }
        if let Some(ms) = self.tuning.keepalive_ms {
            cfg.keepalive_interval = Duration::from_millis(ms as u64);
        }
        if let Some(ms) = self.tuning.nack_delay_ms {
            cfg.nack_delay = Duration::from_millis(ms as u64);
        }
        if let Some(n) = self.tuning.max_nack_retries {
            cfg.max_nack_retries = n;
        }
        if let Some(n) = self.tuning.retransmit_capacity {
            cfg.retransmit_capacity = n;
        }
        if let Some(ms) = self.tuning.hold_max_ms {
            cfg.hold_max = Some(Duration::from_millis(ms as u64));
        }
        // Per-leg equalization (receiver side aligns heterogeneous legs;
        // sender side stamps). When it measures, the single bonding-latency
        // budget becomes the alignment ceiling (`hold_max`) — mirrors the edge's
        // single-knob model so both ends agree.
        let eq = parse_equalization(self.tuning.equalization.as_deref())?;
        cfg.equalization = eq;
        if eq.measures() {
            let budget_ms = self
                .tuning
                .max_bonding_latency_ms
                .map(|m| m as u64)
                .or(self.tuning.hold_max_ms.map(|m| m as u64))
                .unwrap_or(DEFAULT_EQUALIZATION_BUDGET_MS);
            cfg.hold_max = Some(Duration::from_millis(budget_ms));
        }
        if let Some(ref hexkey) = self.tuning.encryption_key {
            let raw = hex_decode32(hexkey)
                .context("bridge encryption_key must be 64 hex chars (32 bytes)")?;
            cfg.encryption_key = Some(raw);
        }
        for p in &self.paths {
            cfg.paths.push(PathConfig {
                id: p.id,
                name: if p.name.is_empty() { format!("leg-{}", p.id) } else { p.name.clone() },
                transport: p.to_path_transport(role)?,
                weight_hint: p.weight_hint,
            });
        }
        Ok(cfg)
    }
}

fn hex_decode32(s: &str) -> Result<Vec<u8>> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("expected 64 hex chars");
    }
    let mut out = Vec::with_capacity(32);
    let b = s.as_bytes();
    for i in (0..64).step_by(2) {
        let hi = (b[i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

// ── Running bridge + registry ──

struct RunningBridge {
    config: BondBridgeConfig,
    started_at: Instant,
    pump: JoinHandle<()>,
    ingress: Arc<BondSocket>,
    egress: Arc<BondSocket>,
}

impl RunningBridge {
    fn shutdown(self) {
        self.pump.abort();
        self.ingress.close();
        self.egress.close();
    }
}

/// Serializable bridge info for REST / health / manager.
#[derive(Debug, Serialize)]
pub struct BondBridgeInfo {
    pub id: String,
    pub name: String,
    pub ingress_flow_id: u32,
    pub egress_flow_id: u32,
    pub ingress_legs: usize,
    pub egress_legs: usize,
    pub uptime_secs: u64,
    /// Recovered from edge A (ingress bond).
    pub bytes_in: u64,
    pub packets_delivered: u64,
    pub gaps_recovered: u64,
    pub gaps_lost: u64,
    /// Sent toward edge B (egress bond).
    pub bytes_out: u64,
}

/// Registry of running relay-hosted bond bridges. Lock-free (`DashMap`).
#[derive(Default)]
pub struct BondBridgeRegistry {
    bridges: DashMap<String, RunningBridge>,
}

impl BondBridgeRegistry {
    pub fn new() -> Self {
        Self { bridges: DashMap::new() }
    }

    /// Start (or replace) a bridge. Idempotent on identical config: a different
    /// config for the same id tears the old one down first.
    pub async fn start(&self, config: BondBridgeConfig) -> Result<()> {
        if config.ingress.flow_id == config.egress.flow_id {
            anyhow::bail!(
                "bridge '{}': ingress.flow_id and egress.flow_id must differ ({})",
                config.id,
                config.ingress.flow_id
            );
        }
        // Replace any existing bridge with this id.
        if let Some((_, old)) = self.bridges.remove(&config.id) {
            old.shutdown();
        }

        let in_cfg = config.ingress.to_socket_config(BridgeSocketRole::Receiver)?;
        let eg_cfg = config.egress.to_socket_config(BridgeSocketRole::Sender)?;
        let eg_ids: Vec<u8> = eg_cfg.paths.iter().map(|p| p.id).collect();

        let ingress = Arc::new(
            BondSocket::receiver(in_cfg)
                .await
                .map_err(|e| anyhow::anyhow!("bridge '{}' ingress (receiver) setup: {e}", config.id))?,
        );
        let egress = Arc::new(match config.egress.scheduler {
            SchedulerKind::WeightedRtt => {
                BondSocket::sender(eg_cfg, WeightedRttScheduler::new(eg_ids.clone()))
                    .await
                    .map_err(|e| anyhow::anyhow!("bridge '{}' egress (sender) setup: {e}", config.id))?
            }
            SchedulerKind::RoundRobin => {
                BondSocket::sender(eg_cfg, RoundRobinScheduler::new(eg_ids.clone()))
                    .await
                    .map_err(|e| anyhow::anyhow!("bridge '{}' egress (sender) setup: {e}", config.id))?
            }
        });

        // Pump: recovered ingress payloads → egress bond.
        let pump_in = ingress.clone();
        let pump_eg = egress.clone();
        let bid = config.id.clone();
        let pump = tokio::spawn(async move {
            loop {
                match pump_in.recv().await {
                    Some(payload) => {
                        if let Err(e) = pump_eg.send(payload, PacketHints::default()).await {
                            tracing::trace!("bridge '{bid}' egress send: {e}");
                        }
                    }
                    None => {
                        tracing::info!("bridge '{bid}' ingress closed");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            "bond bridge '{}' up: ingress flow {} ({} legs) -> egress flow {} ({} legs)",
            config.id,
            config.ingress.flow_id,
            config.ingress.paths.len(),
            config.egress.flow_id,
            config.egress.paths.len(),
        );

        self.bridges.insert(
            config.id.clone(),
            RunningBridge { config, started_at: Instant::now(), pump, ingress, egress },
        );
        Ok(())
    }

    /// Stop + remove a bridge. Returns true if it existed.
    pub fn stop(&self, id: &str) -> bool {
        if let Some((_, b)) = self.bridges.remove(id) {
            tracing::info!("bond bridge '{id}' stopped");
            b.shutdown();
            true
        } else {
            false
        }
    }

    pub fn count(&self) -> usize {
        self.bridges.len()
    }

    pub fn list(&self) -> Vec<BondBridgeInfo> {
        self.bridges
            .iter()
            .map(|e| {
                let b = e.value();
                let in_s = b.ingress.stats();
                let eg_s = b.egress.stats();
                BondBridgeInfo {
                    id: b.config.id.clone(),
                    name: b.config.name.clone(),
                    ingress_flow_id: b.config.ingress.flow_id,
                    egress_flow_id: b.config.egress.flow_id,
                    ingress_legs: b.config.ingress.paths.len(),
                    egress_legs: b.config.egress.paths.len(),
                    uptime_secs: b.started_at.elapsed().as_secs(),
                    bytes_in: in_s.bytes_received.load(Ordering::Relaxed),
                    packets_delivered: in_s.packets_delivered.load(Ordering::Relaxed),
                    gaps_recovered: in_s.gaps_recovered.load(Ordering::Relaxed),
                    gaps_lost: in_s.gaps_lost.load(Ordering::Relaxed),
                    bytes_out: eg_s.bytes_sent.load(Ordering::Relaxed),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"{
        "id": "br1", "name": "edgeA->edgeB",
        "ingress": { "flow_id": 42, "paths": [
            { "id": 0, "name": "5g", "bind": "0.0.0.0:7000" },
            { "id": 1, "name": "sat", "bind": "0.0.0.0:7002" }
        ]},
        "egress": { "flow_id": 99, "paths": [
            { "id": 0, "name": "toB", "remote": "127.0.0.1:7400" }
        ]}
    }"#;

    // A QUIC-leg bridge: ingress legs listen (QUIC server), egress leg dials
    // (QUIC client). Mixed transports are allowed per-leg.
    const QUIC_CFG: &str = r#"{
        "id": "brq", "name": "edgeA->edgeB (quic)",
        "ingress": { "flow_id": 42, "paths": [
            { "id": 0, "name": "5g",  "transport": { "kind": "quic" }, "bind": "0.0.0.0:7400" },
            { "id": 1, "name": "sat", "transport": { "kind": "quic", "server_name": "relay.example" }, "bind": "0.0.0.0:7401" }
        ]},
        "egress": { "flow_id": 99, "paths": [
            { "id": 0, "name": "toB", "transport": { "kind": "quic" }, "remote": "203.0.113.9:7500", "interface": "eth0" }
        ]}
    }"#;

    #[test]
    fn config_parses_and_translates_both_sides() {
        let cfg: BondBridgeConfig = serde_json::from_str(CFG).unwrap();
        let inc = cfg.ingress.to_socket_config(BridgeSocketRole::Receiver).unwrap();
        let egc = cfg.egress.to_socket_config(BridgeSocketRole::Sender).unwrap();
        assert_eq!(inc.flow_id, 42);
        assert_eq!(inc.paths.len(), 2);
        assert_eq!(egc.flow_id, 99);
        assert_eq!(egc.paths.len(), 1);
        // Legacy configs with no `transport` field default to UDP.
        assert!(matches!(inc.paths[0].transport, PathTransport::Udp { bind: Some(_), .. }));
        assert!(matches!(egc.paths[0].transport, PathTransport::Udp { remote: Some(_), .. }));
    }

    #[test]
    fn quic_legs_translate_with_correct_roles() {
        let cfg: BondBridgeConfig = serde_json::from_str(QUIC_CFG).unwrap();
        let inc = cfg.ingress.to_socket_config(BridgeSocketRole::Receiver).unwrap();
        let egc = cfg.egress.to_socket_config(BridgeSocketRole::Sender).unwrap();
        // Ingress QUIC legs are servers, listening on their `bind` addr.
        for p in &inc.paths {
            match &p.transport {
                PathTransport::Quic { role, addr, .. } => {
                    assert_eq!(*role, QuicRole::Server);
                    assert_eq!(addr.port(), if p.id == 0 { 7400 } else { 7401 });
                }
                other => panic!("expected QUIC server leg, got {other:?}"),
            }
        }
        // Egress QUIC leg is a client, dialing its `remote`, NIC-pinned.
        match &egc.paths[0].transport {
            PathTransport::Quic { role, addr, interface, .. } => {
                assert_eq!(*role, QuicRole::Client);
                assert_eq!(addr.port(), 7500);
                assert_eq!(interface.as_deref(), Some("eth0"));
            }
            other => panic!("expected QUIC client leg, got {other:?}"),
        }
    }

    #[test]
    fn quic_ingress_requires_bind() {
        let bad = r#"{
            "id": "x", "ingress": { "flow_id": 1, "paths": [
                { "id": 0, "transport": { "kind": "quic" }, "remote": "1.2.3.4:5" } ]},
            "egress": { "flow_id": 2, "paths": [ { "id": 0, "remote": "1.2.3.4:6" } ]}
        }"#;
        let cfg: BondBridgeConfig = serde_json::from_str(bad).unwrap();
        // QUIC ingress leg with no `bind` is a hard error (clear message).
        assert!(cfg.ingress.to_socket_config(BridgeSocketRole::Receiver).is_err());
    }

    #[tokio::test]
    async fn registry_rejects_same_flow_id() {
        let mut cfg: BondBridgeConfig = serde_json::from_str(CFG).unwrap();
        cfg.egress.flow_id = cfg.ingress.flow_id;
        let reg = BondBridgeRegistry::new();
        assert!(reg.start(cfg).await.is_err());
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn encryption_key_hex_validated() {
        let mut cfg: BondBridgeConfig = serde_json::from_str(CFG).unwrap();
        cfg.ingress.tuning.encryption_key = Some("zz".repeat(32)); // non-hex
        assert!(cfg.ingress.to_socket_config(BridgeSocketRole::Receiver).is_err());
        cfg.ingress.tuning.encryption_key = Some("ab".repeat(32)); // 64 hex
        assert!(cfg.ingress.to_socket_config(BridgeSocketRole::Receiver).is_ok());
    }
}
