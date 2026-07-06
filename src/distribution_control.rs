// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Runtime, manager-overridable distribution config.
//!
//! The bootstrap distribution config comes from the relay's `config.json`, but
//! the manager owns the operational policy — the shared token secret, the
//! auth gates, the advertised public IP / base URL, and the cascade sources —
//! and pushes them over the WS `configure_distribution` command so an operator
//! never hand-edits the relay's config. This module is the shared cell both
//! sides read/write: the manager-client command handler calls
//! [`DistributionControl::apply`] / [`DistributionControl::set_cascade`]; the
//! viewer-distribution subsystem reads the live values on each request.
//!
//! It is **always compiled** (not behind the `viewer-distribution` feature) so
//! the non-feature-gated manager client can hold an `Option<Arc<...>>` handle
//! without a cfg gate. The values are plain data (no str0m types).

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::watch;

use crate::config::{CascadeSource, DistributionConfig};

/// The subset of distribution config the manager can change at runtime.
#[derive(Clone, Debug, Default)]
pub struct RuntimeDistConfig {
    pub token_secret: Option<String>,
    pub require_viewer_token: bool,
    pub require_ingest_token: bool,
    /// Public IP advertised in WHEP ICE candidates.
    pub public_ip: Option<IpAddr>,
    /// Public base URL used to build shareable viewer links (reported to the
    /// manager on health).
    pub public_base_url: Option<String>,
}

impl RuntimeDistConfig {
    /// Derive from the static config, with an optional `public_ip` override.
    pub fn from_config(cfg: &DistributionConfig, public_ip: Option<IpAddr>) -> Self {
        Self {
            token_secret: cfg.token_secret.clone(),
            require_viewer_token: cfg.require_viewer_token,
            require_ingest_token: cfg.require_ingest_token,
            public_ip: public_ip.or_else(|| cfg.public_ip_parsed()),
            public_base_url: cfg.public_base_url.clone(),
        }
    }
}

/// Shared, lock-free runtime config + a cascade-source change channel.
pub struct DistributionControl {
    cfg: ArcSwap<RuntimeDistConfig>,
    cascade_tx: watch::Sender<Vec<CascadeSource>>,
    /// Kept so `cascade_tx.send` always has a receiver (never errors) even
    /// before the cascade supervisor subscribes; also read by `cascade_now`.
    cascade_keep: watch::Receiver<Vec<CascadeSource>>,
}

impl DistributionControl {
    pub fn new(initial: RuntimeDistConfig, cascade: Vec<CascadeSource>) -> Arc<Self> {
        let (cascade_tx, keep) = watch::channel(cascade);
        Arc::new(Self {
            cfg: ArcSwap::from_pointee(initial),
            cascade_tx,
            cascade_keep: keep,
        })
    }

    /// Current cascade-source list (for persistence to config.json).
    pub fn cascade_now(&self) -> Vec<CascadeSource> {
        self.cascade_keep.borrow().clone()
    }

    /// Current runtime config snapshot (cheap, lock-free).
    pub fn load(&self) -> Arc<RuntimeDistConfig> {
        self.cfg.load_full()
    }

    /// Replace the whole runtime config (manager push).
    pub fn store(&self, cfg: RuntimeDistConfig) {
        self.cfg.store(Arc::new(cfg));
    }

    /// Apply a partial manager update: any `Some` field overrides; `None`
    /// leaves the current value. Booleans are always applied.
    pub fn apply(&self, update: DistUpdate) {
        let cur = self.load();
        let next = RuntimeDistConfig {
            token_secret: update.token_secret.or_else(|| cur.token_secret.clone()),
            require_viewer_token: update.require_viewer_token.unwrap_or(cur.require_viewer_token),
            require_ingest_token: update.require_ingest_token.unwrap_or(cur.require_ingest_token),
            public_ip: update.public_ip.or(cur.public_ip),
            public_base_url: update.public_base_url.or_else(|| cur.public_base_url.clone()),
        };
        self.store(next);
    }

    /// Subscribe to cascade-source changes (the supervisor).
    pub fn subscribe_cascade(&self) -> watch::Receiver<Vec<CascadeSource>> {
        self.cascade_tx.subscribe()
    }

    /// Push a new cascade-source list (manager). The supervisor reconciles.
    pub fn set_cascade(&self, sources: Vec<CascadeSource>) {
        let _ = self.cascade_tx.send(sources);
    }
}

/// A partial runtime update from the manager's `configure_distribution` command.
/// `None` fields are left unchanged; `Some` fields override.
#[derive(Debug, Default, Clone)]
pub struct DistUpdate {
    pub token_secret: Option<String>,
    pub require_viewer_token: Option<bool>,
    pub require_ingest_token: Option<bool>,
    pub public_ip: Option<IpAddr>,
    pub public_base_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RuntimeDistConfig {
        RuntimeDistConfig {
            token_secret: Some("aa".into()),
            require_viewer_token: false,
            require_ingest_token: true,
            public_ip: None,
            public_base_url: None,
        }
    }

    #[test]
    fn apply_overrides_some_leaves_none() {
        let c = DistributionControl::new(base(), vec![]);
        c.apply(DistUpdate {
            token_secret: Some("bb".into()),
            require_viewer_token: Some(true),
            public_base_url: Some("https://r".into()),
            ..Default::default()
        });
        let g = c.load();
        assert_eq!(g.token_secret.as_deref(), Some("bb"));
        assert!(g.require_viewer_token);
        // Untouched fields keep their prior value.
        assert!(g.require_ingest_token);
        assert_eq!(g.public_base_url.as_deref(), Some("https://r"));
    }

    #[tokio::test]
    async fn cascade_changes_are_observable() {
        let c = DistributionControl::new(base(), vec![]);
        let mut rx = c.subscribe_cascade();
        c.set_cascade(vec![CascadeSource {
            upstream_whep_url: "http://x/whep/s".into(),
            local_stream: "s".into(),
            token: None,
        }]);
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().len(), 1);
    }
}
