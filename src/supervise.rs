// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What happens when an optional subsystem stops.
//!
//! The relay's job is the opaque forwarder: the QUIC server that carries every
//! relayed edge link. The viewer-distribution subsystem and the native-UDP
//! plane are optional beside it, so a failure in either must cost that
//! subsystem and nothing else. Before relay#15 `main` ended the process when
//! either task finished, which took the forwarder down with it — on
//! 2026-09-22 an origin directory left owned by root put a production relay
//! into a 3 s restart loop until systemd's start limit gave up, with no
//! distribution configured on that host at all.
//!
//! So `main` hands each optional task to [`watch_distribution`] /
//! [`supervise_udp_relay`] instead of waiting on it. When the task ends — an
//! error, an unexpected return, or a panic — the watcher logs it, records it
//! on [`RelayStats`] (which withdraws the subsystem's capability from the
//! manager health payload and reports it on `/health`), and raises a Critical
//! event, and the relay carries on.
//!
//! Distribution is not restarted in-process: the origin hands its drop queue
//! over once (`DistributionControl::drop_rx`), so a second run would silently
//! lose drops. Fixing the cause and restarting the service is the recovery.
//! The native-UDP plane holds no such state, and a bind that fails is often
//! transient — an address that comes up after `network-online`, a port still
//! held by the process being replaced — which systemd's restart used to retry
//! when the failure ended the process. So its bind is retried here, backing
//! off from [`UDP_BIND_RETRY_FIRST`] to [`UDP_BIND_RETRY_MAX`]; once it binds
//! the stop is cleared and an Info event says so. A plane that stops after
//! binding (a receive loop panicked) stays stopped.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::config::RelayConfig;
use crate::manager::events::{category, EventSender, EventSeverity};
use crate::session::SessionContext;
use crate::stats::RelayStats;

/// First wait before the native-UDP plane's bind is tried again.
pub const UDP_BIND_RETRY_FIRST: Duration = Duration::from_secs(5);
/// Longest wait between bind attempts.
pub const UDP_BIND_RETRY_MAX: Duration = Duration::from_secs(60);

/// The reason an optional subsystem's task ended, for the operator.
///
/// An `Ok(())` is still a stop — neither subsystem returns while it is
/// serving — so it is reported as one rather than treated as success.
pub async fn exit_reason(handle: JoinHandle<anyhow::Result<()>>) -> String {
    match handle.await {
        Ok(Ok(())) => "the subsystem returned without an error".to_string(),
        Ok(Err(e)) => format!("{e:#}"),
        Err(join) if join.is_panic() => {
            let panic = join.into_panic();
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "a non-string payload".to_string());
            format!("panicked: {msg}")
        }
        Err(_) => "the task was cancelled".to_string(),
    }
}

/// Record that the viewer-distribution subsystem stopped: log, withdraw its
/// telemetry and capabilities, raise a Critical event. The forwarder keeps
/// running.
pub fn distribution_stopped(stats: &RelayStats, events: &EventSender, reason: &str) {
    tracing::error!(
        "viewer-distribution subsystem stopped: {reason} — the relay keeps forwarding \
         QUIC and native-UDP tunnels; viewers, the origin and DVR are down until the \
         cause is fixed and the relay restarted"
    );
    stats.mark_distribution_stopped(reason.to_string());
    events.emit_with_details(
        EventSeverity::Critical,
        category::DISTRIBUTION,
        format!("Viewer-distribution subsystem stopped: {reason}"),
        serde_json::json!({
            "error_code": "relay_distribution_stopped",
            "error": reason,
        }),
    );
}

/// Record that the native-UDP plane stopped: log, withdraw `udp-relay`, raise
/// a Critical event. QUIC forwarding keeps running.
pub fn udp_relay_stopped(stats: &RelayStats, events: &EventSender, reason: &str) {
    tracing::error!(
        "native-UDP relay plane stopped: {reason} — the relay keeps forwarding QUIC \
         tunnels; native SRT/RIST and relayed bond legs are down until the cause is \
         fixed and the relay restarted"
    );
    stats.mark_udp_relay_stopped(reason.to_string());
    events.emit_with_details(
        EventSeverity::Critical,
        category::TUNNEL,
        format!("Native-UDP relay plane stopped: {reason}"),
        serde_json::json!({
            "error_code": "relay_udp_plane_stopped",
            "transport": "udp",
            "error": reason,
        }),
    );
}

/// Watch the viewer-distribution task; see the module docs.
pub fn watch_distribution(
    handle: JoinHandle<anyhow::Result<()>>,
    stats: Arc<RelayStats>,
    events: EventSender,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let reason = exit_reason(handle).await;
        distribution_stopped(&stats, &events, &reason);
    })
}

/// Record that the native-UDP plane bound after it had been down: clear the
/// stop (the `udp-relay` capability comes back), log, raise an Info event.
pub fn udp_relay_recovered(stats: &RelayStats, events: &EventSender, attempts: u32) {
    tracing::info!("native-UDP relay plane bound after {attempts} attempts");
    stats.clear_udp_relay_stopped();
    events.emit_with_details(
        EventSeverity::Info,
        category::TUNNEL,
        "Native-UDP relay plane started after a failed bind",
        serde_json::json!({
            "error_code": "relay_udp_plane_recovered",
            "transport": "udp",
            "attempts": attempts,
        }),
    );
}

/// Run the native-UDP plane under supervision; see the module docs. `bind` is
/// [`crate::udp_relay::bind_udp_relay`] in production, a parameter so the
/// retry can be tested without contending for real ports.
pub fn supervise_udp_relay<B>(
    bind: B,
    config: RelayConfig,
    ctx: Arc<SessionContext>,
    stats: Arc<RelayStats>,
    events: EventSender,
) -> JoinHandle<()>
where
    B: Fn(&RelayConfig) -> anyhow::Result<Vec<Arc<tokio::net::UdpSocket>>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut attempts = 0u32;
        let mut wait = UDP_BIND_RETRY_FIRST;
        let sockets = loop {
            attempts += 1;
            match bind(&config) {
                Ok(sockets) => break sockets,
                Err(e) => {
                    if attempts == 1 {
                        udp_relay_stopped(&stats, &events, &format!("{e:#}"));
                    } else {
                        tracing::debug!("native-UDP relay bind attempt {attempts} failed: {e:#}");
                    }
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(UDP_BIND_RETRY_MAX);
                }
            }
        };
        if attempts > 1 {
            udp_relay_recovered(&stats, &events, attempts);
        }
        let handle = tokio::spawn(crate::udp_relay::serve_udp_relay(sockets, ctx));
        let reason = exit_reason(handle).await;
        udp_relay_stopped(&stats, &events, &reason);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::events::event_channel;

    #[tokio::test]
    async fn an_error_is_reported_with_its_context() {
        let h = tokio::spawn(async {
            Err(anyhow::anyhow!("Permission denied (os error 13)")
                .context("origin storage dir /var/lib/bilbycast/relay/origin"))
        });
        let reason = exit_reason(h).await;
        assert_eq!(
            reason,
            "origin storage dir /var/lib/bilbycast/relay/origin: Permission denied (os error 13)"
        );
    }

    #[tokio::test]
    async fn a_panic_is_reported_not_propagated() {
        let h: JoinHandle<anyhow::Result<()>> = tokio::spawn(async { panic!("boom") });
        assert_eq!(exit_reason(h).await, "panicked: boom");
        let h: JoinHandle<anyhow::Result<()>> =
            tokio::spawn(async { panic!("{}", String::from("formatted boom")) });
        assert_eq!(exit_reason(h).await, "panicked: formatted boom");
    }

    #[tokio::test]
    async fn a_clean_return_is_still_a_stop() {
        let h = tokio::spawn(async { Ok(()) });
        assert_eq!(exit_reason(h).await, "the subsystem returned without an error");
    }

    #[tokio::test]
    async fn a_stopped_distribution_withdraws_its_telemetry_and_raises_critical() {
        let stats = Arc::new(RelayStats::new());
        let (events, mut rx) = event_channel();
        stats.set_distribution(1, 2, 3, 4, 0, Vec::new());
        assert!(stats.distribution_snapshot().is_some());

        let h = tokio::spawn(async { Err(anyhow::anyhow!("bind failed")) });
        watch_distribution(h, stats.clone(), events).await.unwrap();

        assert!(stats.distribution_snapshot().is_none());
        assert_eq!(stats.distribution_stopped().as_deref().map(String::as_str), Some("bind failed"));
        // A telemetry tick that was already past its own check when the stop
        // landed must not bring the subsystem back.
        stats.set_distribution(1, 2, 3, 4, 0, Vec::new());
        assert!(stats.distribution_snapshot().is_none());

        let ev = rx.try_recv().expect("a Critical event");
        assert_eq!(ev.severity, EventSeverity::Critical);
        assert_eq!(ev.category, category::DISTRIBUTION);
        let details = ev.details.expect("details");
        assert_eq!(details["error_code"], "relay_distribution_stopped");
        assert_eq!(details["error"], "bind failed");
    }

    fn context(stats: &Arc<RelayStats>, events: &EventSender) -> Arc<SessionContext> {
        crate::server::create_session_context(stats.clone(), events.clone(), false, 64, 100)
    }

    /// A bind that fails stops the plane once, loudly; the retry that
    /// succeeds clears it and says so. Before relay#15 the failure ended the
    /// process and systemd's restart was the retry.
    #[tokio::test(start_paused = true)]
    async fn a_failed_bind_is_retried_and_its_recovery_reported() {
        let stats = Arc::new(RelayStats::new());
        let (events, mut rx) = event_channel();
        let tries = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t = tries.clone();
        let bind = move |_: &RelayConfig| {
            if t.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 2 {
                anyhow::bail!("native-UDP relay: no listener could be bound")
            }
            let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
            sock.set_nonblocking(true)?;
            Ok(vec![Arc::new(tokio::net::UdpSocket::from_std(sock)?)])
        };
        let ctx = context(&stats, &events);
        let task = supervise_udp_relay(bind, RelayConfig::default(), ctx, stats.clone(), events);

        tokio::task::yield_now().await;
        assert_eq!(
            stats.udp_relay_stopped().as_deref().map(String::as_str),
            Some("native-UDP relay: no listener could be bound")
        );
        let ev = rx.try_recv().expect("a Critical event for the failed bind");
        assert_eq!(ev.severity, EventSeverity::Critical);
        assert_eq!(ev.category, category::TUNNEL);
        assert_eq!(ev.details.unwrap()["error_code"], "relay_udp_plane_stopped");

        // The second failure is quiet; the third attempt binds.
        tokio::time::advance(UDP_BIND_RETRY_FIRST).await;
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err(), "one Critical per outage, not per attempt");
        tokio::time::advance(UDP_BIND_RETRY_FIRST * 2).await;
        tokio::task::yield_now().await;

        assert!(stats.udp_relay_stopped().is_none(), "a plane that bound is running");
        let ev = rx.try_recv().expect("an Info event for the recovery");
        assert_eq!(ev.severity, EventSeverity::Info);
        let d = ev.details.unwrap();
        assert_eq!(d["error_code"], "relay_udp_plane_recovered");
        assert_eq!(d["attempts"], 3);
        assert_eq!(tries.load(std::sync::atomic::Ordering::Relaxed), 3);
        task.abort();
    }

    #[tokio::test]
    async fn a_plane_that_binds_first_time_raises_nothing() {
        let stats = Arc::new(RelayStats::new());
        let (events, mut rx) = event_channel();
        let bind = |_: &RelayConfig| {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
            sock.set_nonblocking(true)?;
            Ok(vec![Arc::new(tokio::net::UdpSocket::from_std(sock)?)])
        };
        let ctx = context(&stats, &events);
        let task = supervise_udp_relay(bind, RelayConfig::default(), ctx, stats.clone(), events);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(stats.udp_relay_stopped().is_none());
        assert!(rx.try_recv().is_err());
        task.abort();
    }
}
