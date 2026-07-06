// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Cascade: a downstream (regional) relay pulls a stream from an upstream
//! relay's WHEP and re-fans-it-out to its own viewers.
//!
//! This is how the WHEP tier scales past one relay's ~hundreds–low-thousands
//! viewer ceiling: an origin relay feeds N regional relays, each serving
//! nearby viewers. The downstream relay is "just another viewer" of the
//! upstream (a WHEP **client**) that republishes into its local
//! [`DistributionHub`] — so its own viewers, LL-HLS origin, keyframe cache,
//! etc. all work unchanged.
//!
//! The media receive path is shared with WHIP ingest
//! ([`super::whip_ingest::republish_from_session`]) — both terminate a WebRTC
//! session and republish its media to the hub. Only the signalling differs:
//! WHIP ingest is a server (`accept_offer`); cascade is a client
//! (`create_offer` + POST to the upstream's WHEP endpoint).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use std::collections::HashMap;

use crate::config::CascadeSource;
use crate::distribution_control::DistributionControl;

use super::hub::DistributionHub;
use super::webrtc::session::{SessionConfig, SessionEvent, WebrtcSession};
use super::whip_ingest::republish_from_session;

/// Supervise the set of cascade pulls, reconciling running WHEP-client tasks
/// against the (manager-updatable) source list on every change. Keyed by
/// `local_stream`; a source whose URL/token changed is cancelled + respawned.
pub async fn run_cascade_supervisor(
    hub: Arc<DistributionHub>,
    control: Arc<DistributionControl>,
    cancel: CancellationToken,
) {
    let mut rx = control.subscribe_cascade();
    // local_stream -> (source, its cancel token)
    let mut running: HashMap<String, (CascadeSource, CancellationToken)> = HashMap::new();

    loop {
        let sources = rx.borrow_and_update().clone();
        reconcile_cascade(&hub, &control, &cancel, &mut running, sources);
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = rx.changed() => {
                if changed.is_err() { break; } // control dropped
            }
        }
    }
    for (_, (_, c)) in running.drain() {
        c.cancel();
    }
}

fn reconcile_cascade(
    hub: &Arc<DistributionHub>,
    control: &Arc<DistributionControl>,
    parent_cancel: &CancellationToken,
    running: &mut HashMap<String, (CascadeSource, CancellationToken)>,
    sources: Vec<CascadeSource>,
) {
    let desired: HashMap<String, CascadeSource> = sources
        .into_iter()
        .map(|s| (s.local_stream.clone(), s))
        .collect();

    // Cancel pulls that were removed or whose source changed.
    running.retain(|k, (src, c)| match desired.get(k) {
        Some(new) if new == src => true,
        _ => {
            c.cancel();
            false
        }
    });

    // Spawn pulls that are new (or changed and just cancelled above).
    for (k, src) in desired {
        if running.contains_key(&k) {
            continue;
        }
        let child = parent_cancel.child_token();
        running.insert(k, (src.clone(), child.clone()));
        let hub = hub.clone();
        let public_ip = control.load().public_ip;
        tokio::spawn(async move {
            run_cascade(hub, src, public_ip, child).await;
        });
    }
}

/// Run one cascade pull, reconnecting on failure until cancelled. The upstream
/// stream may not exist yet (its edge not connected) — we keep retrying.
pub async fn run_cascade(
    hub: Arc<DistributionHub>,
    source: CascadeSource,
    public_ip: Option<IpAddr>,
    cancel: CancellationToken,
) {
    tracing::info!(
        "cascade: pulling '{}' from {} -> local stream '{}'",
        source.local_stream,
        source.upstream_whep_url,
        source.local_stream
    );
    loop {
        if cancel.is_cancelled() {
            break;
        }
        match cascade_attempt(&hub, &source, public_ip, &cancel).await {
            Ok(()) => tracing::info!(
                "cascade '{}': upstream closed; will reconnect",
                source.local_stream
            ),
            Err(e) => tracing::warn!("cascade '{}': {e:#}; will retry", source.local_stream),
        }
        // Backoff before reconnecting.
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
        }
    }
    tracing::info!("cascade '{}' stopped", source.local_stream);
}

async fn cascade_attempt(
    hub: &DistributionHub,
    source: &CascadeSource,
    public_ip: Option<IpAddr>,
    cancel: &CancellationToken,
) -> Result<()> {
    let bind_addr = match public_ip {
        Some(ip) => SocketAddr::new(ip, 0),
        None => "0.0.0.0:0".parse().unwrap(),
    };
    // Client role (NOT ice-lite): we build the offer.
    let cfg = SessionConfig { bind_addr, public_ip, ice_lite: false };
    let mut client = WebrtcSession::new(&cfg).await.context("create cascade session")?;

    // Recvonly video + audio.
    let (offer, pending) = client
        .create_offer(true, true, false)
        .context("create cascade offer")?;

    let answer = whep_post(&source.upstream_whep_url, source.token.as_deref(), &offer)
        .await
        .context("upstream WHEP exchange")?;

    client
        .apply_answer(&answer, pending)
        .context("apply upstream WHEP answer")?;

    // Drive ICE + DTLS to Connected.
    loop {
        match client.poll_event(cancel).await {
            SessionEvent::Connected => break,
            SessionEvent::Disconnected => return Ok(()),
            _ => {}
        }
    }
    tracing::info!("cascade '{}': connected to upstream", source.local_stream);
    hub.register(&source.local_stream);

    republish_from_session(client, hub, &source.local_stream, cancel).await;

    hub.remove(&source.local_stream);
    Ok(())
}

/// Minimal HTTP/1.1 WHEP POST: send the SDP offer, return the SDP answer.
///
/// Relay-to-relay cascade signalling uses plain `http://` on a trusted network
/// in v1 (the upstream relay's distribution HTTP listener). `https://` upstreams
/// are rejected here — front them at the LB, or use the internal http address.
pub(crate) async fn whep_post(url: &str, token: Option<&str>, offer: &str) -> Result<String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("cascade upstream must be http:// (got {url})"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };

    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/sdp\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        offer.len()
    );
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(offer);

    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("connect timed out")?
    .context("connect upstream")?;

    stream.write_all(req.as_bytes()).await.context("write request")?;

    let mut buf = Vec::with_capacity(4096);
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .context("read timed out")?
        .context("read response")?;

    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed WHEP response"))?;
    let status_line = head.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        bail!("upstream WHEP returned {code}: {}", body.trim());
    }
    if body.trim().is_empty() {
        bail!("upstream WHEP returned an empty answer");
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whep_post_rejects_non_http() {
        // Only checks the URL guard; no network.
        let fut = whep_post("https://x/whep/s", None, "v=0");
        let res = futures_block(fut);
        assert!(res.is_err());
    }

    // Tiny blocking helper so the guard test needs no tokio runtime.
    fn futures_block<F: std::future::Future>(f: F) -> F::Output {
        // The URL guard returns before any await point, so a no-op waker
        // poll is enough to drive it to completion.
        use std::task::{Context, Poll};
        let mut f = Box::pin(f);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("guard should resolve synchronously"),
        }
    }

    fn noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }
}
