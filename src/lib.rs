// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! bilbycast-relay library crate.
//!
//! The relay ships as a binary (`main.rs`), but the modules live here in a
//! library target so integration tests (and, later, embedding) can exercise
//! the real code instead of a reimplementation. The binary is a thin shell
//! that wires these modules together at startup.

pub mod api;
pub mod config;
#[cfg(feature = "viewer-distribution")]
pub mod distribution;
/// Runtime distribution config the manager pushes over WS. Always compiled so
/// the (non-feature-gated) manager client can hold a handle.
pub mod distribution_control;
pub mod manager;
pub mod observability;
pub mod protocol;
pub mod server;
pub mod session;
pub mod stats;
pub mod tunnel_router;
pub mod udp_relay;
pub mod util;

/// Build a tokio `TcpListener` with the dual-stack contract: `IPV6_V6ONLY=1`
/// on v6 sockets, `SO_REUSEADDR` on both families, non-blocking for tokio.
/// Shared by the REST API listener and the distribution HTTP listener.
pub fn build_tcp_listener(
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match addr.ip() {
        std::net::IpAddr::V4(_) => Domain::IPV4,
        std::net::IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if matches!(addr.ip(), std::net::IpAddr::V6(_)) {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}
