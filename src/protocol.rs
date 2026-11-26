// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control protocol messages exchanged on QUIC control streams.
//!
//! This module defines messages for two connection modes:
//! - **Relay mode**: Edge ↔ Relay (EdgeMessage / RelayMessage)
//! - **Direct mode**: Edge ↔ Edge peer-to-peer (PeerMessage)
//!
//! The data plane (StreamHeader, UDP datagrams) is identical in both modes.
//! Messages are length-prefixed: 4-byte big-endian length + JSON payload.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Protocol version ──

/// Current tunnel protocol version. Bump when adding new message types or changing semantics.
///
/// v2 (2026-06): adds the plain-UDP relay data plane (native SRT/RIST over relay
/// without QUIC) — see [`UdpRelayControl`] and [`encode_udp_control`].
pub const TUNNEL_PROTOCOL_VERSION: u32 = 2;

// ── ALPN protocol identifiers ──

/// ALPN protocol for edge-to-relay connections.
pub const ALPN_RELAY: &[u8] = b"bilbycast-relay";

/// ALPN protocol for direct edge-to-edge connections.
/// Used by bilbycast-edge when two edges connect without a relay.
#[allow(dead_code)]
pub const ALPN_DIRECT: &[u8] = b"bilbycast-direct";

/// Messages sent from edge to relay on the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EdgeMessage {
    /// Bind a tunnel endpoint on this edge.
    #[serde(rename = "tunnel_bind")]
    TunnelBind {
        tunnel_id: Uuid,
        direction: TunnelDirection,
        protocol: TunnelProtocol,
        /// HMAC-SHA256 bind token for tunnel authentication (optional, for backwards compat).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bind_token: Option<String>,
    },

    /// Unbind a tunnel.
    #[serde(rename = "tunnel_unbind")]
    TunnelUnbind { tunnel_id: Uuid },

    /// Identify this edge with a stable ID (e.g., manager node_id).
    /// Should be sent before any TunnelBind. Optional — relay falls back to connection_id.
    #[serde(rename = "identify")]
    Identify { edge_id: String },

    /// Keepalive ping.
    #[serde(rename = "ping")]
    Ping,

    /// Protocol version handshake (sent as the first message on the control stream).
    /// Old relays (with resilient deserialization) will ignore this; new relays respond with HelloAck.
    #[serde(rename = "hello")]
    Hello {
        protocol_version: u32,
        software_version: String,
    },
}

/// Messages sent from relay to edge on the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    /// Tunnel is ready (both sides have bound).
    #[serde(rename = "tunnel_ready")]
    TunnelReady { tunnel_id: Uuid },

    /// Tunnel is waiting for the peer to bind.
    #[serde(rename = "tunnel_waiting")]
    TunnelWaiting { tunnel_id: Uuid },

    /// On the control stream: the bind this answers was refused. On a stream
    /// of its own: the other side is gone ([`PEER_DISCONNECTED`],
    /// [`PEER_UNBOUND`]), or with any other reason the side of the edge this is
    /// sent to was removed, and takes a bind to hold again.
    #[serde(rename = "tunnel_down")]
    TunnelDown { tunnel_id: Uuid, reason: String },

    /// Keepalive pong.
    #[serde(rename = "pong")]
    Pong,

    /// Protocol version handshake response.
    /// Sent in reply to an edge's Hello message. Contains the relay's protocol version
    /// so the edge can detect mismatches and log warnings.
    #[serde(rename = "hello_ack")]
    HelloAck {
        protocol_version: u32,
        software_version: String,
    },
}

/// The reasons of a [`RelayMessage::TunnelDown`] that is about the other side of
/// the tunnel. The edge it is sent to still holds its own. Edges tell the two
/// apart by these, so they stay as every release has them.
pub const PEER_DISCONNECTED: &str = "peer disconnected";
/// See [`PEER_DISCONNECTED`].
pub const PEER_UNBOUND: &str = "peer unbound";

/// Direction of this edge's role in the tunnel.
///
/// This is the *edge/relay-internal* perspective, which is the OPPOSITE of the
/// bilbycast-manager UI's "ingress/egress" naming. At the manager level an
/// "ingress node" is the media *source*; that source edge binds here as
/// [`TunnelDirection::Egress`] (it captures local traffic and sends INTO the
/// tunnel). See `bilbycast-manager .../api/tunnels.rs::build_edge_configs` and
/// `bilbycast-edge/src/tunnel/udp_forwarder.rs` (`run_egress` = sender,
/// `run_ingress` = receiver). The relay itself is direction-agnostic — it just
/// forwards between the two bound endpoints — so these labels are purely the
/// slot names used for pairing and reporting (`ingress_edge_id` is the
/// receiver edge, `egress_edge_id` is the source edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelDirection {
    /// Ingress (destination side): relay → this edge → local device. This edge
    /// RECEIVES tunnel traffic and forwards it to a local consumer.
    #[serde(rename = "ingress")]
    Ingress,
    /// Egress (source side): local device → this edge → relay. This edge
    /// captures local traffic on its listen port and SENDS it INTO the tunnel.
    #[serde(rename = "egress")]
    Egress,
}

/// Transport protocol for the tunneled data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelProtocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

// ── Direct mode (edge-to-edge) control messages ──

/// Messages exchanged on the control stream of a direct edge-to-edge QUIC connection.
///
/// In direct mode, two edges connect without a relay. One edge acts as a QUIC
/// server (DirectListen) and the other as a client (DirectConnect). Authentication
/// uses the same HMAC-SHA256 scheme as relay auth, but keyed with a per-tunnel PSK:
/// `token = generate_token(tunnel_id, psk)`.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PeerMessage {
    /// Authenticate with a pre-shared key.
    /// The token is `base64(tunnel_id:hmac_sha256(tunnel_id, psk))`.
    #[serde(rename = "peer_auth")]
    PeerAuth { tunnel_id: Uuid, token: String },

    /// Authentication succeeded, tunnel is ready for data.
    #[serde(rename = "peer_auth_ok")]
    PeerAuthOk { tunnel_id: Uuid },

    /// Authentication failed.
    #[serde(rename = "peer_auth_error")]
    PeerAuthError { reason: String },

    /// Keepalive ping.
    #[serde(rename = "ping")]
    Ping,

    /// Keepalive pong.
    #[serde(rename = "pong")]
    Pong,
}

// ── Data plane (shared between relay and direct modes) ──

/// Header sent at the start of each data QUIC stream (not the control stream).
/// Used to identify which tunnel this stream belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHeader {
    pub tunnel_id: Uuid,
    pub stream_type: StreamType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamType {
    /// A proxied TCP connection.
    #[serde(rename = "tcp")]
    Tcp,
}

// ── Wire format helpers ──

/// Maximum control message size (1 MB).
const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Result of resilient message parsing: either a known typed message or an
/// unknown type that was gracefully skipped (instead of tearing down the connection).
#[derive(Debug, Clone)]
pub enum ParsedMessage<T> {
    /// Successfully deserialized into the expected type.
    Known(T),
    /// The message had an unrecognized "type" tag. The connection stays alive.
    Unknown { msg_type: String },
}

/// Read a length-prefixed JSON message from a QUIC stream.
pub async fn read_message<T: serde::de::DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("message too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Read a length-prefixed JSON message, gracefully handling unknown "type" variants.
///
/// If the message has a "type" tag that doesn't match any known variant of `T`,
/// returns `ParsedMessage::Unknown` instead of an error. This prevents unknown
/// message types (e.g., from a newer protocol version) from tearing down the
/// entire QUIC connection.
pub async fn read_message_resilient<T: serde::de::DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<ParsedMessage<T>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("message too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;

    match serde_json::from_slice::<T>(&buf) {
        Ok(msg) => Ok(ParsedMessage::Known(msg)),
        Err(_) => {
            let msg_type = serde_json::from_slice::<serde_json::Value>(&buf)
                .ok()
                .and_then(|v| v.get("type")?.as_str().map(String::from))
                .unwrap_or_else(|| "unknown".into());
            Ok(ParsedMessage::Unknown { msg_type })
        }
    }
}

/// Write a length-prefixed JSON message to a QUIC stream.
pub async fn write_message<T: Serialize>(
    send: &mut quinn::SendStream,
    msg: &T,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&json).await?;
    Ok(())
}

/// Read a stream header from a newly opened data stream.
pub async fn read_stream_header(recv: &mut quinn::RecvStream) -> anyhow::Result<StreamHeader> {
    read_message(recv).await
}

/// Write a stream header to a newly opened data stream.
pub async fn write_stream_header(
    send: &mut quinn::SendStream,
    header: &StreamHeader,
) -> anyhow::Result<()> {
    write_message(send, header).await
}

/// UDP datagram prefix: 16-byte UUID (binary) prepended to each QUIC datagram.
pub const UDP_DATAGRAM_PREFIX_LEN: usize = 16;

/// Encode a UDP datagram with tunnel_id prefix.
/// Used by edge clients to construct datagrams for sending to the relay.
#[allow(dead_code)]
pub fn encode_udp_datagram(tunnel_id: &Uuid, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(UDP_DATAGRAM_PREFIX_LEN + payload.len());
    buf.extend_from_slice(tunnel_id.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a UDP datagram: extract tunnel_id and payload.
pub fn decode_udp_datagram(data: &[u8]) -> Option<(Uuid, &[u8])> {
    if data.len() < UDP_DATAGRAM_PREFIX_LEN {
        return None;
    }
    let id = Uuid::from_bytes(data[..16].try_into().ok()?);
    Some((id, &data[16..]))
}

// ── Plain-UDP relay data plane (native SRT/RIST over relay, no QUIC) ──
//
// The native path reuses the exact `[16-byte tunnel_id][AEAD payload]` data framing
// above. It rides plain UDP datagrams to the relay's UDP listener instead of QUIC
// datagrams; the relay forwards the datagram verbatim to the paired peer (the edge
// forwarders add/strip the prefix + AEAD — the relay stays opaque).
//
// A small control plane is multiplexed onto the SAME UDP socket using the **all-zero
// (nil) UUID** as a reserved sentinel prefix: a datagram whose 16-byte prefix is nil
// carries a JSON [`UdpRelayControl`] message rather than media. Real tunnel IDs are
// random v4 UUIDs (validation rejects nil), so there is no collision.
//
// This must match `bilbycast-edge/src/tunnel/protocol.rs`.

/// Control messages for the plain-UDP relay data plane.
///
/// Every field after the first four of each variant is optional on the wire
/// (`serde(default)`, and left out when `None`), so each side reads the other's
/// older shape: an edge up to v0.117.0 sends neither `seq` nor `standby`, and a
/// relay up to v0.20.0 answers with `tunnel_id` and `ready` alone. Neither
/// crate denies unknown keys. An `Ack` carrying `peer_live` is how an edge
/// tells a relay that reports liveness from one that does not, so
/// [`TUNNEL_PROTOCOL_VERSION`] stays 2: no type is new and no field changes
/// its meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UdpRelayControl {
    /// edge → relay: register/keepalive this endpoint's `(tunnel_id, direction)` and
    /// prove authorization. Re-sent periodically so the relay learns and maintains this
    /// edge's post-NAT source address (rendezvous) and the edge can detect a dead relay
    /// (no [`UdpRelayControl::Ack`] → failover).
    #[serde(rename = "register")]
    Register {
        tunnel_id: Uuid,
        direction: TunnelDirection,
        /// HMAC-SHA256 bind token (verified against the manager-pushed expected token).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bind_token: Option<String>,
        #[serde(default)]
        protocol_version: u32,
        /// A per-socket counter, starting at a random value and going up by one
        /// per `Register`. The relay echoes it in the `Ack`'s `seq`, so the edge
        /// can match an `Ack` to the `Register` it answers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<u32>,
        /// `true` when the sending socket is not the edge's active one: the edge
        /// stands by on this relay while its media goes through the tunnel's
        /// other relay. A pair standing by on both sides is not counted active.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        standby: Option<bool>,
    },

    /// relay → edge: acknowledge a [`UdpRelayControl::Register`] and report whether both
    /// sides of the tunnel are now registered (media may flow).
    #[serde(rename = "ack")]
    Ack {
        tunnel_id: Uuid,
        /// Both slots of the tunnel hold an address. Unchanged in meaning: a
        /// slot that has gone quiet still counts until the relay clears it.
        ready: bool,
        /// The opposite slot was heard in the last 16 s (monotonic): a
        /// `Register` from it was accepted, or media was forwarded from its
        /// latched address. Present only from a relay after v0.20.0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_live: Option<bool>,
        /// How long both slots have been heard without a break, as observed
        /// at `Register`s. `0` whenever `peer_live` is `false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        live_ms: Option<u64>,
        /// 32 lowercase hex characters, one value per relay process, so an
        /// edge can tell two addresses of one relay from two relays, and a
        /// restarted relay from the one before it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_id: Option<String>,
        /// The `seq` of the `Register` this answers, when it carried one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<u32>,
    },
}

/// Encode a [`UdpRelayControl`] message as a control datagram: nil-UUID prefix + JSON.
pub fn encode_udp_control(msg: &UdpRelayControl) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut buf = Vec::with_capacity(UDP_DATAGRAM_PREFIX_LEN + json.len());
    buf.extend_from_slice(Uuid::nil().as_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// If `data` is a control datagram (nil-UUID prefix), decode the [`UdpRelayControl`].
///
/// Returns `None` for media datagrams (real tunnel UUID prefix) or malformed input.
pub fn try_decode_udp_control(data: &[u8]) -> Option<UdpRelayControl> {
    let (id, payload) = decode_udp_datagram(data)?;
    if !id.is_nil() {
        return None;
    }
    serde_json::from_slice::<UdpRelayControl>(payload).ok()
}

#[cfg(test)]
mod udp_control_tests {
    //! The native plane's control datagrams, old and new shapes. The edge
    //! (`bilbycast-edge/src/tunnel/protocol.rs`) has the same tests.
    use super::*;

    const TUNNEL: &str = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";

    fn tunnel() -> Uuid {
        TUNNEL.parse().unwrap()
    }

    fn decode(json: &str) -> UdpRelayControl {
        let mut datagram = Uuid::nil().as_bytes().to_vec();
        datagram.extend_from_slice(json.as_bytes());
        try_decode_udp_control(&datagram).unwrap_or_else(|| panic!("{json} must decode"))
    }

    fn round_trip(msg: &UdpRelayControl) -> UdpRelayControl {
        try_decode_udp_control(&encode_udp_control(msg).unwrap()).unwrap()
    }

    #[test]
    fn every_new_native_control_field_round_trips() {
        let register = UdpRelayControl::Register {
            tunnel_id: tunnel(),
            direction: TunnelDirection::Ingress,
            bind_token: Some("ab".repeat(32)),
            protocol_version: TUNNEL_PROTOCOL_VERSION,
            seq: Some(u32::MAX),
            standby: Some(true),
        };
        assert_eq!(round_trip(&register), register);
        let ack = UdpRelayControl::Ack {
            tunnel_id: tunnel(),
            ready: true,
            peer_live: Some(false),
            live_ms: Some(604_800_000),
            relay_id: Some("0123456789abcdef0123456789abcdef".into()),
            seq: Some(7),
        };
        assert_eq!(round_trip(&ack), ack);
    }

    #[test]
    fn the_old_native_control_shapes_decode_with_every_new_field_none() {
        assert_eq!(
            decode(&format!(r#"{{"type":"ack","tunnel_id":"{TUNNEL}","ready":true}}"#)),
            UdpRelayControl::Ack {
                tunnel_id: tunnel(),
                ready: true,
                peer_live: None,
                live_ms: None,
                relay_id: None,
                seq: None,
            }
        );
        assert_eq!(
            decode(&format!(
                r#"{{"type":"register","tunnel_id":"{TUNNEL}","direction":"egress","bind_token":"cd","protocol_version":2}}"#
            )),
            UdpRelayControl::Register {
                tunnel_id: tunnel(),
                direction: TunnelDirection::Egress,
                bind_token: Some("cd".into()),
                protocol_version: 2,
                seq: None,
                standby: None,
            }
        );
    }

    #[test]
    fn a_new_native_control_shape_with_an_unknown_key_still_decodes() {
        let ack = decode(&format!(
            r#"{{"type":"ack","tunnel_id":"{TUNNEL}","ready":false,"peer_live":true,"live_ms":42,"relay_id":"ff","seq":3,"later":{{"x":1}}}}"#
        ));
        assert_eq!(
            ack,
            UdpRelayControl::Ack {
                tunnel_id: tunnel(),
                ready: false,
                peer_live: Some(true),
                live_ms: Some(42),
                relay_id: Some("ff".into()),
                seq: Some(3),
            }
        );
        let register = decode(&format!(
            r#"{{"type":"register","tunnel_id":"{TUNNEL}","direction":"ingress","seq":9,"standby":false,"later":null}}"#
        ));
        assert!(matches!(
            register,
            UdpRelayControl::Register { seq: Some(9), standby: Some(false), bind_token: None, protocol_version: 0, .. }
        ));
    }

    /// A field left `None` is not on the wire, so an `Ack` without the new
    /// fields is byte for byte what a relay up to v0.20.0 sends.
    #[test]
    fn a_field_left_none_is_not_on_the_wire() {
        let ack = UdpRelayControl::Ack {
            tunnel_id: tunnel(),
            ready: true,
            peer_live: None,
            live_ms: None,
            relay_id: None,
            seq: None,
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert_eq!(json, format!(r#"{{"type":"ack","tunnel_id":"{TUNNEL}","ready":true}}"#));
        let register = UdpRelayControl::Register {
            tunnel_id: tunnel(),
            direction: TunnelDirection::Ingress,
            bind_token: None,
            protocol_version: 2,
            seq: None,
            standby: None,
        };
        let json = serde_json::to_string(&register).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"type":"register","tunnel_id":"{TUNNEL}","direction":"ingress","protocol_version":2}}"#)
        );
    }
}
