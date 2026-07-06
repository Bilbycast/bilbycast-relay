// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! RFC 6184 H.264 RTP packetizer.
//!
//! VENDORED verbatim from `bilbycast-edge::engine::webrtc::rtp_h264` (pure
//! Rust, no deps). Keep in sync with the edge; both must fragment H.264 the
//! same way for the SFU to interoperate with the edge encoder's output.
//!
//! Converts H.264 NAL units into RTP payloads suitable for WebRTC transport.
//! Supports Single NAL Unit mode (small NALUs) and FU-A fragmentation
//! (large NALUs exceeding the MTU).

/// Maximum RTP payload size for WebRTC (accounting for SRTP overhead).
const MAX_PAYLOAD_SIZE: usize = 1200;

/// FU-A indicator byte: F=0, NRI from NALU, Type=28 (FU-A)
const FU_A_TYPE: u8 = 28;

/// A single RTP payload produced by the packetizer.
pub struct RtpPayload {
    /// RTP payload data (ready to be sent via str0m).
    pub data: Vec<u8>,
    /// Whether this is the last packet of the current access unit (frame).
    /// Set the RTP marker bit on this packet.
    #[allow(dead_code)]
    pub marker: bool,
}

/// H.264 RTP packetizer per RFC 6184.
pub struct H264Packetizer;

impl H264Packetizer {
    /// Packetize a single H.264 NAL unit into one or more RTP payloads.
    ///
    /// - NALUs ≤ `MAX_PAYLOAD_SIZE` are sent as Single NAL Unit packets.
    /// - Larger NALUs are fragmented using FU-A (Fragmentation Unit type A).
    ///
    /// `last_nalu_of_frame` should be true for the last NALU of an access
    /// unit (frame boundary), which sets the RTP marker bit.
    pub fn packetize(nalu: &[u8], last_nalu_of_frame: bool) -> Vec<RtpPayload> {
        if nalu.is_empty() {
            return Vec::new();
        }

        if nalu.len() <= MAX_PAYLOAD_SIZE {
            vec![RtpPayload {
                data: nalu.to_vec(),
                marker: last_nalu_of_frame,
            }]
        } else {
            Self::fragment_fu_a(nalu, last_nalu_of_frame)
        }
    }

    /// Fragment a large NALU using FU-A (Fragmentation Unit type A).
    fn fragment_fu_a(nalu: &[u8], last_nalu_of_frame: bool) -> Vec<RtpPayload> {
        let nalu_header = nalu[0];
        let nri = nalu_header & 0x60;
        let nalu_type = nalu_header & 0x1F;

        let fu_indicator = (nalu_header & 0x80) | nri | FU_A_TYPE;

        let body = &nalu[1..];
        let max_fragment = MAX_PAYLOAD_SIZE - 2;

        let mut payloads = Vec::new();
        let mut offset = 0;

        while offset < body.len() {
            let remaining = body.len() - offset;
            let fragment_size = remaining.min(max_fragment);
            let is_first = offset == 0;
            let is_last = offset + fragment_size >= body.len();

            let fu_header = if is_first {
                0x80 | nalu_type
            } else if is_last {
                0x40 | nalu_type
            } else {
                nalu_type
            };

            let mut data = Vec::with_capacity(2 + fragment_size);
            data.push(fu_indicator);
            data.push(fu_header);
            data.extend_from_slice(&body[offset..offset + fragment_size]);

            payloads.push(RtpPayload {
                data,
                marker: is_last && last_nalu_of_frame,
            });

            offset += fragment_size;
        }

        payloads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_nalu_single_packet() {
        let nalu = vec![0x65, 0x01, 0x02, 0x03];
        let packets = H264Packetizer::packetize(&nalu, true);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, nalu);
        assert!(packets[0].marker);
    }

    #[test]
    fn test_large_nalu_fu_a_fragmentation() {
        let mut nalu = vec![0x65];
        nalu.extend(vec![0xAB; MAX_PAYLOAD_SIZE + 500]);

        let packets = H264Packetizer::packetize(&nalu, true);
        assert!(packets.len() >= 2);

        let fu_indicator = packets[0].data[0];
        let fu_header = packets[0].data[1];
        assert_eq!(fu_indicator & 0x1F, FU_A_TYPE);
        assert_eq!(fu_indicator & 0x60, 0x60);
        assert!(fu_header & 0x80 != 0);
        assert!(fu_header & 0x40 == 0);
        assert_eq!(fu_header & 0x1F, 5);
        assert!(!packets[0].marker);

        let last = &packets[packets.len() - 1];
        let fu_header_last = last.data[1];
        assert!(fu_header_last & 0x80 == 0);
        assert!(fu_header_last & 0x40 != 0);
        assert!(last.marker);

        let mut reassembled = vec![nalu[0]];
        for pkt in &packets {
            reassembled.extend_from_slice(&pkt.data[2..]);
        }
        assert_eq!(reassembled, nalu);
    }

    #[test]
    fn test_marker_only_on_last_nalu() {
        let nalu = vec![0x41, 0x01, 0x02];
        let packets = H264Packetizer::packetize(&nalu, false);
        assert_eq!(packets.len(), 1);
        assert!(!packets[0].marker);
    }

    #[test]
    fn test_empty_nalu() {
        let packets = H264Packetizer::packetize(&[], true);
        assert!(packets.is_empty());
    }
}
