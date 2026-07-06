// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Elementary-stream frame types carried on the viewer-distribution plane.
//!
//! The edge pre-demuxes and pre-transcodes its flow to **browser-ready**
//! elementary streams — H.264 video (Annex-B access units) + Opus audio
//! (raw Opus frames) — and ships those frames to the relay over the
//! distribution ingest. The relay never decodes, demuxes TS, or transcodes:
//! it only RTP-packetizes and DTLS/SRTP-encrypts per viewer. This keeps the
//! relay free of every C codec dependency (no libavcodec, no fdk-aac) and
//! confines the AAC→Opus / HEVC→H.264 normalization burden to the edge,
//! which already owns that machinery.

use bytes::Bytes;

/// Which elementary stream an [`EsFrame`] carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsKind {
    /// H.264 video, one Annex-B access unit per frame (may contain several
    /// start-code-separated NAL units — SPS/PPS/SEI/slice).
    VideoH264,
    /// Opus audio, one encoded Opus frame per [`EsFrame`].
    AudioOpus,
}

impl EsKind {
    /// Wire discriminant for the ingest framing.
    pub fn as_u8(self) -> u8 {
        match self {
            EsKind::VideoH264 => 1,
            EsKind::AudioOpus => 2,
        }
    }

    /// Decode a wire discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(EsKind::VideoH264),
            2 => Some(EsKind::AudioOpus),
            _ => None,
        }
    }
}

/// A single browser-ready elementary-stream frame.
#[derive(Clone, Debug)]
pub struct EsFrame {
    pub kind: EsKind,
    /// Presentation timestamp in a 90 kHz clock (the flow's TS clock). The
    /// relay converts to 48 kHz for Opus at write time.
    pub pts_90k: u64,
    /// Video: one Annex-B access unit. Audio: one Opus frame.
    pub data: Bytes,
    /// Video only: true when this access unit is an IDR (keyframe). Used to
    /// refresh the per-stream keyframe cache so late joiners decode instantly.
    pub keyframe: bool,
}

impl EsFrame {
    pub fn video(pts_90k: u64, data: Bytes, keyframe: bool) -> Self {
        Self { kind: EsKind::VideoH264, pts_90k, data, keyframe }
    }

    pub fn audio(pts_90k: u64, data: Bytes) -> Self {
        Self { kind: EsKind::AudioOpus, pts_90k, data, keyframe: false }
    }
}

/// Split an Annex-B byte stream into its constituent NAL units (payload
/// only, start codes removed). Handles both 3-byte (`00 00 01`) and 4-byte
/// (`00 00 00 01`) start codes.
///
/// Vendored (pure-Rust, no deps) so the relay never links the edge's TS /
/// codec stack. Mirrors `bilbycast-edge::engine::ts_demux::split_annex_b_nalus`.
pub fn split_annex_b_nalus(data: &[u8]) -> Vec<&[u8]> {
    let mut nalus = Vec::new();
    let n = data.len();

    // Cursor = first payload byte after the first start code.
    let mut cursor = match find_start_code(data, 0) {
        Some((pos, len)) => pos + len,
        None => return nalus,
    };

    while cursor < n {
        match find_start_code(data, cursor) {
            Some((sc_pos, sc_len)) => {
                if sc_pos > cursor {
                    nalus.push(&data[cursor..sc_pos]);
                }
                cursor = sc_pos + sc_len;
            }
            None => {
                nalus.push(&data[cursor..n]);
                break;
            }
        }
    }
    nalus
}

/// Find the next Annex-B start code at or after `from`. Returns
/// `(position, length)` — length 4 when an extra leading `00` is present
/// (`00 00 00 01`), else 3 (`00 00 01`). The trailing-zero ambiguity
/// (a NALU payload that ends in `00` immediately before a 3-byte start
/// code) is resolved toward the 4-byte form; the swallowed `00` is a
/// cabac-zero/stuffing byte and carries no slice semantics.
fn find_start_code(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let n = data.len();
    let mut i = from;
    while i + 2 < n {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            if i > 0 && data[i - 1] == 0 {
                return Some((i - 1, 4));
            }
            return Some((i, 3));
        }
        i += 1;
    }
    None
}

/// H.264 NAL unit type from the first payload byte (start code already
/// stripped). Low 5 bits of the header byte.
pub fn h264_nalu_type(nalu: &[u8]) -> u8 {
    nalu.first().map(|b| b & 0x1f).unwrap_or(0)
}

/// True if the access unit contains an IDR slice (NAL type 5).
pub fn au_is_idr(au: &[u8]) -> bool {
    split_annex_b_nalus(au)
        .iter()
        .any(|n| h264_nalu_type(n) == 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_4byte_start_codes() {
        let data = [0, 0, 0, 1, 0x67, 0xaa, 0, 0, 0, 1, 0x68, 0xbb];
        let nalus = split_annex_b_nalus(&data);
        assert_eq!(nalus.len(), 2);
        assert_eq!(nalus[0], &[0x67, 0xaa]);
        assert_eq!(nalus[1], &[0x68, 0xbb]);
    }

    #[test]
    fn splits_3byte_start_codes() {
        let data = [0, 0, 1, 0x41, 0x01, 0, 0, 1, 0x41, 0x02];
        let nalus = split_annex_b_nalus(&data);
        assert_eq!(nalus.len(), 2);
        assert_eq!(nalus[0], &[0x41, 0x01]);
        assert_eq!(nalus[1], &[0x41, 0x02]);
    }

    #[test]
    fn detects_idr_access_unit() {
        // SPS (7) + PPS (8) + IDR (5)
        let au = [
            0, 0, 0, 1, 0x67, 0x42, //
            0, 0, 0, 1, 0x68, 0xce, //
            0, 0, 0, 1, 0x65, 0x88, //
        ];
        assert!(au_is_idr(&au));
        let non_idr = [0, 0, 0, 1, 0x41, 0x9a];
        assert!(!au_is_idr(&non_idr));
    }

    #[test]
    fn es_kind_roundtrips() {
        for k in [EsKind::VideoH264, EsKind::AudioOpus] {
            assert_eq!(EsKind::from_u8(k.as_u8()), Some(k));
        }
        assert_eq!(EsKind::from_u8(0), None);
    }
}
