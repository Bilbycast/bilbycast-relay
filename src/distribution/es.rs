// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// The H.264 NAL unit types this plane reads (ITU-T H.264 Table 7-1).
const NAL_IDR: u8 = 5;
const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;
const NAL_AUD: u8 = 9;

/// The 4-byte Annex-B start code every rebuilt access unit is framed with —
/// the form str0m's depacketizer emits too.
const START_CODE: [u8; 4] = [0, 0, 0, 1];

/// The NAL units of one H.264 access unit, start codes removed.
///
/// Annex B is split on its start codes. A unit whose first byte is not zero
/// is one **bare** NAL — no NAL header byte is ever zero (that would be the
/// unspecified type 0), so it cannot be the opening of a start code — and is
/// returned whole, where [`split_annex_b_nalus`] would find no NAL in it at
/// all.
pub fn access_unit_nalus(au: &[u8]) -> Vec<&[u8]> {
    match au.first() {
        Some(&b) if b != 0 => vec![au],
        _ => split_annex_b_nalus(au),
    }
}

/// True if the access unit contains an IDR slice (NAL type 5). Takes Annex B
/// or one bare NAL (see [`access_unit_nalus`]).
pub fn au_is_idr(au: &[u8]) -> bool {
    access_unit_nalus(au)
        .iter()
        .any(|n| h264_nalu_type(n) == NAL_IDR)
}

/// The latest SPS and PPS an H.264 stream carried in-band (NAL units, start
/// codes removed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H264ParamSets {
    pub sps: Option<Bytes>,
    pub pps: Option<Bytes>,
}

/// What [`restore_param_sets`] made of one access unit.
#[derive(Debug)]
pub struct RestoredAu {
    /// The unit rebuilt as Annex B with the stream's SPS / PPS put back ahead
    /// of its IDR, or `None` when it goes out exactly as it came.
    pub au: Option<Vec<u8>>,
    /// The unit holds an IDR slice.
    pub idr: bool,
    /// The parameter-set cache refreshed from an SPS / PPS this unit carried
    /// that differs from the cached one; `None` when the cache stands.
    pub param_sets: Option<H264ParamSets>,
}

/// Put a stream's SPS and PPS back ahead of an IDR that does not carry its
/// own, so a decoder can start on any IDR.
///
/// A sender need not repeat its parameter sets with every IDR (only libwebrtc
/// does so reliably; an encoder with global headers sends them once). A WHEP
/// viewer that joined after the IDR that carried them — primed with the
/// cached keyframe, or waiting for the next live one — then has slices it
/// cannot decode, and a browser asks for a keyframe (PLI) forever.
///
/// `cached` is the stream's cache *before* this unit. The unit's own
/// parameter sets always win and refresh the cache (returned, so the caller
/// owns where it lives). Only a missing one is inserted, never a replacement:
/// the SPS ahead of everything but an access unit delimiter, the PPS right
/// after the unit's last SPS (its own, or the one just inserted), so a PPS
/// never precedes the SPS it references.
pub fn restore_param_sets(au: &[u8], cached: &H264ParamSets) -> RestoredAu {
    let nalus = access_unit_nalus(au);
    let (mut idr, mut own_sps, mut own_pps) = (false, None, None);
    for &n in &nalus {
        match h264_nalu_type(n) {
            NAL_IDR => idr = true,
            NAL_SPS => own_sps = Some(n),
            NAL_PPS => own_pps = Some(n),
            _ => {}
        }
    }

    // Copied, not sliced out of the unit: a slice would keep the whole IDR
    // buffer alive for as long as the cache holds it.
    let fresh = |own: Option<&[u8]>, cached: &Option<Bytes>| {
        own.filter(|n| cached.as_deref() != Some(*n))
            .map(Bytes::copy_from_slice)
    };
    let new_sps = fresh(own_sps, &cached.sps);
    let new_pps = fresh(own_pps, &cached.pps);
    let param_sets = (new_sps.is_some() || new_pps.is_some()).then(|| H264ParamSets {
        sps: new_sps.or_else(|| cached.sps.clone()),
        pps: new_pps.or_else(|| cached.pps.clone()),
    });

    let insert_sps = cached.sps.as_deref().filter(|_| idr && own_sps.is_none());
    let insert_pps = cached.pps.as_deref().filter(|_| idr && own_pps.is_none());
    if insert_sps.is_none() && insert_pps.is_none() {
        return RestoredAu { au: None, idr, param_sets };
    }

    // `idr` holds, so there is a non-AUD NAL for `first_body` to find.
    let first_body = nalus
        .iter()
        .position(|n| h264_nalu_type(n) != NAL_AUD)
        .unwrap_or(0);
    let last_sps = nalus.iter().rposition(|n| h264_nalu_type(n) == NAL_SPS);
    let inserted: usize = [insert_sps, insert_pps]
        .iter()
        .flatten()
        .map(|n| n.len() + START_CODE.len())
        .sum();
    let mut out = Vec::with_capacity(au.len() + inserted + START_CODE.len());
    let push = |out: &mut Vec<u8>, nalu: &[u8]| {
        out.extend_from_slice(&START_CODE);
        out.extend_from_slice(nalu);
    };
    for (i, &n) in nalus.iter().enumerate() {
        if i == first_body {
            if let Some(sps) = insert_sps {
                push(&mut out, sps);
            }
            if let (None, Some(pps)) = (last_sps, insert_pps) {
                push(&mut out, pps);
            }
        }
        push(&mut out, n);
        if let (true, Some(pps)) = (last_sps == Some(i), insert_pps) {
            push(&mut out, pps);
        }
    }
    RestoredAu { au: Some(out), idr, param_sets }
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
    fn a_bare_nal_is_one_nal_unit() {
        assert_eq!(access_unit_nalus(&[0x65, 0x88]), vec![&[0x65, 0x88][..]]);
        assert!(au_is_idr(&[0x65, 0x88]));
        assert!(!au_is_idr(&[0x41, 0x9a]));
        assert!(access_unit_nalus(&[]).is_empty());
    }

    /// Annex B with every NAL unit given its own `nal_unit_type` header and
    /// two bytes of body.
    fn unit(types: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for t in types {
            out.extend_from_slice(&[0, 0, 0, 1, 0x60 | t, 0x11, 0x22]);
        }
        out
    }

    fn nal_types(au: &[u8]) -> Vec<u8> {
        split_annex_b_nalus(au).iter().map(|n| h264_nalu_type(n)).collect()
    }

    /// Run `restore_param_sets` the way the hub does: the returned cache
    /// replaces the old one.
    fn restore(au: &[u8], cache: &mut H264ParamSets) -> (Vec<u8>, bool) {
        let r = restore_param_sets(au, cache);
        if let Some(sets) = r.param_sets {
            *cache = sets;
        }
        (r.au.unwrap_or_else(|| au.to_vec()), r.idr)
    }

    /// Every IDR goes out behind an SPS and a PPS — the last ones the stream
    /// sent — whether or not the sender repeated them; a non-IDR gets none,
    /// an access unit delimiter stays first, and a unit carrying its own goes
    /// out exactly as it came.
    #[test]
    fn every_idr_goes_out_behind_the_parameter_sets() {
        let mut cache = H264ParamSets::default();

        // No parameter sets seen yet: nothing to put back.
        let (au, idr) = restore(&unit(&[5]), &mut cache);
        assert!(idr);
        assert_eq!(nal_types(&au), vec![5]);

        let own = unit(&[7, 8, 5]);
        let r = restore_param_sets(&own, &cache);
        assert!(r.au.is_none(), "carried its own: not doubled, not rebuilt");
        let sets = r.param_sets.expect("the cache is refreshed from the unit's own");
        assert_eq!(sets.sps.as_deref(), Some(&[0x67, 0x11, 0x22][..]));
        assert_eq!(sets.pps.as_deref(), Some(&[0x68, 0x11, 0x22][..]));
        cache = sets;
        // The same sets again leave the cache alone (no copy per IDR).
        assert!(restore_param_sets(&own, &cache).param_sets.is_none());

        let (au, idr) = restore(&unit(&[1]), &mut cache);
        assert!(!idr);
        assert_eq!(nal_types(&au), vec![1]);
        let (au, idr) = restore(&unit(&[5]), &mut cache);
        assert!(idr);
        assert_eq!(au, unit(&[7, 8, 5]), "the cached sets go back in");
        let (au, _) = restore(&unit(&[9, 6, 5]), &mut cache);
        assert_eq!(nal_types(&au), vec![9, 7, 8, 6, 5], "after the AUD, ahead of the SEI");
    }

    /// Only the missing one is inserted, and never ahead of the SPS a PPS
    /// references: the PPS goes right after the unit's own SPS, a missing SPS
    /// ahead of the unit's own PPS.
    #[test]
    fn a_missing_parameter_set_goes_in_beside_the_one_present() {
        let mut cache = H264ParamSets::default();
        restore(&unit(&[7, 8, 5]), &mut cache);

        let (au, _) = restore(&unit(&[6, 7, 5]), &mut cache);
        assert_eq!(nal_types(&au), vec![6, 7, 8, 5]);
        let (au, _) = restore(&unit(&[6, 8, 5]), &mut cache);
        assert_eq!(nal_types(&au), vec![7, 6, 8, 5]);
    }

    /// A new SPS from the stream replaces the cached one, and goes ahead of
    /// the next IDR that lacks one.
    #[test]
    fn a_changed_sps_replaces_the_cached_one() {
        let mut cache = H264ParamSets::default();
        restore(&unit(&[7, 8, 5]), &mut cache);
        let new_sps = [0, 0, 0, 1, 0x67, 0x64, 0x00, 0x28];
        let mut au = new_sps.to_vec();
        au.extend_from_slice(&unit(&[8, 5]));
        restore(&au, &mut cache);
        assert_eq!(cache.sps.as_deref(), Some(&new_sps[4..]));
        let (au, _) = restore(&unit(&[5]), &mut cache);
        assert!(au.starts_with(&new_sps));
    }

    /// A bare IDR NAL is framed once when the parameter sets go in.
    #[test]
    fn a_bare_idr_is_framed_behind_the_parameter_sets() {
        let mut cache = H264ParamSets::default();
        restore(&unit(&[7, 8, 5]), &mut cache);
        let (au, idr) = restore(&[0x65, 0x11, 0x22], &mut cache);
        assert!(idr);
        assert_eq!(au, unit(&[7, 8, 5]));
    }

    #[test]
    fn es_kind_roundtrips() {
        for k in [EsKind::VideoH264, EsKind::AudioOpus] {
            assert_eq!(EsKind::from_u8(k.as_u8()), Some(k));
        }
        assert_eq!(EsKind::from_u8(0), None);
    }
}
