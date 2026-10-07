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

/// The largest elementary frame the distribution plane takes from any ingest
/// (a generous 4 MiB — a 4K IDR access unit is well under this): a frame on
/// the QUIC ES ingest ([`super::ingest`]), and an access unit a WHIP
/// publisher or cascade upstream builds out of RTP (`whip_ingest`'s
/// assembler).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

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
/// codes removed). One of each: the last ones seen, whatever their ids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H264ParamSets {
    pub sps: Option<Bytes>,
    pub pps: Option<Bytes>,
}

/// The largest SPS or PPS the parameter-set cache keeps. A real one is tens
/// of bytes — a few hundred with VUI and scaling lists.
///
/// The cache used to keep a set of any size and copy it ahead of every later
/// IDR that lacked one, so a publisher could send one megabyte-sized "SPS"
/// and then seven-byte IDRs, and every one went out — to the broadcast ring,
/// the keyframe cache and each viewer's packetizer — a megabyte long
/// (measured: 210 bytes of ingest published as 31 MB).
pub const MAX_PARAM_SET_BYTES: usize = 1024;

/// The payload size str0m 0.24.1's H.264 packetizer is given: its default
/// 1150-byte datagram target (`str0m::DATAGRAM_MTU_TARGET`) less the 16-byte
/// SRTP tag, rounded down to the 16-byte SRTP block — 1120 (`do_payload` in
/// str0m's `media/mod.rs`). The relay sets no MTU of its own.
const STR0M_PAYLOAD_MTU: usize = {
    let rtp = str0m::DATAGRAM_MTU_TARGET - 16;
    rtp - rtp % 16
};

/// The most SPS + PPS bytes that reach a viewer. str0m's packetizer sends an
/// access unit's SPS and PPS as one STAP-A ahead of its first slice — a header
/// byte, then each set behind a two-byte length — and silently sends neither
/// when that packet would exceed [`STR0M_PAYLOAD_MTU`] (`H264Packetizer::emit`
/// in str0m's `packet/h264.rs`). 1115 bytes.
pub const MAX_PARAM_SETS_ON_THE_WIRE: usize = STR0M_PAYLOAD_MTU - 5;

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
/// own, so a decoder can start on any IDR of a stream that uses one SPS and
/// one PPS — the common case.
///
/// A sender need not repeat its parameter sets with every IDR (only libwebrtc
/// does so reliably; an encoder with global headers sends them once). A WHEP
/// viewer that joined after the IDR that carried them — primed with the
/// cached keyframe, or waiting for the next live one — then has slices it
/// cannot decode, and a browser asks for a keyframe (PLI) forever.
///
/// **One of each.** The cache holds the last SPS and the last PPS the stream
/// carried, whatever their ids. A stream that uses several — separate
/// CABAC / CAVLC or field PPSs, from some broadcast and hardware encoders —
/// gets only the last of each back, so a late joiner cannot decode slices
/// that reference the others until an IDR brings its own. Keying the cache by
/// id would gain a WHEP viewer little: str0m's packetizer puts at most one SPS
/// and one PPS — the last of each it has seen — ahead of a slice
/// (`H264Packetizer::emit`), so extra sets in one unit are lost on the wire
/// anyway.
///
/// **Bounded.** A set past [`MAX_PARAM_SET_BYTES`] is never cached — it clears
/// the cached one instead, so a stale set is not put back ahead of an IDR the
/// new one describes — and nothing is inserted when the SPS and PPS the unit
/// would then carry exceed [`MAX_PARAM_SETS_ON_THE_WIRE`], since str0m would
/// send neither. So an insertion adds at most that many bytes to an IDR.
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

    // What the unit's own set does to the cached one: `None` leaves it,
    // `Some(set)` replaces it. Copied, not sliced out of the unit: a slice
    // would keep the whole IDR buffer alive for as long as the cache holds it.
    let update = |own: Option<&[u8]>, cached: &Option<Bytes>| -> Option<Option<Bytes>> {
        let own = own?;
        if own.len() > MAX_PARAM_SET_BYTES {
            return cached.is_some().then_some(None);
        }
        (cached.as_deref() != Some(own)).then(|| Some(Bytes::copy_from_slice(own)))
    };
    let new_sps = update(own_sps, &cached.sps);
    let new_pps = update(own_pps, &cached.pps);
    let param_sets = (new_sps.is_some() || new_pps.is_some()).then(|| H264ParamSets {
        sps: new_sps.unwrap_or_else(|| cached.sps.clone()),
        pps: new_pps.unwrap_or_else(|| cached.pps.clone()),
    });

    let insert_sps = cached.sps.as_deref().filter(|_| idr && own_sps.is_none());
    let insert_pps = cached.pps.as_deref().filter(|_| idr && own_pps.is_none());
    if insert_sps.is_none() && insert_pps.is_none() {
        return RestoredAu { au: None, idr, param_sets };
    }
    let on_the_wire =
        |own: Option<&[u8]>, inserted: Option<&[u8]>| own.or(inserted).map_or(0, <[u8]>::len);
    if on_the_wire(own_sps, insert_sps) + on_the_wire(own_pps, insert_pps)
        > MAX_PARAM_SETS_ON_THE_WIRE
    {
        return RestoredAu {
            au: None,
            idr,
            param_sets,
        };
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

    /// An oversized "SPS" is never cached, and never copied ahead of the IDRs
    /// after it. Before, the cache kept any size: a 1 MiB type-7 NAL and then
    /// thirty seven-byte bare IDRs published 31 MB.
    #[test]
    fn an_oversized_parameter_set_is_never_put_back() {
        let mut cache = H264ParamSets::default();
        let mut huge = vec![0x67];
        huge.resize(1 << 20, 0x11);
        let mut au = vec![0, 0, 0, 1];
        au.extend_from_slice(&huge);
        au.extend_from_slice(&unit(&[8, 5]));
        restore(&au, &mut cache);
        assert_eq!(cache.sps, None, "a 1 MiB SPS is not cached");

        let mut published = 0;
        for _ in 0..30 {
            let (au, idr) = restore(&unit(&[5]), &mut cache);
            assert!(idr);
            published += au.len();
        }
        assert!(
            published <= 30 * (unit(&[5]).len() + MAX_PARAM_SETS_ON_THE_WIRE + 8),
            "30 bare IDRs published {published} bytes"
        );

        // The largest set the cache keeps goes back in as before.
        let mut cache = H264ParamSets::default();
        let mut sps = vec![0x67];
        sps.resize(MAX_PARAM_SET_BYTES, 0x11);
        let mut au = vec![0, 0, 0, 1];
        au.extend_from_slice(&sps);
        au.extend_from_slice(&unit(&[8, 5]));
        restore(&au, &mut cache);
        assert_eq!(cache.sps.as_deref(), Some(&sps[..]));
        let (au, _) = restore(&unit(&[5]), &mut cache);
        assert_eq!(nal_types(&au), vec![7, 8, 5]);
    }

    /// A set the cache will not keep still retires the one it replaces: the
    /// stream has moved on, and the old SPS would describe the next IDR
    /// wrongly.
    #[test]
    fn an_uncacheable_set_retires_the_cached_one() {
        let mut cache = H264ParamSets::default();
        restore(&unit(&[7, 8, 5]), &mut cache);
        assert!(cache.sps.is_some());
        let mut huge = vec![0, 0, 0, 1, 0x67];
        huge.resize(4 + MAX_PARAM_SET_BYTES + 1, 0x11);
        restore(&huge, &mut cache);
        assert_eq!(cache.sps, None, "the stale SPS is gone");
        assert!(cache.pps.is_some(), "the PPS stands");
        let (au, _) = restore(&unit(&[5]), &mut cache);
        assert!(!nal_types(&au).contains(&7), "no stale SPS goes back in");
    }

    /// Nothing is inserted when the SPS and PPS a unit would then carry are
    /// more than str0m's packetizer sends: one byte over its STAP-A budget,
    /// the unit goes out as it came; at the budget, the sets go in.
    #[test]
    fn nothing_is_inserted_past_the_stap_a_budget() {
        assert_eq!(
            STR0M_PAYLOAD_MTU, 1120,
            "str0m's payload MTU moved: re-derive the budget"
        );
        assert_eq!(MAX_PARAM_SETS_ON_THE_WIRE, 1115);

        let sized = |header: u8, len: usize| {
            let mut n = vec![header];
            n.resize(len, 0x11);
            n
        };
        for (sps_len, inserted) in [(MAX_PARAM_SET_BYTES, true), (MAX_PARAM_SET_BYTES, false)] {
            let pps_len = MAX_PARAM_SETS_ON_THE_WIRE - sps_len + usize::from(!inserted);
            let mut cache = H264ParamSets {
                sps: Some(sized(0x67, sps_len).into()),
                pps: Some(sized(0x68, pps_len).into()),
            };
            let (au, _) = restore(&unit(&[5]), &mut cache);
            let types = nal_types(&au);
            if inserted {
                assert_eq!(types, vec![7, 8, 5], "{sps_len} + {pps_len} bytes fit");
            } else {
                assert_eq!(types, vec![5], "{sps_len} + {pps_len} bytes do not");
            }
        }

        // The unit's own SPS counts too: a cached PPS that would push it past
        // the budget stays out.
        let mut cache = H264ParamSets {
            sps: None,
            pps: Some(sized(0x68, MAX_PARAM_SET_BYTES).into()),
        };
        let mut au = vec![0, 0, 0, 1];
        au.extend_from_slice(&sized(0x67, 200));
        au.extend_from_slice(&unit(&[5]));
        let (out, _) = restore(&au, &mut cache);
        assert_eq!(out, au, "{} + {MAX_PARAM_SET_BYTES} bytes do not fit", 200);
    }

    #[test]
    fn es_kind_roundtrips() {
        for k in [EsKind::VideoH264, EsKind::AudioOpus] {
            assert_eq!(EsKind::from_u8(k.as_u8()), Some(k));
        }
        assert_eq!(EsKind::from_u8(0), None);
    }
}
