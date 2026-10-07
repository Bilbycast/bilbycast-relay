// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebRTC (str0m) plumbing for the relay's viewer-distribution SFU.
//!
//! Vendored from bilbycast-edge — the relay runs the ICE-Lite **server**
//! role only (per-viewer WHEP sessions). See the module docs in each file.
//!
//! There is no RTP packetizer here: str0m's writer packetizes each H.264
//! access unit it is handed (see `whep::write_video_au_on`). The relay's own
//! RFC 6184 packetizer (`rtp_h264`, vendored from the edge) was removed with
//! the edge's own copy — feeding its packets to str0m packetized them twice.

pub mod session;
