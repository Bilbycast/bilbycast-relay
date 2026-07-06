// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! WebRTC (str0m) plumbing for the relay's viewer-distribution SFU.
//!
//! Vendored from bilbycast-edge — the relay runs the ICE-Lite **server**
//! role only (per-viewer WHEP sessions). See the module docs in each file.

pub mod rtp_h264;
pub mod session;
