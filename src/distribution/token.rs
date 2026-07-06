// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Short-lived, stateless HMAC tokens for the distribution plane.
//!
//! The manager mints these (same shared `token_secret` it distributes to the
//! relay, the edge, and viewers) and the relay validates them **statelessly**
//! — no DB, no per-token state — mirroring the `authorize_tunnel` HMAC bind
//! pattern used on the opaque forwarder, but with an added expiry so a leaked
//! viewer link stops working.
//!
//! Token format: `{exp}.{hmac_hex}` where
//! `hmac = HMAC-SHA256(secret, "{scope}:{stream}:{exp}")`, `exp` is a unix
//! timestamp (seconds), and `secret` is the 64-hex `token_secret` decoded to
//! 32 bytes. Scope is `viewer` or `ingest`.

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const SCOPE_VIEWER: &str = "viewer";
const SCOPE_INGEST: &str = "ingest";

/// Decode the 64-hex shared secret into raw key bytes.
fn decode_secret(secret_hex: &str) -> Result<Vec<u8>> {
    if secret_hex.len() != 64 || !secret_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("token_secret must be 64 hex chars");
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&secret_hex[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

fn compute_hmac(secret: &[u8], scope: &str, stream: &str, exp: u64) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{scope}:{stream}:{exp}").as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Constant-time compare of two byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a token for `scope`+`stream` expiring at `exp` (unix seconds).
/// Used by the manager (and by tests). Kept here so the mint/verify pair
/// stays in one place and cannot drift.
pub fn mint(secret_hex: &str, scope: &str, stream: &str, exp: u64) -> Result<String> {
    let secret = decode_secret(secret_hex)?;
    let mac = compute_hmac(&secret, scope, stream, exp);
    Ok(format!("{exp}.{}", hex_encode(&mac)))
}

/// Verify a token for a given scope + stream. Checks the HMAC (constant-time)
/// and that it has not expired.
fn verify(secret_hex: &str, scope: &str, stream: &str, token: &str) -> Result<()> {
    let secret = decode_secret(secret_hex)?;
    let (exp_str, hmac_hex) = token
        .split_once('.')
        .ok_or_else(|| anyhow!("malformed token"))?;
    let exp: u64 = exp_str.parse().map_err(|_| anyhow!("bad exp"))?;
    if exp < now_unix() {
        bail!("token expired");
    }
    let expected = compute_hmac(&secret, scope, stream, exp);
    let got = decode_hex(hmac_hex)?;
    if !ct_eq(&expected, &got) {
        bail!("signature mismatch");
    }
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("bad hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

/// Verify a viewer token (WHEP access).
pub fn verify_viewer_token(secret_hex: &str, stream: &str, token: &str) -> Result<()> {
    verify(secret_hex, SCOPE_VIEWER, stream, token)
}

/// Verify an ingest token (edge → relay distribution ingest).
pub fn verify_ingest_token(secret_hex: &str, stream: &str, token: &str) -> Result<()> {
    verify(secret_hex, SCOPE_INGEST, stream, token)
}

/// Mint a viewer token (used by tests / manager-side parity checks).
pub fn mint_viewer_token(secret_hex: &str, stream: &str, exp: u64) -> Result<String> {
    mint(secret_hex, SCOPE_VIEWER, stream, exp)
}

/// Mint an ingest token.
pub fn mint_ingest_token(secret_hex: &str, stream: &str, exp: u64) -> Result<String> {
    mint(secret_hex, SCOPE_INGEST, stream, exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn viewer_token_roundtrips() {
        let exp = now_unix() + 300;
        let tok = mint_viewer_token(SECRET, "stream-a", exp).unwrap();
        assert!(verify_viewer_token(SECRET, "stream-a", &tok).is_ok());
    }

    #[test]
    fn wrong_stream_rejected() {
        let exp = now_unix() + 300;
        let tok = mint_viewer_token(SECRET, "stream-a", exp).unwrap();
        assert!(verify_viewer_token(SECRET, "stream-b", &tok).is_err());
    }

    #[test]
    fn scope_is_enforced() {
        let exp = now_unix() + 300;
        let ingest = mint_ingest_token(SECRET, "s", exp).unwrap();
        // An ingest token must not pass as a viewer token.
        assert!(verify_viewer_token(SECRET, "s", &ingest).is_err());
        assert!(verify_ingest_token(SECRET, "s", &ingest).is_ok());
    }

    #[test]
    fn expired_rejected() {
        let exp = now_unix().saturating_sub(1);
        let tok = mint_viewer_token(SECRET, "s", exp).unwrap();
        assert!(verify_viewer_token(SECRET, "s", &tok).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let exp = now_unix() + 300;
        let mut tok = mint_viewer_token(SECRET, "s", exp).unwrap();
        tok.pop();
        tok.push('0');
        assert!(verify_viewer_token(SECRET, "s", &tok).is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let exp = now_unix() + 300;
        let tok = mint_viewer_token(SECRET, "s", exp).unwrap();
        let other = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(verify_viewer_token(other, "s", &tok).is_err());
    }

    /// Cross-crate parity: this exact vector is asserted identically in
    /// `bilbycast-manager::api::distribution` (the manager mints, the relay
    /// verifies). If the token algorithm changes, both tests must move
    /// together — otherwise minted viewer links stop validating here.
    #[test]
    fn canonical_token_vector() {
        assert_eq!(
            mint_viewer_token(SECRET, "s", 1_800_000_000).unwrap(),
            "1800000000.5b921b8226f1789d832a26c8016fee7caeee65af72655b44626e6da6b9908ffe"
        );
        assert_eq!(
            mint_ingest_token(SECRET, "s", 1_800_000_000).unwrap(),
            "1800000000.19c818cc49417dfa7ec5b597165a348860da53114a8fab20e64eec0920ae3c60"
        );
    }
}
