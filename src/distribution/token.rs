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
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("bad hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

/// Suffixes that mark a stream as a **derived rendition** of another.
///
/// A viewer token is minted for a *source*, and covers that source's derived
/// renditions as well. Kept as one named list rather than open-ended prefix
/// matching, so what a token grants stays enumerable.
const RENDITION_SUFFIXES: &[&str] = &["-proxy"];

/// The source a derived rendition belongs to, if this name is one.
///
/// `"show-proxy"` -> `Some("show")`; `"show"` -> `None`.
fn rendition_source(stream: &str) -> Option<&str> {
    RENDITION_SUFFIXES
        .iter()
        .find_map(|suffix| stream.strip_suffix(suffix))
        .filter(|base| !base.is_empty())
}

/// Verify a viewer token (WHEP + the origin GET when gated).
///
/// **One token covers a source and its derived renditions.** A viewer of the
/// DVR player is watching one thing, but it is delivered as a *pair* --
/// `{stream}` for playback and `{stream}-proxy` for shuttle -- and the two are
/// the same content at two encodings. Requiring a token each meant the main
/// rendition played while the first shuttle silently buffered nothing, with
/// `video.error` still null: it read as a broken transport, not an auth
/// failure.
///
/// A token minted for `show` therefore also admits `show-proxy`. The converse
/// does not hold: a token minted for `show-proxy` admits only `show-proxy`, so
/// handing someone the low-resolution rendition does not hand them the
/// full-resolution one.
///
/// The consequence to be aware of: an unrelated stream *named* `show-proxy` is
/// reachable with a `show` token. Rendition names are derived by convention
/// (`{stream}-proxy`), so that collision is a naming choice, not an accident
/// waiting to happen -- but it is why the suffix list is closed and why the
/// widening is here, in one place, rather than spread across the callers.
pub fn verify_viewer_token(secret_hex: &str, stream: &str, token: &str) -> Result<()> {
    match verify(secret_hex, SCOPE_VIEWER, stream, token) {
        Ok(()) => Ok(()),
        Err(e) => match rendition_source(stream) {
            // Fall back to the source only for a *derived* name, and only
            // after the exact match has already failed.
            Some(source) => verify(secret_hex, SCOPE_VIEWER, source, token).map_err(|_| e),
            None => Err(e),
        },
    }
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

    /// One token covers a source and its derived renditions.
    ///
    /// The DVR player fetches `{stream}` and `{stream}-proxy` as one viewing
    /// session. Scoping a token to a single name meant the main rendition
    /// played and the first shuttle silently buffered nothing.
    #[test]
    fn a_source_token_covers_its_derived_renditions() {
        let exp = now_unix() + 300;
        let tok = mint_viewer_token(SECRET, "show", exp).unwrap();
        assert!(verify_viewer_token(SECRET, "show", &tok).is_ok());
        assert!(verify_viewer_token(SECRET, "show-proxy", &tok).is_ok());
    }

    /// ...and only in that direction. Handing someone the low-resolution
    /// rendition must not hand them the full-resolution one.
    #[test]
    fn a_rendition_token_does_not_grant_its_source() {
        let exp = now_unix() + 300;
        let tok = mint_viewer_token(SECRET, "show-proxy", exp).unwrap();
        assert!(verify_viewer_token(SECRET, "show-proxy", &tok).is_ok());
        assert!(verify_viewer_token(SECRET, "show", &tok).is_err());
    }

    /// The widening must not become "any name that ends in a known suffix".
    #[test]
    fn the_widening_does_not_reach_unrelated_streams() {
        let exp = now_unix() + 300;
        let tok = mint_viewer_token(SECRET, "show", exp).unwrap();
        assert!(verify_viewer_token(SECRET, "other", &tok).is_err());
        assert!(verify_viewer_token(SECRET, "other-proxy", &tok).is_err());
        assert!(verify_viewer_token(SECRET, "showx-proxy", &tok).is_err());
        // A bare suffix has no source to fall back to.
        assert!(verify_viewer_token(SECRET, "-proxy", &tok).is_err());
    }

    /// Ingest is a WRITE surface and is deliberately not widened: a token to
    /// publish a source must not also grant publishing its rendition, which
    /// is a different producer.
    #[test]
    fn ingest_tokens_are_not_widened() {
        let exp = now_unix() + 300;
        let tok = mint_ingest_token(SECRET, "show", exp).unwrap();
        assert!(verify_ingest_token(SECRET, "show", &tok).is_ok());
        assert!(verify_ingest_token(SECRET, "show-proxy", &tok).is_err());
    }

    /// An expired token stays expired however it is matched -- the fallback
    /// must not become a way around the expiry check.
    #[test]
    fn the_fallback_does_not_revive_an_expired_token() {
        let expired = now_unix() - 1;
        let tok = mint_viewer_token(SECRET, "show", expired).unwrap();
        assert!(verify_viewer_token(SECRET, "show", &tok).is_err());
        assert!(verify_viewer_token(SECRET, "show-proxy", &tok).is_err());
    }

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
        // Flip the last signature nibble to a value it is not already, rather
        // than pushing a fixed '0'. `exp` moves every second, so one second in
        // sixteen minted a signature already ending in '0' — the "tamper" was
        // then a no-op and this assertion failed. Nothing caught it: the repo
        // had no CI, and this module only compiles under `viewer-distribution`,
        // which is off by default.
        let last = tok.pop().expect("token is non-empty");
        tok.push(if last == '0' { '1' } else { '0' });
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
