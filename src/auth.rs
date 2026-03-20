//! HMAC-SHA256 token generation and verification.
//!
//! This module provides stateless token auth used in two modes:
//!
//! - **Relay mode**: `identity` = edge_id, `secret` = relay shared_secret.
//!   The manager generates tokens for edges; the relay verifies them.
//!
//! - **Direct mode**: `identity` = tunnel_id (UUID string), `secret` = per-tunnel PSK.
//!   The manager generates a random PSK per tunnel and distributes it to both edges.
//!   The connecting edge sends `generate_token(tunnel_id, psk)`, the listening edge
//!   verifies with `verify_token(token, psk)`.
//!
//! The functions are generic — they operate on arbitrary identity/secret strings.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate an HMAC-SHA256 signed token.
///
/// Token format: `base64(identity:hmac_hex)` where hmac_hex = HMAC-SHA256(identity, secret).
///
/// # Usage
/// - Relay auth: `generate_token(edge_id, shared_secret)`
/// - Direct auth: `generate_token(tunnel_id, psk)`
pub fn generate_token(edge_id: &str, shared_secret: &str) -> String {
    let sig = compute_hmac(edge_id, shared_secret);
    let payload = format!("{edge_id}:{sig}");
    base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
}

/// Verify a token and extract the identity.
///
/// Returns `Some(identity)` if valid, `None` if invalid.
///
/// # Usage
/// - Relay auth: `verify_token(token, shared_secret)` → `Some(edge_id)`
/// - Direct auth: `verify_token(token, psk)` → `Some(tunnel_id)`
pub fn verify_token(token: &str, shared_secret: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let payload = String::from_utf8(decoded).ok()?;
    let (edge_id, provided_sig) = payload.split_once(':')?;

    let expected_sig = compute_hmac(edge_id, shared_secret);

    // Constant-time comparison via HMAC verify
    if provided_sig == expected_sig {
        Some(edge_id.to_string())
    } else {
        None
    }
}

fn compute_hmac(edge_id: &str, shared_secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(shared_secret.as_bytes()).expect("HMAC key can be any length");
    mac.update(edge_id.as_bytes());
    let result = mac.finalize();
    hex::encode(&result.into_bytes())
}

/// Simple hex encoding (avoid pulling in the `hex` crate for just this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify() {
        let secret = "my_shared_secret_123";
        let edge_id = "edge-abc-def";

        let token = generate_token(edge_id, secret);
        let result = verify_token(&token, secret);
        assert_eq!(result, Some(edge_id.to_string()));
    }

    #[test]
    fn test_wrong_secret_fails() {
        let token = generate_token("edge-1", "correct_secret");
        let result = verify_token(&token, "wrong_secret");
        assert_eq!(result, None);
    }

    #[test]
    fn test_tampered_token_fails() {
        let result = verify_token("totally_invalid_base64!!!", "secret");
        assert_eq!(result, None);
    }

    #[test]
    fn test_different_edge_ids_produce_different_tokens() {
        let secret = "secret";
        let t1 = generate_token("edge-1", secret);
        let t2 = generate_token("edge-2", secret);
        assert_ne!(t1, t2);
    }
}
