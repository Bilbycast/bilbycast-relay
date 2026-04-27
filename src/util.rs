// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Shared internal helpers.

/// Constant-time byte comparison to prevent timing attacks on token /
/// HMAC verification.
///
/// This intentionally does **not** early-return on length mismatch — the
/// length difference is folded into the accumulator alongside the
/// per-byte XOR, so the runtime distribution does not leak whether the
/// caller provided a short or long token. Callers should still validate
/// length bounds where appropriate before invoking this; the length
/// folding here is defense-in-depth.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff: u64 = (a.len() as u64) ^ (b.len() as u64);
    for i in 0..max_len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as u64;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_match() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn different_same_length_does_not_match() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"a", b"b"));
    }

    #[test]
    fn different_lengths_do_not_match() {
        // Length difference must not early-return — both branches reach
        // the same accumulator path.
        assert!(!constant_time_eq(b"a", b"abc"));
        assert!(!constant_time_eq(b"abc", b"a"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"x", b""));
    }

    #[test]
    fn prefix_match_does_not_match() {
        assert!(!constant_time_eq(b"hello", b"hello-world"));
        assert!(!constant_time_eq(b"hello-world", b"hello"));
    }
}
