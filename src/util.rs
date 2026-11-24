// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared internal helpers.

use std::net::IpAddr;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

/// How many of something each source address holds.
///
/// A count, the check of it against the cap, and the removal of an entry that
/// has reached zero are each made under the lock of the address's entry. So
/// nothing is counted on an entry that has left the map, and no count is given
/// back on one it was not made on: that would take it below zero, and the
/// address over its cap for good.
#[derive(Default)]
pub struct IpCounts(DashMap<IpAddr, u32>);

impl IpCounts {
    /// Count one more for `ip`, unless that would be more than `cap`. Then
    /// nothing is counted, and the error is how many it would have been.
    pub fn add(&self, ip: IpAddr, cap: u32) -> Result<(), u32> {
        let entry = self.0.entry(ip);
        let count = match &entry {
            Entry::Occupied(held) => held.get() + 1,
            Entry::Vacant(_) => 1,
        };
        if count > cap {
            return Err(count);
        }
        entry.insert(count);
        Ok(())
    }

    /// Give back one that [`Self::add`] counted for `ip`.
    pub fn remove(&self, ip: IpAddr) {
        self.0.remove_if_mut(&ip, |_, held| {
            *held -= 1;
            *held == 0
        });
    }

    /// How many `ip` holds, if it has an entry at all.
    #[cfg(test)]
    pub(crate) fn held(&self, ip: IpAddr) -> Option<u32> {
        self.0.get(&ip).map(|held| *held)
    }
}

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
mod ip_count_tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn a_count_stops_at_the_cap_and_leaves_nothing_behind() {
        let counts = IpCounts::default();
        assert_eq!(counts.add(A, 0), Err(1));
        assert_eq!(counts.held(A), None, "refused its first");

        assert_eq!(counts.add(A, 2), Ok(()));
        assert_eq!(counts.add(A, 2), Ok(()));
        assert_eq!(counts.add(A, 2), Err(3));
        assert_eq!(counts.held(A), Some(2), "refused its third");
        assert_eq!(counts.add(B, 2), Ok(()), "another address");

        counts.remove(A);
        assert_eq!(counts.held(A), Some(1));
        assert_eq!(counts.add(A, 2), Ok(()), "there is room again");
        counts.remove(A);
        counts.remove(A);
        assert_eq!(counts.held(A), None);
        counts.remove(A);
        assert_eq!(counts.held(A), None, "none to give back");
        assert_eq!(counts.held(B), Some(1));
    }

    /// Each thread holds one at a time, so a cap of one each refuses nobody,
    /// and the entry is taken out and put back all the while.
    #[test]
    fn a_count_survives_its_entry_coming_and_going() {
        const THREADS: u32 = 4;
        let counts = &IpCounts::default();
        std::thread::scope(|s| {
            for _ in 0..THREADS {
                s.spawn(move || {
                    for _ in 0..20_000 {
                        assert_eq!(counts.add(A, THREADS), Ok(()));
                        counts.remove(A);
                    }
                });
            }
        });
        assert_eq!(counts.held(A), None);
    }
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
