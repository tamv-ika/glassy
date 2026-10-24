//! Packet number reconstruction and anti-replay window (spec §4).

use crate::consts::REPLAY_WINDOW;
use crate::error::Error;

/// Reconstructs a full packet number from its low 32 bits.
///
/// RFC 9000 Appendix A.3 with `pn_nbits` = 32. The subtraction guards avoid u64
/// underflow where the RFC pseudo-code relies on signed arithmetic.
pub fn decode_pn(largest: u64, low: u32) -> u64 {
    const PN_WIN: u64 = 1 << 32;
    const PN_HWIN: u64 = PN_WIN / 2;
    const PN_MASK: u64 = PN_WIN - 1;
    const MAX_PN: u64 = 1 << 62;

    let expected = largest.saturating_add(1);
    let candidate = (expected & !PN_MASK) | u64::from(low);

    if expected >= PN_HWIN && candidate <= expected - PN_HWIN && candidate < MAX_PN - PN_WIN {
        return candidate + PN_WIN;
    }
    if candidate > expected.saturating_add(PN_HWIN) && candidate >= PN_WIN {
        return candidate - PN_WIN;
    }
    candidate
}

/// Sliding anti-replay window covering `(largest - 256, largest]`.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    bits: [u64; REPLAY_WINDOW / 64],
    largest: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Empty window; `largest` starts at 0 and no packet number is committed.
    pub fn new() -> Self {
        Self {
            bits: [0; REPLAY_WINDOW / 64],
            largest: 0,
        }
    }

    fn slot(pn: u64) -> (usize, u64) {
        let i = (pn % REPLAY_WINDOW as u64) as usize;
        (i / 64, 1u64 << (i % 64))
    }

    /// Read-only check; call [`commit`](Self::commit) only after the AEAD verified.
    pub fn check(&self, pn: u64) -> Result<(), Error> {
        // 0 is reserved for ACCEPT/REJECT and is never a valid DATA packet number.
        if pn == 0 {
            return Err(Error::Replayed);
        }
        if pn.saturating_add(REPLAY_WINDOW as u64) <= self.largest {
            return Err(Error::TooOld);
        }
        if pn > self.largest {
            return Ok(());
        }
        let (word, mask) = Self::slot(pn);
        if self.bits.get(word).is_some_and(|w| w & mask != 0) {
            return Err(Error::Replayed);
        }
        Ok(())
    }

    /// Marks `pn` as seen. Ignores values that `check` would reject as too old.
    pub fn commit(&mut self, pn: u64) {
        if pn == 0 || pn.saturating_add(REPLAY_WINDOW as u64) <= self.largest {
            return;
        }
        if pn > self.largest {
            // Slots are indexed by pn mod 256, so slots re-entering the window must be cleared.
            if pn - self.largest >= REPLAY_WINDOW as u64 {
                self.bits = [0; REPLAY_WINDOW / 64];
            } else {
                for n in self.largest + 1..=pn {
                    let (word, mask) = Self::slot(n);
                    if let Some(w) = self.bits.get_mut(word) {
                        *w &= !mask;
                    }
                }
            }
            self.largest = pn;
        }
        let (word, mask) = Self::slot(pn);
        if let Some(w) = self.bits.get_mut(word) {
            *w |= mask;
        }
    }
    pub fn largest(&self) -> u64 {
        self.largest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    #[test]
    fn decode_pn_small() {
        assert_eq!(decode_pn(0, 1), 1);
    }

    #[test]
    fn decode_pn_crosses_32_bit_boundary() {
        assert_eq!(decode_pn(0xFFFF_FFF0, 2), 0x1_0000_0002);
        assert_eq!(decode_pn(0x1_0000_0005, 0xFFFF_FFFF), 0xFFFF_FFFF);
        assert_eq!(decode_pn(0x1_0000_0005, 3), 0x1_0000_0003);
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check(7), Ok(()));
        w.commit(7);
        assert_eq!(w.check(7), Err(Error::Replayed));
        assert_eq!(w.check(8), Ok(()));
    }

    #[test]
    fn replay_window_edge() {
        let mut w = ReplayWindow::new();
        w.commit(1000);
        assert_eq!(w.check(745), Ok(()));
        assert_eq!(w.check(744), Err(Error::TooOld));
    }

    #[test]
    fn replay_window_jump_clears_bits() {
        let mut w = ReplayWindow::new();
        w.commit(5);
        w.commit(5 + 300);
        assert_eq!(w.check(5), Err(Error::TooOld));
        assert_eq!(w.check(300), Ok(()));
        assert_eq!(w.largest(), 305);
    }

    #[test]
    fn pn_zero_is_replayed() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check(0), Err(Error::Replayed));
        w.commit(500);
        assert_eq!(w.check(0), Err(Error::Replayed));
    }

    proptest! {
        #[test]
        fn window_matches_naive_set(pns in proptest::collection::vec(1u64..2000, 1..400)) {
            let mut w = ReplayWindow::new();
            let mut seen = BTreeSet::new();
            let mut largest = 0u64;
            for pn in pns {
                let expect = if pn + 256 <= largest {
                    Err(Error::TooOld)
                } else if seen.contains(&pn) {
                    Err(Error::Replayed)
                } else {
                    Ok(())
                };
                prop_assert_eq!(w.check(pn), expect);
                if expect.is_ok() {
                    w.commit(pn);
                    seen.insert(pn);
                    largest = largest.max(pn);
                }
                prop_assert_eq!(w.largest(), largest);
            }
        }
    }
}
