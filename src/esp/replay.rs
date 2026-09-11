//! ESP anti-replay sliding window (RFC 4303 §3.4.3, RFC 4301 Appendix C).
//!
//! The window tracks the highest sequence number seen so far (its right edge)
//! and a bitmap of which of the `size` most recent sequence numbers have been
//! received. A packet is accepted when its sequence number is newer than the
//! right edge, or when it lies inside the window and has not been seen yet.
//! Sequence numbers at or below `right_edge - size` are too old and rejected.
//!
//! Only 32-bit sequence numbers are supported (no ESN — the ePDG profile
//! negotiates ESN transform 0).

use log::debug;

/// Smallest window RFC 4303 §3.4.3 allows a receiver to use.
pub const MIN_WINDOW: u32 = 32;

/// RFC 4303 §3.4.3 sliding anti-replay window.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// Window size in sequence numbers (>= 32).
    size: u32,
    /// Highest sequence number accepted so far (right edge); 0 before any packet.
    last_seq: u32,
    /// Ring bitmap: bit for sequence number `s` lives at `s % capacity()`.
    /// Only bits for sequence numbers inside `(last_seq - size, last_seq]` are meaningful.
    bitmap: Vec<u64>,
}

impl ReplayWindow {
    /// Create a window of `size` sequence numbers, rounded up to at least 32.
    pub fn new(size: u32) -> Self {
        let size = size.max(MIN_WINDOW);
        let words = usize::try_from(size.div_ceil(64)).unwrap_or(1);
        ReplayWindow { size, last_seq: 0, bitmap: vec![0u64; words] }
    }

    /// Window size in sequence numbers (after rounding).
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Highest sequence number accepted so far (0 if none).
    pub fn last_seq(&self) -> u32 {
        self.last_seq
    }

    /// Bit capacity of the ring bitmap (a multiple of 64, >= `size`).
    fn capacity(&self) -> u64 {
        self.bitmap.len() as u64 * 64
    }

    fn bit_pos(&self, seq: u32) -> (usize, u64) {
        let idx = u64::from(seq) % self.capacity();
        ((idx / 64) as usize, 1u64 << (idx % 64))
    }

    fn get_bit(&self, seq: u32) -> bool {
        let (w, m) = self.bit_pos(seq);
        self.bitmap.get(w).is_some_and(|word| word & m != 0)
    }

    fn set_bit(&mut self, seq: u32, on: bool) {
        let (w, m) = self.bit_pos(seq);
        if let Some(word) = self.bitmap.get_mut(w) {
            if on {
                *word |= m;
            } else {
                *word &= !m;
            }
        }
    }

    /// Would `seq` be accepted? Does not modify the window. Sequence number 0 is
    /// never valid (RFC 4303 §2.2: the first packet of an SA carries 1).
    pub fn check(&self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.last_seq {
            return true;
        }
        let diff = self.last_seq - seq;
        if diff >= self.size {
            return false; // left of the window: too old
        }
        !self.get_bit(seq)
    }

    /// Record `seq` as received, advancing the window if it is newer than the
    /// right edge. Call only after `check` succeeded AND the packet's ICV verified.
    pub fn update(&mut self, seq: u32) {
        if seq == 0 {
            return;
        }
        if seq > self.last_seq {
            let advance = u64::from(seq - self.last_seq);
            if advance >= self.capacity() {
                // Everything in the old window is now too old: wipe.
                self.bitmap.iter_mut().for_each(|w| *w = 0);
            } else {
                // Clear the bits for the sequence numbers we are sliding over.
                let mut s = self.last_seq.wrapping_add(1);
                while s != seq {
                    self.set_bit(s, false);
                    s = s.wrapping_add(1);
                }
            }
            self.last_seq = seq;
            self.set_bit(seq, true);
        } else {
            let diff = self.last_seq - seq;
            if diff < self.size {
                self.set_bit(seq, true);
            }
        }
    }

    /// `check` followed by `update` when accepted. Returns whether `seq` was accepted.
    /// Use this AFTER the packet's ICV has been verified (RFC 4303 §3.4.3).
    pub fn check_and_update(&mut self, seq: u32) -> bool {
        if self.check(seq) {
            self.update(seq);
            true
        } else {
            debug!("replay window: rejected seq {} (right edge {}, size {})", seq, self.last_seq, self.size);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_up_to_32() {
        assert_eq!(ReplayWindow::new(0).size(), 32);
        assert_eq!(ReplayWindow::new(12).size(), 32);
        assert_eq!(ReplayWindow::new(32).size(), 32);
        assert_eq!(ReplayWindow::new(33).size(), 33);
        assert_eq!(ReplayWindow::new(64).size(), 64);
        assert_eq!(ReplayWindow::new(1024).size(), 1024);
        assert_eq!(ReplayWindow::new(33).bitmap.len(), 1);
        assert_eq!(ReplayWindow::new(65).bitmap.len(), 2);
    }

    #[test]
    fn spec_sequence() {
        let mut w = ReplayWindow::new(12); // -> 32
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(3));
        assert!(w.check_and_update(2));
        assert!(!w.check_and_update(2), "replayed 2 must be rejected");
        assert!(w.check_and_update(100));
        assert!(!w.check_and_update(60), "60 is outside the 32-wide window ending at 100");
        assert!(w.check_and_update(90));
        assert!(!w.check_and_update(90));
        assert!(!w.check_and_update(100));
        assert_eq!(w.last_seq(), 100);
    }

    #[test]
    fn seq_zero_rejected() {
        let mut w = ReplayWindow::new(32);
        assert!(!w.check(0));
        assert!(!w.check_and_update(0));
        assert_eq!(w.last_seq(), 0);
        assert!(w.check_and_update(1));
        assert!(!w.check_and_update(0));
    }

    #[test]
    fn window_edges() {
        let mut w = ReplayWindow::new(32);
        assert!(w.check_and_update(100));
        // window covers (100-32, 100] = 69..=100
        assert!(w.check(69));
        assert!(!w.check(68));
        assert!(w.check_and_update(69));
        assert!(!w.check_and_update(69));
        assert!(w.check_and_update(70));
        // slide by one: 69 falls out
        assert!(w.check_and_update(101));
        assert!(!w.check(69));
        assert!(w.check(70) == false, "70 already received");
        assert!(w.check(71));
    }

    #[test]
    fn sliding_clears_old_bits() {
        let mut w = ReplayWindow::new(32);
        for s in 1..=32 {
            assert!(w.check_and_update(s));
        }
        // Everything 1..=32 seen. Jump ahead by exactly 64 (ring capacity): all bits wiped.
        assert!(w.check_and_update(96));
        // 65..=95 are in-window and unseen — including 65..=95 whose ring slots
        // aliased the old 1..=31 entries.
        for s in 65..=95 {
            assert!(w.check(s), "seq {} should be fresh", s);
        }
        assert!(!w.check(64));
        // Partial slide: from 96 to 120 clears 97..=119 slots (which alias 33..=55).
        assert!(w.check_and_update(120));
        for s in (89..=119).filter(|&s| s != 96) {
            assert!(w.check(s), "seq {} should be fresh", s);
        }
        assert!(!w.check(96));
        assert!(!w.check(88));
    }

    #[test]
    fn large_window_multiword() {
        let mut w = ReplayWindow::new(200);
        assert_eq!(w.size(), 200);
        assert_eq!(w.bitmap.len(), 4);
        assert!(w.check_and_update(1000));
        for s in (801..1000).rev() {
            assert!(w.check_and_update(s), "seq {}", s);
        }
        assert!(!w.check(800));
        for s in 801..=1000 {
            assert!(!w.check(s));
        }
        assert!(w.check_and_update(5000));
        assert!(w.check(4801));
        assert!(!w.check(4800));
    }

    #[test]
    fn max_seq_ok() {
        let mut w = ReplayWindow::new(32);
        assert!(w.check_and_update(u32::MAX - 1));
        assert!(w.check_and_update(u32::MAX));
        assert!(!w.check(u32::MAX));
        assert!(w.check(u32::MAX - 2));
        assert!(!w.check(u32::MAX - 32));
    }

    #[test]
    fn update_ignores_out_of_window() {
        let mut w = ReplayWindow::new(32);
        w.update(100);
        w.update(10); // too old; no-op
        assert_eq!(w.last_seq(), 100);
        assert!(!w.check(10));
    }
}
