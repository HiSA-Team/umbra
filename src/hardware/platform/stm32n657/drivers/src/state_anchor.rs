//! State-continuity anchor in TAMP backup registers, DOUBLE-BUFFERED for atomic
//! commit. The anchor is `{generation, 128-bit root, per-sector parity}` (see the
//! kernel `state_checkpoint` root-in-anchor model). It spans several registers, so
//! a reset landing mid-write would tear it. Two copies (A/B) each carry a trailing
//! generation-echo written LAST: a torn write leaves `generation != echo`, so it is
//! detected and the previous good copy is used instead. `store` always writes the
//! STALE copy, keeping the current newest intact as the fallback until the new echo
//! lands — so at every instant at least one complete valid copy exists.
//!
//! TAMP is Device memory (durable across an immediate reset with NO cache clean —
//! unlike BKPSRAM, per the HW spike) and Secure-write-only, so the root is trusted
//! by access control. The anchor lives past the code-version floor (BKP0R..BKP11R).
//! Generic over MMIO for host tests; implements the kernel `AnchorStore` trait.

use peripheral_regs::{MmioAccess, RealMmio};
pub use crate::tamp_store::TAMP_BKP_BASE;
use kernel::key_storage_server::state_checkpoint::{Anchor, AnchorStore};

// Two 7-register copies past the 12-register (BKP0R..BKP11R) code-version floor.
// Copy layout (7 × 4 bytes): generation | root[0..4] | parity | generation-echo.
//   A = BKP12R..BKP18R (0x30..0x48),  B = BKP19R..BKP25R (0x4C..0x64).
// BKP26R..BKP31R (0x68..0x7C) are left spare.
const COPY_WORDS: u32 = 7;
const COPY_A_BASE: u32 = 12 * 4; // BKP12R = 0x30
const COPY_B_BASE: u32 = COPY_A_BASE + COPY_WORDS * 4; // BKP19R = 0x4C

// Field offsets within a copy.
const GEN_OFF: u32 = 0x00;
const ROOT_OFF: u32 = 0x04; // 4 words = 16 bytes
const PARITY_OFF: u32 = 0x14;
const ECHO_OFF: u32 = 0x18; // written LAST — the commit marker

/// One physical copy as read back from TAMP.
struct RawCopy {
    generation: u32,
    root: [u8; 16],
    parity: u16,
    echo: u32,
}

impl RawCopy {
    /// A copy is a committed anchor iff its echo confirms its generation, and the
    /// generation is non-zero. generation 0 = never-written / cold.
    // ponytail: generation 0 doubles as the cold marker, so the monotonic counter
    // must not wrap back to 0 — 2^32 checkpoints is unreachable at NOR-wear cadence.
    fn valid(&self) -> bool {
        self.generation != 0 && self.generation == self.echo
    }
}

pub struct StateAnchor<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl StateAnchor<RealMmio> {
    pub fn new() -> Self {
        Self { mmio: RealMmio::new(TAMP_BKP_BASE) }
    }
}

impl<M: MmioAccess> StateAnchor<M> {
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    fn read_copy(&self, base: u32) -> RawCopy {
        let generation = self.mmio.read(base + GEN_OFF);
        let mut root = [0u8; 16];
        let mut w = 0;
        while w < 4 {
            let word = self.mmio.read(base + ROOT_OFF + w * 4).to_le_bytes();
            let o = (w * 4) as usize;
            root[o..o + 4].copy_from_slice(&word);
            w += 1;
        }
        let parity = self.mmio.read(base + PARITY_OFF) as u16;
        let echo = self.mmio.read(base + ECHO_OFF);
        RawCopy { generation, root, parity, echo }
    }

    /// Write a copy in field order with the generation-echo LAST (commit marker).
    /// Requires `drivers::tamp_store::init_backup_domain` first (backup APB clock +
    /// DBP). No cache clean — TAMP is Device memory.
    fn write_copy(&self, base: u32, a: &Anchor) {
        self.mmio.write(base + GEN_OFF, a.generation);
        let mut w = 0;
        while w < 4 {
            let o = (w * 4) as usize;
            let mut word = [0u8; 4];
            word.copy_from_slice(&a.root[o..o + 4]);
            self.mmio.write(base + ROOT_OFF + w * 4, u32::from_le_bytes(word));
            w += 1;
        }
        self.mmio.write(base + PARITY_OFF, a.parity as u32);
        self.mmio.write(base + ECHO_OFF, a.generation); // echo LAST = commit
    }

    /// Invalidate the anchor: zero both copies' generation (and echo) so `load`
    /// returns `None` (cold). generation 0 is the cold marker (see `RawCopy::valid`).
    /// Used when an enclave TERMINATES — a completed run must not resume from its
    /// last block-transition checkpoint on a later reset; the next create starts
    /// a fresh run instead. Requires `init_backup_domain` first (DBP + APB clock).
    pub fn invalidate(&self) {
        self.mmio.write(COPY_A_BASE + GEN_OFF, 0);
        self.mmio.write(COPY_A_BASE + ECHO_OFF, 0);
        self.mmio.write(COPY_B_BASE + GEN_OFF, 0);
        self.mmio.write(COPY_B_BASE + ECHO_OFF, 0);
    }
}

impl<M: MmioAccess> AnchorStore for StateAnchor<M> {
    /// The newest valid copy (higher generation). `None` = cold, or both copies torn
    /// (a double fault: a torn write only ever damages the single copy being written).
    fn load(&self) -> Option<Anchor> {
        let a = self.read_copy(COPY_A_BASE);
        let b = self.read_copy(COPY_B_BASE);
        let pick = match (a.valid(), b.valid()) {
            (true, true) => if a.generation >= b.generation { &a } else { &b },
            (true, false) => &a,
            (false, true) => &b,
            (false, false) => return None,
        };
        Some(Anchor { generation: pick.generation, root: pick.root, parity: pick.parity })
    }

    /// Commit into the STALE copy (lower generation / invalid), leaving the current
    /// newest untouched as the fallback until the new echo lands. A torn write here
    /// is detected on the next `load` and that same newest is returned instead.
    fn store(&mut self, new: &Anchor) {
        let a = self.read_copy(COPY_A_BASE);
        let b = self.read_copy(COPY_B_BASE);
        let target = match (a.valid(), b.valid()) {
            // both good → overwrite the older; ties → treat A as newest, write B
            (true, true) => if a.generation >= b.generation { COPY_B_BASE } else { COPY_A_BASE },
            (true, false) => COPY_B_BASE, // A is the survivor → write B
            (false, true) => COPY_A_BASE, // B is the survivor → write A
            (false, false) => COPY_A_BASE, // cold → start with A
        };
        self.write_copy(target, new);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::MmioMem;

    fn anchor(gen: u32, parity: u16) -> Anchor {
        Anchor { generation: gen, root: [gen as u8; 16], parity }
    }

    #[test]
    fn anchor_round_trips() {
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let mut a = StateAnchor::new_with_mmio(mem.handle());
        a.store(&anchor(9, 0b1010));
        let r = a.load().unwrap();
        assert_eq!(r.generation, 9);
        assert_eq!(r.root, [9u8; 16]);
        assert_eq!(r.parity, 0b1010);
    }

    #[test]
    fn cold_both_copies_unwritten_is_none() {
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let a = StateAnchor::new_with_mmio(mem.handle());
        assert!(a.load().is_none());
    }

    #[test]
    fn newest_generation_wins() {
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let mut a = StateAnchor::new_with_mmio(mem.handle());
        a.store(&anchor(1, 0)); // copy A
        a.store(&anchor(2, 0b1)); // copy B (stale target = B)
        assert_eq!(a.load().unwrap().generation, 2);
    }

    #[test]
    fn torn_newest_write_falls_back_to_previous() {
        // gen1 → A, gen2 → B. Simulate the gen2 commit tearing before its echo lands
        // by clobbering B's echo. load must return the still-intact gen1 (copy A).
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let mut a = StateAnchor::new_with_mmio(mem.handle());
        a.store(&anchor(1, 0));
        a.store(&anchor(2, 0b1));
        mem.handle().write(COPY_B_BASE + ECHO_OFF, 0xBAD); // echo != generation
        let r = a.load().unwrap();
        assert_eq!(r.generation, 1, "torn newest → previous copy survives");
        assert_eq!(r.root, [1u8; 16]);
    }

    #[test]
    fn store_targets_stale_copy_across_three_generations() {
        // gen1→A, gen2→B, gen3→A (alternation). Tearing gen3 (copy A) must fall back
        // to gen2 (copy B) — proving gen3 did NOT overwrite the gen2 survivor.
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let mut a = StateAnchor::new_with_mmio(mem.handle());
        a.store(&anchor(1, 0));
        a.store(&anchor(2, 0));
        a.store(&anchor(3, 0));
        assert_eq!(a.load().unwrap().generation, 3);
        mem.handle().write(COPY_A_BASE + ECHO_OFF, 0xBAD); // tear gen3 (in copy A)
        assert_eq!(a.load().unwrap().generation, 2, "gen2 survivor was preserved");
    }

    #[test]
    fn anchor_lives_past_the_code_version_floor() {
        // Floor table occupies BKP0R..BKP11R (0x00..0x30); both copies start at/after
        // 0x30, so a floor bump and an anchor store never collide.
        assert!(COPY_A_BASE >= 12 * 4);
        assert!(COPY_B_BASE + COPY_WORDS * 4 <= 32 * 4); // fits within BKP0R..BKP31R
    }
}
