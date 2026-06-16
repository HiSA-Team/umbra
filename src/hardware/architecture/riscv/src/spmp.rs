//! SPMP arbitration policy model (S-mode).
//!
//! See `book/src/decisions/008-riscv-spmp-arbitration.md`. This struct is the
//! host-testable *policy mirror*; the on-target CSR side-effects (the indirect
//! Sscsrind sequence `siselect`/`sireg`/`sireg2`, plus the M-mode `mpmpdeleg`
//! delegation) are applied in a later phase by `apply()`. Keeping the policy
//! here means the two invariants Umbra relies on are unit-tested without
//! hardware:
//!   1. SPMP can only *restrict within* the PMP grant (`clamp`).
//!   2. The monitor hands the host a world with no live enclave SPMP entries
//!      (`reset_to_baseline`).

use umbra_error::{UmbraError, UmbraResult};

/// Permission a granted SPMP entry confers. `Off` = no rule (entry disabled).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpmpPerm {
    Off,
    Ro,
    Rw,
    Rwx,
}

/// One SPMP region. `base`/`end`/`perm` feed the on-target `apply()` (later
/// phase); the policy tests only need to know whether an entry is live.
#[derive(Clone, Copy)]
#[allow(dead_code)] // base/end/perm are read by the on-target apply() (later phase)
struct Entry {
    base: u32,
    end: u32,
    perm: SpmpPerm,
}

/// Host-testable mirror of the S-mode SPMP entry table. The patchset exposes
/// up to 64 SPMP entries; Umbra's enclave model needs only a handful (its own
/// region plus a shared parameter window), so the mirror caps at 8.
pub struct SpmpModel {
    entries: [Option<Entry>; SpmpModel::SLOTS],
}

impl SpmpModel {
    const SLOTS: usize = 8;

    /// A fresh model with every entry disabled (the monitor's baseline).
    pub const fn new() -> Self {
        SpmpModel {
            entries: [None; Self::SLOTS],
        }
    }

    /// Disable every entry — the monitor calls this on each ring transition so
    /// no stale enclave SPMP rule governs the U-mode host (invariant 2).
    pub fn reset_to_baseline(&mut self) {
        self.entries = [None; Self::SLOTS];
    }

    /// True when no entry is live (post-baseline, or a fresh model).
    pub fn all_off(&self) -> bool {
        self.entries.iter().all(|e| e.is_none())
    }

    /// Record a live SPMP grant in `slot`. Callers are expected to have already
    /// `clamp`ed `[base, end)` to the enclave's PMP window. A `slot` past the
    /// mirrored table is a programming invariant violation, surfaced as an
    /// [`UmbraError`] rather than an index panic.
    pub fn grant(&mut self, slot: usize, base: u32, end: u32, perm: SpmpPerm) -> UmbraResult<()> {
        if slot >= Self::SLOTS {
            return Err(UmbraError::InternalInvariant {
                context: "SPMP slot index out of range",
            });
        }
        self.entries[slot] = Some(Entry { base, end, perm });
        Ok(())
    }

    /// Intersect a requested span `[b, e)` with the PMP window `[pb, pe)`. SPMP
    /// can never widen beyond what PMP already permits (invariant 1): the result
    /// is `[max(b,pb), min(e,pe))`.
    pub fn clamp(b: u32, e: u32, pb: u32, pe: u32) -> (u32, u32) {
        (b.max(pb), e.min(pe))
    }

    /// Decide whether a **U-mode** access of `want` to `addr` is permitted under
    /// the current entries. SPMP gates U-mode with *deny-by-default*: the access
    /// is allowed only if some live entry covers `addr` in `[base, end)` and
    /// confers at least `want` (R ⊆ Rw ⊆ Rwx). This is the host mirror of the
    /// on-target SPMP check and encodes the negative-isolation invariant the
    /// monitor relies on — an enclave can never reach monitor or other-domain
    /// memory it was never granted (the runtime complement is the QEMU smoke).
    pub fn u_mode_can_access(&self, addr: u32, want: SpmpPerm) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|e| addr >= e.base && addr < e.end && perm_covers(e.perm, want))
    }
}

/// True when a granted `SpmpPerm` confers at least the requested access `want`.
/// Permission lattice: `Ro ⊂ Rw ⊂ Rwx`; `Off` confers nothing; a `want` of
/// `Off` is meaningless and never granted.
fn perm_covers(granted: SpmpPerm, want: SpmpPerm) -> bool {
    match want {
        SpmpPerm::Off => false,
        SpmpPerm::Ro => matches!(granted, SpmpPerm::Ro | SpmpPerm::Rw | SpmpPerm::Rwx),
        SpmpPerm::Rw => matches!(granted, SpmpPerm::Rw | SpmpPerm::Rwx),
        SpmpPerm::Rwx => granted == SpmpPerm::Rwx,
    }
}

impl Default for SpmpModel {
    fn default() -> Self {
        Self::new()
    }
}

// ── On-target SPMP CSR programming (indirect Sscsrind access) ────────────────
//
// SPMP registers are reached indirectly: `siselect (0x150) = 0x100 + index`,
// then `sireg (0x151)` ↔ `spmpaddr[index]`, `sireg2 (0x152)` ↔ `spmpcfg[index]`.
// The cfg byte adds bit 8 = UMODE (rule applies to U-mode) and bit 9 = SHARED.
// Entries are only programmable once the monitor delegates rules to S via
// `mpmpdeleg (0x316)`, and a rule only takes effect once its `spmpen (0x183)`
// bit is set. M-mode default-allows itself and S-mode; only U-mode is gated by
// SPMP — so the monitor grants the host its window here.

/// SPMP cfg byte bits (see the patched `target/riscv/spmp.h`).
pub mod cfg_bits {
    /// Read.
    pub const R: u32 = 1 << 0;
    /// Write.
    pub const W: u32 = 1 << 1;
    /// Execute.
    pub const X: u32 = 1 << 2;
    /// Address-match mode: top-of-range.
    pub const TOR: u32 = 1 << 3;
    /// Address-match mode: naturally-aligned power-of-two region.
    pub const NAPOT: u32 = 3 << 3;
    /// Lock.
    pub const LOCK: u32 = 1 << 7;
    /// Rule applies to U-mode (and, without SHARED, *denies* S-mode).
    pub const UMODE: u32 = 1 << 8;
    /// Shared region: grants both S-mode and U-mode (per the SPMP truth table).
    pub const SHARED: u32 = 1 << 9;
}

/// Delegate SPMP rules to S-mode so entries become programmable and active.
/// `mpmpdeleg` (CSR `0x316`) reserves rules to M; `num_deleg_rules = 64 -
/// mpmpdeleg`. Must be `< 64` (and `> last_locked_PMP_rule`) before any entry
/// can be written.
#[cfg(target_arch = "riscv32")]
pub fn set_mpmpdeleg(value: u32) {
    // SAFETY: writes the architectural mpmpdeleg CSR.
    unsafe { core::arch::asm!("csrw 0x316, {v}", v = in(reg) value) };
}

/// Program SPMP entry `index` in TOR mode: `spmpaddr[index] = top >> 2` (the
/// exclusive top, paired with the previous entry as the base) and
/// `spmpcfg[index] = cfg`. Access is via the indirect CSRs (`siselect` selects
/// `0x100 + index`, `sireg`/`sireg2` carry addr/cfg). A `cfg` of `0` leaves the
/// entry OFF (a bare boundary for the next TOR rule). Without the `sspmpen`
/// extension a non-OFF entry is auto-active, so no SPMPEN write is needed.
#[cfg(target_arch = "riscv32")]
pub fn write_tor_entry(index: u32, top: u32, cfg: u32) {
    use core::arch::asm;
    // SAFETY: indirect SPMP CSR programming; requires prior `set_mpmpdeleg`.
    unsafe {
        asm!("csrw 0x150, {v}", v = in(reg) 0x100 + index); // siselect
        asm!("csrw 0x151, {v}", v = in(reg) top >> 2); // sireg  = spmpaddr[index]
        asm!("csrw 0x152, {v}", v = in(reg) cfg); // sireg2 = spmpcfg[index]
    }
}

/// Program SPMP entry `index` as a NAPOT region covering `[base, base + size)`
/// (`size` a power of two `>= 8`, `base` naturally aligned). The `cfg` carries
/// the permission/UMODE/SHARED bits; the NAPOT `A` field is added here. Same
/// indirect-CSR path as [`write_tor_entry`].
#[cfg(target_arch = "riscv32")]
pub fn write_napot_entry(index: u32, base: u32, size: u32, cfg: u32) {
    use core::arch::asm;
    let napot = (base | (size / 2 - 1)) >> 2;
    let full_cfg = cfg | cfg_bits::NAPOT;
    // SAFETY: indirect SPMP CSR programming; requires prior `set_mpmpdeleg`.
    unsafe {
        asm!("csrw 0x150, {v}", v = in(reg) 0x100 + index); // siselect
        asm!("csrw 0x151, {v}", v = in(reg) napot); // sireg  = spmpaddr[index]
        asm!("csrw 0x152, {v}", v = in(reg) full_cfg); // sireg2 = spmpcfg[index]
    }
}

#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn set_mpmpdeleg(_value: u32) {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn write_tor_entry(_index: u32, _top: u32, _cfg: u32) {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn write_napot_entry(_index: u32, _base: u32, _size: u32, _cfg: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_records_a_live_entry() {
        let mut model = SpmpModel::new();
        assert!(model.all_off());
        model
            .grant(0, 0x8004_0000, 0x8004_4000, SpmpPerm::Rw)
            .unwrap();
        assert!(!model.all_off());
    }

    #[test]
    fn grant_rejects_out_of_range_slot() {
        let mut model = SpmpModel::new();
        let err = model
            .grant(99, 0x8004_0000, 0x8004_4000, SpmpPerm::Rw)
            .unwrap_err();
        assert_eq!(
            err,
            UmbraError::InternalInvariant {
                context: "SPMP slot index out of range"
            }
        );
        assert!(model.all_off(), "a rejected grant must not record an entry");
    }

    #[test]
    fn baseline_disables_every_spmp_entry() {
        let mut model = SpmpModel::new();
        model
            .grant(0, 0x8004_0000, 0x8004_4000, SpmpPerm::Rw)
            .unwrap();
        model
            .grant(3, 0x8005_0000, 0x8005_1000, SpmpPerm::Ro)
            .unwrap();
        model.reset_to_baseline();
        assert!(
            model.all_off(),
            "host must run with no live enclave SPMP entries"
        );
    }

    #[test]
    fn grant_cannot_exceed_pmp_window() {
        // SPMP grant is intersected with the PMP window; it can never widen it.
        let g = SpmpModel::clamp(0x8004_0000, 0x8005_0000, 0x8004_0000, 0x8004_8000);
        assert_eq!(g, (0x8004_0000, 0x8004_8000)); // clamped down to the PMP top
    }

    #[test]
    fn clamp_is_identity_when_inside_window() {
        let g = SpmpModel::clamp(0x8004_1000, 0x8004_2000, 0x8004_0000, 0x8004_8000);
        assert_eq!(g, (0x8004_1000, 0x8004_2000));
    }

    // ── Negative isolation: an enclave (U-mode) must not reach memory it was
    //    never granted. These assert the *denial* path, the host complement to
    //    the QEMU end-to-end smoke (which asserts the happy path runs). ─────────

    /// Addresses where the enclave holds a monitor-owned word and its own data.
    const MONITOR_ADDR: u32 = 0x8000_0000; // monitor .text/.data, never granted
    const ENCLAVE_BASE: u32 = 0x8004_0000;
    const ENCLAVE_END: u32 = 0x8004_4000;

    fn model_with_enclave_rw() -> SpmpModel {
        let mut m = SpmpModel::new();
        m.grant(0, ENCLAVE_BASE, ENCLAVE_END, SpmpPerm::Rw).unwrap();
        m
    }

    #[test]
    fn enclave_is_denied_access_to_monitor_memory() {
        let m = model_with_enclave_rw();
        // Inside its own granted window: allowed.
        assert!(m.u_mode_can_access(ENCLAVE_BASE + 0x1000, SpmpPerm::Ro));
        assert!(m.u_mode_can_access(ENCLAVE_BASE + 0x1000, SpmpPerm::Rw));
        // Monitor memory was never granted: read and write are DENIED.
        assert!(!m.u_mode_can_access(MONITOR_ADDR, SpmpPerm::Ro));
        assert!(!m.u_mode_can_access(MONITOR_ADDR, SpmpPerm::Rw));
    }

    #[test]
    fn deny_is_the_default_with_no_entries() {
        let m = SpmpModel::new();
        assert!(!m.u_mode_can_access(ENCLAVE_BASE, SpmpPerm::Ro));
        assert!(!m.u_mode_can_access(MONITOR_ADDR, SpmpPerm::Ro));
    }

    #[test]
    fn enclave_rw_grant_does_not_confer_execute() {
        // A data (Rw) grant must not let the enclave execute from that page —
        // W^X at the policy layer.
        let m = model_with_enclave_rw();
        assert!(!m.u_mode_can_access(ENCLAVE_BASE + 0x1000, SpmpPerm::Rwx));
    }

    #[test]
    fn grant_window_is_half_open() {
        // [base, end): the top boundary belongs to the next region, not this one.
        let m = model_with_enclave_rw();
        assert!(m.u_mode_can_access(ENCLAVE_BASE, SpmpPerm::Ro)); // base included
        assert!(!m.u_mode_can_access(ENCLAVE_END, SpmpPerm::Ro)); // end excluded
        assert!(!m.u_mode_can_access(ENCLAVE_BASE - 1, SpmpPerm::Ro)); // below base
    }

    #[test]
    fn baseline_revokes_all_enclave_access_for_the_host() {
        // After a ring transition the monitor resets to baseline; the previously
        // granted enclave window must no longer be reachable.
        let mut m = model_with_enclave_rw();
        assert!(m.u_mode_can_access(ENCLAVE_BASE + 0x1000, SpmpPerm::Ro));
        m.reset_to_baseline();
        assert!(!m.u_mode_can_access(ENCLAVE_BASE + 0x1000, SpmpPerm::Ro));
    }
}
