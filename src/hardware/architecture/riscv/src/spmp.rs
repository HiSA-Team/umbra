//! On-target sPMP entry programming (M-mode delegated; gates U-mode only).
//!
//! The flipped ring model runs the enclave in U-mode, and on the SPMP-patched
//! QEMU a U-mode access is denied-by-default unless a live sPMP rule grants it
//! (every U/S access is checked against PMP AND sPMP). So the per-world swap must
//! also install the enclave's sPMP grants — see
//! `book/src/decisions/008-riscv-spmp-arbitration.md`. This module is only the
//! raw CSR programming; the host-testable PMP world model lives in
//! [`crate::pmp_world`]. The PMP->sPMP trap-and-emulate gateway and Smstateen
//! remain deferred to a later slice.
//!
//! sPMP registers are reached indirectly: `siselect (0x150) = 0x100 + index`,
//! then `sireg (0x151)` ↔ `spmpaddr[index]`, `sireg2 (0x152)` ↔ `spmpcfg[index]`.
//! Entries are programmable only once the monitor delegates rules to S via
//! `mpmpdeleg (0x316)`. M-mode default-allows itself and S-mode; only U-mode is
//! gated — so these grants exist to let the U-mode enclave execute.
//!
//! Entries are auto-active because the configured QEMU has `sspmpen` disabled
//! (`-cpu rv32,spmp=true`); enabling `sspmpen` would additionally require writing
//! the per-entry `spmpen` CSR (0x183).

/// sPMP cfg byte bits (see the patched `target/riscv/spmp.h`).
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
    /// Rule applies to U-mode (and, without SHARED, denies S-mode).
    pub const UMODE: u32 = 1 << 8;
    /// Shared region: grants both S-mode and U-mode.
    pub const SHARED: u32 = 1 << 9;
}

/// Delegate sPMP rules to S-mode so entries become programmable and active.
/// `num_deleg_rules = 64 - mpmpdeleg`; must be `< 64` and `> last_locked_PMP_rule`
/// (the monitor's `.text` lock is PMP entry 1, so any value in `2..=63` works).
#[cfg(target_arch = "riscv32")]
pub fn set_mpmpdeleg(value: u32) {
    // SAFETY: writes the architectural mpmpdeleg CSR (M-mode).
    unsafe { core::arch::asm!("csrw 0x316, {v}", v = in(reg) value) };
}

/// Program sPMP entry `index` as a NAPOT region covering `[base, base + size)`
/// (`size` a power of two `>= 8`, `base` naturally aligned). `cfg` carries the
/// permission/UMODE/SHARED bits; the NAPOT `A` field is added here. Indirect-CSR
/// path; requires a prior [`set_mpmpdeleg`] delegating this index.
#[cfg(target_arch = "riscv32")]
pub fn write_napot_entry(index: u32, base: u32, size: u32, cfg: u32) {
    use core::arch::asm;
    let napot = (base | (size / 2 - 1)) >> 2;
    let full_cfg = cfg | cfg_bits::NAPOT;
    // SAFETY: indirect sPMP CSR programming; requires prior set_mpmpdeleg.
    unsafe {
        asm!("csrw 0x150, {v}", v = in(reg) 0x100 + index); // siselect
        asm!("csrw 0x151, {v}", v = in(reg) napot); // sireg  = spmpaddr[index]
        asm!("csrw 0x152, {v}", v = in(reg) full_cfg); // sireg2 = spmpcfg[index]
    }
}

/// Disable sPMP entry `index` (cfg = 0 / OFF). Same indirect-CSR path as the
/// writers. Used by the per-transition reset so an entry one world programmed
/// never governs the other world.
#[cfg(target_arch = "riscv32")]
pub fn disable_entry(index: u32) {
    use core::arch::asm;
    // SAFETY: indirect SPMP CSR programming; requires prior set_mpmpdeleg.
    unsafe {
        asm!("csrw 0x150, {v}", v = in(reg) 0x100 + index); // siselect
        asm!("csrw 0x152, {v}", v = in(reg) 0u32); // sireg2 = spmpcfg[index] = OFF
    }
}

/// Smstateen: gate the indirect-CSR (`siselect`/`sireg`/`sireg2`) mechanism so an
/// S-mode guest cannot program sPMP directly behind the PMP→sPMP gateway — its
/// indirect-CSR access then traps to M (which always retains access via the
/// `priv == M` short-circuit in `smstateen_acc_ok`). Grants S every *other*
/// `mstateen0` bit (so the host keeps FCSR/AIA/envcfg/... — `mstateen0` resets to
/// 0 = deny-all, so we must grant) and clears only bit 60, the indirect-select
/// enable (named `SVSLCT` in the patched QEMU; the architectural `CSRIND`
/// control). On RV32 `mstateen0` splits into `mstateen0` (CSR 0x30c, low 32) +
/// `mstateen0h` (CSR 0x31c, high 32); bit 60 is bit 28 of the high word.
/// Requires the CPU built with Smstateen (`-cpu ...,smstateen=true`); a no-op
/// (and the gateway's direct-sPMP deny is moot) on a CPU without it.
#[cfg(target_arch = "riscv32")]
pub fn gate_guest_indirect_csr() {
    use core::arch::asm;
    // SAFETY: writes the architectural mstateen0/mstateen0h CSRs (M-mode).
    unsafe {
        asm!("csrw 0x30c, {v}", v = in(reg) 0xFFFF_FFFFu32); // mstateen0  = grant all
        asm!("csrw 0x31c, {v}", v = in(reg) 0xFFFF_FFFFu32 & !(1u32 << 28)); // mstateen0h: clear SVSLCT(60)
    }
}

#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn gate_guest_indirect_csr() {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn set_mpmpdeleg(_value: u32) {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn write_napot_entry(_index: u32, _base: u32, _size: u32, _cfg: u32) {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn disable_entry(_index: u32) {}
