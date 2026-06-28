//! PMP region programming (M-mode)
//!
//! PMP is the layer that makes the M-mode monitor the sole arbiter of the
//! inter-domain boundary (see `book/src/decisions/008-riscv-spmp-arbitration.md`):
//! SPMP can only ever restrict *within* a PMP grant. This module programs PMP
//! entries in TOR (top-of-range) mode and locks the monitor's own code via
//! ePMP.
//!
//! The pure address math + slot validation is host-tested; the raw `csrw
//! pmpaddrN`/`pmpcfgN` writes need compile-time-literal CSR operands, so they
//! live behind a `target_arch = "riscv32"` cfg with a no-op host stub.

use crate::csr::{PmpCfg, PmpMode};
use umbra_error::{UmbraError, UmbraResult};

/// Highest usable PMP entry index (RV32 implementations provide 16: 0..=15).
pub const MAX_PMP_SLOT: usize = 15;

/// A physical span `[base, end)` granted to a domain.
pub struct Region {
    pub base: u32,
    pub end: u32,
}

impl Region {
    pub const fn new(base: u32, end: u32) -> Self {
        Region { base, end }
    }
}

/// `pmpaddr` holds the physical address shifted right by 2 (it addresses
/// 4-byte words).
#[inline]
pub const fn pmpaddr_value(phys: u32) -> u32 {
    phys >> 2
}

/// Program PMP entry `slot` in TOR mode to cover `region` with `cfg`. TOR pairs
/// `pmpaddr[slot-1] = base` with `pmpaddr[slot] = end`, so `slot` must be in
/// `1..=MAX_PMP_SLOT`.
pub fn set_tor(slot: usize, region: &Region, cfg: PmpCfg) -> UmbraResult<()> {
    if slot == 0 || slot > MAX_PMP_SLOT {
        return Err(UmbraError::InternalInvariant {
            context: "PMP TOR slot out of range (1..=15)",
        });
    }
    write_pmpaddr(slot - 1, pmpaddr_value(region.base))?;
    write_pmpaddr(slot, pmpaddr_value(region.end))?;
    write_pmpcfg_byte(slot, cfg.mode(PmpMode::Tor).bits())?;
    Ok(())
}

/// ePMP self-lock: install a **Locked** (L=1) read+execute TOR rule over the
/// monitor's own `.text` in PMP `slot`. The Lock bit binds the rule to M-mode as
/// well (standard PMP semantics — no Smepmp/MML required), so even a bug in the
/// monitor cannot overwrite its own code: a store into `.text` faults, while
/// read+execute stay permitted so the monitor keeps running.
///
/// Place this at a LOWER PMP index than the broad inter-domain grant so it wins
/// for the `.text` range (PMP priority = lowest matching index).
///
/// NOTE: full Smepmp MML+MMWP (M-mode default-deny + W^X over every M region) is
/// deliberately deferred. The monitor directly reads/writes U/S memory — it
/// copies and decrypts enclave code from the host image into the Secure ESS —
/// which has no clean MML "M=RW + U=RWX" single-rule encoding; closing that
/// needs M-only bounce buffers or dynamic RLB reprogramming (tracked follow-up).
/// The Locked `.text` rule delivers the core TCB code-integrity property today.
pub fn self_lock_monitor(slot: usize, text: &Region) -> UmbraResult<()> {
    set_tor(slot, text, PmpCfg::new().r().x().lock())
}

/// Turn PMP entry `slot` OFF (mode `Off`, no permissions). Used when switching
/// worlds to revoke an entry the other world owned, so no stale grant survives.
///
/// Unlike [`set_tor`], slot 0 is valid here: Off mode clears the entry's cfg byte
/// and needs no predecessor `pmpaddr`, so the whole `0..=MAX_PMP_SLOT` range applies.
pub fn disable(slot: usize) -> UmbraResult<()> {
    if slot > MAX_PMP_SLOT {
        return Err(UmbraError::InternalInvariant {
            context: "PMP slot out of range (0..=15)",
        });
    }
    write_pmpcfg_byte(slot, PmpCfg::new().bits())?;
    Ok(())
}

// ── Target CSR writes (RV32) ────────────────────────────────────────────────

#[cfg(target_arch = "riscv32")]
fn write_pmpaddr(idx: usize, val: u32) -> UmbraResult<()> {
    use core::arch::asm;
    // SAFETY: each arm writes a single architectural PMP address CSR.
    unsafe {
        match idx {
            0 => asm!("csrw pmpaddr0, {v}", v = in(reg) val),
            1 => asm!("csrw pmpaddr1, {v}", v = in(reg) val),
            2 => asm!("csrw pmpaddr2, {v}", v = in(reg) val),
            3 => asm!("csrw pmpaddr3, {v}", v = in(reg) val),
            4 => asm!("csrw pmpaddr4, {v}", v = in(reg) val),
            5 => asm!("csrw pmpaddr5, {v}", v = in(reg) val),
            6 => asm!("csrw pmpaddr6, {v}", v = in(reg) val),
            7 => asm!("csrw pmpaddr7, {v}", v = in(reg) val),
            8 => asm!("csrw pmpaddr8, {v}", v = in(reg) val),
            9 => asm!("csrw pmpaddr9, {v}", v = in(reg) val),
            10 => asm!("csrw pmpaddr10, {v}", v = in(reg) val),
            11 => asm!("csrw pmpaddr11, {v}", v = in(reg) val),
            12 => asm!("csrw pmpaddr12, {v}", v = in(reg) val),
            13 => asm!("csrw pmpaddr13, {v}", v = in(reg) val),
            14 => asm!("csrw pmpaddr14, {v}", v = in(reg) val),
            15 => asm!("csrw pmpaddr15, {v}", v = in(reg) val),
            _ => {
                return Err(UmbraError::InternalInvariant {
                    context: "pmpaddr index out of range",
                })
            }
        }
    }
    Ok(())
}

#[cfg(target_arch = "riscv32")]
fn write_pmpcfg_byte(slot: usize, byte: u8) -> UmbraResult<()> {
    use core::arch::asm;
    // RV32 packs four cfg bytes per pmpcfgN CSR: entries 0..3 in pmpcfg0, etc.
    let reg = slot / 4;
    let shift = (slot % 4) * 8;
    let mask: u32 = 0xFFu32 << shift;
    let ins: u32 = (byte as u32) << shift;
    // SAFETY: read-modify-write of the architectural pmpcfgN CSR for `reg`.
    unsafe {
        let mut cur: u32;
        match reg {
            0 => {
                asm!("csrr {c}, pmpcfg0", c = out(reg) cur);
                cur = (cur & !mask) | ins;
                asm!("csrw pmpcfg0, {c}", c = in(reg) cur);
            }
            1 => {
                asm!("csrr {c}, pmpcfg1", c = out(reg) cur);
                cur = (cur & !mask) | ins;
                asm!("csrw pmpcfg1, {c}", c = in(reg) cur);
            }
            2 => {
                asm!("csrr {c}, pmpcfg2", c = out(reg) cur);
                cur = (cur & !mask) | ins;
                asm!("csrw pmpcfg2, {c}", c = in(reg) cur);
            }
            3 => {
                asm!("csrr {c}, pmpcfg3", c = out(reg) cur);
                cur = (cur & !mask) | ins;
                asm!("csrw pmpcfg3, {c}", c = in(reg) cur);
            }
            _ => {
                return Err(UmbraError::InternalInvariant {
                    context: "pmpcfg register index out of range",
                })
            }
        }
    }
    Ok(())
}

/// Raise `mseccfg.MML | MMWP` (full Smepmp lockdown). Reserved for the deferred
/// full-MML step (see [`self_lock_monitor`]); not wired yet because the monitor
/// still accesses U/S memory directly, which MML's encodings can't express
/// cleanly. Kept so the follow-up only has to call it after staging M-only
/// bounce buffers.
#[allow(dead_code)]
#[cfg(target_arch = "riscv32")]
fn set_mseccfg_mml_mmwp() -> UmbraResult<()> {
    use core::arch::asm;
    // mseccfg = 0x747; set MML (bit 0) | MMWP (bit 1).
    // SAFETY: a CSR set of two architecturally-defined mseccfg bits.
    unsafe { asm!("csrs 0x747, {v}", v = in(reg) 0b11u32) };
    Ok(())
}

// ── Host stubs (so the pure logic is testable off-target) ───────────────────

#[cfg(not(target_arch = "riscv32"))]
fn write_pmpaddr(_idx: usize, _val: u32) -> UmbraResult<()> {
    Ok(())
}
#[cfg(not(target_arch = "riscv32"))]
fn write_pmpcfg_byte(_slot: usize, _byte: u8) -> UmbraResult<()> {
    Ok(())
}
#[allow(dead_code)]
#[cfg(not(target_arch = "riscv32"))]
fn set_mseccfg_mml_mmwp() -> UmbraResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_rejects_out_of_range_slot() {
        assert_eq!(
            disable(16).unwrap_err(),
            UmbraError::InternalInvariant {
                context: "PMP slot out of range (0..=15)"
            }
        );
    }

    #[test]
    fn disable_accepts_valid_slot() {
        // On host the CSR write is a no-op; exercises the validation path.
        assert!(disable(5).is_ok());
    }

    #[test]
    fn pmpaddr_is_phys_shifted_right_two() {
        assert_eq!(pmpaddr_value(0x8004_0000), 0x2001_0000);
        assert_eq!(pmpaddr_value(0x8004_8000), 0x2001_2000);
    }

    #[test]
    fn set_tor_rejects_slot_zero() {
        let r = Region::new(0x8004_0000, 0x8004_8000);
        let err = set_tor(0, &r, PmpCfg::new().rwx()).unwrap_err();
        assert_eq!(
            err,
            UmbraError::InternalInvariant {
                context: "PMP TOR slot out of range (1..=15)"
            }
        );
    }

    #[test]
    fn set_tor_rejects_slot_above_max() {
        let r = Region::new(0x8004_0000, 0x8004_8000);
        assert!(set_tor(16, &r, PmpCfg::new().rwx()).is_err());
    }

    #[test]
    fn set_tor_accepts_valid_slot() {
        let r = Region::new(0x8004_0000, 0x8004_8000);
        // On host the CSR writes are no-ops; this exercises the validation path.
        assert!(set_tor(1, &r, PmpCfg::new().rwx()).is_ok());
    }
}
