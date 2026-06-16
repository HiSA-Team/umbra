//! M-mode trap decode + frame.
//!
//! Every `ecall` from U (host) and S (enclave), and every PMP access fault,
//! funnels through the monitor's trap handler — the single mediation point that
//! keeps the M-mode monitor the sole arbiter. This module owns the pure decode
//! (host-tested) and the mapping of PMP faults onto [`UmbraError`]; the trap
//! entry/restore assembly and `mtvec` wiring land with the monitor dispatch.

use umbra_error::UmbraError;

/// Saved integer context at a trap. `regs[0]` (`x0`) is unused but kept so the
/// array is indexable by register number (`a7` = `regs[17]`, `a0` = `regs[10]`,
/// `sp` = `regs[2]`). Layout is fixed by `start.S` (`repr(C)`): the 32 GPRs,
/// then `mepc`, `mcause`, `mtval`, `mstatus`. `Copy` so the monitor can snapshot
/// the host context across an enclave entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    pub regs: [u32; 32],
    pub mepc: u32,
    pub mcause: u32,
    pub mtval: u32,
    pub mstatus: u32,
}

/// `mstatus.MPP` field (bits 12:11): the privilege `mret` returns to.
const MSTATUS_MPP_MASK: u32 = 0b11 << 11;
const MSTATUS_MPP_S: u32 = 0b01 << 11;
// MPP = 00 is U-mode (no bits set).

impl TrapFrame {
    /// Make the next `mret` from this frame land in S-mode (used to enter the
    /// enclave). The trapped-from value is U (the host), so this rewrites MPP.
    pub fn return_to_supervisor(&mut self) {
        self.mstatus = (self.mstatus & !MSTATUS_MPP_MASK) | MSTATUS_MPP_S;
    }
}

/// Decoded trap cause (the subset the monitor acts on).
#[derive(Debug, PartialEq, Eq)]
pub enum Trap {
    /// `ecall` from U-mode (the untrusted host).
    EcallFromU,
    /// `ecall` from S-mode (the enclave).
    EcallFromS,
    /// PMP-denied load — `addr` is `mtval` (the faulting address).
    LoadAccessFault { addr: u32 },
    /// PMP-denied store — `addr` is `mtval`.
    StoreAccessFault { addr: u32 },
    /// Machine timer interrupt (CLINT `mtimecmp` expired) — the preemption tick
    /// that lets the monitor suspend a running enclave.
    TimerInterrupt,
    /// Any other cause (carries the raw `mcause`).
    Other(u32),
}

/// `mcause` top bit (RV32): set ⇒ interrupt, clear ⇒ synchronous exception.
const MCAUSE_INTERRUPT: u32 = 1 << 31;
/// Machine timer interrupt code (low bits of `mcause` when the interrupt bit set).
const IRQ_MACHINE_TIMER: u32 = 7;

/// Decode `mcause`/`mtval` into a [`Trap`]. Interrupts have `mcause` bit 31 set
/// (machine timer = 7); exception codes: 8 = ecall from U, 9 = ecall from S,
/// 5 = load access fault, 7 = store access fault. Note the store-fault code (7,
/// interrupt bit clear) does NOT collide with the timer interrupt (7, interrupt
/// bit set) — the bit-31 test separates them.
pub fn decode(mcause: u32, mtval: u32) -> Trap {
    if mcause & MCAUSE_INTERRUPT != 0 {
        return match mcause & !MCAUSE_INTERRUPT {
            IRQ_MACHINE_TIMER => Trap::TimerInterrupt,
            _ => Trap::Other(mcause),
        };
    }
    match mcause {
        8 => Trap::EcallFromU,
        9 => Trap::EcallFromS,
        5 => Trap::LoadAccessFault { addr: mtval },
        7 => Trap::StoreAccessFault { addr: mtval },
        other => Trap::Other(other),
    }
}

impl Trap {
    /// A PMP/SPMP access fault maps to the platform-generic memory-protection
    /// error — the [`UmbraError::MemProtectDenied`] variant documented as the
    /// RISC-V PMP backend. Non-fault traps return `None`.
    pub fn as_mem_protect_error(&self) -> Option<UmbraError> {
        match *self {
            Trap::LoadAccessFault { addr } | Trap::StoreAccessFault { addr } => {
                Some(UmbraError::MemProtectDenied { addr })
            }
            _ => None,
        }
    }
}

// ── Target CSR setup (RV32) ─────────────────────────────────────────────────

/// Point `mtvec` at the monitor's trap entry (direct mode). `entry` must be
/// 4-byte aligned.
#[cfg(target_arch = "riscv32")]
pub fn set_mtvec(entry: usize) {
    // SAFETY: writes the architectural mtvec CSR (direct mode, low bits 0).
    unsafe { core::arch::asm!("csrw mtvec, {e}", e = in(reg) entry) };
}

/// Point `mscratch` at the monitor's trap stack top. The trap entry swaps `sp`
/// with `mscratch`, so this must be set before any U/S code runs.
#[cfg(target_arch = "riscv32")]
pub fn set_mscratch(stack_top: usize) {
    // SAFETY: writes the architectural mscratch CSR.
    unsafe { core::arch::asm!("csrw mscratch, {s}", s = in(reg) stack_top) };
}

/// Ensure `ecall`s from both U and S trap to M by clearing their delegation
/// bits in `medeleg` (bit 8 = U-ecall, bit 9 = S-ecall). The monitor mediates
/// every ring transition, so neither is delegated to S-mode.
#[cfg(target_arch = "riscv32")]
pub fn route_ecalls_to_m() {
    let bits: u32 = (1 << 8) | (1 << 9);
    // SAFETY: clears two architecturally-defined medeleg bits.
    unsafe { core::arch::asm!("csrc medeleg, {b}", b = in(reg) bits) };
}

#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn set_mtvec(_entry: usize) {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn route_ecalls_to_m() {}
#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn set_mscratch(_stack_top: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecall_from_u_decodes() {
        assert_eq!(decode(8, 0), Trap::EcallFromU);
    }

    #[test]
    fn ecall_from_s_decodes() {
        assert_eq!(decode(9, 0), Trap::EcallFromS);
    }

    #[test]
    fn pmp_load_fault_carries_addr() {
        assert_eq!(
            decode(5, 0x8004_0000),
            Trap::LoadAccessFault { addr: 0x8004_0000 }
        );
    }

    #[test]
    fn pmp_store_fault_carries_addr() {
        assert_eq!(
            decode(7, 0x8004_4000),
            Trap::StoreAccessFault { addr: 0x8004_4000 }
        );
    }

    #[test]
    fn unknown_cause_is_other() {
        assert_eq!(decode(3, 0), Trap::Other(3));
    }

    #[test]
    fn machine_timer_interrupt_decodes() {
        // mcause = interrupt bit (31) | code 7.
        assert_eq!(decode(0x8000_0007, 0), Trap::TimerInterrupt);
    }

    #[test]
    fn store_fault_and_timer_interrupt_do_not_collide() {
        // Both carry low-bits 7; only the interrupt bit distinguishes them.
        assert_eq!(
            decode(7, 0x8004_0000),
            Trap::StoreAccessFault { addr: 0x8004_0000 }
        );
        assert_eq!(decode(0x8000_0007, 0x8004_0000), Trap::TimerInterrupt);
    }

    #[test]
    fn unknown_interrupt_keeps_raw_mcause() {
        assert_eq!(decode(0x8000_0003, 0), Trap::Other(0x8000_0003));
    }

    #[test]
    fn access_fault_maps_to_mem_protect_denied() {
        let t = decode(5, 0x8004_0000);
        assert_eq!(
            t.as_mem_protect_error(),
            Some(UmbraError::MemProtectDenied { addr: 0x8004_0000 })
        );
    }

    #[test]
    fn ecall_is_not_a_mem_protect_error() {
        assert_eq!(decode(8, 0).as_mem_protect_error(), None);
    }
}
