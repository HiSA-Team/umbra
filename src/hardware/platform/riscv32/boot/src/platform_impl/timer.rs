//! M-mode preemption timer (QEMU `virt` CLINT) — the RISC-V counterpart of the
//! STM32 SysTick that preempts a running enclave.
//!
//! The CLINT `mtimecmp` is armed `quantum` ticks ahead of `mtime`; when it
//! expires the hart takes a **machine timer interrupt**. Because machine
//! interrupts are always taken while the hart is in a lower privilege (the
//! enclave runs in S-mode, the host in U-mode), the monitor regains control,
//! snapshots the enclave's full register context, and hands the time-slice back
//! to the host (the scheduler) with status SUSPENDED — exactly the cooperative
//! preemption model L552 implements with SysTick + PSP context save/restore.
//!
//! The timer is armed on every `enclave_enter` and disabled the moment the
//! enclave suspends or terminates, so the untrusted host itself is never
//! preempted (it is just the scheduler loop).

/// Machine timer-slice length, in CLINT `mtime` ticks (QEMU `virt` runs the
/// CLINT at 10 MHz, so this is ~5 ms). Chosen so the demo enclave is preempted a
/// handful of times before it completes, while staying well above the trap
/// save/restore cost so each slice makes forward progress.
pub const QUANTUM_TICKS: u32 = 50_000;

#[cfg(target_arch = "riscv32")]
const CLINT_MTIMECMP: usize = 0x0200_4000; // hart 0
#[cfg(target_arch = "riscv32")]
const CLINT_MTIME: usize = 0x0200_BFF8;

/// `mie.MTIE` — machine timer-interrupt enable (bit 7).
#[cfg(target_arch = "riscv32")]
const MIE_MTIE: u32 = 1 << 7;

/// Arm `mtimecmp = mtime + QUANTUM_TICKS` using the standard race-free RV32
/// 64-bit write sequence (set the high word to all-ones first so no spurious
/// interrupt fires mid-update).
#[cfg(target_arch = "riscv32")]
pub fn arm() {
    use core::ptr::{read_volatile, write_volatile};
    // SAFETY: CLINT MMIO at fixed QEMU `virt` addresses; M-mode owns the timer.
    unsafe {
        let mt_lo = CLINT_MTIME as *const u32;
        let mt_hi = (CLINT_MTIME + 4) as *const u32;
        // Read the 64-bit mtime atomically (retry on high-word rollover).
        let (lo, hi) = loop {
            let h1 = read_volatile(mt_hi);
            let l = read_volatile(mt_lo);
            let h2 = read_volatile(mt_hi);
            if h1 == h2 {
                break (l, h1);
            }
        };
        let target = (((hi as u64) << 32) | lo as u64).wrapping_add(QUANTUM_TICKS as u64);
        let cmp_lo = CLINT_MTIMECMP as *mut u32;
        let cmp_hi = (CLINT_MTIMECMP + 4) as *mut u32;
        write_volatile(cmp_hi, 0xFFFF_FFFF);
        write_volatile(cmp_lo, target as u32);
        write_volatile(cmp_hi, (target >> 32) as u32);
    }
}

/// Enable machine timer interrupts (`mie.MTIE`). Machine interrupts are taken
/// unconditionally while the hart is in S/U, so this is all that is needed to
/// preempt the enclave/host — `mstatus.MIE` only gates M-mode itself.
#[cfg(target_arch = "riscv32")]
pub fn enable() {
    // SAFETY: sets one architecturally-defined mie bit.
    unsafe { core::arch::asm!("csrs mie, {b}", b = in(reg) MIE_MTIE) };
}

/// Disable machine timer interrupts (`mie.MTIE`). Called the instant the
/// enclave suspends or terminates so the host scheduler runs un-preempted.
#[cfg(target_arch = "riscv32")]
pub fn disable() {
    // SAFETY: clears one architecturally-defined mie bit.
    unsafe { core::arch::asm!("csrc mie, {b}", b = in(reg) MIE_MTIE) };
}

// ── Host stubs (off-target builds) ──────────────────────────────────────────
#[cfg(not(target_arch = "riscv32"))]
pub fn arm() {}
#[cfg(not(target_arch = "riscv32"))]
pub fn enable() {}
#[cfg(not(target_arch = "riscv32"))]
pub fn disable() {}
