//! Virtualized CLINT timer for the S-mode guest. Umbra owns the real `mtimecmp`;
//! the guest's `mtimecmp` MMIO word is carved out of its grant (mod.rs) so its
//! writes fault here. We keep a per-domain virtual deadline and program the real
//! `mtimecmp = min()` — currently the only active domain is the guest; the `min()`
//! is the hook for the enclave-preemption deadline (`platform_impl::timer`).

use core::cell::UnsafeCell;
use umbra_riscv_arch::paravirt::{vtimer_due, vtimer_min};
use umbra_riscv_arch::trap::TrapFrame;

const CLINT_MTIMECMP: usize = 0x0200_4000; // hart 0
const CLINT_MTIME: usize = 0x0200_BFF8;
/// The 8-byte `mtimecmp` window carved out of the guest's MMIO grant.
const MTIMECMP_LO: u32 = 0x0200_4000;
const MTIMECMP_HI_END: u32 = 0x0200_4008;

struct VTimer {
    /// Guest's virtual `mtimecmp` (`None` until first programmed).
    guest_deadline: Option<u64>,
    /// Latched low word between the guest's lo/hi write pair (RV32 writes lo then hi).
    pending_lo: u32,
}
struct VTimerCell(UnsafeCell<VTimer>);
// SAFETY: single-hart cooperative monitor; the trap handler is the sole accessor.
unsafe impl Sync for VTimerCell {}
static VTIMER: VTimerCell = VTimerCell(UnsafeCell::new(VTimer {
    guest_deadline: None,
    pending_lo: 0,
}));

fn vt() -> &'static mut VTimer {
    // SAFETY: sole accessor in the cooperative single-hart handler.
    unsafe { &mut *VTIMER.0.get() }
}

/// Read the live 64-bit CLINT `mtime` (race-free high-word retry).
pub fn mtime() -> u64 {
    use core::ptr::read_volatile;
    // SAFETY: fixed CLINT MMIO; M-mode owns the timer.
    unsafe {
        let lo = CLINT_MTIME as *const u32;
        let hi = (CLINT_MTIME + 4) as *const u32;
        loop {
            let h1 = read_volatile(hi);
            let l = read_volatile(lo);
            let h2 = read_volatile(hi);
            if h1 == h2 {
                return ((h1 as u64) << 32) | l as u64;
            }
        }
    }
}

/// Program the real `mtimecmp` from the active virtual deadlines. Currently only
/// the guest is active; the enclave-preemption deadline joins the `min()` later.
fn reprogram() {
    use core::ptr::write_volatile;
    let target = vtimer_min(&[vt().guest_deadline]).unwrap_or(u64::MAX);
    // SAFETY: standard race-free RV32 64-bit mtimecmp write.
    unsafe {
        let cmp_lo = CLINT_MTIMECMP as *mut u32;
        let cmp_hi = (CLINT_MTIMECMP + 4) as *mut u32;
        write_volatile(cmp_hi, 0xFFFF_FFFF);
        write_volatile(cmp_lo, target as u32);
        write_volatile(cmp_hi, (target >> 32) as u32);
    }
}

/// True iff `addr` is inside the carved 8-byte guest `mtimecmp` window.
pub fn is_mtimecmp(addr: u32) -> bool {
    (MTIMECMP_LO..MTIMECMP_HI_END).contains(&addr)
}

/// Emulate the guest's faulting `mtimecmp` access. `is_store` distinguishes the
/// decoded faulting instruction; `store_val`/`rd` come from the trap frame.
/// `insn_len` is the byte length of the faulting instruction (2 for an RVC
/// `c.lw`/`c.sw`, 4 for a 32-bit `lw`/`sw`) — Tock is built `riscv32imac`, so the
/// CLINT accesses are compressed. Returns `true` (handled), advancing `mepc` by
/// the instruction length. The decode is done by the dispatch
/// (`try_handle_vtimer_fault`); this entry point takes the operands.
pub fn emulate_access(
    frame: &mut TrapFrame,
    addr: u32,
    is_store: bool,
    store_val: u32,
    rd: u8,
    insn_len: u32,
) -> bool {
    let lo = addr == MTIMECMP_LO;
    if is_store {
        if lo {
            vt().pending_lo = store_val; // latch; commit on the hi write
        } else {
            let d = ((store_val as u64) << 32) | vt().pending_lo as u64;
            vt().guest_deadline = Some(d);
            reprogram();
        }
    } else if frame_rd_valid(rd) {
        let d = vt().guest_deadline.unwrap_or(u64::MAX);
        frame.regs[rd as usize] = if lo { d as u32 } else { (d >> 32) as u32 };
    }
    frame.mepc += insn_len;
    true
}

fn frame_rd_valid(rd: u8) -> bool {
    rd != 0
}

/// On a machine timer interrupt with no enclave to preempt: if the guest's
/// deadline is due, the dispatch reflects cause-7 (see interrupt.rs). This reports
/// whether the guest deadline is due now, and re-arms past it so the next tick is
/// the guest's next deadline (the guest reprograms `mtimecmp` in its handler).
pub fn guest_due() -> bool {
    vtimer_due(vt().guest_deadline, mtime())
}
