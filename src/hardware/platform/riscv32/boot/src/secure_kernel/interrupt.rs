//! Reflect machine interrupts into the S-mode guest (manual virtual-trap
//! injection) and emulate the guest's `mret`. Builds on the shadow M-CSR file
//! (paravirt.rs) and the pure bit-math (umbra-riscv-arch::paravirt).

use umbra_riscv_arch::paravirt::{
    irq_mcause, is_mret, mstatus_mpp_is_supervisor, mstatus_trap_enter, mstatus_trap_return,
};
use umbra_riscv_arch::trap::TrapFrame;

use super::paravirt::{shadow_get, shadow_set};

// Shadow machine-CSR numbers.
const MSTATUS: u16 = 0x300;
const MIE: u16 = 0x304;
const MTVEC: u16 = 0x305;
const MEPC: u16 = 0x341;
const MCAUSE: u16 = 0x342;
const MIP: u16 = 0x344;

const MSTATUS_MIE_BIT: u32 = 1 << 3;
/// The machine interrupt bits Umbra virtualizes for the guest: timer (7) +
/// external (11). The real `mie`/`mip` machine bits are owned here.
const VIRT_IRQ_BITS: u32 = (1 << 7) | (1 << 11);

/// `mie`/`mip` bit for an interrupt `cause` (7 timer, 11 external).
fn irq_bit(cause: u32) -> u32 {
    1 << cause
}

/// True iff the guest currently accepts interrupt `cause`
/// (`shadow.mstatus.MIE && shadow.mie[cause]`).
fn guest_can_take(cause: u32) -> bool {
    shadow_get(MSTATUS) & MSTATUS_MIE_BIT != 0 && shadow_get(MIE) & irq_bit(cause) != 0
}

/// Mask `cause` in the REAL `mie` so the source stops re-trapping into M while the
/// interrupt is outstanding to the guest. A machine interrupt is taken on every
/// instruction boundary while the hart is in S/U, so a level-asserted source (the
/// 16550 THRE/RX line, an expired `mtimecmp`) would storm the monitor until the
/// guest claims/reprograms it. We re-arm the bit in `sync_real_mie_to_guest` once
/// the guest acks (on its `mret`).
fn real_mie_clear(cause: u32) {
    // SAFETY: clears one architecturally-defined mie bit.
    unsafe { core::arch::asm!("csrc mie, {b}", b = in(reg) irq_bit(cause)) };
}

/// Re-arm the REAL virtualized `mie` bits (timer/external) to match the guest's
/// shadow `mie`. Called once the guest has serviced (and claimed at the PLIC /
/// reprogrammed `mtimecmp`) the reflected interrupt, so the now-quiesced source
/// can fire again. Only the timer/external bits are touched.
fn sync_real_mie_to_guest() {
    let want = shadow_get(MIE) & VIRT_IRQ_BITS;
    // SAFETY: sets/clears only the two virtualized mie bits to the guest's intent.
    unsafe {
        core::arch::asm!("csrs mie, {s}", s = in(reg) want);
        core::arch::asm!("csrc mie, {c}", c = in(reg) (!want) & VIRT_IRQ_BITS);
    }
}

/// Reconcile the guest's shadow `mip` timer/external bits with the real hart.
/// After the guest claims the device (PLIC complete / `mtimecmp` reprogram) the
/// real `MEIP`/`MTIP` reflect reality, so mirror them into the shadow the guest
/// reads — otherwise a stale shadow-pending bit makes the guest re-dispatch.
fn sync_shadow_mip_from_real() {
    let real: u32;
    // SAFETY: reads the architectural mip CSR.
    unsafe { core::arch::asm!("csrr {r}, mip", r = out(reg) real) };
    shadow_set(
        MIP,
        (shadow_get(MIP) & !VIRT_IRQ_BITS) | (real & VIRT_IRQ_BITS),
    );
}

/// Reflect machine interrupt `cause` into the guest. Always mask the real source
/// first (it is level-asserted and would storm) and mirror the pending bit into
/// the guest's shadow `mip`. If the guest has interrupts masked, leave it latched
/// pending and resume — `redeliver_pending` injects it once the guest unmasks.
/// Otherwise build the virtual M-trap into the guest's `mtvec` handler; the
/// dispatch does the real `mret` after this returns (`frame.mepc` = guest mtvec).
pub fn inject_guest_irq(frame: &mut TrapFrame, cause: u32) {
    real_mie_clear(cause);
    shadow_set(MIP, shadow_get(MIP) | irq_bit(cause));
    if !guest_can_take(cause) {
        return; // latched pending; redelivered when the guest unmasks
    }
    // Virtual trap: stash guest PC, set cause, transform mstatus, redirect to mtvec.
    shadow_set(MEPC, frame.mepc);
    shadow_set(MCAUSE, irq_mcause(cause));
    shadow_set(MSTATUS, mstatus_trap_enter(shadow_get(MSTATUS)));
    // Direct mode; ignore the mtvec mode bits. frame still has MPP=S (host
    // world), so the real mret lands back in S at the guest's mtvec.
    frame.mepc = shadow_get(MTVEC) & !0x3;
}

/// Emulate the guest's `mret` (illegal-instruction trap from S). Pops the virtual
/// trap: restore shadow mstatus, return real PC to shadow `mepc`. Returns `true`
/// if the trapping instruction was `mret`. The guest has now serviced the
/// reflected interrupt, so reconcile shadow `mip` with the (claimed) real sources
/// and re-arm the real `mie` bits it wants, then redeliver anything still pending.
pub fn try_handle_mret(frame: &mut TrapFrame) -> bool {
    // SAFETY: mepc points at the guest's trapping instruction in the host region;
    // M-mode bypasses the unlocked PMP grant, so the read is valid.
    let word = unsafe { core::ptr::read_volatile(frame.mepc as *const u32) };
    if !is_mret(word) {
        return false;
    }
    let restored = mstatus_trap_return(shadow_get(MSTATUS));
    shadow_set(MSTATUS, restored);
    frame.mepc = shadow_get(MEPC);
    // MPP-aware return: supervisor now, user once nested U-entry is supported.
    // frame.mstatus.MPP is already supervisor here.
    if mstatus_mpp_is_supervisor(restored) {
        frame.return_to_supervisor();
    } else {
        frame.return_to_user();
    }
    sync_shadow_mip_from_real();
    sync_real_mie_to_guest();
    redeliver_pending(frame);
    true
}

/// After the guest re-enables interrupts, inject the highest-priority still-pending
/// cause (external before timer). Called from `mret` emulation and the `mstatus`/
/// `mie` shadow-write path. `inject_guest_irq` owns the shadow `mip` bit; it is
/// cleared by `sync_shadow_mip_from_real` once the guest claims the source.
pub fn redeliver_pending(frame: &mut TrapFrame) {
    for cause in [11u32, 7u32] {
        if shadow_get(MIP) & irq_bit(cause) != 0 && guest_can_take(cause) {
            inject_guest_irq(frame, cause);
            return;
        }
    }
}
