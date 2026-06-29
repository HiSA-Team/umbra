//! Gateway shadow PMP table + emulation. The S-mode guest believes it owns
//! M-mode PMP; its PMP CSR accesses trap to M and land here. We mirror the
//! registers in a shadow, and for every PMP entry the guest writes we program a
//! clamped U-mode sPMP entry (index 2 + i) so the guest's intent fences its
//! U-tasks. The host (S) is never gated by sPMP; only its U-tasks are.

use umbra_riscv_arch::paravirt::{
    apply_csr, clamp_to_world, decode_csr, decode_pmp_napot, is_mcsr, is_mcsr_rw, is_pmp_csr,
    mcsr_ro_value, pmp_csr_index, CsrOp, MCSR_RW,
};
use umbra_riscv_arch::spmp::{self, cfg_bits};
use umbra_riscv_arch::trap::TrapFrame;

use super::{HOST_REGION_BASE, HOST_WORLD_END};

/// Guest PMP entries we shadow (sPMP entries 2..=7 → 6 PMP entries).
const SHADOW_ENTRIES: usize = 6;
/// First sPMP entry index the guest shadow uses (0/1 are the enclave's).
const SHADOW_SPMP_BASE: u32 = 2;

struct GuestPmp {
    /// pmpcfg packed words 0..3 (RV32: 4 entry-bytes each).
    cfg: [u32; 4],
    /// pmpaddr entries 0..15.
    addr: [u32; 16],
}

use core::cell::UnsafeCell;
struct Shadow(UnsafeCell<GuestPmp>);
// SAFETY: single-hart cooperative monitor; the trap handler is the sole accessor.
unsafe impl Sync for Shadow {}
static SHADOW: Shadow = Shadow(UnsafeCell::new(GuestPmp {
    cfg: [0; 4],
    addr: [0; 16],
}));

fn shadow() -> &'static mut GuestPmp {
    // SAFETY: sole accessor in the cooperative single-hart handler.
    unsafe { &mut *SHADOW.0.get() }
}

/// Read the cfg byte for PMP entry `i` (0..15) from the shadow.
fn cfg_byte(g: &GuestPmp, i: usize) -> u8 {
    (g.cfg[i / 4] >> ((i % 4) * 8)) as u8
}

/// Virtual machine-CSR file for the S-mode guest. One slot per `MCSR_RW` entry,
/// indexed by position in `MCSR_RW`. Read-only CSRs come from `mcsr_ro_value`.
struct GuestMCsr {
    vals: [u32; MCSR_RW.len()],
}

struct MCsrCell(UnsafeCell<GuestMCsr>);
// SAFETY: single-hart cooperative monitor; the trap handler is the sole accessor.
unsafe impl Sync for MCsrCell {}
static MCSR: MCsrCell = MCsrCell(UnsafeCell::new(GuestMCsr {
    vals: [0; MCSR_RW.len()],
}));

fn mcsr() -> &'static mut GuestMCsr {
    // SAFETY: sole accessor in the cooperative single-hart handler.
    unsafe { &mut *MCSR.0.get() }
}

/// Read the guest's view of machine CSR `csr` (RO constant or RW shadow).
fn read_mcsr(g: &GuestMCsr, csr: u16) -> u32 {
    if let Some(v) = mcsr_ro_value(csr) {
        return v;
    }
    match MCSR_RW.iter().position(|&c| c == csr) {
        Some(i) => g.vals[i],
        None => 0,
    }
}

/// Read the real machine `mip` CSR (hardware interrupt-pending bits).
fn read_real_mip() -> u32 {
    let v: u32;
    // SAFETY: reads the architectural mip CSR (M-mode).
    unsafe { core::arch::asm!("csrr {r}, mip", r = out(reg) v) };
    v
}

/// Emulate a machine-CSR op against the virtual file. Returns `true` (handled).
fn emulate_mcsr(frame: &mut TrapFrame, op: CsrOp) -> bool {
    use umbra_riscv_arch::paravirt::CsrKind::*;
    let operand = match op.kind {
        Rwi | Rsi | Rci => op.rs1_uimm as u32,
        _ => g_reg(frame, op.rs1_uimm),
    };
    let g = mcsr();
    let old = read_mcsr(g, op.csr);
    // `mip` (0x344) is hardware-driven: MTIP tracks `mtime >= mtimecmp` (the vtimer
    // keeps the real `mtimecmp` = the guest's deadline) and MEIP tracks the PLIC
    // (independent of the MEIE mask). The guest must read the REAL pending bits, not
    // the shadow — otherwise it busy-loops servicing a timer/PLIC interrupt whose
    // CSR view never clears (it "disables" the timer by writing `mtimecmp`, which the
    // vtimer absorbs without touching the shadow `mip`).
    let rd_val = if op.csr == 0x344 {
        read_real_mip()
    } else {
        old
    };
    if op.rd != 0 {
        frame.regs[op.rd as usize] = rd_val; // read-return the (real, for mip) value
    }
    if is_mcsr_rw(op.csr) {
        let new = apply_csr(op.kind, old, operand);
        if let Some(i) = MCSR_RW.iter().position(|&c| c == op.csr) {
            g.vals[i] = new; // shadow only — no real machine effect (incl. mseccfg)
        }
    }
    frame.mepc += 4; // Zicsr is always 32-bit
    true
}

/// Read the guest's shadow value of machine CSR `csr` (RW shadow slot; 0 if
/// the CSR is not in the shadow). For RO CSRs use `mcsr_ro_value`.
pub fn shadow_get(csr: u16) -> u32 {
    read_mcsr(mcsr(), csr)
}

/// Write the guest's shadow value of machine CSR `csr` (no effect if `csr` is
/// not an `MCSR_RW` entry).
pub fn shadow_set(csr: u16, val: u32) {
    let pos = MCSR_RW.iter().position(|&c| c == csr);
    if let Some(i) = pos {
        mcsr().vals[i] = val;
    }
}

/// Program (or disable) sPMP entry `2 + i` from shadow PMP entry `i`.
fn program_spmp_for(g: &GuestPmp, i: usize) {
    let spmp_idx = SHADOW_SPMP_BASE + i as u32;
    if spmp_idx >= SHADOW_SPMP_BASE + SHADOW_ENTRIES as u32 {
        return; // beyond the shadow budget
    }
    match decode_pmp_napot(cfg_byte(g, i), g.addr[i]) {
        Some((base, end, r, w, x)) => {
            match clamp_to_world(base, end, HOST_REGION_BASE, HOST_WORLD_END) {
                Some((b, e)) => {
                    let mut bits = cfg_bits::UMODE;
                    if r {
                        bits |= cfg_bits::R;
                    }
                    if w {
                        bits |= cfg_bits::W;
                    }
                    if x {
                        bits |= cfg_bits::X;
                    }
                    spmp::write_napot_entry(spmp_idx, b, e - b, bits);
                }
                None => spmp::disable_entry(spmp_idx), // outside world → deny
            }
        }
        None => spmp::disable_entry(spmp_idx), // OFF / non-NAPOT → no grant
    }
}

/// Handle a trapped guest PMP CSR op. Returns `true` if it was emulated.
pub fn try_handle_paravirt_csr(frame: &mut TrapFrame) -> bool {
    if frame.mcause != 2 || !frame.trapped_from_supervisor() {
        return false; // not an illegal instruction from the guest
    }
    // SAFETY: mepc points at the guest's trapping instruction in the host region;
    // M-mode bypasses the unlocked PMP grant, so the read is valid.
    let word = unsafe { core::ptr::read_volatile(frame.mepc as *const u32) };
    let op = match decode_csr(word) {
        Some(op) => op,
        None => return false, // genuine illegal instruction → fault handler
    };
    // Smstateen (mstateen0 bit 60 cleared) routes the guest's DIRECT
    // sPMP/indirect-CSR access here too (siselect 0x150 / sireg 0x151 / sireg2
    // 0x152). The guest must go through PMP emulation, so deny the direct write:
    // skip it (no effect) and log once. Placed before the PMP-CSR filter so the
    // indirect range is handled rather than falling through to the fault dump.
    if matches!(op.csr, 0x150 | 0x151 | 0x152) {
        crate::raw_print::print_str("[GW] denied direct guest sPMP write\n");
        frame.mepc += 4;
        return true;
    }
    if is_mcsr(op.csr) {
        let handled = emulate_mcsr(frame, op);
        if matches!(op.csr, 0x300 | 0x304) {
            crate::secure_kernel::interrupt::redeliver_pending(frame);
        }
        return handled;
    }
    if !is_pmp_csr(op.csr) {
        return false; // not an emulated CSR → genuine illegal instruction
    }
    let (is_cfg, idx) = match pmp_csr_index(op.csr) {
        Some(v) => v,
        None => return false,
    };
    let g = shadow();
    // operand: register value, or zero-extended 5-bit immediate for the i-forms.
    use umbra_riscv_arch::paravirt::CsrKind::*;
    let operand = match op.kind {
        Rwi | Rsi | Rci => op.rs1_uimm as u32,
        _ => g_reg(frame, op.rs1_uimm),
    };
    // read-return the OLD value into rd (x0 discards)
    let old = if is_cfg { g.cfg[idx] } else { g.addr[idx] };
    if op.rd != 0 {
        frame.regs[op.rd as usize] = old;
    }
    let new = apply_csr(op.kind, old, operand);
    if is_cfg {
        g.cfg[idx] = new;
        // a pmpcfg write touches entries [idx*4 .. idx*4+4)
        for e in idx * 4..idx * 4 + 4 {
            program_spmp_for(g, e);
        }
    } else {
        g.addr[idx] = new;
        program_spmp_for(g, idx);
    }
    frame.mepc += 4; // Zicsr is always 32-bit
    true
}

/// Read register `n` from the trap frame (x0 reads as 0).
fn g_reg(frame: &TrapFrame, n: u8) -> u32 {
    if n == 0 {
        0
    } else {
        frame.regs[n as usize]
    }
}

/// Re-install every live guest shadow sPMP entry (called on entry to host-world).
pub fn reinstall_shadow() {
    let g = shadow();
    for i in 0..SHADOW_ENTRIES {
        program_spmp_for(g, i);
    }
}

/// Disable every guest shadow sPMP entry (called on entry to enclave-world, so a
/// guest UMODE rule never governs the enclave U-task).
pub fn disable_shadow() {
    for i in 0..SHADOW_ENTRIES as u32 {
        spmp::disable_entry(SHADOW_SPMP_BASE + i);
    }
}
