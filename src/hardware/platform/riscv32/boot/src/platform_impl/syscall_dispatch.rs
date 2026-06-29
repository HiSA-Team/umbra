//! Trap entry dispatch + untrusted-world preparation.
//!
//! `_mtrap_entry` (in `start.S`) saves the trap frame and calls [`rust_mtrap`],
//! the single mediation point for every ring transition: `ecall`s route to the
//! enclave API surface, everything else (memory-protection faults) goes to the
//! fault handler. This is the RISC-V analog of the STM32 platforms' SVC/SysTick
//! trampolines.

use umbra_riscv_arch::trap::{self, Trap, TrapFrame};

use super::{timer, Rv32VirtPlatform};
use crate::{api_impl, handlers, secure_kernel};

/// The M-mode trap handler, called from `_mtrap_entry`.
#[no_mangle]
pub extern "C" fn rust_mtrap(frame: &mut TrapFrame) {
    match trap::decode(frame.mcause, frame.mtval) {
        Trap::EcallFromU | Trap::EcallFromS => api_impl::dispatch(frame),
        Trap::TimerInterrupt => {
            // Enclave preemption first; else if the guest's vtimer deadline is due,
            // reflect a machine-timer interrupt into the S-guest; else a stray tick.
            if !secure_kernel::try_preempt(frame) {
                if secure_kernel::vtimer_guest_due() {
                    secure_kernel::inject_guest_irq(frame, 7);
                } else {
                    timer::disable();
                }
            }
        }
        Trap::ExternalInterrupt => secure_kernel::inject_guest_irq(frame, 11),
        _ => {
            if !secure_kernel::try_handle_return(frame)
                && !secure_kernel::try_handle_ess_miss(frame)
                && !secure_kernel::try_handle_mret(frame)
                && !try_handle_vtimer_fault(frame)
                && !secure_kernel::try_handle_paravirt_csr(frame)
            {
                handlers::unexpected_trap(frame);
            }
        }
    }
}

/// A guest access to the carved `mtimecmp` window faults (load/store access).
/// Decode the faulting word load/store enough to emulate it. Tock is built
/// `riscv32imac`, so its CLINT accesses are 16-bit RVC (`c.lw`/`c.sw`); a wrong
/// length here both mis-reads the operands AND mis-advances `mepc` (skipping the
/// next 2-byte instruction), so both the 16- and 32-bit encodings are handled.
fn try_handle_vtimer_fault(frame: &mut TrapFrame) -> bool {
    let addr = match trap::decode(frame.mcause, frame.mtval) {
        Trap::LoadAccessFault { addr } | Trap::StoreAccessFault { addr } => addr,
        _ => return false,
    };
    if !secure_kernel::is_mtimecmp(addr) {
        return false;
    }
    // SAFETY: mepc is the guest's faulting instruction in the host region.
    let lo16 = unsafe { core::ptr::read_volatile(frame.mepc as *const u16) };
    let (is_store, store_val, rd, insn_len) = if lo16 & 0x3 != 0x3 {
        // 16-bit compressed. The CL (`c.lw`) / CS (`c.sw`) formats address regs
        // x8..x15 via the 3-bit field at bits 4:2 (rd' for loads, rs2' for stores).
        let funct3 = (lo16 >> 13) & 0x7;
        let reg = 8 + ((lo16 >> 2) & 0x7) as u8;
        match (lo16 & 0x3, funct3) {
            (0b00, 0b110) => (true, frame.regs[reg as usize], 0u8, 2u32), // c.sw
            (0b00, 0b010) => (false, 0u32, reg, 2u32),                    // c.lw
            _ => return false, // not a word load/store we model
        }
    } else {
        // 32-bit. STORE (sw) opcode 0x23, LOAD (lw) opcode 0x03.
        let word = unsafe { core::ptr::read_volatile(frame.mepc as *const u32) };
        let opcode = word & 0x7f;
        if opcode != 0x23 && opcode != 0x03 {
            return false;
        }
        let is_store = opcode == 0x23;
        let rd = ((word >> 7) & 0x1f) as u8; // for loads
        let rs2 = ((word >> 20) & 0x1f) as u8; // for stores
        let store_val = if rs2 == 0 {
            0
        } else {
            frame.regs[rs2 as usize]
        };
        (is_store, store_val, rd, 4u32)
    };
    secure_kernel::vtimer_emulate(frame, addr, is_store, store_val, rd, insn_len)
}

impl Rv32VirtPlatform {
    /// Prepare the hand-off to the untrusted world. The PMP/SPMP grants and the
    /// trap vector are already programmed in `init_security`, so there is
    /// nothing further to stage on QEMU; the method exists to match the
    /// platform boot contract.
    pub(super) fn configure_untrusted_boot_impl(&self) {}
}
