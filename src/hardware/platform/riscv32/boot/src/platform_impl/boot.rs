//! Boot bring-up — the `init_*` phases of the `PlatformBoot` sequence.
//!
//! On QEMU `virt` the clocks and GPIO need no setup, the "UART init" just emits
//! the boot line, and the security phase installs the whole M-mode protection
//! stack: MMU off (Bare), trap vector + trap stack, `ecall` routing to M, and
//! the outer PMP fence (the host-world context).

use umbra_riscv_arch::csr;
use umbra_riscv_arch::pmp::{self, Region};
use umbra_riscv_arch::trap;

use super::Rv32VirtPlatform;
use crate::{crypto_impl, raw_print, secure_kernel};

extern "C" {
    fn _mtrap_entry();
    static _stack_top: u8;
    static _stext: u8;
    static _etext: u8;
}

impl Rv32VirtPlatform {
    /// QEMU `virt` runs at a fixed rate — no clock tree to configure.
    pub(super) fn init_clocks_impl(&self) {}

    /// No board GPIO on the `virt` machine.
    pub(super) fn init_gpio_impl(&self) {}

    /// The 16550 UART needs no initialization on QEMU; emit the Umbra logo and
    /// boot banner — the same output the STM32 platforms print.
    pub(super) fn init_uart_impl(&self) {
        raw_print::print_str("\n");
        raw_print::print_str("   ___       ___       ___       ___       ___   \n");
        raw_print::print_str("  /\\__\\     /\\__\\     /\\  \\     /\\  \\     /\\  \\  \n");
        raw_print::print_str(" /:/ _/_   /::L_L_   /::\\  \\   /::\\  \\   /::\\  \\ \n");
        raw_print::print_str("/:/_/\\__\\ /:/L:\\__\\ /::\\:\\__\\ /::\\:\\__\\ /::\\:\\__\\\n");
        raw_print::print_str("\\:\\/:/  / \\/_/:/  / \\:\\::/  / \\;:::/  / \\/\\::/  /\n");
        raw_print::print_str(" \\::/  /    /:/  /   \\::/  /   |:\\/__/    /:/  / \n");
        raw_print::print_str("  \\/__/     \\/__/     \\/__/     \\|__|     \\/__/  \n");
        raw_print::print_str("\n");
        raw_print::print_str("[UMBRASecureBoot] Secure Boot started\n");
    }

    /// Install the M-mode protection stack: keep the MMU off (physical
    /// addressing only), point `mtvec` at the trap entry, route all `ecall`s to
    /// M, and install the host-world PMP context (sPMP is off in this slice).
    pub(super) fn init_security_impl(&self) {
        csr::disable_mmu();
        trap::set_mtvec(_mtrap_entry as *const () as usize);
        // SAFETY: `_stack_top` is the linker-defined top of RAM.
        trap::set_mscratch(core::ptr::addr_of!(_stack_top) as usize);
        trap::route_ecalls_to_m();
        // ePMP self-lock (PMP slot 1, lowest index → highest priority): a Locked
        // R+X rule over the monitor's own `.text`. The Lock bit binds it to
        // M-mode too, so the monitor cannot overwrite its own code — a store
        // into `.text` faults. Programmed BEFORE `enter_host_world` so it wins
        // for the `.text` range (slot 1 < slot 3 → lower PMP index = higher
        // priority).
        // SAFETY: linker-defined bounds of the monitor's `.text`.
        let stext = core::ptr::addr_of!(_stext) as u32;
        let etext = core::ptr::addr_of!(_etext) as u32;
        let _ = pmp::self_lock_monitor(1, &Region::new(stext, etext));
        // Outer fence is per-world (see secure_kernel::enter_host_world /
        // enter_enclave_world). Delegate sPMP rules once (num_deleg_rules =
        // 64-32 = 32) AND set the PMP enforcement window (max_pmp_index = 32).
        // Load-bearing for both the per-world PMP grants and the guest shadow /
        // enclave sPMP entries. MUST precede enter_host_world(), which now
        // programs sPMP (disable enclave entries 0/1 + reinstall guest shadow).
        umbra_riscv_arch::spmp::set_mpmpdeleg(32);
        // Smstateen hardening: deny the S-mode guest the indirect-CSR mechanism
        // (siselect/sireg) so it cannot program sPMP directly — it must go
        // through the PMP->sPMP gateway. M always retains access; the host keeps
        // every other mstateen0 feature. Inert unless the CPU has Smstateen.
        umbra_riscv_arch::spmp::gate_guest_indirect_csr();
        secure_kernel::enter_host_world();
        raw_print::print_str(
            "[UMBRASecureBoot] PMP world-switch armed (host-world; monitor .text ePMP-locked)\n",
        );
    }

    /// Initialize the monitor's crypto engine + enclave kernel.
    pub(super) fn init_kernel_impl(&self) {
        crypto_impl::init();
        secure_kernel::init();
        raw_print::print_str("[UMBRASecureBoot] Kernel Initialized\n");
    }

    /// No external flash on QEMU; the enclave blob is in-image.
    pub(super) fn init_external_flash_impl(&self) -> bool {
        false
    }
}
