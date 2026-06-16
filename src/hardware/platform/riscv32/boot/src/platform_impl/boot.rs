//! Boot bring-up — the `init_*` phases of the `PlatformBoot` sequence.
//!
//! On QEMU `virt` the clocks and GPIO need no setup, the "UART init" just emits
//! the boot line, and the security phase installs the whole M-mode protection
//! stack: MMU off (Bare), trap vector + trap stack, `ecall` routing to M, the
//! outer PMP fence, and the per-purpose SPMP regions.

use umbra_riscv_arch::csr::{self, PmpCfg};
use umbra_riscv_arch::pmp::{self, Region};
use umbra_riscv_arch::{spmp, trap};

use super::Rv32VirtPlatform;
use crate::{crypto_impl, raw_print, secure_kernel};
use secure_kernel::{ENC_REGION_BASE, ENC_REGION_SIZE, HOST_REGION_BASE, HOST_REGION_SIZE};

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
    /// M, program the outer PMP fence, and set up the SPMP regions.
    pub(super) fn init_security_impl(&self) {
        csr::disable_mmu();
        trap::set_mtvec(_mtrap_entry as *const () as usize);
        // SAFETY: `_stack_top` is the linker-defined top of RAM.
        trap::set_mscratch(core::ptr::addr_of!(_stack_top) as usize);
        trap::route_ecalls_to_m();
        // ePMP self-lock (PMP slot 1, lowest index → highest priority): a Locked
        // R+X rule over the monitor's own `.text`. The Lock bit binds it to
        // M-mode too, so the monitor cannot overwrite its own code — a store
        // into `.text` faults. Programmed BEFORE the broad grant so it wins for
        // the `.text` range.
        // SAFETY: linker-defined bounds of the monitor's `.text`.
        let stext = core::ptr::addr_of!(_stext) as u32;
        let etext = core::ptr::addr_of!(_etext) as u32;
        let _ = pmp::self_lock_monitor(1, &Region::new(stext, etext));
        // Outer PMP fence (slot 3, higher index): grant the inter-domain RAM
        // window. Unlocked, so M-mode bypasses it (retaining its data access to
        // the host image + Secure ESS); U/S get the envelope and SPMP restricts
        // within. The `.text` lock above takes priority for its sub-range.
        let _ = pmp::set_tor(
            3,
            &Region::new(0x8000_0000, 0x9000_0000),
            PmpCfg::new().rwx(),
        );
        setup_spmp();
        raw_print::print_str(
            "[UMBRASecureBoot] PMP/sPMP setup completed (monitor .text ePMP-locked)\n",
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

/// Program the SPMP regions for the externally-loaded U-mode host and its
/// embedded enclave (S-mode and M-mode default-allow; U-mode is default-denied
/// unless a rule grants it):
///
/// - host working region — **UMODE** R|W|X: the host runs entirely here
///   (code/rodata/data/bss/stack).
/// - enclave + scan region — **SHARED** R|X: the host (U) reads it to scan for
///   the enclave header, and the enclave (S) fetches its code from it.
/// - the enclave stack (`ENC_SP`) and everything else is left **unruled**, so
///   S-mode default-allows it while U-mode is default-denied — that denial is
///   the SPMP fence keeping the untrusted host out of the enclave's stack and
///   the monitor's memory.
fn setup_spmp() {
    use spmp::cfg_bits as c;
    spmp::set_mpmpdeleg(32); // delegate rules so entries are programmable + active
    spmp::write_napot_entry(0, ENC_REGION_BASE, ENC_REGION_SIZE, c::R | c::X | c::SHARED);
    spmp::write_napot_entry(
        1,
        HOST_REGION_BASE,
        HOST_REGION_SIZE,
        c::R | c::W | c::X | c::UMODE,
    );
}
