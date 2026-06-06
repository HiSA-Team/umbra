//! Sleep / wakeup hooks and the final hand-off from Secure to Non-Secure
//! world.
//!: extracted from `platform_impl.rs`. The
//! `jump_to_ns` path is the last thing the Secure kernel runs at boot —
//! after this the NS host owns the CPU until a Secure call comes through
//! the NSC veneers in `arm/asm/nsc_veneers.s` (see invariant CJ4 in
//! `mod.rs`).
//! `#[cfg(feature = "benchmark")]` cold/warm-boot detection via RCC_CSR
//! BORRSTF is preserved verbatim — this path drives the L552 / L562
//! TACLeBench harness in `benchmark.rs`.

use super::Stm32l5Platform;

impl Stm32l5Platform {
    pub(super) fn jump_to_ns_impl(&self) -> ! {
        crate::raw_print::print_str("[UMBRASecureBoot] Jumping to Non-Secure World\n");

        #[cfg(feature = "benchmark")]
        {
            const RCC_CSR: *mut u32 = 0x5002_1094 as *mut u32;
            const BORRSTF_BIT: u32 = 1 << 27;
            const RMVF_BIT: u32 = 1 << 23;

            let csr = unsafe { core::ptr::read_volatile(RCC_CSR) };
            let is_cold_boot = (csr & BORRSTF_BIT) != 0;
            unsafe {
                core::ptr::write_volatile(RCC_CSR, csr | RMVF_BIT);
            }

            if is_cold_boot {
                crate::raw_print::print_str(
                    "[UMBRASecureBoot] Cold boot: skipping benchmark (press reset to run)\n",
                );
            } else {
                crate::raw_print::print_str("[UMBRASecureBoot] Warm reset: running benchmark\n");
                let serial = drivers::uart::Uart::new_lpuart1_and_configure(9600);
                crate::benchmark::run_all(&serial);
            }
        }

        unsafe {
            crate::trampoline_to_ns();
        }
        loop {}
    }
}
