//! Unified panic policy for the Umbra Secure side.
//! Every fault handler and the kernel `#[panic_handler]` MUST end with a call
//! to `handle()` (when a `PanicInfo` is available) or `handle_fault()` (when
//! the handler has already dumped via `panic_dump`). Behaviour is governed by
//! the panic-policy ADR:
//! - Default (production): UART log (via `handle`) + system reset.
//! - With Cargo feature `debug-halt`: UART log + WFI loop.
//! `system_reset` is currently inlined here rather than in a separate
//! `umbra-arch-arm::reset` module because the `arm` crate already depends on
//! `kernel`; adding the reverse dependency would create a cycle. The
//! architectural cleanup is scheduled for the workspace refactor.

use core::panic::PanicInfo;

/// Unified panic-policy entry point WITH `PanicInfo` (called from the kernel
/// `#[panic_handler]`).
/// Logs `[PANIC] <file>:<line>` via UART, then delegates to `terminate()`.
pub fn handle(info: &PanicInfo<'_>) -> ! {
    log_panic_to_uart(info);
    terminate()
}

/// Panic-policy entry point WITHOUT a `PanicInfo` — called from fault
/// handlers (HardFault, BusFault, SecureFault, UsageFault) which have
/// already logged via their own `panic_dump` / `dump_stack_frame` and only
/// need the reset/halt step.
pub fn handle_fault() -> ! {
    terminate()
}

/// Shared termination step. Internal — public callers go through `handle()`
/// or `handle_fault()` so the log/no-log distinction stays at the surface.
fn terminate() -> ! {
    #[cfg(not(feature = "debug-halt"))]
    {
        // Production path: system reset.
        #[cfg(all(target_arch = "arm", target_os = "none"))]
        system_reset();
        // Fallback for non-ARM builds (host tests): spin.
        #[cfg(not(all(target_arch = "arm", target_os = "none")))]
        loop {
            core::hint::spin_loop();
        }
    }

    #[cfg(feature = "debug-halt")]
    {
        #[cfg(all(target_arch = "arm", target_os = "none"))]
        // SAFETY: `wfi` is an unprivileged hint instruction; no memory state
        // matters since we never return.
        unsafe {
            loop {
                core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
            }
        }
        #[cfg(not(all(target_arch = "arm", target_os = "none")))]
        loop {
            core::hint::spin_loop();
        }
    }
}

/// Raise `SCB.AIRCR.SYSRESETREQ` (ARMv8-M ARM B1.1).
/// Inlined in the kernel crate to avoid a `kernel → arm → kernel` dependency
/// cycle; will move to `umbra-arch-arm::reset` during the workspace
/// refactor.
#[cfg(all(target_arch = "arm", target_os = "none"))]
#[inline(never)]
fn system_reset() -> ! {
    const SCB_AIRCR: *mut u32 = 0xE000_ED0C as *mut u32;
    const VECTKEY: u32 = 0x05FA_0000;
    const SYSRESETREQ_BIT: u32 = 1 << 2;

    // SAFETY: SCB.AIRCR is a Cortex-M architectural register at a fixed
    // address; writing VECTKEY|SYSRESETREQ is the architecturally-defined
    // way to request a system reset. The two DSBs frame the write so any
    // pending UART buffer drains (first DSB) and the reset request is
    // observed before any subsequent instruction (second DSB). The final
    // `wfi` loop is defensive — it executes only if the reset is somehow
    // suppressed.
    unsafe {
        core::arch::asm!("dsb 0xF", options(nomem, nostack, preserves_flags));
        core::ptr::write_volatile(SCB_AIRCR, VECTKEY | SYSRESETREQ_BIT);
        core::arch::asm!("dsb 0xF", options(nomem, nostack, preserves_flags));
        loop {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    fn umbra_debug_print_imp(ptr: *const u8);
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
fn log_panic_to_uart(info: &PanicInfo<'_>) {
    use core::fmt::Write;

    struct LocalWriter {
        buf: [u8; 128],
        len: usize,
    }
    impl LocalWriter {
        const CAP: usize = 127;
        fn flush(&mut self) {
            if self.len == 0 {
                return;
            }
            self.buf[self.len] = 0;
            // SAFETY: null-terminated at self.len; pointer outlives the call.
            unsafe {
                umbra_debug_print_imp(self.buf.as_ptr());
            }
            self.len = 0;
        }
    }
    impl Write for LocalWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &b in s.as_bytes() {
                if self.len >= Self::CAP {
                    self.flush();
                }
                self.buf[self.len] = b;
                self.len += 1;
            }
            Ok(())
        }
    }

    let mut w = LocalWriter {
        buf: [0; 128],
        len: 0,
    };
    let _ = w.write_str("\n[PANIC] ");
    if let Some(loc) = info.location() {
        let _ = write!(&mut w, "{}:{}", loc.file(), loc.line());
    } else {
        let _ = w.write_str("<no location>");
    }
    let _ = w.write_str("\n");
    w.flush();
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
fn log_panic_to_uart(_info: &PanicInfo<'_>) {
    // Host-test stub. The umbra-pal-test crate () will replace this.
}
