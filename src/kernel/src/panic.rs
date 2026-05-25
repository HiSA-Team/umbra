//! Kernel panic handler.
//!
//! Routes `panic!` to UART via `umbra_debug_print_imp` (provided by the
//! platform boot crate, e.g. `src/hardware/platform/stm32l552/boot/src/api_impl.rs`).
//! Emits `[KERNEL PANIC] <file>:<line>\n` then halts.
//!
//! Why a fixed-size buffer + `core::fmt::Write`:
//! `no_std` has no allocator, and `umbra_debug_print_imp` accepts a
//! null-terminated C string. We accumulate formatted bytes in a stack
//! buffer; when the buffer fills, we null-terminate, flush, and continue.

use core::fmt::{self, Write};
use core::panic::PanicInfo;

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    fn umbra_debug_print_imp(ptr: *const u8);
}

struct UartWriter {
    buf: [u8; 128],
    len: usize,
}

impl UartWriter {
    const CAP: usize = 127; // 128 - 1 byte for null terminator

    fn new() -> Self {
        Self { buf: [0; 128], len: 0 }
    }

    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        self.buf[self.len] = 0;
        #[cfg(all(target_arch = "arm", target_os = "none"))]
        // SAFETY: buffer is null-terminated at `self.len`; pointer outlives the call.
        unsafe {
            umbra_debug_print_imp(self.buf.as_ptr());
        }
        self.len = 0;
    }
}

impl Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
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

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    #[cfg(all(target_arch = "arm", target_os = "none"))]
    {
        let mut w = UartWriter::new();
        let _ = w.write_str("\n[KERNEL PANIC] ");
        if let Some(loc) = info.location() {
            let _ = write!(&mut w, "{}:{}", loc.file(), loc.line());
        } else {
            let _ = w.write_str("<no location>");
        }
        let _ = w.write_str("\n");
        w.flush();
    }
    loop {}
}
