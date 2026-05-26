//! Direct-MMIO LPUART1 fault dumper. Bypasses Tock's debug writer so it
//! works during early boot, before the console capsule is up, and during
//! any panic. Reads NS CFSR/HFSR/MMFAR/BFAR and writes hex to LPUART1
//! at 9600 baud.
//!
//! The Umbra Secure-side handler can't read these — it sees only the
//! Secure-aliased SCB view, which is always 0 for NS faults — so the
//! dumper has to run from NS. Recovery is a hardware reset.

fn lpuart1_write_byte(b: u8) {
    let isr = 0x4000_8000_u32 as *const u32;
    let tdr = 0x4000_8028_u32 as *mut u32;
    // SAFETY: LPUART1 MMIO. Bit 7 of ISR is TXE — wait for the previous
    // byte to be latched before writing the next one.
    unsafe {
        while core::ptr::read_volatile(isr.offset(0x1C / 4)) & 0x80 == 0 {}
        core::ptr::write_volatile(tdr, b as u32);
    }
}

fn lpuart1_write_str(s: &str) {
    for b in s.bytes() {
        lpuart1_write_byte(b);
    }
}

fn lpuart1_write_hex(v: u32) {
    let h = b"0123456789abcdef";
    for i in (0..8).rev() {
        lpuart1_write_byte(h[((v >> (i * 4)) & 0xf) as usize]);
    }
}

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    lpuart1_write_str("\r\n[NS PANIC]\r\n");
    // SAFETY: read-only MMIO accesses on the standard Cortex-M SCB.
    unsafe {
        let cfsr = core::ptr::read_volatile(0xE000_ED28 as *const u32);
        let hfsr = core::ptr::read_volatile(0xE000_ED2C as *const u32);
        let mmfar = core::ptr::read_volatile(0xE000_ED34 as *const u32);
        let bfar = core::ptr::read_volatile(0xE000_ED38 as *const u32);
        lpuart1_write_str("  CFSR=0x");
        lpuart1_write_hex(cfsr);
        lpuart1_write_str("  HFSR=0x");
        lpuart1_write_hex(hfsr);
        lpuart1_write_str("\r\n  MMFAR=0x");
        lpuart1_write_hex(mmfar);
        lpuart1_write_str("  BFAR=0x");
        lpuart1_write_hex(bfar);
        lpuart1_write_str("\r\n");
    }
    loop {
        cortexm33::support::nop();
    }
}

/// Enable MEMFAULTENA / BUSFAULTENA / USGFAULTENA in SHCSR. Call FIRST
/// inside `main()` so subsequent faults populate CFSR instead of
/// escalating to HardFault with CFSR=0.
pub unsafe fn shcsr_enable_per_fault_handlers() {
    const SHCSR_ADDR: *mut u32 = 0xE000ED24 as *mut u32;
    const MEMFAULTENA: u32 = 1 << 16;
    const BUSFAULTENA: u32 = 1 << 17;
    const USGFAULTENA: u32 = 1 << 18;
    let cur = core::ptr::read_volatile(SHCSR_ADDR);
    core::ptr::write_volatile(SHCSR_ADDR, cur | MEMFAULTENA | BUSFAULTENA | USGFAULTENA);
}
