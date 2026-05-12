//! UART driver for STM32N657
//!
//! USART1 @ 0x52001000 (Secure) / 0x42001000 (NS) — APB2
//! NUCLEO-N657X0-Q ST-Link VCP: USART1 on PE5 (TX, AF7) / PE6 (RX, AF7)
//!
//! USART1 kernel clock = 150 MHz (IC mux from PLL, NOT PCLK2).
//! SYSCLK = HSI = 64 MHz but USART1 uses a separate IC clock.
//!   - GDB debug:   USART1 clock = 32 MHz  → BRR=278  (Boot ROM bypass, no PLL)
//!   - FSBL boot:   USART1 clock = 150 MHz → BRR=1302 (Boot ROM configured PLL)

use peripheral_regs::{read_register, write_register};

// Secure alias — works regardless of RIFSC SECCFGR state.
// SECCFGR0=0 in dev mode, so NS alias also works, but Secure is safer.
const USART1_BASE: *const u32 = 0x5200_1000 as *const u32;

const CR1_OFFSET: u32 = 0x00;
const BRR_OFFSET: u32 = 0x0C;
const ISR_OFFSET: u32 = 0x1C;
const TDR_OFFSET: u32 = 0x28;

pub struct Uart {
    regs: *const u32,
}

impl Uart {
    /// Configure USART1 for the given baud rate.
    /// Clock = 150 MHz (FSBL boot) or 32 MHz (GDB debug).
    /// Using 150 MHz — matches the first successful FSBL test.
    pub fn new_usart1_and_configure(baud: u32) -> Self {
        let regs = USART1_BASE;
        let brr = 150_000_000u32 / baud;

        unsafe {
            write_register(regs, CR1_OFFSET, 0);
            write_register(regs, 0x2C, 0);       // clear PRESC
            write_register(regs, BRR_OFFSET, brr);
            write_register(regs, CR1_OFFSET, (1 << 0) | (1 << 3));
        }

        Uart { regs }
    }

    /// BRR sweep: tries multiple clock assumptions at 115200 baud.
    pub fn calibrate_and_configure() -> Self {
        let regs = USART1_BASE;
        // Exhaustive sweep: every 8 MHz from 8 to 600
        let candidates: [(u32, &str); 25] = [
            (69,   "008"), (139,  "016"), (208,  "024"), (278,  "032"),
            (347,  "040"), (417,  "048"), (486,  "056"), (556,  "064"),
            (625,  "072"), (694,  "080"), (764,  "088"), (834,  "096"),
            (1042, "120"), (1302, "150"), (1389, "160"), (1563, "180"),
            (1736, "200"), (2170, "250"), (2604, "300"), (3038, "350"),
            (3472, "400"), (3906, "450"), (4340, "500"), (4774, "550"),
            (5208, "600"),
        ];
        for &(brr, label) in &candidates {
            unsafe {
                write_register(regs, CR1_OFFSET, 0);
                write_register(regs, 0x2C, 0);
                write_register(regs, BRR_OFFSET, brr);
                write_register(regs, CR1_OFFSET, (1 << 0) | (1 << 3));
            }
            for _ in 0..50_000u32 { core::hint::spin_loop(); }
            let uart = Uart { regs };
            uart.write_str("OK@");
            uart.write_str(label);
            uart.write_str("\r\n");
            unsafe { while read_register(regs, ISR_OFFSET) & (1 << 6) == 0 {} }
        }
        // Keep last BRR; caller will see which label was readable
        Uart { regs }
    }

    pub fn write_str(&self, s: &str) {
        for b in s.bytes() {
            self.write_byte(b);
        }
    }

    fn write_byte(&self, byte: u8) {
        unsafe {
            while read_register(self.regs, ISR_OFFSET) & (1 << 7) == 0 {}
            write_register(self.regs, TDR_OFFSET, byte as u32);
        }
    }
}
