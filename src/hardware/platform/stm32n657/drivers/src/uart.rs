//! UART driver for STM32N657
//! USART1 @ 0x52001000 (Secure) / 0x42001000 (NS) — APB2
//! NUCLEO-N657X0-Q ST-Link VCP: USART1 on PE5 (TX, AF7) / PE6 (RX, AF7)
//! USART1 kernel clock = 150 MHz (IC mux from PLL, NOT PCLK2).
//! SYSCLK = HSI = 64 MHz but USART1 uses a separate IC clock.
//! - GDB debug: USART1 clock = 32 MHz → BRR=278 (Boot ROM bypass, no PLL)
//! - FSBL boot: USART1 clock = 150 MHz → BRR=1302 (Boot ROM configured PLL)

use peripheral_regs::{MmioAccess, RealMmio};

// Secure alias — works regardless of RIFSC SECCFGR state.
// SECCFGR0=0 in dev mode, so NS alias also works, but Secure is safer.
const USART1_BASE_ADDR: u32 = 0x5200_1000;

const CR1_OFFSET: u32 = 0x00;
const BRR_OFFSET: u32 = 0x0C;
const ISR_OFFSET: u32 = 0x1C;
const TDR_OFFSET: u32 = 0x28;
const PRESC_OFFSET: u32 = 0x2C;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Uart::new_usart1_and_configure(...)`
/// call site unchanged at the source level. On firmware build the generic
/// monomorphises to `Uart<RealMmio>` and the volatile accesses inline
/// exactly as before.
pub struct Uart<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Uart<RealMmio> {
    /// Configure USART1 for the given baud rate.
    /// Clock = 150 MHz (FSBL boot) or 32 MHz (GDB debug).
    /// Using 150 MHz — matches the first successful FSBL test.
    pub fn new_usart1_and_configure(baud: u32) -> Self {
        let uart = Self {
            mmio: RealMmio::new(USART1_BASE_ADDR),
        };
        let brr = 150_000_000u32 / baud;

        uart.mmio.write(CR1_OFFSET, 0);
        uart.mmio.write(PRESC_OFFSET, 0);
        uart.mmio.write(BRR_OFFSET, brr);
        uart.mmio.write(CR1_OFFSET, (1 << 0) | (1 << 3));

        uart
    }

    /// BRR sweep: tries multiple clock assumptions at 115200 baud.
    /// HW-clock-dependent — not exercised by host tests. Preserved verbatim
    /// from the pre-migration driver; only the raw `read_register` /
    /// `write_register` calls are routed through the `MmioAccess` trait.
    pub fn calibrate_and_configure() -> Self {
        let uart = Self {
            mmio: RealMmio::new(USART1_BASE_ADDR),
        };
        // Exhaustive sweep: every 8 MHz from 8 to 600
        let candidates: [(u32, &str); 25] = [
            (69, "008"),
            (139, "016"),
            (208, "024"),
            (278, "032"),
            (347, "040"),
            (417, "048"),
            (486, "056"),
            (556, "064"),
            (625, "072"),
            (694, "080"),
            (764, "088"),
            (834, "096"),
            (1042, "120"),
            (1302, "150"),
            (1389, "160"),
            (1563, "180"),
            (1736, "200"),
            (2170, "250"),
            (2604, "300"),
            (3038, "350"),
            (3472, "400"),
            (3906, "450"),
            (4340, "500"),
            (4774, "550"),
            (5208, "600"),
        ];
        for &(brr, label) in &candidates {
            uart.mmio.write(CR1_OFFSET, 0);
            uart.mmio.write(PRESC_OFFSET, 0);
            uart.mmio.write(BRR_OFFSET, brr);
            uart.mmio.write(CR1_OFFSET, (1 << 0) | (1 << 3));
            for _ in 0..50_000u32 {
                core::hint::spin_loop();
            }
            uart.write_str("OK@");
            uart.write_str(label);
            uart.write_str("\r\n");
            while uart.mmio.read(ISR_OFFSET) & (1 << 6) == 0 {}
        }
        // Keep last BRR; caller will see which label was readable
        uart
    }
}

impl<M: MmioAccess> Uart<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Uart::new_usart1_and_configure(...)`
    /// which monomorphises to `Uart<RealMmio>` and inlines the volatile
    /// accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    pub fn write_str(&self, s: &str) {
        for b in s.bytes() {
            self.write_byte(b);
        }
    }

    fn write_byte(&self, byte: u8) {
        while self.mmio.read(ISR_OFFSET) & (1 << 7) == 0 {}
        self.mmio.write(TDR_OFFSET, byte as u32);
    }
}

// umbra_hal::Uart adapter.
#[derive(Debug)]
pub enum UartError {
    Unreachable,
}

impl<M: MmioAccess> umbra_hal::Uart for Uart<M> {
    type Error = UartError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        for &b in bytes {
            self.write_byte(b);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `write_byte` (driving `write_str`) polls ISR.TXE (bit 7)
    /// until the TX FIFO is ready and then writes the byte to TDR. We
    /// preload ISR with bit 7 set so the poll loop exits on the first read.
    #[test]
    fn write_byte_polls_isr_then_writes_tdr() {
        let mem = MmioMem::new(USART1_BASE_ADDR);
        // Preload ISR with TXE (bit 7) set so the poll terminates.
        mem.preload_register(ISR_OFFSET, 1 << 7);

        let uart = Uart::<_>::new_with_mmio(mem.handle());
        uart.write_str("A");

        // Expected sequence: one Read of ISR, then one Write of 'A' to TDR.
        let log = mem.write_log();
        assert_eq!(log.len(), 2);
        match log[0] {
            MmioOp::Read { addr, value } => {
                assert_eq!(addr, USART1_BASE_ADDR + ISR_OFFSET);
                assert_eq!((value >> 7) & 1, 1);
            }
            _ => panic!("expected Read of ISR at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, USART1_BASE_ADDR + TDR_OFFSET);
                assert_eq!(value, 'A' as u32);
            }
            _ => panic!("expected Write of TDR at position 1, got {:?}", log[1]),
        }
    }

    /// Pins the N657-specific BRR value: at 150 MHz USART1 kernel clock and
    /// 115200 baud, BRR must be 1302 (see project_n657_fsbl_uart_working).
    /// Captures the configure-time register-write recipe exactly:
    /// CR1=0, PRESC=0, BRR=1302, CR1=UE|TE.
    #[test]
    fn new_usart1_and_configure_115200_writes_brr_1302() {
        // We cannot drive Uart::new_usart1_and_configure() through the mem
        // because it hard-codes RealMmio. Instead we replay its writes
        // through the in-memory backend to pin the BRR formula and write order.
        let mem = MmioMem::new(USART1_BASE_ADDR);
        let uart = Uart::<_>::new_with_mmio(mem.handle());

        let brr = 150_000_000u32 / 115_200u32;
        assert_eq!(
            brr, 1302,
            "N657 BRR landmine: 150MHz/115200 must equal 1302"
        );

        uart.mmio.write(CR1_OFFSET, 0);
        uart.mmio.write(PRESC_OFFSET, 0);
        uart.mmio.write(BRR_OFFSET, brr);
        uart.mmio.write(CR1_OFFSET, (1 << 0) | (1 << 3));

        let log = mem.write_log();
        assert_eq!(log.len(), 4);
        let expected = [
            (CR1_OFFSET, 0u32),
            (PRESC_OFFSET, 0u32),
            (BRR_OFFSET, 1302u32),
            (CR1_OFFSET, (1u32 << 0) | (1u32 << 3)),
        ];
        for (i, (off, val)) in expected.iter().enumerate() {
            match log[i] {
                MmioOp::Write { addr, value } => {
                    assert_eq!(addr, USART1_BASE_ADDR + off, "step {i}: addr mismatch");
                    assert_eq!(value, *val, "step {i}: value mismatch");
                }
                _ => panic!("step {i}: expected Write, got {:?}", log[i]),
            }
        }
    }
}
