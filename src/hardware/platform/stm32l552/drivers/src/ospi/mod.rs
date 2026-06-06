//! OCTOSPI1 driver for STM32L562 (Octa-SPI flash bringup).
//! Memory-mapped 1-8-8 mode for the MX25LM51245G on the L562E-DK board.
//! Pair-up with `ofd.rs` (OTFDEC) when reads must be transparently
//! decrypted — and see ofd.rs for the silicon limitation that bans DMA
//! reads from the OCTOSPI window.
//! # Prescaler must move with the system clock (DCR2.PRESCALER)
//! After bringing sysclk up to 110 MHz, the original `PRESCALER = 0x02`
//! (divider /3) produced an OCTOSPI clock of ~36.7 MHz — over the
//! reliable Page Program timing for the MX25LM51245G in 1-1-1 SPI mode.
//! Symptom: `init_external_flash` reaches "OCTOSPI memory-mapped OK"
//! then issues an implicit reset to RSS (`PC = 0x0C00_00D4`) on the next
//! flash write. Fix: `DCR2.PRESCALER = 0x07` (divider /8 → ~13.75 MHz).
//! Memory-mapped reads stay fast; erase and Page Program become reliable.
//! See

#![cfg(feature = "stm32l562")]
#![allow(dead_code, unused_imports)]

// OCTOSPI1 register base. On STM32L5 the OCTOSPI1 control registers live
// in the extended AHB3 peripheral range (AHB3PERIPH_BASE + 0x1000), not the
// normal 0x5002_xxxx APB/AHB area. Per STM32L562xx CMSIS header:
// AHB3PERIPH_BASE_S = PERIPH_BASE_S(0x5000_0000) + 0x0402_0000 = 0x5402_0000
// OCTOSPI1_R_BASE_S = AHB3PERIPH_BASE_S + 0x1000 = 0x5402_1000
pub const OCTOSPI1_BASE_ADDR: u32 = 0x5402_1000; // Secure alias
pub const OCTOSPI_MEMMAP_BASE: u32 = 0x9000_0000;

// Register offsets (subset used during bringup)
pub(crate) const OCTOSPI_CR_OFFSET: u32 = 0x000;
pub(crate) const OCTOSPI_DCR1_OFFSET: u32 = 0x008;
pub(crate) const OCTOSPI_DCR2_OFFSET: u32 = 0x00C;
pub(crate) const OCTOSPI_SR_OFFSET: u32 = 0x020;
pub(crate) const OCTOSPI_FCR_OFFSET: u32 = 0x024;
pub(crate) const OCTOSPI_DLR_OFFSET: u32 = 0x040; // Data length register (SVD-verified)
pub(crate) const OCTOSPI_AR_OFFSET: u32 = 0x048; // Address register     (SVD-verified; draft had 0x120 which is ABR — corrected)
pub(crate) const OCTOSPI_DR_OFFSET: u32 = 0x050; // Data register        (SVD-verified)
pub(crate) const OCTOSPI_CCR_OFFSET: u32 = 0x100;
pub(crate) const OCTOSPI_TCR_OFFSET: u32 = 0x108;
pub(crate) const OCTOSPI_IR_OFFSET: u32 = 0x110;
pub(crate) const OCTOSPI_WCCR_OFFSET: u32 = 0x180; // Write comm config reg   (SVD-verified; offset 0x180)
pub(crate) const OCTOSPI_WTCR_OFFSET: u32 = 0x188; // Write timing config reg  (SVD-verified; offset 0x188; DCYC bits [4:0])
pub(crate) const OCTOSPI_WIR_OFFSET: u32 = 0x190; // Write instruction reg    (SVD-verified; offset 0x190; draft +0x10 was correct)

use peripheral_regs::{MmioAccess, RealMmio};

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `OspiDriver::new()` call site
/// unchanged at the source level — the firmware build monomorphises to
/// `OspiDriver<RealMmio>` and inlines the `volatile_register` accesses just
/// like before.
/// `base` is retained alongside `mmio` because the OCTOSPI DR data port
/// (`OCTOSPI_DR_OFFSET`) is accessed as a **byte** in indirect-read /
/// page-program flows. The `MmioAccess` trait only exposes 32-bit
/// read/write, so the byte-port accesses must remain raw
/// `core::ptr::{read_volatile, write_volatile}` against `base + offset` to
/// preserve the OCTOSPI FIFO state-machine semantics. Tests do not exercise
/// the byte-port path.
pub struct OspiDriver<M: MmioAccess = RealMmio> {
    pub(crate) mmio: M,
    pub(crate) base: u32,
}

// MX25LM51245G SPI command opcodes (reset-state 1-1-1 SPI mode).
pub(crate) const CMD_READ_STATUS: u8 = 0x05;
pub(crate) const CMD_WRITE_ENABLE: u8 = 0x06;
pub(crate) const CMD_PAGE_PROGRAM: u8 = 0x02; // 3-byte address, 256-byte page
pub(crate) const CMD_SECTOR_ERASE: u8 = 0x20; // 4 KB sector erase; 0xD8 = 64 KB block erase
pub(crate) const STATUS_WIP_MASK: u8 = 0x01;

mod init;
mod memory_mapped;
mod sfdp;
mod transfer;

pub use init::*;
pub use memory_mapped::*;
pub use sfdp::*;
pub use transfer::*;

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Return the value of the n-th Write in `log` (regardless of address) —
    /// mirrors the helper used in `dma.rs` so the OSPI test asserts read
    /// identically to the canonical pattern.
    fn nth_write(log: &[MmioOp], n: usize) -> (u32, u32) {
        let mut seen = 0;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if seen == n {
                    return (addr, value);
                }
                seen += 1;
            }
        }
        panic!("log only contains {seen} writes, wanted index {n}");
    }

    fn count_writes(log: &[MmioOp]) -> usize {
        let mut n = 0;
        for op in log {
            if matches!(op, MmioOp::Write { .. }) {
                n += 1;
            }
        }
        n
    }

    /// Verifies `configure_octospi_dcr_and_enable` performs the canonical
    /// OCTOSPI bringup arm sequence (cold-path territory — must NOT be
    /// reordered):
    /// * Read CR
    /// * Write CR with EN=0 (disable while reconfiguring)
    /// * Write DCR1 (MTYP=Standard, DEVSIZE=25, CSHT=3)
    /// * Write DCR2 (PRESCALER=7 → /8 divider)
    /// * Read CR
    /// * Write CR with EN=1 (re-enable)
    /// Pins the L562 cold-boot register-write order so a future refactor
    /// cannot inadvertently reorder DCR1/DCR2/EN — see file-header note
    /// on the `init_external_flash` OCTOSPI state machine sensitivity.
    #[test]
    fn configure_octospi_dcr_and_enable_emits_correct_sequence() {
        let mem = MmioMem::new(OCTOSPI1_BASE_ADDR);
        // Preload CR with a non-zero value so the disable/re-enable
        // read-modify-write steps are observable as distinct writes.
        mem.preload_register(OCTOSPI_CR_OFFSET, 0x0000_0001);

        let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());
        ospi.configure_octospi_dcr_and_enable();

        let log = mem.write_log();

        // Expected: 4 writes (CR disable, DCR1, DCR2, CR enable).
        assert_eq!(
            count_writes(&log),
            4,
            "expected 4 writes (CR disable, DCR1, DCR2, CR enable), log = {log:?}",
        );

        // [0] CR ← (preloaded & !1) = 0 (EN cleared).
        let (a0, v0) = nth_write(&log, 0);
        assert_eq!(
            a0,
            OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET,
            "first write must target CR"
        );
        assert_eq!(v0 & 1, 0, "first write must clear CR.EN");

        // [1] DCR1 ← (0b000<<24) | (25<<16) | (3<<8).
        let expected_dcr1 = (25u32 << 16) | (3u32 << 8);
        let (a1, v1) = nth_write(&log, 1);
        assert_eq!(
            a1,
            OCTOSPI1_BASE_ADDR + OCTOSPI_DCR1_OFFSET,
            "second write must target DCR1"
        );
        assert_eq!(v1, expected_dcr1, "DCR1 must encode DEVSIZE=25, CSHT=3");

        // [2] DCR2 ← 0x0000_0007 (PRESCALER=7).
        let (a2, v2) = nth_write(&log, 2);
        assert_eq!(
            a2,
            OCTOSPI1_BASE_ADDR + OCTOSPI_DCR2_OFFSET,
            "third write must target DCR2"
        );
        assert_eq!(v2, 0x0000_0007, "DCR2.PRESCALER must be 7 (→ /8 divider)");

        // [3] CR ← (... | 1) — EN re-asserted.
        let (a3, v3) = nth_write(&log, 3);
        assert_eq!(
            a3,
            OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET,
            "fourth write must target CR"
        );
        assert_eq!(v3 & 1, 1, "fourth write must set CR.EN");
    }

    /// Smaller smoke test — verifies `new_with_mmio` constructs a driver
    /// that records its base address correctly and routes a one-off
    /// register write through the injected MMIO handle. Independent from
    /// the larger DCR/EN sequence so a regression in the constructor
    /// surfaces with a focused message.
    #[test]
    fn new_with_mmio_routes_through_injected_handle() {
        let mem = MmioMem::new(OCTOSPI1_BASE_ADDR);
        let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());

        // Issue a register write through the driver's mmio handle directly
        // and verify it lands at the expected absolute address.
        ospi.mmio.write(OCTOSPI_IR_OFFSET, 0x0000_000B); // FAST_READ opcode

        let log = mem.write_log();
        assert_eq!(count_writes(&log), 1);
        let (a, v) = nth_write(&log, 0);
        assert_eq!(a, OCTOSPI1_BASE_ADDR + OCTOSPI_IR_OFFSET);
        assert_eq!(v, 0x0000_000B);
        // base field stays in sync with the constructor.
        assert_eq!(ospi.base, OCTOSPI1_BASE_ADDR);
    }
}
