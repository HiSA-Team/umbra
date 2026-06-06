// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! On-The-Fly Decryption Engine (OTFDEC) for STM32L562 OCTOSPI window.
//! Memory-mapped reads from `0x9000_0000` return PLAINTEXT once OTFDEC has
//! been programmed with the region's key and start/end addresses — but
//! only for transactions issued by the Cortex-M33 core bus (I-bus /
//! D-bus). The peripheral is gated by `#[cfg(feature = "stm32l562")]`
//! because the OCTOSPI + OTFDEC stack is L562-only.
//! # Silicon limitation: DMA reads return zero-fill, NOT decrypted data
//! Exhaustively tested 2026-04-18:
//! DMA reads from the OCTOSPI memory-mapped window go through the AHB
//! master path which **bypasses OTFDEC decryption**, despite RM0438
//! §2.1.4 implying a DMA→BusMatrix→OTFDEC→OCTOSPI route. Five DMA
//! configurations were validated (SECM=1/0 × SSEC/DSEC permutations) —
//! all return `0x0000_0000` with `CNDTR=0` and no TEIF. Pre-fill scratch
//! with `0xDEADBEEF` and DMA still writes `0x00000000`, so the DMA does
//! transfer, just with zero source.
//! Operational consequence: any code that needs decrypted bytes from
//! OCTOSPI must use CPU `core::ptr::copy_nonoverlapping` (or a `volatile`
//! loop). DMA from internal flash on L552/L562 still works fine — this
//! is OCTOSPI-window-specific.
//! G3 speculative prefetch on L562 therefore uses CPU-initiated reads
//! inside PendSV / interrupt handlers, never DMA.

// STM32L5xxxx OTFDEC Driver
// On-The-Fly Decryption Engine for external memories.

#[cfg(feature = "stm32l562")]
use crate::rcc::{self, Rcc};
#[cfg(feature = "stm32l562")]
use peripheral_regs::{MmioAccess, RealMmio};

#[cfg(feature = "stm32l562")]
const OTFDEC_BASE_ADDR: u32 = 0x520C5000; // Secure Base Address (SVD: 0x420C5000 -> 0x520C5000)

#[cfg(feature = "stm32l562")]
const OTFDEC_CR_OFFSET: u32 = 0x000;
#[cfg(feature = "stm32l562")]
const OTFDEC_ISR_OFFSET: u32 = 0x300;
#[cfg(feature = "stm32l562")]
const OTFDEC_ICR_OFFSET: u32 = 0x304;

// Region 1 Offsets (Region 2, 3, 4 follow at +0x30 stride)
#[cfg(feature = "stm32l562")]
const REGION_STRIDE: u32 = 0x30;
#[cfg(feature = "stm32l562")]
const R1_CFGR_OFFSET: u32 = 0x20;
#[cfg(feature = "stm32l562")]
const R1_SADR_OFFSET: u32 = 0x24; // Start Address
#[cfg(feature = "stm32l562")]
const R1_EADR_OFFSET: u32 = 0x28; // End Address
#[cfg(feature = "stm32l562")]
const R1_NONCER0_OFFSET: u32 = 0x2C;
#[cfg(feature = "stm32l562")]
const R1_NONCER1_OFFSET: u32 = 0x30;
#[cfg(feature = "stm32l562")]
const R1_KEYR0_OFFSET: u32 = 0x34;
#[cfg(feature = "stm32l562")]
const R1_KEYR1_OFFSET: u32 = 0x38;
#[cfg(feature = "stm32l562")]
const R1_KEYR2_OFFSET: u32 = 0x3C;
#[cfg(feature = "stm32l562")]
const R1_KEYR3_OFFSET: u32 = 0x40;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `OfdDriver::new()` call site
/// unchanged at the source level — the firmware build monomorphises to
/// `OfdDriver<RealMmio>` and inlines the `volatile_register` accesses just
/// like before.
/// # L562 cold-boot sensitivity
/// The OTFDEC cold-path (boot.rs `init_external_flash_impl` cipher cycle)
/// is the suspected origin of the L562 intermittent "Kernel Initialized"
/// hang — see The
/// register-write order, the MODE-before-KEY sequencing (AN5281 §3.4),
/// and the NONCE / KEY / SADR / EADR / REG_EN ordering inside
/// `configure_region` are timing-sensitive. **Do not reorder, batch, or
/// elide any register write in `configure_region` or `set_enciphering`.**
#[cfg(feature = "stm32l562")]
pub struct OfdDriver<M: MmioAccess = RealMmio> {
    mmio: M,
}

#[cfg(not(feature = "stm32l562"))]
pub struct OfdDriver;

#[derive(Clone, Copy)]
pub enum Region {
    Region1 = 0,
    Region2 = 1,
    Region3 = 2,
    Region4 = 3,
}

pub enum KeyMode {
    Instruction = 0,
    Data = 1,
    InstructionAndData = 2,
}

pub struct Config {
    pub start_addr: u32,
    pub end_addr: u32,
    /// 64-bit nonce stored as a big-endian byte array: `nonce[0]` is
    /// the most-significant byte, `nonce[7]` the least-significant.
    /// `configure_region` maps `nonce[0..4]` → NONCER1 (high word)
    /// and `nonce[4..8]` → NONCER0 (low word).
    pub nonce: [u8; 8],
    /// 128-bit AES key stored as a big-endian byte array: `key[0]` is
    /// the most-significant byte, `key[15]` the least-significant.
    /// `configure_region` maps `key[0..4]` → KEYR3 (most-significant
    /// 32-bit word) down to `key[12..16]` → KEYR0 (least-significant
    /// word), following the ST HAL convention where KEYR0 holds the
    /// LSW of the 128-bit key.
    pub key: [u8; 16],
    pub mode: KeyMode,
    pub enable: bool,
}

#[cfg(feature = "stm32l562")]
impl OfdDriver<RealMmio> {
    pub fn new() -> Self {
        // Firmware-only RCC gate-enable. Kept inside the RealMmio impl so
        // host tests using `new_with_mmio` skip the Rcc HW singleton (which
        // is not yet migrated to MmioAccess). The OTFDEC clock MUST be
        // enabled before any CR / ISR / region-register access — moving
        // this call later in the boot sequence would re-introduce the
        // pre-clock register-access fault.
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::OTFDEC);

        Self {
            mmio: RealMmio::new(OTFDEC_BASE_ADDR),
        }
    }
}

#[cfg(feature = "stm32l562")]
impl<M: MmioAccess> OfdDriver<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `OfdDriver::new()` which monomorphises
    /// to `OfdDriver<RealMmio>` and inlines the volatile accesses (and gates
    /// the RCC clock). Host callers must seed any HW-side-state bits via
    /// `MmioMem::preload_register` before invoking driver methods.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    pub fn configure_region(&mut self, region: Region, config: Config) {
        let region_idx = region as u32;
        let cfgr_off = R1_CFGR_OFFSET + region_idx * REGION_STRIDE;
        let sadr_off = R1_SADR_OFFSET + region_idx * REGION_STRIDE;
        let eadr_off = R1_EADR_OFFSET + region_idx * REGION_STRIDE;
        let nonce0_off = R1_NONCER0_OFFSET + region_idx * REGION_STRIDE;
        let nonce1_off = R1_NONCER1_OFFSET + region_idx * REGION_STRIDE;
        let key0_off = R1_KEYR0_OFFSET + region_idx * REGION_STRIDE;
        let key1_off = R1_KEYR1_OFFSET + region_idx * REGION_STRIDE;
        let key2_off = R1_KEYR2_OFFSET + region_idx * REGION_STRIDE;
        let key3_off = R1_KEYR3_OFFSET + region_idx * REGION_STRIDE;

        // 1. Disable region.
        self.mmio.clear_bit(cfgr_off, 0); // REG_EN

        if !config.enable {
            return;
        }

        // 2. MODE before KEY (MODE write clears KEY register per AN5281 §3.4).
        let mode_val: u32 = match config.mode {
            KeyMode::Instruction => 0,
            KeyMode::Data => 1,
            KeyMode::InstructionAndData => 2,
        };
        let mut cfgr = self.mmio.read(cfgr_off);
        cfgr &= !(0b11 << 4);
        cfgr |= mode_val << 4;
        self.mmio.write(cfgr_off, cfgr);

        // 3. KEY (128-bit, written MSB-first per AN5281).
        self.mmio.write(
            key0_off,
            u32::from_be_bytes(config.key[12..16].try_into().unwrap()),
        );
        self.mmio.write(
            key1_off,
            u32::from_be_bytes(config.key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            key2_off,
            u32::from_be_bytes(config.key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            key3_off,
            u32::from_be_bytes(config.key[0..4].try_into().unwrap()),
        );

        // 4. NONCE (64-bit).
        self.mmio.write(
            nonce0_off,
            u32::from_be_bytes(config.nonce[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            nonce1_off,
            u32::from_be_bytes(config.nonce[0..4].try_into().unwrap()),
        );

        // 5. Start / End addresses.
        self.mmio.write(sadr_off, config.start_addr);
        self.mmio.write(eadr_off, config.end_addr);

        // 6. Enable region.
        self.mmio.set_bit(cfgr_off, 0); // REG_EN
    }

    pub fn is_region_enabled(&self, region: Region) -> bool {
        let base = R1_CFGR_OFFSET + (region as u32 * REGION_STRIDE);
        let val = self.mmio.read(base);
        (val & 1) != 0
    }

    /// Reads the OTFDEC Interrupt Status Register (ISR, offset 0x300).
    /// Bits: SEIF=0 (security error), XONEIF=1 (execute-only non-exec),
    /// KEIF=2 (key error). Used for bringup telemetry and fault diagnosis.
    pub fn isr(&self) -> u32 {
        self.mmio.read(OTFDEC_ISR_OFFSET)
    }

    /// Clears all OTFDEC interrupt flags (SEIF | XONEIF | KEIF) via ICR (offset 0x304).
    pub fn icr_clear(&mut self) {
        self.mmio.write(OTFDEC_ICR_OFFSET, 0x7);
    }

    /// Set or clear the ENC (encryption mode) bit in the OTFDEC CR register.
    /// Per STM32L562.svd OTFDEC1.CR: ENC is bit 0 (bitOffset=0, bitWidth=1).
    /// When ENC=1, OTFDEC operates in enciphering mode (plaintext in → ciphertext
    /// written to flash via OCTOSPI). When ENC=0, it operates in the default
    /// deciphering mode (ciphertext in flash → plaintext at AHB read time).
    /// Call this before `configure_region` so the region is enabled with the
    /// correct ENC state already in CR.
    pub fn set_enciphering(&mut self, enabled: bool) {
        if enabled {
            self.mmio.set_bit(OTFDEC_CR_OFFSET, 0);
        } else {
            self.mmio.clear_bit(OTFDEC_CR_OFFSET, 0);
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Inline host tests — gated `#[cfg(all(test, feature = "stm32l562"))]` so
// they only compile under the L562 build. The default L552 `cargo test --lib`
// invocation skips them (no symbol references are visible to the test
// harness in that configuration). Run them with:
// cargo test --lib --features stm32l562
// from the `umbra-l552-drivers` crate root.
// ────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, feature = "stm32l562"))]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    fn count_writes(log: &[MmioOp]) -> usize {
        let mut n = 0;
        for op in log {
            if matches!(op, MmioOp::Write { .. }) {
                n += 1;
            }
        }
        n
    }

    fn nth_write_value(log: &[MmioOp], n: usize) -> (u32, u32) {
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

    /// Verifies that `configure_region` emits the AN5281 §3.4 register-write
    /// recipe in order: REG_EN clear → MODE RMW → 4× KEYR → 2× NONCER →
    /// SADR → EADR → REG_EN set. This is the L562 cold-boot timing-sensitive
    /// sequence; reordering any write here is suspected to be the OTFDEC
    /// intermittent-hang root cause (memory
    ///).
    #[test]
    fn configure_region_emits_an5281_write_sequence() {
        let mem = MmioMem::new(OTFDEC_BASE_ADDR);
        // Pre-seed CFGR with arbitrary upper bits so the MODE RMW step is
        // observable — bits 31..6 must survive, bits 5..4 must be cleared
        // then set to the requested mode encoding.
        let cfgr_off = R1_CFGR_OFFSET; // Region1 → region_idx = 0
        mem.preload_register(cfgr_off, 0xDEAD_BEE0); // bit 0 already clear

        let mut ofd = OfdDriver::<_>::new_with_mmio(mem.handle());

        let cfg = Config {
            start_addr: 0x9000_0000,
            end_addr: 0x9000_3FFF,
            nonce: [0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3],
            key: [
                0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31,
                0x32, 0x33,
            ],
            mode: KeyMode::InstructionAndData, // mode_val = 2
            enable: true,
        };

        ofd.configure_region(Region::Region1, cfg);

        let log = mem.write_log();

        // Expected write recipe (Region1, region_idx=0):
        // [0] CFGR ← REG_EN cleared (clear_bit = read + write)
        // [1] CFGR ← MODE field set (RMW)
        // [2] KEYR0 ← key[12..16] BE word
        // [3] KEYR1 ← key[ 8..12] BE word
        // [4] KEYR2 ← key[ 4.. 8] BE word
        // [5] KEYR3 ← key[ 0.. 4] BE word
        // [6] NONCER0 ← nonce[4..8] BE word
        // [7] NONCER1 ← nonce[0..4] BE word
        // [8] SADR ← start_addr
        // [9] EADR ← end_addr
        // [10] CFGR ← REG_EN set (set_bit = read + write)
        assert_eq!(count_writes(&log), 11, "expected 11 writes, got {:?}", log);

        // Verify the KEYR ordering: KEYR0 holds LSW (key[12..16]).
        let (k0_addr, k0_val) = nth_write_value(&log, 2);
        assert_eq!(k0_addr, OTFDEC_BASE_ADDR + R1_KEYR0_OFFSET, "KEYR0 addr");
        assert_eq!(
            k0_val,
            u32::from_be_bytes([0x30, 0x31, 0x32, 0x33]),
            "KEYR0 value"
        );

        let (k3_addr, k3_val) = nth_write_value(&log, 5);
        assert_eq!(k3_addr, OTFDEC_BASE_ADDR + R1_KEYR3_OFFSET, "KEYR3 addr");
        assert_eq!(
            k3_val,
            u32::from_be_bytes([0x00, 0x01, 0x02, 0x03]),
            "KEYR3 value"
        );

        // NONCER0 = nonce[4..8], NONCER1 = nonce[0..4].
        let (n0_addr, n0_val) = nth_write_value(&log, 6);
        assert_eq!(
            n0_addr,
            OTFDEC_BASE_ADDR + R1_NONCER0_OFFSET,
            "NONCER0 addr"
        );
        assert_eq!(
            n0_val,
            u32::from_be_bytes([0xB0, 0xB1, 0xB2, 0xB3]),
            "NONCER0 value"
        );

        let (n1_addr, n1_val) = nth_write_value(&log, 7);
        assert_eq!(
            n1_addr,
            OTFDEC_BASE_ADDR + R1_NONCER1_OFFSET,
            "NONCER1 addr"
        );
        assert_eq!(
            n1_val,
            u32::from_be_bytes([0xA0, 0xA1, 0xA2, 0xA3]),
            "NONCER1 value"
        );

        // SADR / EADR.
        let (s_addr, s_val) = nth_write_value(&log, 8);
        assert_eq!(s_addr, OTFDEC_BASE_ADDR + R1_SADR_OFFSET, "SADR addr");
        assert_eq!(s_val, 0x9000_0000, "SADR value");
        let (e_addr, e_val) = nth_write_value(&log, 9);
        assert_eq!(e_addr, OTFDEC_BASE_ADDR + R1_EADR_OFFSET, "EADR addr");
        assert_eq!(e_val, 0x9000_3FFF, "EADR value");

        // Final REG_EN-set write (set_bit RMW: bit 0 set, upper bits
        // preserved from MODE-write step which left CFGR = 0xDEAD_BEE0 with
        // MODE field cleared then set to 2 << 4 = 0x20 → 0xDEAD_BEA0 (bits
        // 5..4 cleared, then 10b set in those positions = 0xDEAD_BEA0+0x20).
        // Then REG_EN set adds bit 0 → 0xDEAD_BEA1.
        let (en_addr, en_val) = nth_write_value(&log, 10);
        assert_eq!(
            en_addr,
            OTFDEC_BASE_ADDR + R1_CFGR_OFFSET,
            "REG_EN set addr"
        );
        assert_eq!(en_val & 1, 1, "REG_EN bit must be set");
        // MODE field [5:4] must be 0b10 (InstructionAndData).
        assert_eq!((en_val >> 4) & 0b11, 0b10, "MODE field must be 10b");
        // Upper bits 31..6 must survive end-to-end.
        assert_eq!(
            en_val & 0xFFFF_FFC0,
            0xDEAD_BEC0,
            "upper CFGR bits must survive"
        );
    }

    /// Verifies that `set_enciphering(true)` emits a read-modify-write to
    /// OTFDEC_CR that sets bit 0 (ENC) without disturbing upper bits. This
    /// guards against a regression where the RMW would lose ENC=1 if the
    /// MmioAccess `set_bit` default impl ever changed.
    #[test]
    fn set_enciphering_true_preserves_upper_cr_bits() {
        let mem = MmioMem::new(OTFDEC_BASE_ADDR);
        // Pre-seed CR with all upper bits set so the RMW step is observable.
        mem.preload_register(OTFDEC_CR_OFFSET, 0xFFFF_FFFE); // ENC=0

        let mut ofd = OfdDriver::<_>::new_with_mmio(mem.handle());
        ofd.set_enciphering(true);

        // set_bit = 1 read + 1 write.
        let log = mem.write_log();
        assert_eq!(count_writes(&log), 1, "set_enciphering must emit 1 Write");

        let (addr, value) = nth_write_value(&log, 0);
        assert_eq!(addr, OTFDEC_BASE_ADDR + OTFDEC_CR_OFFSET, "CR addr");
        assert_eq!(value, 0xFFFF_FFFF, "ENC set + upper bits preserved");
    }
}
