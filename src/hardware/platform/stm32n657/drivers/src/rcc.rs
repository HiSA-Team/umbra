//! RCC driver for STM32N657 — Reset and Clock Control
//! Base address: 0x56028000 (Secure), 0x46028000 (NS)
//! Register offsets from RM0486:
//! AHB3ENR = 0x258 (crypto: RNG=0, HASH=1, CRYP=2, SAES=4, PKA=8, RIFSC=9)
//! AHB4ENR = 0x25C (GPIO A-Q + PWR + CRC)
//! APB2ENR = 0x26C (USART1=4)
//! # Clock tree post.0 (production setting)
//! | Clock | Frequency | Source |
//! |-------|-----------|--------|
//! | CPUCLK (M55 core, SysTick) | 800 MHz | IC1 ← PLL1÷1 |
//! | AXI / SYSCLK | 400 MHz | IC2 ← PLL1÷2 |
//! | HCLK (AHB peripherals) | 200 MHz | AXI ÷ HPRE(2) |
//! | PCLK1/PCLK2 | 200 MHz | HCLK ÷ PPRE(1) |
//! | USART1 kernel | 64 MHz | HSI (CCIPR13.USART1SEL = 6) |
//! | XSPI2 source | 50 MHz | IC3 ← PLL1÷16 |
//! USART1 is intentionally on HSI rather than a PLL1-derived IC mux so the
//! UART stays usable across PLL retunes (.1+ touches PLL3 for NPU).
//! BRR = 64 MHz / 115200 ≈ 556 (0.08 % baud error).
//! HCLK = 200 MHz follows ST's `SystemClock_Config` HPRE=DIV2 choice ("AHB
//! max is below 400 on N657"). Boot ROM left HCLK = AXI = 400; that is out
//! of ST's tested spec and we step it down explicitly in `init_clocks`.
//! # Six bring-up landmines hit during.0
//! 1. **PLL1 cannot be reconfigured while CPU is sourced from it.** Writing
//! `RCC_CCR.PLL1ONC` halts the core mid-instruction with no fault.
//! `CPUSW`+`SYSSW` must move to HSI BEFORE `PLL1ONC` is touched.
//! 2. **`CPUSWS` / `SYSSWS` readback fields are at write-position + 4.**
//! CPUSW writes [17:16], readback CPUSWS at [21:20]. Off-by-2 spins
//! forever with the same hang signature as #1.
//! 3. **`HSIRDY` is bit 3 of RCC_SR**, NOT bit 8 (which is PLL1RDY).
//! First-pass typo passed by accident because Boot ROM left both ready.
//! 4. **PLL field encodings differ from IC dividers.** PLLM/N/P take raw
//! values (write 25 for N=25); IC dividers take (divider-1) (write 1
//! for div=2). Off-by-one → double or zero clock → silent bricking.
//! 5. **RCC_CSR (0x800) and RCC_CCR (0x1000) are write-1-to-act registers,
//! NOT read-modify-write.** Write a 1-bit mask to set / clear the state
//! bit; writing 0 elsewhere is a no-op. RMW here would be wrong.
//! 6. **Nucleo-N657X0-Q "SMPS overdrive" is just `PB12 = HIGH`** (external
//! SMPS regulator switched by GPIO). Do not look for PWR_CR1 pokes; ST
//! BSP only writes that GPIO.
//! # M55 cache contract (.1.a.1 / G.1.a.1.b)
//! I-cache + D-cache enable at the end of `init_clocks` (post-PLL switch).
//! Prerequisite peculiar to the M55: `MEMSYSCTL.MSCR.ICACTIVE` (bit 13) /
//! `DCACTIVE` (bit 12) at `0xE001_E000` must be set BEFORE the standard
//! `SCB.CCR.IC/DC` enables. Forgetting silently no-ops the SCB write.
//! Cache coherency for executable bytes (DMA-loaded enclave blocks):
//! `DSB → DCCMVAC per 32-byte line → DSB → ICIALLU → DSB → ISB`.
//! Centralized in `secure_kernel::load_block_n657`. Skipping any DSB or
//! ICIALLU produces MMFSR.IACCVIOL at the enclave's first PC.

use peripheral_regs::{write_register, MmioAccess, RealMmio};

// Secure alias — works regardless of RIFSC SECCFGR state.
const RCC_BASE_ADDR: u32 = 0x5602_8000;
const CR_OFFSET: u32 = 0x00;
const CFGR1_OFFSET: u32 = 0x1C;
const AHB3ENR_OFFSET: u32 = 0x258;
const AHB4ENR_OFFSET: u32 = 0x25C;
const APB2ENR_OFFSET: u32 = 0x26C;
const AHB5ENR_OFFSET: u32 = 0x260;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Rcc::new()` call site unchanged at
/// the source level — the firmware build monomorphises to `Rcc<RealMmio>`
/// and inlines the volatile accesses exactly as before.
/// First N657 driver to migrate. Mirrors the L552 `Rcc<M>` shape commit
/// 37d2589 byte-for-byte where the register-write sequence overlaps.
pub struct Rcc<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Rcc<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(RCC_BASE_ADDR),
        }
    }

    /// Compatibility wrapper kept so existing call sites
    /// (`drivers::rcc::Rcc::set_vtor_ns(0x2400_0000)` in
    /// boot/syscall_dispatch.rs) continue to compile unchanged after the
    /// `Rcc<M>` migration. New callers should prefer the free function
    /// `rcc::set_vtor_ns` directly.
    #[allow(dead_code)]
    pub fn set_vtor_ns(vtor_ns: u32) {
        set_vtor_ns(vtor_ns);
    }
}

impl<M: MmioAccess> Rcc<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Rcc::new()` which monomorphises to
    /// `Rcc<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Force system clock back to HSI 64 MHz.
    /// The Boot ROM may have switched to PLL at a higher frequency.
    /// We need a known clock to calculate UART BRR correctly.
    /// Register-write sequence MUST be preserved byte-for-byte (see
    /// landmines #1 / #2 in the module doc — Boot ROM PLL retuning is
    /// HW-state-sensitive).
    pub fn force_hsi(&self) {
        // Ensure HSI is ON (CR bit 0 = HSION)
        let cr = self.mmio.read(CR_OFFSET);
        self.mmio.write(CR_OFFSET, cr | 1);

        // Wait for HSI ready (CR bit 2 = HSIRDY)
        while self.mmio.read(CR_OFFSET) & (1 << 2) == 0 {}

        // Switch system clock to HSI: CFGR1 SW[1:0] = 00
        let cfgr1 = self.mmio.read(CFGR1_OFFSET);
        self.mmio.write(CFGR1_OFFSET, cfgr1 & !0x3);

        // Wait for SWS[1:0] = 00 (HSI selected as system clock)
        while self.mmio.read(CFGR1_OFFSET) & (0x3 << 3) != 0 {}
    }

    /// Enable a clock bit in the AHB3ENR register (crypto: HASH, CRYP, RNG, SAES, PKA).
    /// AHB3ENR offset = 0x258 (load-bearing per memory
    /// `project_n657_rcc_register_map`). Semantics: read-OR-write — bits
    /// already enabled stay set.
    pub fn enable_ahb3_clock(&self, bit: u8) {
        let val = self.mmio.read(AHB3ENR_OFFSET);
        self.mmio.write(AHB3ENR_OFFSET, val | (1 << bit));
    }

    /// Enable a clock bit in the AHB4ENR register (GPIO ports + PWR + CRC).
    /// AHB4ENR offset = 0x25C (load-bearing per memory
    /// `project_n657_rcc_register_map`).
    pub fn enable_ahb4_clock(&self, bit: u8) {
        let val = self.mmio.read(AHB4ENR_OFFSET);
        self.mmio.write(AHB4ENR_OFFSET, val | (1 << bit));
    }

    /// Enable a clock bit in the APB2ENR register (USART1, etc.).
    pub fn enable_apb2_clock(&self, bit: u8) {
        let val = self.mmio.read(APB2ENR_OFFSET);
        self.mmio.write(APB2ENR_OFFSET, val | (1 << bit));
    }

    /// Enable a clock bit in the AHB5ENR register (XSPI, MCE, DMA2D, etc.).
    pub fn enable_ahb5_clock(&self, bit: u8) {
        let val = self.mmio.read(AHB5ENR_OFFSET);
        self.mmio.write(AHB5ENR_OFFSET, val | (1 << bit));
    }
}

// Sets the Non-Secure VTOR. Placed in `rcc` for convenience as RCC
// initialisation is the earliest boot stage with peripheral access.
// Kept as a free function (not a method on `Rcc<M>`) because it writes to
// a fixed system-control address (`SCB_NS.VTOR @ 0xE002_ED08`) that is
// independent of the RCC base — generic-ifying over the in-memory backend
// would not give a useful host-test surface and would force every caller
// to spell out the monomorphisation. Mirrors L552 rcc.rs shape.
pub fn set_vtor_ns(vtor_ns: u32) {
    // SAFETY: SCB_NS.VTOR is a system-control MMIO register; this is the
    // documented mechanism for the Secure world to install the Non-Secure
    // vector table base.
    unsafe {
        write_register(0xE002_ED08 as *const u32, 0, vtor_ns);
    }
}

// AHB4ENR bit positions for GPIO ports
pub const GPIOAEN: u8 = 0;
pub const GPIOBEN: u8 = 1;
pub const GPIOCEN: u8 = 2;
pub const GPIODEN: u8 = 3;
pub const GPIOEEN: u8 = 4;
pub const GPIOFEN: u8 = 5;
pub const GPIOGEN: u8 = 6;

// AHB3ENR bit positions (crypto peripherals)
pub const RNGEN: u8 = 0;
pub const HASHEN: u8 = 1;
pub const CRYP1EN: u8 = 2;
pub const SAESEN: u8 = 4;
pub const PKAEN: u8 = 8;

// APB2ENR bit positions
pub const USART1EN: u8 = 4;

// AHB5ENR bit positions (XSPI, MCE, DMA, etc.)
pub const XSPI2EN: u8 = 12;
pub const XSPIMEN: u8 = 13;
pub const MCE1EN: u8 = 14;
pub const MCE2EN: u8 = 15;

// ────────────────────────────────────────────────────────────────────────────
// umbra_hal::Rcc adapter.
// N657's production PLL bring-up is split across the Boot ROM (initial
// PLL1 setup) + Umbra FSBL.0 retune to 800 MHz (per memory
// project_n657_sysclk_800mhz). Neither lives in `Rcc::*` inherent
// methods today — both are in platform_impl.rs. The trait method here
// is a stub that documents N657's "PLL already configured" production
// state; can lift the retune into `Rcc` once the L552 +
// N657 init_clocks logic is unified.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RccError {
    /// Reserved.
    Unreachable,
}

impl<M: MmioAccess> umbra_hal::Rcc for Rcc<M> {
    type Error = RccError;

    fn init_sysclk_pll(&mut self) -> Result<(), Self::Error> {
        // N657 PLL1 is set up by the Boot ROM, then Umbra FSBL.0
        // retunes to 800 MHz. Both happen in platform_impl.rs, not here.
        // No-op marker so the trait surface is satisfied.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `enable_ahb3_clock(HASHEN=1)` issues a read-OR-write to
    /// RCC_AHB3ENR at offset 0x258 that sets bit 1 (HASH) while preserving
    /// other bits. AHB3ENR offset is load-bearing per memory
    ///.
    #[test]
    fn enable_ahb3_clock_sets_hash_bit_at_0x258() {
        let mem = MmioMem::new(RCC_BASE_ADDR);
        // Preload AHB3ENR with bit 0 set (RNG) — must survive the RMW.
        mem.preload_register(AHB3ENR_OFFSET, 1 << 0);

        let rcc = Rcc::<_>::new_with_mmio(mem.handle());
        rcc.enable_ahb3_clock(HASHEN);

        let log = mem.write_log();
        // read-OR-write = 1 Read + 1 Write.
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[0] {
            MmioOp::Read { addr, .. } => {
                assert_eq!(addr, RCC_BASE_ADDR + AHB3ENR_OFFSET);
            }
            _ => panic!("expected Read AHB3ENR at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + AHB3ENR_OFFSET);
                // bit 1 (HASH) set, bit 0 (RNG) preserved.
                assert_eq!(value, (1 << 0) | (1 << 1));
            }
            _ => panic!("expected Write AHB3ENR at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies `enable_ahb4_clock(GPIOAEN=0)` issues a read-OR-write to
    /// RCC_AHB4ENR at offset 0x25C. AHB4ENR offset is load-bearing per
    /// (GPIO bus).
    #[test]
    fn enable_ahb4_clock_sets_gpioa_bit_at_0x25c() {
        let mem = MmioMem::new(RCC_BASE_ADDR);
        let rcc = Rcc::<_>::new_with_mmio(mem.handle());
        rcc.enable_ahb4_clock(GPIOAEN);

        let log = mem.write_log();
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + AHB4ENR_OFFSET);
                assert_eq!(value, 1 << 0); // GPIOA bit
            }
            _ => panic!("expected Write AHB4ENR at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies `force_hsi` issues the documented register-write sequence:
    /// (1) CR read + write (HSION), (2) CR poll for HSIRDY=1,
    /// (3) CFGR1 read + write (SW=00), (4) CFGR1 poll for SWS=00.
    /// Seeds the mem so HSIRDY (bit 2) is already set and SWS (bits [4:3])
    /// is already 00 — both polls exit on the first iteration. Verifies
    /// the offset constants (CR=0x00, CFGR1=0x1C) and the SW-clear mask.
    #[test]
    fn force_hsi_writes_cr_then_cfgr1_with_sw_cleared() {
        let mem = MmioMem::new(RCC_BASE_ADDR);
        // HSIRDY=1 (bit 2) so the first poll exits immediately. Also seed
        // SW=11 (PLL) so the CFGR1 write must clear it; SWS=00 (bits [4:3])
        // so the second poll exits immediately. SWS readback bits 3-4 stay 0.
        mem.preload_register(CR_OFFSET, 1 << 2);
        mem.preload_register(CFGR1_OFFSET, 0x3); // SW=11, SWS=00

        let rcc = Rcc::<_>::new_with_mmio(mem.handle());
        rcc.force_hsi();

        let log = mem.write_log();
        // Sequence: CR read, CR write(HSION), CR read(poll HSIRDY=1 exits),
        // CFGR1 read, CFGR1 write(SW cleared), CFGR1 read(poll SWS=00 exits).
        assert_eq!(log.len(), 6, "log = {:?}", log);

        // log[0]: CR read.
        assert!(matches!(log[0], MmioOp::Read { addr, .. } if addr == RCC_BASE_ADDR + CR_OFFSET));
        // log[1]: CR write — HSION (bit 0) set, HSIRDY (bit 2) preserved.
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + CR_OFFSET);
                assert_eq!(value, (1 << 2) | 1);
            }
            _ => panic!("expected Write CR at position 1, got {:?}", log[1]),
        }
        // log[2]: CR read (HSIRDY poll).
        assert!(matches!(log[2], MmioOp::Read { addr, .. } if addr == RCC_BASE_ADDR + CR_OFFSET));
        // log[3]: CFGR1 read.
        assert!(
            matches!(log[3], MmioOp::Read { addr, .. } if addr == RCC_BASE_ADDR + CFGR1_OFFSET)
        );
        // log[4]: CFGR1 write — SW[1:0] cleared (was 11 → now 00).
        match log[4] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + CFGR1_OFFSET);
                assert_eq!(value & 0x3, 0); // SW field cleared
            }
            _ => panic!("expected Write CFGR1 at position 4, got {:?}", log[4]),
        }
        // log[5]: CFGR1 read (SWS poll).
        assert!(
            matches!(log[5], MmioOp::Read { addr, .. } if addr == RCC_BASE_ADDR + CFGR1_OFFSET)
        );
    }
}
