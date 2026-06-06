// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! Clock + cache + NPU bring-up — moved from the monolithic `platform_impl.rs`
//! during. Pure file reorganization; no semantic
//! changes. See `mod.rs` for the original module docs and landmine catalogue.

use arm::mmio::{DCISW, ICIALLU, SCB_CCR, SCB_CCSIDR, SCB_CSSELR};

/// Re-secure RISUP 106 (NPU config port) by setting SECCFGR3 bit 10, then
/// read the register back to confirm the write was honoured. The N657 RIFSC
/// is the platform's memory-protection controller (the GTZC/MPCBB analogue on
/// L5), so a refused re-secure surfaces as the platform-generic
/// `UmbraError::MemProtectDenied { addr }` — here the RIFSC SECCFGR3 address.
fn resecure_npu_risup() -> umbra_error::UmbraResult<()> {
    unsafe {
        let rifsc = 0x5402_4000usize;
        let reg = (rifsc + 0x01C) as *mut u32;
        let seccfgr3 = core::ptr::read_volatile(reg as *const u32);
        core::ptr::write_volatile(reg, seccfgr3 | (1u32 << 10));
        if core::ptr::read_volatile(reg as *const u32) & (1u32 << 10) == 0 {
            return Err(umbra_error::UmbraError::MemProtectDenied { addr: reg as u32 });
        }
    }
    Ok(())
}

pub fn init_clocks() {
    // RIFSC unlock: try to clear SECCFGR + PRIVCFGR.
    // If GLOCK is set by Boot ROM, writes are silently ignored — peripherals
    // stay Secure and must be accessed via Secure alias (0x5x...).
    // The diagnostic in main.rs reads and prints the actual state.
    unsafe {
        let rifsc = 0x5402_4000usize;
        let glock = core::ptr::read_volatile(rifsc as *const u32);
        if glock & 1 == 0 {
            // GLOCK clear — we can modify RIFSC
            let mut i: u32 = 0;
            while i < 6 {
                let off = (i as usize) * 4;
                // Check per-peripheral lock before writing
                let rcfglockr = core::ptr::read_volatile((rifsc + 0x050 + off) as *const u32);
                if rcfglockr == 0 {
                    core::ptr::write_volatile((rifsc + 0x010 + off) as *mut u32, 0);
                    core::ptr::write_volatile((rifsc + 0x030 + off) as *mut u32, 0);
                } else {
                    let mask = !rcfglockr;
                    let sec = core::ptr::read_volatile((rifsc + 0x010 + off) as *const u32);
                    core::ptr::write_volatile((rifsc + 0x010 + off) as *mut u32, sec & !mask);
                    let priv_ = core::ptr::read_volatile((rifsc + 0x030 + off) as *const u32);
                    core::ptr::write_volatile((rifsc + 0x030 + off) as *mut u32, priv_ & !mask);
                }
                i += 1;
            }
        }
        // If GLOCK=1: skip writes (would be ignored anyway).
        // All subsequent peripheral access uses Secure alias to work either way.
    }

    // Re-secure RISUP 106 (NPU configuration port).
    // The unlock loop above cleared every SECCFGR bit so the NS host can
    // touch any peripheral. But per RM0486 §6.3.4, the NPU has a "secure
    // guard" override: if its configuration RISUP is NS-accessible, the
    // RIMU forces all of NPU's AXI master transactions to NS *regardless
    // of RIMC.MSEC=1*. That lands all NPU bytecode/weight/activation
    // fetches as NS-CID=1 transactions, which RISAF12 (XSPI2) and RISAF3
    // (AXISRAM2) reject at their defaults (Sec-Priv-CID=1 only) — the
    // NPU surfaces this as EPC.IRQ.ERR_START (bit 3) on every kick.
    // Setting SECCFGR3 bit 10 = 1 makes the NPU Secure-only configurable,
    // disabling the secure-guard override and letting our RIMC tag stand.
    // RISUP 106 (NPU) sits in SECCFGR3 (covers RISUPs 96-127); 106-96=10.
    // Skips silently if RCFGLOCKR3 bit 10 was set by Boot ROM. The N657
    // host application has no business touching NPU registers; only the
    // Secure enclave does.
    if let Err(umbra_error::UmbraError::MemProtectDenied { addr }) = resecure_npu_risup() {
        // RCFGLOCKR3 bit 10 was locked by Boot ROM, so the re-secure write was
        // ignored: the NPU keeps its secure-guard NS override. Non-fatal for
        // hosts that never touch the NPU (bare_metal); Secure NPU inference
        // (object_detection) would fail downstream with EPC.IRQ.ERR_START.
        crate::raw_print::print_str("[UMBRASecureBoot] RIFSC re-secure denied at 0x");
        crate::raw_print::print_hex(addr);
        crate::raw_print::print_str(" (NPU RISUP106 locked)\n");
    }

    // RCC Secure alias (0x56028000). Register map (RM0486):
    // AHB3ENR (0x258): crypto — RNGEN=0, HASHEN=1, CRYPEN=2, SAESEN=4
    // AHB4ENR (0x25C): GPIO A-Q + PWR + CRC
    // APB2ENR (0x26C): USART1EN=4
    unsafe {
        let rcc_s = 0x5602_8000usize;

        // Enable GPIOB + GPIOE + GPIOG clocks (AHB4ENR bits 1,4,6).
        // GPIOB is for PB12 = Nucleo board-level external SMPS overdrive
        // (`STM32Cube_FW_N6/Drivers/BSP/STM32N6xx_Nucleo/stm32n6xx_nucleo.c:169`),
        // required before bumping CPU above 400 MHz.
        let ahb4 = core::ptr::read_volatile((rcc_s + 0x25C) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x25C) as *mut u32,
            ahb4 | (1 << 1) | (1 << 4) | (1 << 6), // GPIOBEN + GPIOEEN + GPIOGEN
        );

        // Enable USART1 clock (APB2ENR bit 4)
        let apb2 = core::ptr::read_volatile((rcc_s + 0x26C) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x26C) as *mut u32, apb2 | (1 << 4));

        // Enable HASH + CRYP clocks (AHB3ENR bits 1,2)
        let ahb3 = core::ptr::read_volatile((rcc_s + 0x258) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x258) as *mut u32,
            ahb3 | (1 << 1) | (1 << 2), // HASHEN + CRYPEN
        );

        // AXISRAM3 enable removed: RAMCFG (0x52023000+) is RIFSC-blocked from
        // FSBL Secure code. Host now uses AXISRAM1 NS alias (0x24000000) which
        // is always powered by Boot ROM (RCC_MEMENR.AXISRAM1EN=1 default).
    }

    // ── PLL1: CPU SYSCLK = 800 MHz, AXI = 400 MHz, HCLK = 200 MHz ─────
    // Mirrors ST's `SystemClock_Config` for PLL1 only (PLL3 for the NPU
    // is configured separately further down).
    // Source: host/STM32N6-GettingStarted-ObjectDetection/Application/
    // NUCLEO-N657X0-Q/Src/main.c:591-694, decoded against:
    // - STM32Cube_FW_N6/Drivers/STM32N6xx_HAL_Driver/Src/stm32n6xx_hal_rcc.c
    // - STM32Cube_FW_N6/Drivers/CMSIS/Device/ST/STM32N6xx/Include/stm32n657xx.h
    // Field encoding pitfalls:
    // - PLLM/N raw (write 25 for N=25), IC divider as (divider-1).
    // - CSR/CCR are write-1-set / write-1-clear (not RMW).
    // - SMPS "overdrive" on this Nucleo = drive PB12 high (board GPIO,
    // NOT a chip PWR_CR1 poke). VOSCR is left at Boot ROM default —
    // ST's reference doesn't touch it either.
    unsafe {
        let rcc_s = 0x5602_8000usize;
        let gpiob_s = 0x5602_0400usize; // GPIOB Secure alias

        // Switch USART1 kernel clock to HSI (64 MHz) BEFORE PLL1
        // changes, so the post-bump banner survives. Boot ROM defaults USART1
        // to IC9-from-PLL1 (= 150 MHz), which would retune to a garbled
        // value when we reprogram PLL1 below.
        // CCIPR13 (offset 0x174) USART1SEL[2:0] = 6 (HSI).
        let ccipr13 = core::ptr::read_volatile((rcc_s + 0x174) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x174) as *mut u32, (ccipr13 & !0x7) | 6);

        // SMPS overdrive: PB12 mode = output, drive high.
        let moder = core::ptr::read_volatile(gpiob_s as *const u32);
        core::ptr::write_volatile(gpiob_s as *mut u32, (moder & !(0b11 << 24)) | (0b01 << 24)); // PB12 = output
        core::ptr::write_volatile((gpiob_s + 0x18) as *mut u32, 1 << 12); // BS12

        // HSI sanity (Boot ROM should leave HSIRDY=1).
        while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 3) == 0 {}

        // Switch CPUSW + SYSSW to HSI BEFORE disabling PLL1.
        // Boot ROM has PLL1 ≈ 1200 MHz feeding CPU via IC1 (PLL1/3 = 400 MHz)
        // and USART1 via IC9 (PLL1/8 = 150 MHz). Writing PLL1ONC while PLL1
        // is the active CPU clock source halts the core mid-instruction
        // with no fault. ST's HAL handles this implicitly inside
        // HAL_RCC_ClockConfig before HAL_RCC_OscConfig.
        // Per stm32n657xx.h: CPUSW [17:16] / CPUSWS readback [21:20];
        // SYSSW [25:24] / SYSSWS readback [29:28].
        let cfgr1 = core::ptr::read_volatile((rcc_s + 0x020) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x020) as *mut u32,
            cfgr1 & !((0x3 << 16) | (0x3 << 24)),
        ); // CPUSW=0, SYSSW=0 → HSI
        while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 20) & 0x3 != 0 {}
        while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 28) & 0x3 != 0 {}
        // CPU + AXI now on HSI = 64 MHz. Safe to disable PLL1.

        // Disable PLL1 before reconfig. CCR is clear-only.
        core::ptr::write_volatile((rcc_s + 0x1000) as *mut u32, 1 << 8); // PLL1ONC
        while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 8) != 0 {}

        // Program PLL1 dividers/multiplier (HSI / M=2 × N=25 = 800 MHz VCO,
        // P1=P2=1 → 800 MHz output). Integer mode (MODSSDIS=1, MODDSEN=0, frac=0).
        // PLL1CFGR3 mode bit FIRST (rcc.c:2139).
        core::ptr::write_volatile((rcc_s + 0x088) as *mut u32, 1 << 2); // MODSSDIS=1
                                                                        // PLL1CFGR1: SEL[30:28]=0 (HSI), DIVM[25:20]=2, DIVN[19:8]=25, BYP=0
        core::ptr::write_volatile(
            (rcc_s + 0x080) as *mut u32,
            (0u32 << 28) | (2u32 << 20) | (25u32 << 8),
        );
        // PLL1CFGR2: DIVNFRAC=0
        core::ptr::write_volatile((rcc_s + 0x084) as *mut u32, 0);
        // PLL1CFGR3 final: PDIV1=1, PDIV2=1, PDIVEN=1, MODSSDIS=1, MODSSRST=1
        core::ptr::write_volatile(
            (rcc_s + 0x088) as *mut u32,
            (1u32 << 27) | (1u32 << 24) | (1u32 << 30) | (1u32 << 2) | (1u32 << 0),
        );

        // Enable PLL1, wait for lock. CSR is set-only.
        core::ptr::write_volatile((rcc_s + 0x800) as *mut u32, 1 << 8); // PLL1ONS
        while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 8) == 0 {}

        // Configure IC1 (CPU = PLL1/1 = 800 MHz) and IC2 (AXI = PLL1/2 = 400 MHz).
        // Encoding: SEL[29:28] | ((divider-1) << 16). PLL1 = SEL 0.
        core::ptr::write_volatile((rcc_s + 0x0C4) as *mut u32, (0u32 << 28) | (0u32 << 16)); // IC1 div 1
        core::ptr::write_volatile((rcc_s + 0x0C8) as *mut u32, (0u32 << 28) | (1u32 << 16)); // IC2 div 2

        // Enable IC2 output (DIVENSR is set-only). IC1 always-enabled
        // when CPUSW selects it; IC11/IC6 left disabled (used in G.1).
        core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 1); // IC2ENS

        // Bus prescalers: HPRE=001 (HCLK = AXI/2 = 200 MHz). PPRE=000 (DIV1).
        // Matches ST main.c:667 RCC_HCLK_DIV2.
        // We tried HPRE=000 (HCLK = 400 MHz) once to halve NPU poll-loop
        // MMIO latency. Result: no UART output, system never boots.
        // 200 MHz is the AHB max for this part — confirmed empirically.
        let cfgr2 = core::ptr::read_volatile((rcc_s + 0x024) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x024) as *mut u32,
            (cfgr2 & !((0x7 << 20) | (0x7 << 4) | 0x7)) | (0x1 << 20),
        );

        // Switch CPUCLK to IC1 (CPUSW=3 in CFGR1[17:16]; readback CPUSWS at [21:20]).
        let cfgr1 = core::ptr::read_volatile((rcc_s + 0x020) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x020) as *mut u32,
            (cfgr1 & !(0x3 << 16)) | (0x3 << 16),
        );
        while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 20) & 0x3 != 0x3 {}

        // Switch SYSCLK to IC2/IC6/IC11 mux (SYSSW=3 at [25:24]; readback SYSSWS at [29:28]).
        let cfgr1 = core::ptr::read_volatile((rcc_s + 0x020) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x020) as *mut u32,
            (cfgr1 & !(0x3 << 24)) | (0x3 << 24),
        );
        while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 28) & 0x3 != 0x3 {}
        // CPU now 800 MHz; AXI 400 MHz; HCLK 200 MHz; USART1 stays on HSI=64 MHz.

        // ── PLL3 = 900 MHz for the NPU clock band ─────────────────────────
        // HSI / M=8 × N=225 = 1800 MHz VCO, P1=1, P2=2 → 900 MHz output.
        // Routed via IC11 (SEL=PLL3, div=1) to ck_icn_npu / ck_icn_axisram.
        // IC11 is enabled in DIVENSR but not yet selected by any peripheral
        // — the NPU peripheral comes online further below.
        // Unlike PLL1, PLL3 isn't currently driving any active clock
        // (Boot ROM only configured PLL1), so we don't need the
        // CPUSW/SYSSW-to-HSI dance before disabling. Direct disable is safe.
        // Source: ST `SystemClock_Config` main.c:620-627 + register layout
        // mirrors PLL1's at offsets 0x0A0/0x0A4/0x0A8 (vs 0x080/0x084/0x088).

        // Disable PLL3 (CCR write-1-clear, bit 10).
        core::ptr::write_volatile((rcc_s + 0x1000) as *mut u32, 1 << 10); // PLL3ONC
        while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 10) != 0 {}

        // Program PLL3 dividers/multiplier.
        // Force MODSSDIS=1 first (rcc.c:2139 ordering).
        core::ptr::write_volatile((rcc_s + 0x0A8) as *mut u32, 1 << 2); // MODSSDIS
                                                                        // PLL3CFGR1: SEL[30:28]=0 (HSI), DIVM[25:20]=8, DIVN[19:8]=225, BYP=0
        core::ptr::write_volatile(
            (rcc_s + 0x0A0) as *mut u32,
            (0u32 << 28) | (8u32 << 20) | (225u32 << 8),
        );
        // PLL3CFGR2: DIVNFRAC=0 (integer mode)
        core::ptr::write_volatile((rcc_s + 0x0A4) as *mut u32, 0);
        // PLL3CFGR3 final: PDIV1=1, PDIV2=2, PDIVEN=1, MODSSDIS=1, MODSSRST=1
        core::ptr::write_volatile(
            (rcc_s + 0x0A8) as *mut u32,
            (1u32 << 27) | (2u32 << 24) | (1u32 << 30) | (1u32 << 2) | (1u32 << 0),
        );

        // Enable PLL3, wait for lock (bit 10 in CSR/SR).
        core::ptr::write_volatile((rcc_s + 0x800) as *mut u32, 1 << 10); // PLL3ONS
        while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 10) == 0 {}

        // IC11: SEL=PLL3 (0x2 << 28 = 0x2000_0000), divider=1
        // (write 0 to INT field). Output = PLL3/1 = 900 MHz.
        core::ptr::write_volatile((rcc_s + 0x0EC) as *mut u32, (0x2u32 << 28) | (0u32 << 16));

        // Enable IC11 in DIVENSR (set-only, bit 10).
        // SYSSW=3 (IC2/IC6/IC11) was already selected above;
        // the NPU peripheral will source IC11 when it comes online.
        core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 10); // IC11ENS

        // IC6 = PLL3 / 1 = 900 MHz, drives sysc_ck (NPU compute
        // clock) when SYSSW=3 (already selected above). Without this
        // IC6 stays disabled and sysc_ck falls back to its prior source
        // (HSI ≈ 64 MHz), running NPU compute at ~14× below spec.
        // IC6 register at RCC + 0x0D8 (= 0x0C4 + 4 × (6-1)). Enable bit
        // in DIVENSR is bit 5. RM0486 §14.6.1 + Figure 46.
        core::ptr::write_volatile((rcc_s + 0x0D8) as *mut u32, (0x2u32 << 28) | (0u32 << 16)); // SEL=PLL3, div 1
        core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 5); // IC6ENS

        // ── NPU peripheral + AXISRAM3-6 + CACHEAXI ────────────────────────
        // Mirrors ST's `NPURam_enable` (Cube template `main.c:440-490`).
        // Sequence:
        // - NPU clock + reset pulse (RCC.AHB5ENR.NPUEN, AHB5RSTSR/CR bit 31)
        // - AXISRAM3..6 bank clocks (RCC.MEMENR bits 0-3)
        // - RAMCFG clock + per-bank power-on (clear RAMCFG.CR.SRAMSD bit 20)
        // - CACHEAXIRAM clock + CACHEAXI clock + reset pulse
        // AXISRAM3-6 are 4 × 448 KB scratch banks for NPU activations. They
        // start clock-gated AND with RAMCFG.SRAMSD=1 (power-down) after
        // reset, so both gates need to be opened. CACHEAXI is the NPU's
        // weight cache — without it, weight reads from XSPI2 would not be
        // cached → 10-50× perf drop per ST audit notes.

        // RIMC: tag NPU bus master with CID=1, SEC, PRIV.
        // When NPU acts as bus master (reading/writing model buffers and
        // scratch in AXISRAM), RIFSC stamps each access with the master
        // CID + security attribute.
        // The enclave runs Secure-side and keeps model I/O buffers at
        // 0x342E0000 (Secure-aliased AXISRAM). The NPU blob's hardcoded
        // references are all 0x34xxxxxx Secure addresses, so the NPU
        // master must also be Secure for IDAU to permit those accesses.
        // {CID=1, SEC, PRIV} matches ST's all-Secure reference design.
        // RIMC_ATTR layout (stm32n657xx.h):
        // bits [6:4] MCID, bit [8] MSEC, bit [9] MPRIV
        // Address: RIFSC_S + 0xC10 + 4*master_idx; NPU master_idx = 1.
        core::ptr::write_volatile(
            0x5402_4C14 as *mut u32,
            (1u32 << 4) | (1u32 << 8) | (1u32 << 9),
        ); /* CID=1 SEC PRIV */

        // NPU peripheral clock (AHB5ENR bit 31).
        let ahb5 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x260) as *mut u32, ahb5 | (1u32 << 31));

        // NPU reset pulse. AHB5RSTSR (0x0A20) is set-only;
        // AHB5RSTCR (0x1220) is clear-only. Bit 31 = NPURSTS/NPURSTC.
        core::ptr::write_volatile((rcc_s + 0x0A20) as *mut u32, 1u32 << 31); // assert reset
        cortex_m::asm::dsb();
        core::ptr::write_volatile((rcc_s + 0x1220) as *mut u32, 1u32 << 31); // release reset
        cortex_m::asm::dsb();

        // AXISRAM3..6 + CACHEAXIRAM bank clocks (MEMENR @ 0x024C).
        // AXISRAM3EN..6EN at bits 0..3; CACHEAXIRAMEN at bit 10.
        let memenr = core::ptr::read_volatile((rcc_s + 0x24C) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x24C) as *mut u32, memenr | 0xF | (1 << 10));

        // RAMCFG controller clock (AHB2ENR @ 0x0254 bit 12).
        let ahb2 = core::ptr::read_volatile((rcc_s + 0x254) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x254) as *mut u32, ahb2 | (1u32 << 12));
        cortex_m::asm::dsb();

        // Power on AXISRAM3..6 by clearing RAMCFG.CR.SRAMSD (bit 20)
        // for each bank. Banks default to power-down after reset; clearing
        // SRAMSD wakes them. Per-bank RAMCFG bases (Secure alias):
        // SRAM3_AXI = 0x5202_3100, SRAM4 = 0x5202_3180,
        // SRAM5 = 0x5202_3200, SRAM6 = 0x5202_3280.
        // CR is at offset 0x00 of each instance.
        for ramcfg_base in [0x5202_3100usize, 0x5202_3180, 0x5202_3200, 0x5202_3280] {
            let cr = core::ptr::read_volatile(ramcfg_base as *const u32);
            core::ptr::write_volatile(ramcfg_base as *mut u32, cr & !(1u32 << 20));
        }
        cortex_m::asm::dsb();

        // CACHEAXI peripheral clock (AHB5ENR bit 30).
        let ahb5 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x260) as *mut u32, ahb5 | (1u32 << 30));

        // CACHEAXI reset pulse (AHB5RSTSR/CR bit 30).
        core::ptr::write_volatile((rcc_s + 0x0A20) as *mut u32, 1u32 << 30); // assert
        cortex_m::asm::dsb();
        core::ptr::write_volatile((rcc_s + 0x1220) as *mut u32, 1u32 << 30); // release
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // ── IAC + sleep-mode for NPU subsystem ────────────────────────────
        // IAC = Illegal Access Controller — records RIF violations to its
        // own ISR register (offset 0x0 of the IAC peripheral, debugger-
        // readable). Mirrors ST's `IAC_Config` (Cube template `main.c:417-
        // 423`). NVIC-side IRQ enable and a trap handler are not wired
        // yet — they're only needed once RIF violations actually fire.
        // RIMC NPU master config is handled above; SECCFGR3 bit 10
        // re-secure of RISUP 106 (NPU) happens at the top of init_clocks.

        // IAC clock enable (AHB3ENR @ 0x258 bit 10).
        let ahb3 = core::ptr::read_volatile((rcc_s + 0x258) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x258) as *mut u32, ahb3 | (1 << 10));

        // IAC reset pulse (AHB3RSTSR @ 0xA18 / RSTCR @ 0x1218 bit 10).
        core::ptr::write_volatile((rcc_s + 0x0A18) as *mut u32, 1 << 10); // assert
        cortex_m::asm::dsb();
        core::ptr::write_volatile((rcc_s + 0x1218) as *mut u32, 1 << 10); // release
        cortex_m::asm::dsb();

        // Sleep-mode bits so FreeRTOS WFE-idle doesn't gate the
        // NPU subsystem mid-inference (CPU sleeps but NPU keeps running).
        // AHB5LPENR (0x2A0): bit 30 CACHEAXI, bit 31 NPU
        // MEMLPENR (0x28C): bits 0-3 AXISRAM3..6, bit 10 CACHEAXIRAM
        // AHB2LPENR (0x294): bit 12 RAMCFG
        // Mirrors ST's `set_clk_sleep_mode` (main.c:365-387).
        let ahb5lp = core::ptr::read_volatile((rcc_s + 0x2A0) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x2A0) as *mut u32,
            ahb5lp | (1u32 << 30) | (1u32 << 31),
        );
        let memlp = core::ptr::read_volatile((rcc_s + 0x28C) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x28C) as *mut u32, memlp | 0xF | (1 << 10));
        let ahb2lp = core::ptr::read_volatile((rcc_s + 0x294) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x294) as *mut u32, ahb2lp | (1u32 << 12));
        cortex_m::asm::dsb();
    }

    // ── Enable I-cache + D-cache ──────────────────────────────────────
    // M55 has integrated I-cache + D-cache (vs M33's optional only-I).
    // Sequence: MEMSYSCTL.MSCR.ICACTIVE → SCB_EnableICache →
    // MSCR.DCACTIVE → SCB_EnableDCache. The MEMSYSCTL "active" power-on
    // bits are M55-specific and required *before* the standard SCB
    // enable — forgetting them silently no-ops the SCB write.
    // Caches were defensively *disabled* by `_umb_start` in startup_n657.s
    // because Boot ROM DMA'd the FSBL image into AXISRAM2 (potentially
    // stale cache lines). Re-enabling them after invalidate is the
    // canonical pattern.
    unsafe {
        let mscr = 0xE001_E000 as *mut u32; // MEMSYSCTL.MSCR
        let scb_ccr = SCB_CCR;
        let scb_ccsidr = SCB_CCSIDR;
        let scb_csselr = SCB_CSSELR;
        let scb_iciallu = ICIALLU;
        let scb_dcisw = DCISW;

        // ─── I-cache ───
        // Power on: MSCR.ICACTIVE (bit 13).
        let m = core::ptr::read_volatile(mscr);
        core::ptr::write_volatile(mscr, m | (1 << 13));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Invalidate (single-shot register; any write clears the whole I-cache).
        core::ptr::write_volatile(scb_iciallu, 0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Enable: CCR.IC (bit 17).
        let c = core::ptr::read_volatile(scb_ccr);
        core::ptr::write_volatile(scb_ccr, c | (1 << 17));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // ─── D-cache ───
        // Power on: MSCR.DCACTIVE (bit 12).
        let m = core::ptr::read_volatile(mscr);
        core::ptr::write_volatile(mscr, m | (1 << 12));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // Select L1 D-cache (CSSELR.LEVEL=0, IND=0). Required before
        // CCSIDR read returns valid geometry.
        core::ptr::write_volatile(scb_csselr, 0);
        cortex_m::asm::dsb();

        // Read geometry: NUMSETS [27:13], ASSOCIATIVITY [12:3] (both
        // store value-1, so loop counts from value down to 0 inclusive).
        let ccsidr = core::ptr::read_volatile(scb_ccsidr);
        let numsets = (ccsidr >> 13) & 0x7FFF;
        let assoc = (ccsidr >> 3) & 0x3FF;

        // Invalidate every (set, way) line. DCISW field layout:
        // Way [31:30], Set [13:5]. Standard ARM reference impl pattern.
        let mut set = numsets;
        loop {
            let mut way = assoc;
            loop {
                core::ptr::write_volatile(scb_dcisw, (way << 30) | (set << 5));
                if way == 0 {
                    break;
                }
                way -= 1;
            }
            if set == 0 {
                break;
            }
            set -= 1;
        }
        cortex_m::asm::dsb();

        // Enable: CCR.DC (bit 16). Coherency between this cache and the
        // I-cache for the enclave-load path is handled inside
        // `secure_kernel::load_block_n657` (DCCMVAC per loaded line +
        // ICIALLU at end), so by the time the enclave executes its
        // first instruction the just-written bytes are visible to
        // I-cache via RAM rather than stale through the bypass path.
        let c = core::ptr::read_volatile(scb_ccr);
        core::ptr::write_volatile(scb_ccr, c | (1 << 16));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
}
