use arm::mmio::{
    DCISW, ICIALLU, NVIC_ITNS1,
    SCB_CCR, SCB_CCSIDR, SCB_CSSELR, SCB_SHCSR,
    SYST_CSR,
};
use kernel::platform::PlatformBoot;
use drivers::gpio::{Gpio, Port, PinMode};

// _umb_fsbl_image_end no longer used — enclave_base is now fixed at HOST_FLASH_END

pub struct Stm32n657Platform;

impl Stm32n657Platform {
    pub fn new() -> Self { Stm32n657Platform }
}

impl PlatformBoot for Stm32n657Platform {
    fn init_clocks(&self) {
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
                    let rcfglockr = core::ptr::read_volatile(
                        (rifsc + 0x050 + off) as *const u32
                    );
                    if rcfglockr == 0 {
                        core::ptr::write_volatile((rifsc + 0x010 + off) as *mut u32, 0);
                        core::ptr::write_volatile((rifsc + 0x030 + off) as *mut u32, 0);
                    } else {
                        let mask = !rcfglockr;
                        let sec = core::ptr::read_volatile(
                            (rifsc + 0x010 + off) as *const u32
                        );
                        core::ptr::write_volatile(
                            (rifsc + 0x010 + off) as *mut u32, sec & !mask
                        );
                        let priv_ = core::ptr::read_volatile(
                            (rifsc + 0x030 + off) as *const u32
                        );
                        core::ptr::write_volatile(
                            (rifsc + 0x030 + off) as *mut u32, priv_ & !mask
                        );
                    }
                    i += 1;
                }
            }
            // If GLOCK=1: skip writes (would be ignored anyway).
            // All subsequent peripheral access uses Secure alias to work either way.
        }

        // G.2.b — re-secure RISUP 106 (NPU configuration port).
        //
        // The unlock loop above cleared every SECCFGR bit so the NS host can
        // touch any peripheral. But per RM0486 §6.3.4, the NPU has a "secure
        // guard" override: if its configuration RISUP is NS-accessible, the
        // RIMU forces all of NPU's AXI master transactions to NS *regardless
        // of RIMC.MSEC=1*. That lands all NPU bytecode/weight/activation
        // fetches as NS-CID=1 transactions, which RISAF12 (XSPI2) and RISAF3
        // (AXISRAM2) reject at their defaults (Sec-Priv-CID=1 only) — the
        // NPU surfaces this as EPC.IRQ.ERR_START (bit 3) on every kick.
        //
        // Setting SECCFGR3 bit 10 = 1 makes the NPU Secure-only configurable,
        // disabling the secure-guard override and letting our RIMC tag stand.
        // RISUP 106 (NPU) sits in SECCFGR3 (covers RISUPs 96-127); 106-96=10.
        //
        // Skips silently if RCFGLOCKR3 bit 10 was set by Boot ROM. The N657
        // host application has no business touching NPU registers; only the
        // Secure enclave does.
        unsafe {
            let rifsc = 0x5402_4000usize;
            let seccfgr3 = core::ptr::read_volatile((rifsc + 0x01C) as *const u32);
            core::ptr::write_volatile(
                (rifsc + 0x01C) as *mut u32,
                seccfgr3 | (1u32 << 10),
            );
        }

        // RCC Secure alias (0x56028000). Register map (RM0486):
        //   AHB3ENR (0x258): crypto — RNGEN=0, HASHEN=1, CRYPEN=2, SAESEN=4
        //   AHB4ENR (0x25C): GPIO A-Q + PWR + CRC
        //   APB2ENR (0x26C): USART1EN=4
        unsafe {
            let rcc_s = 0x5602_8000usize;

            // Enable GPIOB + GPIOE + GPIOG clocks (AHB4ENR bits 1,4,6).
            // GPIOB is for PB12 = Nucleo board-level external SMPS overdrive
            // (`STM32Cube_FW_N6/Drivers/BSP/STM32N6xx_Nucleo/stm32n6xx_nucleo.c:169`),
            // required before bumping CPU above 400 MHz.
            let ahb4 = core::ptr::read_volatile((rcc_s + 0x25C) as *const u32);
            core::ptr::write_volatile(
                (rcc_s + 0x25C) as *mut u32,
                ahb4 | (1 << 1) | (1 << 4) | (1 << 6) // GPIOBEN + GPIOEEN + GPIOGEN
            );

            // Enable USART1 clock (APB2ENR bit 4)
            let apb2 = core::ptr::read_volatile((rcc_s + 0x26C) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x26C) as *mut u32, apb2 | (1 << 4));

            // Enable HASH + CRYP clocks (AHB3ENR bits 1,2)
            let ahb3 = core::ptr::read_volatile((rcc_s + 0x258) as *const u32);
            core::ptr::write_volatile(
                (rcc_s + 0x258) as *mut u32,
                ahb3 | (1 << 1) | (1 << 2) // HASHEN + CRYPEN
            );

            // AXISRAM3 enable removed: RAMCFG (0x52023000+) is RIFSC-blocked from
            // FSBL Secure code. Host now uses AXISRAM1 NS alias (0x24000000) which
            // is always powered by Boot ROM (RCC_MEMENR.AXISRAM1EN=1 default).
        }

        // ── PLL1: CPU SYSCLK = 800 MHz, AXI = 400 MHz, HCLK = 200 MHz ─────
        // Mirrors ST's `SystemClock_Config` for PLL1 only (PLL3 for the NPU
        // is configured separately further down).
        // Source: host/STM32N6-GettingStarted-ObjectDetection/Application/
        //   NUCLEO-N657X0-Q/Src/main.c:591-694, decoded against:
        //   - STM32Cube_FW_N6/Drivers/STM32N6xx_HAL_Driver/Src/stm32n6xx_hal_rcc.c
        //   - STM32Cube_FW_N6/Drivers/CMSIS/Device/ST/STM32N6xx/Include/stm32n657xx.h
        //
        // Field encoding pitfalls:
        //   - PLLM/N raw (write 25 for N=25), IC divider as (divider-1).
        //   - CSR/CCR are write-1-set / write-1-clear (not RMW).
        //   - SMPS "overdrive" on this Nucleo = drive PB12 high (board GPIO,
        //     NOT a chip PWR_CR1 poke). VOSCR is left at Boot ROM default —
        //     ST's reference doesn't touch it either.
        unsafe {
            let rcc_s = 0x5602_8000usize;
            let gpiob_s = 0x5602_0400usize; // GPIOB Secure alias

            // Step 1 — Switch USART1 kernel clock to HSI (64 MHz) BEFORE PLL1
            // changes, so the post-bump banner survives. Boot ROM defaults USART1
            // to IC9-from-PLL1 (= 150 MHz), which would retune to a garbled
            // value when we reprogram PLL1 below.
            // CCIPR13 (offset 0x174) USART1SEL[2:0] = 6 (HSI).
            let ccipr13 = core::ptr::read_volatile((rcc_s + 0x174) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x174) as *mut u32,
                (ccipr13 & !0x7) | 6);

            // Step 2 — SMPS overdrive: PB12 mode = output, drive high.
            let moder = core::ptr::read_volatile(gpiob_s as *const u32);
            core::ptr::write_volatile(gpiob_s as *mut u32,
                (moder & !(0b11 << 24)) | (0b01 << 24)); // PB12 = output
            core::ptr::write_volatile((gpiob_s + 0x18) as *mut u32, 1 << 12); // BS12

            // Step 3 — HSI sanity (Boot ROM should leave HSIRDY=1).
            while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 3) == 0 {}

            // Step 4 — Switch CPUSW + SYSSW to HSI BEFORE disabling PLL1.
            // Boot ROM has PLL1 ≈ 1200 MHz feeding CPU via IC1 (PLL1/3 = 400 MHz)
            // and USART1 via IC9 (PLL1/8 = 150 MHz). Writing PLL1ONC while PLL1
            // is the active CPU clock source halts the core mid-instruction
            // with no fault. ST's HAL handles this implicitly inside
            // HAL_RCC_ClockConfig before HAL_RCC_OscConfig.
            // Per stm32n657xx.h: CPUSW [17:16] / CPUSWS readback [21:20];
            //                    SYSSW [25:24] / SYSSWS readback [29:28].
            let cfgr1 = core::ptr::read_volatile((rcc_s + 0x020) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x020) as *mut u32,
                cfgr1 & !((0x3 << 16) | (0x3 << 24))); // CPUSW=0, SYSSW=0 → HSI
            while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 20) & 0x3 != 0 {}
            while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 28) & 0x3 != 0 {}
            // CPU + AXI now on HSI = 64 MHz. Safe to disable PLL1.

            // Step 5 — Disable PLL1 before reconfig. CCR is clear-only.
            core::ptr::write_volatile((rcc_s + 0x1000) as *mut u32, 1 << 8); // PLL1ONC
            while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 8) != 0 {}

            // Step 6 — Program PLL1 dividers/multiplier (HSI / M=2 × N=25 = 800 MHz VCO,
            // P1=P2=1 → 800 MHz output). Integer mode (MODSSDIS=1, MODDSEN=0, frac=0).
            // PLL1CFGR3 mode bit FIRST (rcc.c:2139).
            core::ptr::write_volatile((rcc_s + 0x088) as *mut u32, 1 << 2); // MODSSDIS=1
            // PLL1CFGR1: SEL[30:28]=0 (HSI), DIVM[25:20]=2, DIVN[19:8]=25, BYP=0
            core::ptr::write_volatile((rcc_s + 0x080) as *mut u32,
                (0u32 << 28) | (2u32 << 20) | (25u32 << 8));
            // PLL1CFGR2: DIVNFRAC=0
            core::ptr::write_volatile((rcc_s + 0x084) as *mut u32, 0);
            // PLL1CFGR3 final: PDIV1=1, PDIV2=1, PDIVEN=1, MODSSDIS=1, MODSSRST=1
            core::ptr::write_volatile((rcc_s + 0x088) as *mut u32,
                (1u32 << 27) | (1u32 << 24) | (1u32 << 30) | (1u32 << 2) | (1u32 << 0));

            // Step 7 — Enable PLL1, wait for lock. CSR is set-only.
            core::ptr::write_volatile((rcc_s + 0x800) as *mut u32, 1 << 8); // PLL1ONS
            while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 8) == 0 {}

            // Step 8 — Configure IC1 (CPU = PLL1/1 = 800 MHz) and IC2 (AXI = PLL1/2 = 400 MHz).
            // Encoding: SEL[29:28] | ((divider-1) << 16). PLL1 = SEL 0.
            core::ptr::write_volatile((rcc_s + 0x0C4) as *mut u32, (0u32 << 28) | (0u32 << 16)); // IC1 div 1
            core::ptr::write_volatile((rcc_s + 0x0C8) as *mut u32, (0u32 << 28) | (1u32 << 16)); // IC2 div 2

            // Step 9 — Enable IC2 output (DIVENSR is set-only). IC1 always-enabled
            // when CPUSW selects it; IC11/IC6 left disabled (used in G.1).
            core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 1); // IC2ENS

            // Step 10 — Bus prescalers: HPRE=001 (HCLK = AXI/2 = 200 MHz). PPRE=000 (DIV1).
            // Matches ST main.c:667 RCC_HCLK_DIV2.
            //
            // We tried HPRE=000 (HCLK = 400 MHz) once to halve NPU poll-loop
            // MMIO latency. Result: no UART output, system never boots.
            // 200 MHz is the AHB max for this part — confirmed empirically.
            let cfgr2 = core::ptr::read_volatile((rcc_s + 0x024) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x024) as *mut u32,
                (cfgr2 & !((0x7 << 20) | (0x7 << 4) | 0x7)) | (0x1 << 20));

            // Step 11 — Switch CPUCLK to IC1 (CPUSW=3 in CFGR1[17:16]; readback CPUSWS at [21:20]).
            let cfgr1 = core::ptr::read_volatile((rcc_s + 0x020) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x020) as *mut u32,
                (cfgr1 & !(0x3 << 16)) | (0x3 << 16));
            while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 20) & 0x3 != 0x3 {}

            // Step 12 — Switch SYSCLK to IC2/IC6/IC11 mux (SYSSW=3 at [25:24]; readback SYSSWS at [29:28]).
            let cfgr1 = core::ptr::read_volatile((rcc_s + 0x020) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x020) as *mut u32,
                (cfgr1 & !(0x3 << 24)) | (0x3 << 24));
            while (core::ptr::read_volatile((rcc_s + 0x020) as *const u32) >> 28) & 0x3 != 0x3 {}
            // CPU now 800 MHz; AXI 400 MHz; HCLK 200 MHz; USART1 stays on HSI=64 MHz.

            // ── PLL3 = 900 MHz for the NPU clock band ─────────────────────────
            // HSI / M=8 × N=225 = 1800 MHz VCO, P1=1, P2=2 → 900 MHz output.
            // Routed via IC11 (SEL=PLL3, div=1) to ck_icn_npu / ck_icn_axisram.
            // IC11 is enabled in DIVENSR but not yet selected by any peripheral
            // — the NPU peripheral comes online further below.
            //
            // Unlike PLL1, PLL3 isn't currently driving any active clock
            // (Boot ROM only configured PLL1), so we don't need the
            // CPUSW/SYSSW-to-HSI dance before disabling. Direct disable is safe.
            //
            // Source: ST `SystemClock_Config` main.c:620-627 + register layout
            // mirrors PLL1's at offsets 0x0A0/0x0A4/0x0A8 (vs 0x080/0x084/0x088).

            // Step 13 — Disable PLL3 (CCR write-1-clear, bit 10).
            core::ptr::write_volatile((rcc_s + 0x1000) as *mut u32, 1 << 10); // PLL3ONC
            while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 10) != 0 {}

            // Step 14 — Program PLL3 dividers/multiplier.
            // Force MODSSDIS=1 first (rcc.c:2139 ordering).
            core::ptr::write_volatile((rcc_s + 0x0A8) as *mut u32, 1 << 2); // MODSSDIS
            // PLL3CFGR1: SEL[30:28]=0 (HSI), DIVM[25:20]=8, DIVN[19:8]=225, BYP=0
            core::ptr::write_volatile((rcc_s + 0x0A0) as *mut u32,
                (0u32 << 28) | (8u32 << 20) | (225u32 << 8));
            // PLL3CFGR2: DIVNFRAC=0 (integer mode)
            core::ptr::write_volatile((rcc_s + 0x0A4) as *mut u32, 0);
            // PLL3CFGR3 final: PDIV1=1, PDIV2=2, PDIVEN=1, MODSSDIS=1, MODSSRST=1
            core::ptr::write_volatile((rcc_s + 0x0A8) as *mut u32,
                (1u32 << 27) | (2u32 << 24) | (1u32 << 30) | (1u32 << 2) | (1u32 << 0));

            // Step 15 — Enable PLL3, wait for lock (bit 10 in CSR/SR).
            core::ptr::write_volatile((rcc_s + 0x800) as *mut u32, 1 << 10); // PLL3ONS
            while core::ptr::read_volatile((rcc_s + 0x004) as *const u32) & (1 << 10) == 0 {}

            // Step 16 — IC11: SEL=PLL3 (0x2 << 28 = 0x2000_0000), divider=1
            // (write 0 to INT field). Output = PLL3/1 = 900 MHz.
            core::ptr::write_volatile((rcc_s + 0x0EC) as *mut u32,
                (0x2u32 << 28) | (0u32 << 16));

            // Step 17 — Enable IC11 in DIVENSR (set-only, bit 10).
            // No SYSSW change needed: SYSSW=3 (IC2/IC6/IC11) was set in step 12,
            // and the NPU peripheral will source IC11 when it comes online in G.1.a.3.
            core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 10); // IC11ENS

            // Step 17a — IC6 = PLL3 / 1 = 900 MHz, drives sysc_ck (NPU compute
            // clock) when SYSSW=3 (already selected at Step 12). Without this
            // IC6 stays disabled and sysc_ck falls back to its prior source
            // (HSI ≈ 64 MHz), running NPU compute at ~14× below spec.
            // IC6 register at RCC + 0x0D8 (= 0x0C4 + 4 × (6-1)). Enable bit
            // in DIVENSR is bit 5. RM0486 §14.6.1 + Figure 46.
            core::ptr::write_volatile((rcc_s + 0x0D8) as *mut u32,
                (0x2u32 << 28) | (0u32 << 16));         // SEL=PLL3, div 1
            core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 5); // IC6ENS

            // ── NPU peripheral + AXISRAM3-6 + CACHEAXI ────────────────────────
            // Mirrors ST's `NPURam_enable` (Cube template `main.c:440-490`).
            // Sequence:
            //   - NPU clock + reset pulse (RCC.AHB5ENR.NPUEN, AHB5RSTSR/CR bit 31)
            //   - AXISRAM3..6 bank clocks (RCC.MEMENR bits 0-3)
            //   - RAMCFG clock + per-bank power-on (clear RAMCFG.CR.SRAMSD bit 20)
            //   - CACHEAXIRAM clock + CACHEAXI clock + reset pulse
            //
            // AXISRAM3-6 are 4 × 448 KB scratch banks for NPU activations. They
            // start clock-gated AND with RAMCFG.SRAMSD=1 (power-down) after
            // reset, so both gates need to be opened. CACHEAXI is the NPU's
            // weight cache — without it, weight reads from XSPI2 would not be
            // cached → 10-50× perf drop per ST audit notes.

            // Step 17b — RIMC: tag NPU bus master with CID=1, SEC, PRIV.
            //   When NPU acts as bus master (reading/writing model buffers and
            //   scratch in AXISRAM), RIFSC stamps each access with the master
            //   CID + security attribute.
            //
            //   G.2.b (enclave-driven inference): the enclave runs Secure-side
            //   and keeps model I/O buffers at 0x342E0000 (Secure-aliased
            //   AXISRAM). The NPU blob's hardcoded references are all 0x34xxxxxx
            //   Secure addresses, so the NPU master must also be Secure for IDAU
            //   to permit those accesses. {CID=1, SEC, PRIV} matches ST's
            //   all-Secure reference design (SystemClock_Config).
            //
            //   Historical note: G.1.b.3 attempted NS-host inference with NPU
            //   tagged NS (bit[8]=0) and model addresses patched to 0x24xxxxxx,
            //   but the NPU IRQ never fired — dead end documented in
            //   project_n657_npu_ns_dead_end.md. Reverting to SEC here.
            //
            //   RIMC_ATTR layout (stm32n657xx.h):
            //     bits [6:4] MCID, bit [8] MSEC, bit [9] MPRIV
            //   Address: RIFSC_S + 0xC10 + 4*master_idx; NPU master_idx = 1.
            core::ptr::write_volatile(0x5402_4C14 as *mut u32,
                (1u32 << 4) | (1u32 << 8) | (1u32 << 9)); /* CID=1 SEC PRIV — G.2.b */

            // Step 18 — NPU peripheral clock (AHB5ENR bit 31).
            let ahb5 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x260) as *mut u32, ahb5 | (1u32 << 31));

            // Step 19 — NPU reset pulse. AHB5RSTSR (0x0A20) is set-only;
            // AHB5RSTCR (0x1220) is clear-only. Bit 31 = NPURSTS/NPURSTC.
            core::ptr::write_volatile((rcc_s + 0x0A20) as *mut u32, 1u32 << 31); // assert reset
            cortex_m::asm::dsb();
            core::ptr::write_volatile((rcc_s + 0x1220) as *mut u32, 1u32 << 31); // release reset
            cortex_m::asm::dsb();

            // Step 20 — AXISRAM3..6 + CACHEAXIRAM bank clocks (MEMENR @ 0x024C).
            // AXISRAM3EN..6EN at bits 0..3; CACHEAXIRAMEN at bit 10.
            let memenr = core::ptr::read_volatile((rcc_s + 0x24C) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x24C) as *mut u32,
                memenr | 0xF | (1 << 10));

            // Step 21 — RAMCFG controller clock (AHB2ENR @ 0x0254 bit 12).
            let ahb2 = core::ptr::read_volatile((rcc_s + 0x254) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x254) as *mut u32,
                ahb2 | (1u32 << 12));
            cortex_m::asm::dsb();

            // Step 22 — Power on AXISRAM3..6 by clearing RAMCFG.CR.SRAMSD (bit 20)
            // for each bank. Banks default to power-down after reset; clearing
            // SRAMSD wakes them. Per-bank RAMCFG bases (Secure alias):
            //   SRAM3_AXI = 0x5202_3100, SRAM4 = 0x5202_3180,
            //   SRAM5     = 0x5202_3200, SRAM6 = 0x5202_3280.
            // CR is at offset 0x00 of each instance.
            for ramcfg_base in [0x5202_3100usize, 0x5202_3180, 0x5202_3200, 0x5202_3280] {
                let cr = core::ptr::read_volatile(ramcfg_base as *const u32);
                core::ptr::write_volatile(ramcfg_base as *mut u32, cr & !(1u32 << 20));
            }
            cortex_m::asm::dsb();

            // Step 23 — CACHEAXI peripheral clock (AHB5ENR bit 30).
            let ahb5 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x260) as *mut u32, ahb5 | (1u32 << 30));

            // Step 24 — CACHEAXI reset pulse (AHB5RSTSR/CR bit 30).
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
            //
            // RIMC NPU master config is at Step 17b above; SECCFGR3 bit 10
            // re-secure of RISUP 106 (NPU) happens at the top of init_clocks.

            // Step 25 — IAC clock enable (AHB3ENR @ 0x258 bit 10).
            let ahb3 = core::ptr::read_volatile((rcc_s + 0x258) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x258) as *mut u32, ahb3 | (1 << 10));

            // Step 26 — IAC reset pulse (AHB3RSTSR @ 0xA18 / RSTCR @ 0x1218 bit 10).
            core::ptr::write_volatile((rcc_s + 0x0A18) as *mut u32, 1 << 10); // assert
            cortex_m::asm::dsb();
            core::ptr::write_volatile((rcc_s + 0x1218) as *mut u32, 1 << 10); // release
            cortex_m::asm::dsb();

            // Step 27 — Sleep-mode bits so FreeRTOS WFE-idle doesn't gate the
            // NPU subsystem mid-inference (CPU sleeps but NPU keeps running).
            //   AHB5LPENR (0x2A0): bit 30 CACHEAXI, bit 31 NPU
            //   MEMLPENR  (0x28C): bits 0-3 AXISRAM3..6, bit 10 CACHEAXIRAM
            //   AHB2LPENR (0x294): bit 12 RAMCFG
            // Mirrors ST's `set_clk_sleep_mode` (main.c:365-387).
            let ahb5lp = core::ptr::read_volatile((rcc_s + 0x2A0) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x2A0) as *mut u32,
                ahb5lp | (1u32 << 30) | (1u32 << 31));
            let memlp = core::ptr::read_volatile((rcc_s + 0x28C) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x28C) as *mut u32,
                memlp | 0xF | (1 << 10));
            let ahb2lp = core::ptr::read_volatile((rcc_s + 0x294) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x294) as *mut u32,
                ahb2lp | (1u32 << 12));
            cortex_m::asm::dsb();
        }

        // ── Enable I-cache + D-cache ──────────────────────────────────────
        // M55 has integrated I-cache + D-cache (vs M33's optional only-I).
        // Sequence: MEMSYSCTL.MSCR.ICACTIVE → SCB_EnableICache →
        // MSCR.DCACTIVE → SCB_EnableDCache. The MEMSYSCTL "active" power-on
        // bits are M55-specific and required *before* the standard SCB
        // enable — forgetting them silently no-ops the SCB write.
        //
        // Caches were defensively *disabled* by `_umb_start` in startup_n657.s
        // because Boot ROM DMA'd the FSBL image into AXISRAM2 (potentially
        // stale cache lines). Re-enabling them after invalidate is the
        // canonical pattern.
        unsafe {
            let mscr      = 0xE001_E000 as *mut u32;          // MEMSYSCTL.MSCR
            let scb_ccr   = SCB_CCR;
            let scb_ccsidr = SCB_CCSIDR;
            let scb_csselr = SCB_CSSELR;
            let scb_iciallu = ICIALLU;
            let scb_dcisw   = DCISW;

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
            let ccsidr  = core::ptr::read_volatile(scb_ccsidr);
            let numsets = (ccsidr >> 13) & 0x7FFF;
            let assoc   = (ccsidr >> 3)  & 0x3FF;

            // Invalidate every (set, way) line. DCISW field layout:
            // Way [31:30], Set [13:5]. Standard ARM reference impl pattern.
            let mut set = numsets;
            loop {
                let mut way = assoc;
                loop {
                    core::ptr::write_volatile(scb_dcisw, (way << 30) | (set << 5));
                    if way == 0 { break; }
                    way -= 1;
                }
                if set == 0 { break; }
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

    fn init_gpio(&self) {
        // GPIO is RIF-aware — has its own internal SECCFGR, reset to 0 (NS).
        // NS alias works for GPIO, but we use the GPIO driver which already
        // handles this. The main.rs diagnostic does early GPIO setup via
        // Secure alias before this point.

        // NUCLEO-N657X0-Q user LEDs — all on GPIOG
        // LED1 (Blue)  = PG8
        // LED2 (Red)   = PG10
        // LED3 (Green) = PG0
        let gpio_g = Gpio::new(Port::GpioG);
        gpio_g.set_mode(0, PinMode::Output);   // LED3 green
        gpio_g.set_mode(8, PinMode::Output);   // LED1 blue
        gpio_g.set_mode(10, PinMode::Output);  // LED2 red
        gpio_g.pin_set(0);

        // USART1 pins: PE5 = TX (AF7), PE6 = RX (AF7)
        let gpio_e = Gpio::new(Port::GpioE);
        gpio_e.set_mode(5, PinMode::Alternate);
        gpio_e.set_af(5, 7);
        gpio_e.set_mode(6, PinMode::Alternate);
        gpio_e.set_af(6, 7);
    }

    fn init_uart(&self) {
        // USART1 via Secure alias. Kernel clock = HSI = 64 MHz (set in init_clocks
        // step 1: CCIPR13.USART1SEL = 6). BRR = 64_000_000 / 115200 ≈ 555.5 → 556
        // (0.08% baud error, well within UART receiver tolerance).
        unsafe {
            let u1 = 0x5200_1000usize;
            core::ptr::write_volatile(u1 as *mut u32, 0);                   // CR1=0
            core::ptr::write_volatile((u1 + 0x2C) as *mut u32, 0);          // PRESC=0
            core::ptr::write_volatile((u1 + 0x0C) as *mut u32, 556);        // BRR (HSI/115200)
            core::ptr::write_volatile(u1 as *mut u32, (1 << 0) | (1 << 3)); // UE+TE
            let mut w: u32 = 0;
            while w < 10_000 { core::hint::spin_loop(); w = w.wrapping_add(1); }
        }

        // Banner + Secure Boot started — output must match
        // `tools/golden_uart.log` for the smoke-test harness to pass.
        crate::raw_print::print_str("\n");
        crate::raw_print::print_str("   ___       ___       ___       ___       ___   \n");
        crate::raw_print::print_str("  /\\__\\     /\\__\\     /\\  \\     /\\  \\     /\\  \\  \n");
        crate::raw_print::print_str(" /:/ _/_   /::L_L_   /::\\  \\   /::\\  \\   /::\\  \\ \n");
        crate::raw_print::print_str("/:/_/\\__\\ /:/L:\\__\\ /::\\:\\__\\ /::\\:\\__\\ /::\\:\\__\\\n");
        crate::raw_print::print_str("\\:\\/:/  / \\/_/:/  / \\:\\::/  / \\;:::/  / \\/\\::/  /\n");
        crate::raw_print::print_str(" \\::/  /    /:/  /   \\::/  /   |:\\/__/    /:/  / \n");
        crate::raw_print::print_str("  \\/__/     \\/__/     \\/__/     \\|__|     \\/__/  \n");
        crate::raw_print::print_str("\n");
        crate::raw_print::print_str("[UMBRASecureBoot] Secure Boot started\n");
    }

    fn init_security(&self) {
        use arm::sau;
        use arm::mpu;
        use drivers::risaf::{Risaf, RisafInstance};

        // VTOR already set by main.rs Phase 0c (0x34180000).

        // 1. Enable configurable fault handlers (SHCSR) and clear residual
        //    Secure-side stack limits left by Boot ROM. PSPLIM_S in particular
        //    was found set high enough to corrupt enclave PSP exception
        //    entry — same class of landmine as MSPLIM_NS earlier.
        unsafe {
            let shcsr = SCB_SHCSR;
            let val = core::ptr::read_volatile(shcsr);
            core::ptr::write_volatile(shcsr, val | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19));
            cortex_m::register::msplim::write(0u32);
            cortex_m::register::psplim::write(0u32);
            // Kick IWDG between heavy operations
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);
        }

        // 2. SAU init + enable (all Secure — NS regions added in configure_ns_boot)
        let mut sau_driver = sau::SauDriver::new();
        unsafe {
            sau_driver.init();
            sau_driver.enable();
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);
        }

        // 3. MPU init + enable with PRIVDEFENA
        let mut mpu_driver = mpu::MpuDriver::new();
        unsafe {
            mpu_driver.init();
            mpu_driver.set_mair(0, 0xFF);
            mpu_driver.enable();
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);
        }

        // 4. RISAF — open the host's address window (0x24000000–0x240FFFFF)
        //    to NS access by the CPU master.
        //
        // RM0486 §2.3.2 Table 1 splits this 1 MB view across TWO RISAF
        // instances: 0x34000000–0x34063FFF is FLEXRAM (RISAF7, 400 KB),
        // 0x34064000–0x340FFFFF is AXISRAM1 proper (RISAF2, ~624 KB). Both
        // must be configured for NS — without RISAF7 the lower 400 KB stays
        // governed by its default region 0 (Secure+CID=1) and any NS access
        // to the host's vector table at 0x24000000 is silently denied.
        Risaf::new(RisafInstance::Risaf7).configure_region(
            1, 0x3400_0000, 0x3406_3FFF, false, 0xFF, 0xFF, 0,
        );
        // Region 1: NS host (0x34064000–0x340DFFFF, ~496 KB). Host runs
        // unprivileged in NS, all CIDs RW.
        // Region 2: Secure ESS / EFBC / PSP (0x340E0000–0x340FFFFF, 128 KB).
        // Enclaves run UNPRIVILEGED in Secure; without an explicit region the
        // default region 0 (Secure+priv+CID=1) blocks every unprivileged
        // load, store and exception-entry stack push, raising SFSR.AUVIOL.
        let risaf2 = Risaf::new(RisafInstance::Risaf2);
        risaf2.configure_region(
            1, 0x3406_4000, 0x340D_FFFF, false, 0xFF, 0xFF, 0,
        );
        risaf2.configure_region(
            2, 0x340E_0000, 0x340F_FFFF, true,  0xFF, 0xFF, 0,
        );
        unsafe {
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);
        }
    }

    fn init_kernel(&self) {

        unsafe {
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            // Build UmbraCryptoEngine (Hash + AesEmulated), install it as
            // the kernel's `dyn CryptoEngine`, then let `Kernel::init_keys`
            // derive enc/hmac keys via vtable dispatch and `.rodata` label
            // slices. The linker ORIGIN must be `0x34180400` (0x400 past
            // the FSBL signing header), otherwise `.rodata` reads return
            // signed-image bytes and key derivation breaks.
            let hash_driver = drivers::hash::Hash::new();
            let aes_driver = drivers::aes::AesEmulated::new();
            super::GLOBAL_CRYPTO = Some(super::crypto_impl::UmbraCryptoEngine::new(
                hash_driver, aes_driver,
            ));
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            let crypto_engine = (*(&raw mut super::GLOBAL_CRYPTO)).as_mut().unwrap();
            let guards = &mut *(&raw mut super::GLOBAL_GUARDS);

            let kernel = super::secure_kernel::Kernel::new(guards, Some(crypto_engine));
            super::secure_kernel::Kernel::init(kernel);
            if let Some(k) = super::secure_kernel::Kernel::get() {
                k.init_keys();
            }
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            crate::raw_print::print_str("[UMBRASecureBoot] Kernel Initialized\n");
        }
    }

    fn init_external_flash(&self) -> bool {
        // XSPI2 memory-mapped + MCE2 fast block cipher.
        //
        // Root cause of previous XSPI2 failure: we used AHB5RSTR (0x220, read-only
        // status) instead of AHB5RSTSR/AHB5RSTCR (0xA20/0x1220, write-1-to-set/clear).
        // The reset never happened, so Boot ROM's CID lock stayed on XSPI2/XSPIM.
        //
        // Fix: use RSTSR/RSTCR pair (from ST's system_stm32n6xx_fsbl.c SystemInit).
        // Then follow ST's init: XSPIM clock first, then XSPI2, MODE=0, hclk5.

        unsafe {
            let rcc_s = 0x5602_8000usize;
            let xspi2 = 0x5802_A000usize;
            let xspim = 0x5802_B400usize;

            // ── Step 1: Reset XSPI1 + XSPI2 + XSPIM via RSTSR/RSTCR ─────────
            // N6 uses split reset registers (NOT the single AHB5RSTR at 0x220):
            //   AHB5RSTSR (0xA20)  — write-1-to-SET (assert reset)
            //   AHB5RSTCR (0x1220) — write-1-to-CLEAR (release reset)
            // Must also reset XSPI1 (bit 5): Boot ROM left it EN=1, and XSPIM
            // can only be modified when ALL XSPI controllers are disabled.
            core::ptr::write_volatile((rcc_s + 0xA20) as *mut u32,
                (1 << 13) | (1 << 12) | (1 << 5)); // XSPIM + XSPI2 + XSPI1
            let mut d: u32 = 0;
            while d < 1_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
            core::ptr::write_volatile((rcc_s + 0x1220) as *mut u32,
                (1 << 13) | (1 << 12) | (1 << 5)); // release XSPIM + XSPI2 + XSPI1
            d = 0;
            while d < 1_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            // ── Step 2: Enable clocks (XSPIM first, then XSPI2 — ST's order) ─
            let ahb5 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x260) as *mut u32,
                ahb5 | (1 << 13) | (1 << 5)); // XSPIMEN + XSPI1EN first
            let ahb5_2 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x260) as *mut u32,
                ahb5_2 | (1 << 12) | (1 << 15)); // then XSPI2EN + MCE2EN

            // ── Step 3: Kernel clock = IC3 from PLL1 (like ST's XSPI_NOR) ───
            // hclk5 (SEL=00) and per_ck (SEL=01) don't reach XSPI2 — N6 kernel
            // clocks require explicitly configured IC dividers.
            // ST's XSPI_NOR_MemoryMapped_DTR uses IC3 from PLL1 with divider=6.
            //
            // IC3CFGR (0xCC): IC3SEL[29:28]=00 (PLL1), IC3INT[23:16]=divider-1
            // DIVENSR (0xA40): write-1-to-set IC enable. IC3 = bit 2.
            // CCIPR6 XSPI2SEL=10 selects ic3_ck.
            //
            // PLL1 is 800 MHz, so the IC3 divider is set to 16 → XSPI source
            // = 50 MHz. Higher rates risked exceeding the DCYC=20 dummy-cycle
            // window for the on-board NOR flash.
            core::ptr::write_volatile((rcc_s + 0xCC) as *mut u32,
                (0b00 << 28) | (15 << 16)); // IC3SEL=PLL1, IC3INT=15 (div by 16)
            // Enable IC3 via DIVENSR (write-1-to-set, offset 0xA40)
            core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 2); // IC3EN
            let mut dw: u32 = 0;
            while dw < 1_000 { core::hint::spin_loop(); dw = dw.wrapping_add(1); }

            // Select IC3 as XSPI2 kernel clock
            let ccipr6 = core::ptr::read_volatile((rcc_s + 0x158) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x158) as *mut u32,
                (ccipr6 & !(0b11 << 4)) | (0b10 << 4)); // XSPI2SEL=10 (ic3_ck)

            // ── Step 4: VDDIO3 supply for Port N I/Os ────────────────────────
            let pwr = 0x5602_4800usize;
            let svmcr3 = core::ptr::read_volatile((pwr + 0x03C) as *const u32);
            core::ptr::write_volatile((pwr + 0x03C) as *mut u32,
                svmcr3 | (1 << 9) | (1 << 1) | (1 << 26));
            let mut rdy: u32 = 0;
            while rdy < 100_000 {
                if core::ptr::read_volatile((pwr + 0x03C) as *const u32) & (1 << 17) != 0 { break; }
                rdy = rdy.wrapping_add(1);
            }
            let syscfg = 0x5600_8000usize;
            core::ptr::write_volatile((syscfg + 0x05C) as *mut u32,
                (0x7 << 4) | (0x8 << 8) | (1 << 1));
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            // ── Step 5: GPIO Port N for XSPI Port2 (AF9, very high speed) ────
            let gpion = 0x5602_3400usize;
            let ahb4 = core::ptr::read_volatile((rcc_s + 0x25C) as *const u32);
            core::ptr::write_volatile((rcc_s + 0x25C) as *mut u32, ahb4 | (1 << 13));
            let af_pins: [u32; 10] = [1, 2, 3, 4, 5, 6, 8, 9, 10, 11];
            let mut moder = core::ptr::read_volatile(gpion as *const u32);
            let mut pi: usize = 0;
            while pi < 10 {
                let p = af_pins[pi];
                moder = (moder & !(0b11 << (p * 2))) | (0b10 << (p * 2));
                pi += 1;
            }
            core::ptr::write_volatile(gpion as *mut u32, moder);
            let mut ospeedr = core::ptr::read_volatile((gpion + 0x08) as *const u32);
            pi = 0;
            while pi < 10 { ospeedr |= 0b11 << (af_pins[pi] * 2); pi += 1; }
            core::ptr::write_volatile((gpion + 0x08) as *mut u32, ospeedr);
            let mut afrl = core::ptr::read_volatile((gpion + 0x20) as *const u32);
            pi = 0;
            while pi < 6 {
                let p = af_pins[pi];
                afrl = (afrl & !(0xF << (p * 4))) | (9 << (p * 4));
                pi += 1;
            }
            core::ptr::write_volatile((gpion + 0x20) as *mut u32, afrl);
            let mut afrh = core::ptr::read_volatile((gpion + 0x24) as *const u32);
            pi = 6;
            while pi < 10 {
                let p = af_pins[pi] - 8;
                afrh = (afrh & !(0xF << (p * 4))) | (9 << (p * 4));
                pi += 1;
            }
            core::ptr::write_volatile((gpion + 0x24) as *mut u32, afrh);
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            // ── Step 6: XSPIM config (MODE=0, CSSEL_OVR_EN, REQ2ACK_TIME) ───
            // MODE=0 (direct: XSPI2→Port2), NCS1 override, req2ack=1
            core::ptr::write_volatile(xspim as *mut u32,
                (1u32 << 16) | (1u32 << 4)); // REQ2ACK_TIME=1, CSSEL_OVR_EN=1

            // ── Step 7: Configure XSPI2 (while disabled) ─────────────────────
            // DCR1: MTYP=Macronix(001), DEVSIZE=25, CSHT=1
            core::ptr::write_volatile((xspi2 + 0x008) as *mut u32,
                (0b001 << 24) | (25 << 16) | (1 << 8));
            // DCR2: prescaler=4
            core::ptr::write_volatile((xspi2 + 0x00C) as *mut u32, 4);
            let mut bw: u32 = 0;
            while bw < 100_000 {
                if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & (1 << 5) == 0 { break; }
                bw = bw.wrapping_add(1);
            }

            // ── Step 8: Enable XSPI2 ─────────────────────────────────────────
            core::ptr::write_volatile(xspi2 as *mut u32, 1); // EN=1
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            d = 0;
            while d < 5_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }

            // ── Step 9: SPI flash reset (0x66 + 0x99) ────────────────────────
            core::ptr::write_volatile((xspi2 + 0x100) as *mut u32, 0b001); // IMODE=1line
            core::ptr::write_volatile((xspi2 + 0x108) as *mut u32, 0);
            core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x66);
            let mut t: u32 = 0;
            while t < 100_000 {
                if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & 2 != 0 { break; }
                t = t.wrapping_add(1);
            }
            core::ptr::write_volatile((xspi2 + 0x028) as *mut u32, 2);
            core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x99);
            t = 0;
            while t < 100_000 {
                if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & 2 != 0 { break; }
                t = t.wrapping_add(1);
            }
            core::ptr::write_volatile((xspi2 + 0x028) as *mut u32, 2);
            d = 0;
            while d < 50_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            // ── Step 10: READ_ID (0x9F) ──────────────────────────────────────
            core::ptr::write_volatile(xspi2 as *mut u32, (0b01u32 << 28) | 1);
            cortex_m::asm::dsb(); cortex_m::asm::isb();
            core::ptr::write_volatile((xspi2 + 0x040) as *mut u32, 2);
            core::ptr::write_volatile((xspi2 + 0x108) as *mut u32, 1 << 30);
            core::ptr::write_volatile((xspi2 + 0x100) as *mut u32,
                (0b001 << 24) | (0b001 << 0));
            cortex_m::asm::dsb();
            core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x9F);

            t = 0;
            while t < 200_000 {
                if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & 2 != 0 { break; }
                t = t.wrapping_add(1);
            }

            let sr_id = core::ptr::read_volatile((xspi2 + 0x024) as *const u32);
            if sr_id & 2 != 0 {
                // ID read OK — discard the value, just clear the flag.
                let _id = core::ptr::read_volatile((xspi2 + 0x050) as *const u32);
                core::ptr::write_volatile((xspi2 + 0x028) as *mut u32, 2);
            } else {
                // ID read failed — soft error, continue to memory-mapped mode
                // anyway. If memory-mapped probe also fails, downstream code
                // will surface the issue.
            }

            // ── Step 11: Memory-mapped mode ──────────────────────────────────
            let cr_cur = core::ptr::read_volatile(xspi2 as *const u32);
            core::ptr::write_volatile(xspi2 as *mut u32, cr_cur | (1 << 1));
            bw = 0;
            while bw < 10_000 {
                if core::ptr::read_volatile(xspi2 as *const u32) & (1 << 1) == 0 { break; }
                bw = bw.wrapping_add(1);
            }
            core::ptr::write_volatile(xspi2 as *mut u32, 0);
            core::ptr::write_volatile((xspi2 + 0x100) as *mut u32,
                (0b001 << 24) | (0b11 << 12) | (0b001 << 8) | (0b001 << 0));
            core::ptr::write_volatile((xspi2 + 0x108) as *mut u32, 8 | (1 << 30));
            core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x0C);
            core::ptr::write_volatile(xspi2 as *mut u32, (0b11u32 << 28) | 1);
            d = 0;
            while d < 10_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }

            // Discard the memory-mapped probe — used to be printed for
            // bring-up validation; XSPI2 access is now confirmed by the
            // host/enclave lifecycle running successfully.
            let _probe = core::ptr::read_volatile(0x7000_0000 as *const u32);

            // ── Step 12: XSPI2 layout (plaintext-flash model) ────────────────
            // MCE2 encryption-at-rest is not enabled. Confidentiality comes
            // from the inner enclave encryption applied by
            // `protect_enclave.py --hmac-over-plaintext`; integrity comes
            // from the chained-HMAC measurement. MCE2 stays in passthrough.
            //
            // XSPI2 layout:
            //   0x70000000-0x70030000  FSBL signed image
            //   0x70080000+            Host binary (plaintext) — enclave
            //                          header at 0x70090000, code follows
            //                          in plaintext.
            //
            // `xspi.rs` exposes minimal SPI / OPI write primitives that are
            // kept `pub` as artifacts for a possible future revival of the
            // chip-as-oracle write path (currently blocked by an OPI WREN
            // chip-side issue documented in the design notes).
            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

            // ── Step 13: Disable MCE2 region 1 (passthrough on AXI reads) ────
            // Boot ROM may leave MCE2 region 1 enabled in Fast Block mode.
            // Explicitly disable to guarantee plaintext reads from XSPI2 at
            // 0x70080000+. No key/nonce config — MCE2 stays inert.
            let mce = drivers::mce::Mce2::new();
            mce.disable_region1();

            true
        }
    }

    fn configure_ns_boot(&self) {
        use arm::sau;

        // 1. Disable Secure SysTick (NS gets its own if needed)
        unsafe {
            core::ptr::write_volatile(SYST_CSR, 0x00);
        }

        // 1b. Mark NPU/CACHEAXI peripheral IRQs as NS-targeted via NVIC_ITNS.
        //     Default NVIC_ITNS = 0 ⇒ all IRQs target the Secure NVIC. From NS
        //     code, NVIC_EnableIRQ silently no-ops on Secure-targeted IRQs, so
        //     a future NS-side NPU handler wouldn't take effect.
        //     NVIC_ITNS layout: 16 × 32-bit registers, each covers 32 IRQs.
        //     NPU0_IRQn=53 → ITNS1, bit 21. Setting bits 21-25 ⇒
        //     NPU0/1/2/3 + CACHEAXI all NS-targeted.
        unsafe {
            let itns1 = NVIC_ITNS1;
            let v = core::ptr::read_volatile(itns1);
            core::ptr::write_volatile(itns1,
                v | (1u32 << 21) | (1u32 << 22) | (1u32 << 23)
                  | (1u32 << 24) | (1u32 << 25));
        }

        // 2. Set VTOR_NS to AXISRAM1 NS view (host vector table base)
        //    SCB_NS->VTOR at 0xE002ED08
        drivers::rcc::Rcc::set_vtor_ns(0x2400_0000);

        // 3. Configure SAU NS regions so the host can run.
        //    SAU is enabled in init_security() but with no regions, so
        //    everything defaults to Secure. We need explicit NS regions.
        //
        //    SAU regions are 32-byte aligned. limit_addr is INCLUSIVE.
        //    nsc=0 → Non-Secure region, en=1 → enabled.
        let mut sau_driver = sau::SauDriver::new();
        unsafe {
            // Region 0: AXISRAM1 NS view for host (0x24000000 - 0x240FFFE0, 1MB).
            // (AXISRAM3 was the design choice but RAMCFG enable is RIFSC-blocked.)
            let mut r0 = sau::SauRegionConfig::new();
            r0.set_rnum(0);
            r0.set_base_addr(0x2400_0000);
            r0.set_limit_addr(0x240F_FFE0);
            r0.set_nsc(0);
            r0.set_en(1);
            sau_driver.create_region(&r0);

            // Region 1: Peripheral NS aliases (0x42000000 - 0x4FFFFFFF).
            //           Includes USART, GPIO, DMA NS aliases needed by host.
            let mut r1 = sau::SauRegionConfig::new();
            r1.set_rnum(1);
            r1.set_base_addr(0x4200_0000);
            r1.set_limit_addr(0x4FFF_FFE0);
            r1.set_nsc(0);
            r1.set_en(1);
            sau_driver.create_region(&r1);

            // Region 2: NSC veneers (0x341AB400 - 0x341AC3E0, 4KB).
            //           Marked NSC (nsc=1) so the SG instruction is valid here.
            //           Required for NS→Secure transition via umbra_* veneers.
            let mut r2 = sau::SauRegionConfig::new();
            r2.set_rnum(2);
            r2.set_base_addr(0x341A_B400);
            r2.set_limit_addr(0x341A_C3E0);
            r2.set_nsc(1); // NSC: address callable via SG
            r2.set_en(1);
            sau_driver.create_region(&r2);

            // Region 3: AXISRAM2-6 NS aliases (0x24100000 - 0x243BFFE0, ~3 MB).
            //           Required for object_detection_n657 host so the Cube-AI
            //           runtime can access NPU activation buffers (the network
            //           model places activations in AXISRAM5 etc.). Without
            //           this, NS reads of 0x24[1-3]xxxxx fault at SAU
            //           (SFSR=INVTRAN+LSPERR). RISAF for these banks may also
            //           need NS region config — that's a follow-up if RISAF
            //           rejects after SAU passes.
            let mut r3 = sau::SauRegionConfig::new();
            r3.set_rnum(3);
            r3.set_base_addr(0x2410_0000);
            r3.set_limit_addr(0x243B_FFE0);
            r3.set_nsc(0);
            r3.set_en(1);
            sau_driver.create_region(&r3);

            core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32); // IWDG
        }
    }

    fn jump_to_ns(&self) -> ! {
        // Copy the NS host image from XSPI2 (where flash_n657.sh placed it
        // at 0x70080000) into AXISRAM1 via the NS alias 0x24000000. Writing
        // through the NS alias is required: after init_security configured
        // RISAF7+RISAF2 region 1 with SEC=0, only NS-tagged requests reach
        // AXISRAM1, and the bus tag is derived from the address (Secure CPU
        // + NS address ⇒ NS request).
        const HOST_FLASH_BASE: u32 = 0x7008_0000;
        const HOST_NS_BASE:    u32 = 0x2400_0000;
        // 128 KB copy: covers the host code/.text/.data (≤16 KB) AND the
        // enclave region pinned at offset 0x10000 in host.ld (header +
        // up to 1 KB code). Larger copies are also fine — AXISRAM1 NS
        // has 896 KB available — but 128 KB is the minimum that lets the
        // FreeRTOS NS host (`freertos_n657`) scan AXISRAM1 for UMBR
        // enclave magic at 0x24010000+. The bare-metal host doesn't need
        // the scan path (uses linker symbol directly) but copying the
        // extra bytes is harmless.
        const HOST_COPY_SIZE:  u32 = 0x2_0000;

        unsafe {
            let src = HOST_FLASH_BASE as *const u8;
            let dst = HOST_NS_BASE    as *mut u8;
            let mut i: u32 = 0;
            while i < HOST_COPY_SIZE {
                let b = core::ptr::read_volatile(src.add(i as usize));
                core::ptr::write_volatile(dst.add(i as usize), b);
                i += 1;
            }
            cortex_m::asm::dsb();
            cortex_m::asm::isb();

            // Boot ROM leaves MSPLIM_NS = PSPLIM_NS = 0x24106FF0 (its own
            // pre-handoff stack limit). With our MSP_NS = 0x240FFFFC, every
            // NS exception entry would underflow the limit and raise
            // STKOF (NS UFSR bit 4) — which then escalates to a Secure
            // HardFault with FORCED-only HFSR and no other clue. Clearing
            // both limits is mandatory before BLXNS.
            // msplim_ns / psplim_ns are v8-M Security Extension stack-limit
            // registers for the Non-Secure side, accessible only from Secure
            // mode. cortex-m 0.7 does NOT expose these in `cortex_m::register`,
            // so inline asm stays here.
            core::arch::asm!("msr msplim_ns, {0}", in(reg) 0u32);
            core::arch::asm!("msr psplim_ns, {0}", in(reg) 0u32);
        }

        crate::raw_print::print_str("[UMBRASecureBoot] Jumping to Non-Secure World\n");

        unsafe { super::trampoline_to_ns(); }
        loop { core::hint::spin_loop(); }
    }
}
