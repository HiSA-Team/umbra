// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! Secure security setup + Non-Secure boot trampolines.
//! Hosts `init_security` (SAU/MPU/RISAF), `configure_untrusted_boot` (NS SAU
//! regions + VTOR_NS) and `jump_to_untrusted` (the NS world handoff). Lifted
//! verbatim from the monolithic `platform_impl.rs` during
//!. Pure file reorganization; no semantic changes.

use arm::mmio::{NVIC_ITNS1, SCB_SHCSR, SYST_CSR};

pub fn init_security() {
    use arm::mpu;
    use arm::sau;
    use drivers::risaf::{Risaf, RisafInstance};

    // VTOR already set by main.rs (0x34180000).

    // 0. DEV-ONLY: open the debug access port before anything else locks down,
    // so a debugger can attach to the FSBL on closed/locked parts. No-op on
    // this open Nucleo. Gated behind `dev_debug` — never in production.
    #[cfg(feature = "dev_debug")]
    super::power::enable_dev_debug();

    // 1. Enable configurable fault handlers (SHCSR) and clear residual
    // Secure-side stack limits left by Boot ROM. PSPLIM_S in particular
    // was found set high enough to corrupt enclave PSP exception
    // entry — same class of landmine as MSPLIM_NS earlier.
    unsafe {
        let shcsr = SCB_SHCSR;
        let val = core::ptr::read_volatile(shcsr);
        core::ptr::write_volatile(shcsr, val | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19));
        cortex_m::register::msplim::write(0u32);
        cortex_m::register::psplim::write(0u32);
        // Kick IWDG between heavy operations
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);
    }

    // 2. SAU init + enable (all Secure — NS regions added in configure_untrusted_boot)
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
    // to NS access by the CPU master.
    // RM0486 §2.3.2 Table 1 splits this 1 MB view across TWO RISAF
    // instances: 0x34000000–0x34063FFF is FLEXRAM (RISAF7, 400 KB),
    // 0x34064000–0x340FFFFF is AXISRAM1 proper (RISAF2, ~624 KB). Both
    // must be configured for NS — without RISAF7 the lower 400 KB stays
    // governed by its default region 0 (Secure+CID=1) and any NS access
    // to the host's vector table at 0x24000000 is silently denied.
    Risaf::new(RisafInstance::Risaf7).configure_region(
        1,
        0x3400_0000,
        0x3406_3FFF,
        false,
        0xFF,
        0xFF,
        0,
    );
    // Region 1: NS host (0x34064000–0x340DFFFF, ~496 KB). Host runs
    // unprivileged in NS, all CIDs RW.
    // Region 2: Secure ESS / EFBC / PSP (0x340E0000–0x340FFFFF, 128 KB).
    // Enclaves run UNPRIVILEGED in Secure; without an explicit region the
    // default region 0 (Secure+priv+CID=1) blocks every unprivileged
    // load, store and exception-entry stack push, raising SFSR.AUVIOL.
    let risaf2 = Risaf::new(RisafInstance::Risaf2);
    risaf2.configure_region(1, 0x3406_4000, 0x340D_FFFF, false, 0xFF, 0xFF, 0);
    risaf2.configure_region(2, 0x340E_0000, 0x340F_FFFF, true, 0xFF, 0xFF, 0);
    unsafe {
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);
    }
}

pub fn configure_untrusted_boot() {
    use arm::sau;

    // 1. Disable Secure SysTick (NS gets its own if needed)
    unsafe {
        core::ptr::write_volatile(SYST_CSR, 0x00);
    }

    // 1b. Mark NPU/CACHEAXI peripheral IRQs as NS-targeted via NVIC_ITNS.
    // Default NVIC_ITNS = 0 ⇒ all IRQs target the Secure NVIC. From NS
    // code, NVIC_EnableIRQ silently no-ops on Secure-targeted IRQs, so
    // a future NS-side NPU handler wouldn't take effect.
    // NVIC_ITNS layout: 16 × 32-bit registers, each covers 32 IRQs.
    // NPU0_IRQn=53 → ITNS1, bit 21. Setting bits 21-25 ⇒
    // NPU0/1/2/3 + CACHEAXI all NS-targeted.
    unsafe {
        let itns1 = NVIC_ITNS1;
        let v = core::ptr::read_volatile(itns1);
        core::ptr::write_volatile(
            itns1,
            v | (1u32 << 21) | (1u32 << 22) | (1u32 << 23) | (1u32 << 24) | (1u32 << 25),
        );
    }

    // 2. Set VTOR_NS to AXISRAM1 NS view (host vector table base)
    // SCB_NS->VTOR at 0xE002ED08
    drivers::rcc::Rcc::set_vtor_ns(0x2400_0000);

    // 3. Configure SAU NS regions so the host can run.
    // SAU is enabled in init_security() but with no regions, so
    // everything defaults to Secure. We need explicit NS regions.
    // SAU regions are 32-byte aligned. limit_addr is INCLUSIVE.
    // nsc=0 → Non-Secure region, en=1 → enabled.
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
        // Includes USART, GPIO, DMA NS aliases needed by host.
        let mut r1 = sau::SauRegionConfig::new();
        r1.set_rnum(1);
        r1.set_base_addr(0x4200_0000);
        r1.set_limit_addr(0x4FFF_FFE0);
        r1.set_nsc(0);
        r1.set_en(1);
        sau_driver.create_region(&r1);

        // Region 2: NSC veneers (0x341AB400 - 0x341AC3E0, 4KB).
        // Marked NSC (nsc=1) so the SG instruction is valid here.
        // Required for NS→Secure transition via umbra_* veneers.
        let mut r2 = sau::SauRegionConfig::new();
        r2.set_rnum(2);
        r2.set_base_addr(0x341A_B400);
        r2.set_limit_addr(0x341A_C3E0);
        r2.set_nsc(1); // NSC: address callable via SG
        r2.set_en(1);
        sau_driver.create_region(&r2);

        // Region 3: AXISRAM2-6 NS aliases (0x24100000 - 0x243BFFE0, ~3 MB).
        // Required for object_detection host so the Cube-AI
        // runtime can access NPU activation buffers (the network
        // model places activations in AXISRAM5 etc.). Without
        // this, NS reads of 0x24[1-3]xxxxx fault at SAU
        // (SFSR=INVTRAN+LSPERR). RISAF for these banks may also
        // need NS region config — that's a follow-up if RISAF
        // rejects after SAU passes.
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

pub fn jump_to_untrusted() -> ! {
    // The very last Secure action before NS. Raise HDPL1→HDPL2 so the
    // HDPL1 DHUK that wrapped enc_key is no longer derivable by NS or
    // enclaves. CRYP's already-shared key (KEYVALID) survives the bump, so
    // runtime enclave decrypt keeps working. Reversible (POR clears HDPL).
    crate::hdpl::raise_hdpl_to_2();

    // Copy the NS host image from XSPI2 (where flash_n657.sh placed it
    // at 0x70080000) into AXISRAM1 via the NS alias 0x24000000. Writing
    // through the NS alias is required: after init_security configured
    // RISAF7+RISAF2 region 1 with SEC=0, only NS-tagged requests reach
    // AXISRAM1, and the bus tag is derived from the address (Secure CPU
    // + NS address ⇒ NS request).
    const HOST_FLASH_BASE: u32 = 0x7008_0000;
    const HOST_NS_BASE: u32 = 0x2400_0000;
    // 128 KB copy: covers the host code/.text/.data (≤16 KB) AND the
    // enclave region pinned at offset 0x10000 in host.ld (header +
    // up to 1 KB code). Larger copies are also fine — AXISRAM1 NS
    // has 896 KB available — but 128 KB is the minimum that lets the
    // FreeRTOS NS host (`stm32n657/freertos`) scan AXISRAM1 for UMBR
    // enclave magic at 0x24010000+. The bare-metal host doesn't need
    // the scan path (uses linker symbol directly) but copying the
    // extra bytes is harmless.
    const HOST_COPY_SIZE: u32 = 0x2_0000;

    unsafe {
        let src = HOST_FLASH_BASE as *const u8;
        let dst = HOST_NS_BASE as *mut u8;
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

    unsafe {
        crate::trampoline_to_ns();
    }
    loop {
        core::hint::spin_loop();
    }
}
