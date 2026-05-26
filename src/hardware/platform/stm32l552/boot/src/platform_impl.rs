//! STM32L5 (L552 + L562) platform implementation.

use arm::mmio::{NVIC_ISER0, NVIC_ISER1, SCB_SHCSR, SYST_CSR};
use kernel::platform::PlatformBoot;

// ─── Static NS-MPU layout (Tock-host-port spec §4.2) ──────────────────────
//
// Six regions plus the PPB region (7 total) describing the Non-Secure MPU
// layout Umbra Secure programs once during configure_ns_boot(), then leaves
// immutable for the lifetime of the system. Tock runs in NS with a NoopMpu
// stub that never rewrites these registers; the actual memory protection
// lives here.
//
// Region 3/4 split (kernel-RAM 64K / app-RAM 128K at 0x20010000) is mirrored
// by a linker ASSERT in
// host/stm32l552/tock/boards/nucleo_l552ze_q_umbra/layout.ld — if Tock's
// kernel-RAM footprint grows past 64K, the assert fires AND this constant
// must be rebalanced in lockstep.
//
// Spec: docs/superpowers/specs/2026-05-26-tock-host-port-umbra-owned-mpu-design.md

use arm::mpu::{NsMpuRegion, MpuAccessPermission, MpuExecuteNever};

const NS_MPU_LAYOUT_L552: [NsMpuRegion; 7] = [
    // Region 0: Tock kernel flash + vectors — priv-RX
    NsMpuRegion {
        base_addr:  0x0804_0000,
        limit_addr: 0x0806_FFFF,
        ap: MpuAccessPermission::ROPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionPermitted,
        attr_index: 0,
    },
    // Region 1: TBF apps flash — unpriv-RX
    NsMpuRegion {
        base_addr:  0x0807_0000,
        limit_addr: 0x0807_7FFF,
        ap: MpuAccessPermission::ROAny,
        xn: MpuExecuteNever::ExecutionPermitted,
        attr_index: 0,
    },
    // Region 2: Enclave NS flash — unpriv-RX (Tock app reads when calling umbra_create)
    NsMpuRegion {
        base_addr:  0x0807_8000,
        limit_addr: 0x0807_FFFF,
        ap: MpuAccessPermission::ROAny,
        xn: MpuExecuteNever::ExecutionPermitted,
        attr_index: 0,
    },
    // Region 3: Tock kernel RAM — priv-RW, XN
    NsMpuRegion {
        base_addr:  0x2000_0000,
        limit_addr: 0x2000_FFFF,
        ap: MpuAccessPermission::RWPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 0,
    },
    // Region 4: App RAM (PSP stacks, grants, heap) — unpriv-RW, XN
    NsMpuRegion {
        base_addr:  0x2001_0000,
        limit_addr: 0x2002_FFFF,
        ap: MpuAccessPermission::RWAny,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 0,
    },
    // Region 5: NS peripherals (LPUART1, RCC, GPIO …) — priv-RW, XN, Device
    NsMpuRegion {
        base_addr:  0x4000_0000,
        limit_addr: 0x5FFF_FFFF,
        ap: MpuAccessPermission::RWPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 1,
    },
    // Region 6: PPB (SCB, SysTick, NVIC) — priv-RW, XN, Device
    NsMpuRegion {
        base_addr:  0xE000_0000,
        limit_addr: 0xE00F_FFFF,
        ap: MpuAccessPermission::RWPrivilegedOnly,
        xn: MpuExecuteNever::ExecutionNever,
        attr_index: 1,
    },
];

pub struct Stm32l5Platform;

impl Stm32l5Platform {
    pub fn new() -> Self {
        Stm32l5Platform
    }

}

impl PlatformBoot for Stm32l5Platform {
    fn init_clocks(&self) {
        let rcc = drivers::rcc::Rcc::new();

        // ── Bring SYSCLK from MSI 4 MHz to PLL 110 MHz ────────────────
        // Mandatory order — RM0438 §6.1 / §3.8:
        //   1. Enable PWR clock so we can write PWR_CR1.VOS
        //   2. PWR_CR1.VOS = Range 0 (Boost) — required above 80 MHz
        //   3. FLASH_ACR.LATENCY = 5 + ICEN + DCEN + PRFTEN — required
        //      above 60 MHz to avoid BusFault on first secure-flash read
        //   4. Enable HSI16
        //   5. Configure + enable PLL on HSI16 (110 MHz)
        //   6. Switch SYSCLK source to PLL
        //
        // Inverting any pair raises BusFault (under-WS) or undervolts
        // the chip (PLL faster than VOS allows).
        rcc.enable_clock(drivers::rcc::peripherals::PWR);
        let pwr = drivers::pwr::Pwr::new();
        pwr.set_vos_range_boost();

        let flash = drivers::flash::Flash::new();
        flash.set_latency_5ws_enable_cache();

        rcc.enable_hsi16();
        rcc.enable_pll_hsi16_110mhz();
        rcc.switch_sysclk_to_pll();

        // ── Now SYSCLK = 110 MHz. Existing peripheral enables follow. ──

        // GPIO clock (board-specific port)
        #[cfg(feature = "stm32l562")]
        rcc.enable_clock(drivers::rcc::peripherals::GPIOD);
        #[cfg(not(feature = "stm32l562"))]
        rcc.enable_clock(drivers::rcc::peripherals::GPIOB);

        // Security peripherals
        rcc.enable_clock(drivers::rcc::peripherals::GTZC);

        // DMA
        rcc.enable_clock(drivers::rcc::peripherals::DMA1);
        rcc.enable_clock(drivers::rcc::peripherals::DMA2);

        // L562 USART1 kernel clock = HSI16 (SYSCLK-independent baudrate)
        #[cfg(feature = "stm32l562")]
        rcc.select_usart1_hsi16();
    }

    fn init_gpio(&self) {
        #[cfg(feature = "stm32l562")]
        let (port, pin) = (drivers::gpio::Port::GpioD, 3);
        #[cfg(not(feature = "stm32l562"))]
        let (port, pin) = (drivers::gpio::Port::GpioB, 7);

        let gpio_led = drivers::gpio::Gpio::new(port);
        gpio_led.set_mode(pin, drivers::gpio::PinMode::Output);

        // boot_tests GPIO diagnostic: toggle LED to verify HAL.
        // No UART prints here — init_gpio runs before init_uart.
        // Diagnostic messages are printed by test_gpio() after UART is up.
        #[cfg(feature = "boot_tests")]
        {
            #[cfg(feature = "stm32l562")]
            {
                gpio_led.pin_set(pin);
                gpio_led.pin_reset(pin);
            }
            #[cfg(not(feature = "stm32l562"))]
            {
                gpio_led.pin_reset(pin);
                gpio_led.pin_set(pin);
            }
        }
    }

    fn init_uart(&self) {
        let serial = drivers::uart::Uart::new_lpuart1_and_configure(9600);

        serial.write("\n");
        serial.write("   ___       ___       ___       ___       ___   \n");
        serial.write("  /\\__\\     /\\__\\     /\\  \\     /\\  \\     /\\  \\  \n");
        serial.write(" /:/ _/_   /::L_L_   /::\\  \\   /::\\  \\   /::\\  \\ \n");
        serial.write("/:/_/\\__\\ /:/L:\\__\\ /::\\:\\__\\ /::\\:\\__\\ /::\\:\\__\\\n");
        serial.write("\\:\\/:/  / \\/_/:/  / \\:\\::/  / \\;:::/  / \\/\\::/  /\n");
        serial.write(" \\::/  /    /:/  /   \\::/  /   |:\\/__/    /:/  / \n");
        serial.write("  \\/__/     \\/__/     \\/__/     \\|__|     \\/__/  \n");
        serial.write("\n");
        serial.write("[UMBRASecureBoot] Secure Boot started\n");

        #[cfg(feature = "boot_tests")]
        {
            let umb_stack_size_val = unsafe { &super::_umb_stack_size as *const u32 as u32 };
            let umb_estack_val = unsafe { &super::_umb_estack as *const u32 as u32 };
            let sp: u32 = cortex_m::register::msp::read() as u32;
            let used_stack = umb_estack_val - sp;
            let remaining_stack = umb_stack_size_val - used_stack;

            serial.write("[UMBRASecureBoot] Stack Info:\n");
            serial.write("  _umb_stack_size: 0x");
            crate::raw_print::print_hex(umb_stack_size_val);
            serial.write("\n");
            serial.write("  Current Secure Stack Usage: 0x");
            crate::raw_print::print_hex(used_stack);
            serial.write(" (SP: 0x");
            crate::raw_print::print_hex(sp);
            serial.write(")\n");
            serial.write("  Remaining Secure Stack: 0x");
            crate::raw_print::print_hex(remaining_stack);
            serial.write("\n");
        }
    }

    fn init_security(&self) {
        use arm::sau;
        use arm::mpu;
        use drivers::gtzc;
        use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
        use kernel::common::memory_layout::{MemoryBlockList, MemoryBlockSecurityAttribute};

        //////////////////////////////
        // INITIALIZE MEMORY GUARDS //
        //////////////////////////////

        let mut sau_driver = sau::SauDriver::new();
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] SAU started\n");

        let mut gtzc_driver = gtzc::GtzcDriver::new();
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] GTZC started\n");

        sau_driver.memory_security_guard_init();
        gtzc_driver.memory_security_guard_init();

        // Enable SecureFault (SHCSR.SECUREFAULTENA = bit 19) and MemManage
        // (MEMFAULTENA = bit 16). Without SECUREFAULTENA a secure-state
        // instruction fetch into an MPCBB-NS slot would escalate to HardFault
        // and bypass the Rust `umbra_secure_fault_handler` / ESS-miss recovery
        // path.
        #[cfg(feature = "ess_miss_recovery")]
        {
            let shcsr = SCB_SHCSR;
            unsafe {
                let before = core::ptr::read_volatile(shcsr);
                #[cfg(feature = "boot_tests")]
                {
                    crate::raw_print::print_str("[UMBRASecureBoot] SHCSR before: 0x");
                    crate::raw_print::print_hex(before);
                    crate::raw_print::print_str("\n");
                }
                // 16=MEMFAULTENA, 17=BUSFAULTENA, 18=USGFAULTENA, 19=SECUREFAULTENA.
                // Enabling BUS/USG prevents silent escalation so a misrouted fault
                // surfaces in its own handler instead of the HardFault sink.
                core::ptr::write_volatile(shcsr, before | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19));
                #[cfg(feature = "boot_tests")]
                {
                    let after = core::ptr::read_volatile(shcsr);
                    crate::raw_print::print_str("[UMBRASecureBoot] SHCSR after:  0x");
                    crate::raw_print::print_hex(after);
                    crate::raw_print::print_str("\n");
                }
            }
        }

        // Ensure UsageFault is always enabled (needed for enclave
        // termination detection even without ess_miss_recovery).
        unsafe {
            let shcsr = SCB_SHCSR;
            let val = core::ptr::read_volatile(shcsr);
            if (val & (1 << 18)) == 0 {
                core::ptr::write_volatile(shcsr, val | (1 << 18));
            }
        }

        let mut mpu_driver = mpu::MpuDriver::new();
        unsafe {
            mpu_driver.init();
            // MAIR0 attr 0 = Normal memory, Outer+Inner WB-WA Non-transient (0xFF).
            // RLAR writes that leave AttrIndx=0 (the default in configure_region and
            // in the raw MPU writes in api_impl.rs) pick this attribute. Without this
            // step attr 0 is 0x00 (Device-nGnRnE), and Cortex-M33 treats stack access
            // to Device memory as CONSTRAINED UNPREDICTABLE — the enclave's first
            // `push {r7, lr}` faults with MemManage.DACCVIOL even though the region
            // AP bits permit the write.
            mpu_driver.set_mair(0, 0xFF);
            mpu_driver.enable();
        }
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] MPU started\n");

        // MPU Test: Configure Region 0 for 0x20008000 - 0x2000803F as RW
        let mut region_config = mpu::MpuRegionConfig::new();
        region_config.rnum = 0;
        region_config.base_addr = 0x20008000;
        region_config.limit_addr = 0x2000803F;
        region_config.ap = mpu::MpuAccessPermission::RWPrivilegedOnly;
        region_config.sh = mpu::MpuShareability::NonShareable;
        region_config.xn = mpu::MpuExecuteNever::ExecutionPermitted;
        region_config.enable = true;
        unsafe { mpu_driver.configure_region(&region_config); }
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("\t[UMBRASecureBoot] MPU Region 0 Configured: 0x20008000 (RW Priv)\n");

        //////////////////////////////////////////////////
        // CONFIGURE NON-SECURE CODE - FLASH CONTROLLER //
        //////////////////////////////////////////////////

        // The flash controller is initially configured offline at the bank level.
        // Currently, 0x08000000 is designated as watermarked (i.e., secure),
        // while 0x08040000 is non-watermarked, making it non-secure.
        // Pages (2 KB each) within non-watermarked blocks can be selectively modified to be secure.

        /////////////////////////////////////
        // CONFIGURE NON-SECURE CODE - SAU //
        /////////////////////////////////////

        let mut mbl = MemoryBlockList::create_from_range(0x08040000, 0x08080000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        sau_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("\t[UMBRASecureBoot] Untrusted Memory Block Range: 0x08040000 - 0x08080000\n");

        /////////////////////////////////////
        // CONFIGURE NON-SECURE DATA - SAU //
        /////////////////////////////////////

        // Let's use region 1 to split SRAM1
        // 0x20000000 - 0x20020000: Non-Secure (Host)
        // 0x20020000 - 0x20030000: Secure (EFBC)

        // SAU: Mark Host region as Untrusted
        mbl = MemoryBlockList::create_from_range(0x20000000, 0x20020000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        sau_driver.memory_security_guard_create(&mbl);

        /////////////////////////////////////////////////
        // CONFIGURE NON-SECURE DATA - SRAM CONTROLLER //
        /////////////////////////////////////////////////

        // GTZC: Mark Host region as Untrusted
        mbl = MemoryBlockList::create_from_range(0x20000000, 0x20020000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        gtzc_driver.memory_security_guard_create(&mbl);

        // GTZC: Mark EFBC region as Trusted
        mbl = MemoryBlockList::create_from_range(0x20020000, 0x20030000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Trusted);
        gtzc_driver.memory_security_guard_create(&mbl);

        // SRAM2 (ESS) - Already correct?
        // See memory.ld in host/
        mbl = MemoryBlockList::create_from_range(0x20030000, 0x2003E000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Trusted);
        gtzc_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("\t[UMBRASecureBoot] Trusted Memory Block Range: 0x20020000 - 0x2003E000\n");

        ///////////////////////////////////
        // CONFIGURE NON-SECURE CALLABLE //
        ///////////////////////////////////

        // Configure the non-secure callable region here
        mbl = MemoryBlockList::create_from_range(0x08030000, 0x0803ffe0);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::TrustedGateway);
        sau_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("\t[UMBRASecureBoot] Trusted Gateway Memory Block Range:0x08030000 - 0x0803ffe0\n");

        /////////////////////////////////////
        // DMA Demo                        //
        /////////////////////////////////////
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] TEST DMA\n");

        // Enable NVIC for DMA1 Channel 1 (IRQ 29)
        // Enable NVIC for DMA1 Channels 1-4 (IRQ 29, 30, 31, 32)
        unsafe {
            let nvic_iser0 = NVIC_ISER0;
            let nvic_iser1 = NVIC_ISER1;
            // IRQ 29, 30, 31 in ISER0
            *nvic_iser0 |= (1 << 29) | (1 << 30) | (1 << 31);
            // IRQ 32 in ISER1 (Bit 0)
            *nvic_iser1 |= 1 << 0;

            // Enable Global Interrupts
            cortex_m::interrupt::enable();
        }

        /////////////////////////////////////
        // CONFIGURE NON-SECURE PERIPHERALS - SAU //
        /////////////////////////////////////
        // We must explicitly mark the Non-Secure Peripheral range (0x40000000 - 0x5FFFFFFF) as Non-Secure in SAU.
        // Otherwise, CPU treats accesses as Secure, causing Secure Fault from Non-Secure world.
        // Range: 0x40000000 - 0x4FFFFFFF (Peripherals on AHB/APB)
        mbl = MemoryBlockList::create_from_range(0x40000000, 0x50000000);
        mbl.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
        sau_driver.memory_security_guard_create(&mbl);
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("\t[UMBRASecureBoot] Untrusted Peripheral Range: 0x40000000 - 0x50000000\n");
    }

    fn init_kernel(&self) {
        // boot_tests: HASH test
        #[cfg(feature = "boot_tests")]
        {
            crate::raw_print::print_str("[UMBRASecureBoot] TEST HASH\n");
            use drivers::hash::{Hash, Algorithm, DataType};
            let mut hash = Hash::new();
            let key = "test".as_bytes();
            let data = "ForzaNapoliSempre".as_bytes();
            let mut ctx = hash.start(Algorithm::SHA256, DataType::Width8, Some(key));
            hash.update(&mut ctx, data);
            let mut digest = [0u8; 32];
            hash.finish(ctx, &mut digest);
            crate::raw_print::print_str("\t[HMAC] SHA256: ");
            crate::raw_print::print_hex_bytes(&digest);
            crate::raw_print::print_str("\n");
        }

        // boot_tests: AES test
        #[cfg(feature = "boot_tests")]
        {
            crate::raw_print::print_str("[UMBRASecureBoot] TEST AES\n");
            #[cfg(feature = "stm32l562")]
            use drivers::aes::AesHardware as AesImpl;
            #[cfg(not(feature = "stm32l562"))]
            use drivers::aes::AesEmulated as AesImpl;
            use drivers::aes::AesEngine;

            let mut aes = AesImpl::new();
            let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
            let input: [u8; 16] = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
            let expected: [u8; 16] = [0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97];
            let mut output = [0u8; 16];
            let mut check = [0u8; 16];

            #[cfg(feature = "stm32l562")]
            crate::raw_print::print_str("\t[AES] Does AES-128 HW Test.. \n");
            #[cfg(not(feature = "stm32l562"))]
            crate::raw_print::print_str("\t[AES] Does AES-128 SW Test.. \n");

            aes.init(&key, None);
            aes.encrypt_block(&input, &mut output);
            crate::raw_print::print_str("\t[AES] Encrypted: ");
            crate::raw_print::print_hex_bytes(&output);
            crate::raw_print::print_str("\n");

            if output == expected {
                crate::raw_print::print_str("\t[AES] Encryption MATCH\n");
            } else {
                crate::raw_print::print_str("\t[AES] Encryption FAIL\n");
            }
            aes.decrypt_block(&output, &mut check);
            if check == input {
                crate::raw_print::print_str("\t[AES] Decryption MATCH\n");
            } else {
                crate::raw_print::print_str("\t[AES] Decryption FAIL\n");
            }
        }

        // Kernel init
        unsafe {
            let hash_driver = drivers::hash::Hash::new();
            #[cfg(feature = "stm32l562")]
            use drivers::aes::AesHardware as AesImpl;
            #[cfg(not(feature = "stm32l562"))]
            use drivers::aes::AesEmulated as AesImpl;

            let aes_driver = AesImpl::new();
            super::GLOBAL_CRYPTO = Some(super::crypto_impl::UmbraCryptoEngine::new(hash_driver, aes_driver));

            let crypto_engine = (*(&raw mut super::GLOBAL_CRYPTO)).as_mut().unwrap();
            let guards = &mut *(&raw mut super::GLOBAL_GUARDS);

            let kernel = super::secure_kernel::Kernel::new(guards, Some(crypto_engine));
            super::secure_kernel::Kernel::init(kernel);
            if let Some(k) = super::secure_kernel::Kernel::get() {
                k.init_keys();
            }
        }
        crate::raw_print::print_str("[UMBRASecureBoot] Kernel Initialized\n");
    }

    fn init_external_flash(&self) -> bool {
        #[cfg(all(feature = "stm32l562", not(feature = "benchmark")))]
        {
            use drivers::ospi::{OspiDriver, OCTOSPI_MEMMAP_BASE};
            use drivers::ofd::{OfdDriver, Region, KeyMode, Config as OfdConfig};

            let rcc = drivers::rcc::Rcc::new();
            let ospi = OspiDriver::new();
            ospi.init();
            match ospi.enable_memory_mapped_octa() {
                Ok(()) => {
                    #[cfg(feature = "boot_tests")]
                    crate::raw_print::print_str("[UMBRASecureBoot] OCTOSPI memory-mapped OK\n");
                }
                Err(msg) => {
                    crate::raw_print::print_str("[UMBRASecureBoot] OCTOSPI FAIL: ");
                    crate::raw_print::print_str(msg);
                    crate::raw_print::print_str("\n");
                    loop { core::hint::spin_loop(); }
                }
            }

            const OTFDEC_REGION_SIZE: usize = 0x4000;
            const OTFDEC_NUM_SECTORS: usize = OTFDEC_REGION_SIZE / 0x1000;
            const OTFDEC_NUM_PAGES: usize = OTFDEC_REGION_SIZE / 256;
            const OTFDEC_NUM_WORDS: usize = OTFDEC_REGION_SIZE / 4;

            let s2_fail = || -> ! { loop { core::hint::spin_loop(); } };

            rcc.reset_otfdec();

            let raw = unsafe {
                super::key_derivation::derive_otfdec_raw(
                    (*(&raw mut super::GLOBAL_CRYPTO)).as_mut().unwrap()
                )
            };
            let mut otfdec_key = [0u8; 16];
            let mut otfdec_nonce = [0u8; 8];
            let mut i = 0;
            while i < 16 { otfdec_key[i] = raw[i]; i += 1; }
            i = 0;
            while i < 8 { otfdec_nonce[i] = raw[16 + i]; i += 1; }

            let ofd_cfg = |enable: bool| OfdConfig {
                start_addr: OCTOSPI_MEMMAP_BASE,
                end_addr: OCTOSPI_MEMMAP_BASE + (OTFDEC_REGION_SIZE as u32) - 1,
                nonce: otfdec_nonce, key: otfdec_key,
                mode: KeyMode::InstructionAndData, enable,
            };

            const UBMR_MAGIC_LE: u32 = 0x524D4255;
            let probe_word = unsafe { core::ptr::read_volatile(OCTOSPI_MEMMAP_BASE as *const u32) };
            let mut ofd = OfdDriver::new();

            if probe_word == UBMR_MAGIC_LE {
                // ============ COLD PATH: full three-phase cipher cycle ============
                unsafe {
                    for i in 0..OTFDEC_REGION_SIZE {
                        super::PLAINTEXT_BUF[i] = core::ptr::read_volatile(
                            (OCTOSPI_MEMMAP_BASE + i as u32) as *const u8
                        );
                    }

                    // ---- SRAM->SRAM cipher via OTFDEC ENC ----
                    ofd.set_enciphering(true);
                    ofd.configure_region(Region::Region1, ofd_cfg(true));
                    if !ofd.is_region_enabled(Region::Region1) { s2_fail(); }
                    for i in 0..OTFDEC_NUM_WORDS {
                        let mm_addr = (OCTOSPI_MEMMAP_BASE as usize) + i * 4;
                        let pt_word = core::ptr::read_unaligned(
                            ((&raw const super::PLAINTEXT_BUF).cast::<u8>() as usize + i * 4) as *const u32,
                        );
                        core::ptr::write_volatile(mm_addr as *mut u32, pt_word);
                        let ct_word = core::ptr::read_volatile(mm_addr as *const u32);
                        core::ptr::write_unaligned(
                            ((&raw mut super::CIPHERTEXT_BUF).cast::<u8>() as usize + i * 4) as *mut u32,
                            ct_word,
                        );
                    }
                    // RM0438: CR.ENC writable only when all regions disabled.
                    ofd.configure_region(Region::Region1, ofd_cfg(false));
                    ofd.set_enciphering(false);

                    // ---- erase + indirect-program ciphertext ----
                    rcc.reset_ospi();
                    ospi.init();
                    if ospi.disable_memory_mapped().is_err() { s2_fail(); }
                    for s in 0..OTFDEC_NUM_SECTORS {
                        if ospi.sector_erase_4k((s * 0x1000) as u32).is_err() { s2_fail(); }
                    }
                    rcc.reset_ospi();
                    ospi.init();
                    for p in 0..OTFDEC_NUM_PAGES {
                        let off = p * 256;
                        let slice = core::slice::from_raw_parts(
                            (&raw const super::CIPHERTEXT_BUF).cast::<u8>().add(off),
                            256,
                        );
                        if ospi.page_program(off as u32, slice).is_err() { s2_fail(); }
                        rcc.reset_ospi();
                        ospi.init();
                    }

                    // ---- mm-READ + OTFDEC DEC verify ----
                    rcc.reset_ospi();
                    ospi.init();
                    if ospi.enable_memory_mapped_octa().is_err() { s2_fail(); }
                    ofd.configure_region(Region::Region1, ofd_cfg(true));

                    let mut verify_pass = true;
                    for i in 0..OTFDEC_NUM_WORDS {
                        let got = core::ptr::read_volatile(
                            ((OCTOSPI_MEMMAP_BASE as usize) + i * 4) as *const u32,
                        );
                        let want = core::ptr::read_unaligned(
                            ((&raw const super::PLAINTEXT_BUF).cast::<u8>() as usize + i * 4) as *const u32,
                        );
                        if got != want { verify_pass = false; break; }
                    }
                    if !verify_pass { s2_fail(); }
                }
            } else {
                // ============ WARM PATH: ciphertext already on flash ============
                ofd.set_enciphering(false);
                ofd.configure_region(Region::Region1, ofd_cfg(true));
                if !ofd.is_region_enabled(Region::Region1) { s2_fail(); }
                let dec_word = unsafe { core::ptr::read_volatile(OCTOSPI_MEMMAP_BASE as *const u32) };
                if dec_word != UBMR_MAGIC_LE { s2_fail(); }
            }

            return true;
        }

        #[cfg(not(all(feature = "stm32l562", not(feature = "benchmark"))))]
        { false }
    }

    fn configure_ns_boot(&self) {
        // Disable Secure SysTick
        unsafe {
            let syst_csr = SYST_CSR;
            core::ptr::write_volatile(syst_csr, 0x00);
        }
        #[cfg(feature = "boot_tests")]
        crate::raw_print::print_str("[UMBRASecureBoot] SysTick configured (disabled)\n");

        // Point VTOR_NS to SRAM (0x20000000) where the NS host copies its
        // vector table during .data initialization.  The IDAU on STM32L5
        // classifies 0x08040000 as Secure for data reads, so the hardware
        // vector fetch fails if VTOR points to flash.  SRAM is genuinely NS.
        drivers::rcc::Rcc::set_vtor_ns(0x20000000);

        // Hand Tock a pre-configured Non-Secure MPU per spec §4.2.
        // After this call the NS-MPU is locked: nothing in NS rewrites it.
        // (Tock's cortexm33::mpu is replaced with NoopMpu in the board crate.)
        unsafe {
            arm::mpu::program_ns_mpu(&NS_MPU_LAYOUT_L552);
        }
    }

    fn jump_to_ns(&self) -> ! {
        crate::raw_print::print_str("[UMBRASecureBoot] Jumping to Non-Secure World\n");

        #[cfg(feature = "benchmark")]
        {
            const RCC_CSR: *mut u32 = 0x5002_1094 as *mut u32;
            const BORRSTF_BIT: u32 = 1 << 27;
            const RMVF_BIT: u32 = 1 << 23;

            let csr = unsafe { core::ptr::read_volatile(RCC_CSR) };
            let is_cold_boot = (csr & BORRSTF_BIT) != 0;
            unsafe { core::ptr::write_volatile(RCC_CSR, csr | RMVF_BIT); }

            if is_cold_boot {
                crate::raw_print::print_str("[UMBRASecureBoot] Cold boot: skipping benchmark (press reset to run)\n");
            } else {
                crate::raw_print::print_str("[UMBRASecureBoot] Warm reset: running benchmark\n");
                let serial = drivers::uart::Uart::new_lpuart1_and_configure(9600);
                super::benchmark::run_all(&serial);
            }
        }

        unsafe { super::trampoline_to_ns(); }
        loop {}
    }
}
