//! Bring-up: clock (PLL 110 MHz), flash, PWR, GPIO, UART, kernel init,
//! external flash (OCTOSPI + OTFDEC on L562).
//!: extracted from `platform_impl.rs`. The
//! `init_clocks` 7-step ordering and the L562-specific OCTOSPI/OTFDEC
//! cold/warm paths in `init_external_flash` are preserved verbatim — see
//! the four invariants in `mod.rs` and the `drivers::rcc` module docs.

use super::Stm32l5Platform;

impl Stm32l5Platform {
    pub(super) fn init_clocks_impl(&self) {
        let rcc = drivers::rcc::Rcc::new();

        // ── Bring SYSCLK from MSI 4 MHz to PLL 110 MHz ────────────────
        // Mandatory order — RM0438 §6.1 / §3.8:
        // 1. Enable PWR clock so we can write PWR_CR1.VOS
        // 2. PWR_CR1.VOS = Range 0 (Boost) — required above 80 MHz
        // 3. FLASH_ACR.LATENCY = 5 + ICEN + DCEN + PRFTEN — required
        // above 60 MHz to avoid BusFault on first secure-flash read
        // 4. Enable HSI16
        // 5. Configure + enable PLL on HSI16 (110 MHz)
        // 6. Switch SYSCLK source to PLL
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

    pub(super) fn init_gpio_impl(&self) {
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

    pub(super) fn init_uart_impl(&self) {
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
            let umb_stack_size_val = unsafe { &crate::_umb_stack_size as *const u32 as u32 };
            let umb_estack_val = unsafe { &crate::_umb_estack as *const u32 as u32 };
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

    pub(super) fn init_kernel_impl(&self) {
        // boot_tests: HASH test
        #[cfg(feature = "boot_tests")]
        {
            crate::raw_print::print_str("[UMBRASecureBoot] TEST HASH\n");
            use drivers::hash::{Algorithm, DataType, Hash};
            let mut hash = Hash::new();
            let key = "test".as_bytes();
            let data = "ForzaNapoliSempre".as_bytes();
            let mut ctx = hash
                .start(Algorithm::SHA256, DataType::Width8, Some(key))
                .expect("hash self-test: start");
            hash.update(&mut ctx, data).expect("hash self-test: update");
            let mut digest = [0u8; 32];
            hash.finish(ctx, &mut digest)
                .expect("hash self-test: finish");
            crate::raw_print::print_str("\t[HMAC] SHA256: ");
            crate::raw_print::print_hex_bytes(&digest);
            crate::raw_print::print_str("\n");
        }

        // boot_tests: AES test
        #[cfg(feature = "boot_tests")]
        {
            crate::raw_print::print_str("[UMBRASecureBoot] TEST AES\n");
            #[cfg(not(feature = "stm32l562"))]
            use drivers::aes::AesEmulated as AesImpl;
            use drivers::aes::AesEngine;
            #[cfg(feature = "stm32l562")]
            use drivers::aes::AesHardware as AesImpl;

            let mut aes = AesImpl::new();
            let key: [u8; 16] = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ];
            let input: [u8; 16] = [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ];
            let expected: [u8; 16] = [
                0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
                0xef, 0x97,
            ];
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
            #[cfg(not(feature = "stm32l562"))]
            use drivers::aes::AesEmulated as AesImpl;
            #[cfg(feature = "stm32l562")]
            use drivers::aes::AesHardware as AesImpl;

            let aes_driver = AesImpl::new();
            crate::GLOBAL_CRYPTO = Some(crate::crypto_impl::UmbraCryptoEngine::new(
                hash_driver,
                aes_driver,
            ));

            let crypto_engine = (*(&raw mut crate::GLOBAL_CRYPTO)).as_mut().unwrap();
            let guards = &mut *(&raw mut crate::GLOBAL_GUARDS);

            let kernel = crate::secure_kernel::Kernel::new(guards, Some(crypto_engine));
            crate::secure_kernel::Kernel::init(kernel);
            if let Some(k) = crate::secure_kernel::Kernel::get() {
                if k.init_keys().is_err() {
                    // KDF HASH engine wedged: derived keys would be all-zero.
                    // Fail closed and visible rather than booting on bad keys.
                    crate::raw_print::print_str("[UMBRASecureBoot] key-init FAIL\n");
                    loop {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        crate::raw_print::print_str("[UMBRASecureBoot] Kernel Initialized\n");
    }

    pub(super) fn init_external_flash_impl(&self) -> bool {
        #[cfg(all(feature = "stm32l562", not(feature = "benchmark")))]
        {
            use drivers::ofd::{Config as OfdConfig, KeyMode, OfdDriver, Region};
            use drivers::ospi::{OspiDriver, OCTOSPI_MEMMAP_BASE};

            // Progress beacons are gated behind `boot_tests`: production boot
            // stays quiet, but a full per-stage trace of the OTFDEC cold/warm
            // state machine is one feature-flag away when debugging an
            // intermittent hang. Failure sinks (`s2_fail` / OCTOSPI FAIL)
            // always print, so a stuck boot is never silent.
            macro_rules! trace_str {
                ($s:expr) => {{
                    #[cfg(feature = "boot_tests")]
                    crate::raw_print::print_str($s);
                }};
            }
            macro_rules! trace_hex {
                ($v:expr) => {{
                    #[cfg(feature = "boot_tests")]
                    {
                        crate::raw_print::print_str("0x");
                        crate::raw_print::print_hex($v);
                        crate::raw_print::print_str("\n");
                    }
                }};
            }

            let rcc = drivers::rcc::Rcc::new();
            let ospi = OspiDriver::new();
            ospi.init();
            match ospi.enable_memory_mapped_octa() {
                Ok(()) => {
                    trace_str!("[UMBRASecureBoot] extflash: mm-ok\n");
                }
                Err(msg) => {
                    crate::raw_print::print_str("[UMBRASecureBoot] OCTOSPI FAIL: ");
                    crate::raw_print::print_str(msg);
                    crate::raw_print::print_str("\n");
                    loop {
                        core::hint::spin_loop();
                    }
                }
            }

            const OTFDEC_REGION_SIZE: usize = 0x4000;
            const OTFDEC_NUM_SECTORS: usize = OTFDEC_REGION_SIZE / 0x1000;
            const OTFDEC_NUM_PAGES: usize = OTFDEC_REGION_SIZE / 256;
            const OTFDEC_NUM_WORDS: usize = OTFDEC_REGION_SIZE / 4;

            let s2_fail = |tag: &str| -> ! {
                crate::raw_print::print_str("[UMBRASecureBoot] extflash-fail: ");
                crate::raw_print::print_str(tag);
                crate::raw_print::print_str("\n");
                loop {
                    core::hint::spin_loop();
                }
            };

            rcc.reset_otfdec();

            let raw = match unsafe {
                crate::key_derivation::derive_otfdec_raw(
                    (*(&raw mut crate::GLOBAL_CRYPTO)).as_mut().unwrap(),
                )
            } {
                Ok(r) => r,
                Err(_) => s2_fail("keyderiv-hash"),
            };
            let mut otfdec_key = [0u8; 16];
            let mut otfdec_nonce = [0u8; 8];
            let mut i = 0;
            while i < 16 {
                otfdec_key[i] = raw[i];
                i += 1;
            }
            i = 0;
            while i < 8 {
                otfdec_nonce[i] = raw[16 + i];
                i += 1;
            }

            let ofd_cfg = |enable: bool| OfdConfig {
                start_addr: OCTOSPI_MEMMAP_BASE,
                end_addr: OCTOSPI_MEMMAP_BASE + (OTFDEC_REGION_SIZE as u32) - 1,
                nonce: otfdec_nonce,
                key: otfdec_key,
                mode: KeyMode::InstructionAndData,
                enable,
            };

            const UBMR_MAGIC_LE: u32 = 0x524D4255;
            let probe_word = unsafe { core::ptr::read_volatile(OCTOSPI_MEMMAP_BASE as *const u32) };
            trace_str!("[UMBRASecureBoot] extflash: probe=");
            trace_hex!(probe_word);
            let mut ofd = OfdDriver::new();

            if probe_word == UBMR_MAGIC_LE {
                // ============ COLD PATH: full three-phase cipher cycle ============
                trace_str!("[UMBRASecureBoot] extflash: cold-enter\n");
                unsafe {
                    for i in 0..OTFDEC_REGION_SIZE {
                        crate::PLAINTEXT_BUF[i] =
                            core::ptr::read_volatile((OCTOSPI_MEMMAP_BASE + i as u32) as *const u8);
                    }

                    // ---- SRAM->SRAM cipher via OTFDEC ENC ----
                    ofd.set_enciphering(true);
                    ofd.configure_region(Region::Region1, ofd_cfg(true));
                    if !ofd.is_region_enabled(Region::Region1) {
                        s2_fail("cold-otfdec-region");
                    }
                    for i in 0..OTFDEC_NUM_WORDS {
                        let mm_addr = (OCTOSPI_MEMMAP_BASE as usize) + i * 4;
                        let pt_word = core::ptr::read_unaligned(
                            ((&raw const crate::PLAINTEXT_BUF).cast::<u8>() as usize + i * 4)
                                as *const u32,
                        );
                        core::ptr::write_volatile(mm_addr as *mut u32, pt_word);
                        let ct_word = core::ptr::read_volatile(mm_addr as *const u32);
                        core::ptr::write_unaligned(
                            ((&raw mut crate::CIPHERTEXT_BUF).cast::<u8>() as usize + i * 4)
                                as *mut u32,
                            ct_word,
                        );
                    }
                    // RM0438: CR.ENC writable only when all regions disabled.
                    ofd.configure_region(Region::Region1, ofd_cfg(false));
                    ofd.set_enciphering(false);
                    trace_str!("[UMBRASecureBoot] extflash: cold-encrypted\n");

                    // ---- erase + indirect-program ciphertext ----
                    rcc.reset_ospi();
                    ospi.init();
                    if ospi.disable_memory_mapped().is_err() {
                        s2_fail("cold-disable-mm");
                    }
                    for s in 0..OTFDEC_NUM_SECTORS {
                        if ospi.sector_erase_4k((s * 0x1000) as u32).is_err() {
                            s2_fail("cold-erase");
                        }
                    }
                    trace_str!("[UMBRASecureBoot] extflash: cold-erased\n");
                    rcc.reset_ospi();
                    ospi.init();
                    for p in 0..OTFDEC_NUM_PAGES {
                        let off = p * 256;
                        let slice = core::slice::from_raw_parts(
                            (&raw const crate::CIPHERTEXT_BUF).cast::<u8>().add(off),
                            256,
                        );
                        if ospi.page_program(off as u32, slice).is_err() {
                            s2_fail("cold-page-program");
                        }
                        rcc.reset_ospi();
                        ospi.init();
                    }

                    trace_str!("[UMBRASecureBoot] extflash: cold-programmed\n");

                    // ---- mm-READ + OTFDEC DEC verify ----
                    rcc.reset_ospi();
                    ospi.init();
                    if ospi.enable_memory_mapped_octa().is_err() {
                        s2_fail("cold-mm-reenter");
                    }
                    ofd.configure_region(Region::Region1, ofd_cfg(true));

                    let mut verify_pass = true;
                    for i in 0..OTFDEC_NUM_WORDS {
                        let got = core::ptr::read_volatile(
                            ((OCTOSPI_MEMMAP_BASE as usize) + i * 4) as *const u32,
                        );
                        let want = core::ptr::read_unaligned(
                            ((&raw const crate::PLAINTEXT_BUF).cast::<u8>() as usize + i * 4)
                                as *const u32,
                        );
                        if got != want {
                            verify_pass = false;
                            break;
                        }
                    }
                    if !verify_pass {
                        s2_fail("cold-verify-mismatch");
                    }
                    trace_str!("[UMBRASecureBoot] extflash: cold-verify-ok\n");
                }
            } else {
                // ============ WARM PATH: ciphertext already on flash ============
                trace_str!("[UMBRASecureBoot] extflash: warm-enter\n");
                ofd.set_enciphering(false);
                ofd.configure_region(Region::Region1, ofd_cfg(true));
                if !ofd.is_region_enabled(Region::Region1) {
                    s2_fail("warm-otfdec-region");
                }
                let dec_word =
                    unsafe { core::ptr::read_volatile(OCTOSPI_MEMMAP_BASE as *const u32) };
                trace_str!("[UMBRASecureBoot] extflash: warm-decword=");
                trace_hex!(dec_word);
                if dec_word != UBMR_MAGIC_LE {
                    s2_fail("warm-magic-mismatch");
                }
            }

            trace_str!("[UMBRASecureBoot] extflash: done\n");
            return true;
        }

        #[cfg(not(all(feature = "stm32l562", not(feature = "benchmark"))))]
        {
            false
        }
    }
}
