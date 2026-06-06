// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! Peripheral bring-up — GPIO + UART + kernel/crypto install.
//! Lifted verbatim from the monolithic `platform_impl.rs` during
//!. Pure file reorganization; no semantic changes. The
//! `super::super::` paths reach the parent crate root (where `GLOBAL_CRYPTO`
//! / `GLOBAL_GUARDS` / `secure_kernel` / `crypto_impl` live).

use drivers::gpio::{Gpio, PinMode, Port};

pub fn init_gpio() {
    // GPIO is RIF-aware — has its own internal SECCFGR, reset to 0 (NS).
    // NS alias works for GPIO, but we use the GPIO driver which already
    // handles this. The main.rs diagnostic does early GPIO setup via
    // Secure alias before this point.

    // NUCLEO-N657X0-Q user LEDs — all on GPIOG
    // LED1 (Blue) = PG8
    // LED2 (Red) = PG10
    // LED3 (Green) = PG0
    let gpio_g = Gpio::new(Port::GpioG);
    gpio_g.set_mode(0, PinMode::Output); // LED3 green
    gpio_g.set_mode(8, PinMode::Output); // LED1 blue
    gpio_g.set_mode(10, PinMode::Output); // LED2 red
    gpio_g.pin_set(0);

    // USART1 pins: PE5 = TX (AF7), PE6 = RX (AF7)
    let gpio_e = Gpio::new(Port::GpioE);
    gpio_e.set_mode(5, PinMode::Alternate);
    gpio_e.set_af(5, 7);
    gpio_e.set_mode(6, PinMode::Alternate);
    gpio_e.set_af(6, 7);
}

pub fn init_uart() {
    // USART1 via Secure alias. Kernel clock = HSI = 64 MHz (CCIPR13.USART1SEL = 6,
    // set in init_clocks). BRR = 64_000_000 / 115200 ≈ 555.5 → 556
    // (0.08% baud error, well within UART receiver tolerance).
    unsafe {
        let u1 = 0x5200_1000usize;
        core::ptr::write_volatile(u1 as *mut u32, 0); // CR1=0
        core::ptr::write_volatile((u1 + 0x2C) as *mut u32, 0); // PRESC=0
        core::ptr::write_volatile((u1 + 0x0C) as *mut u32, 556); // BRR (HSI/115200)
        core::ptr::write_volatile(u1 as *mut u32, (1 << 0) | (1 << 3)); // UE+TE
        let mut w: u32 = 0;
        while w < 10_000 {
            core::hint::spin_loop();
            w = w.wrapping_add(1);
        }
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

pub fn init_kernel() {
    unsafe {
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        // Build UmbraCryptoEngine (Hash + AesEmulated), install it as
        // the kernel's `dyn CryptoEngine`, then let `Kernel::init_keys`
        // derive enc/hmac keys via vtable dispatch and `.rodata` label
        // slices. The linker ORIGIN must be `0x34180400` (0x400 past
        // the FSBL signing header), otherwise `.rodata` reads return
        // signed-image bytes and key derivation breaks.
        let hash_driver = drivers::hash::Hash::new();
        #[cfg(feature = "n657_aes_hw")]
        let aes_driver = drivers::aes::AesHardware::new();
        #[cfg(not(feature = "n657_aes_hw"))]
        let aes_driver = drivers::aes::AesEmulated::new();

        // AES KAT — runs before installing the engine so that a HW
        // failure panics with a clear cause instead of silent corruption.
        // NIST SP800-38A F.1.1 ECB-AES128 Vector 1 (matches L552 KAT).
        #[cfg(feature = "n657_aes_hw")]
        {
            use drivers::aes::AesEngine;
            let mut kat = drivers::aes::AesHardware::new();
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
            kat.init(&key, None);
            kat.encrypt_block(&input, &mut output);
            crate::raw_print::print_str("[UMBRASecureBoot] AES KAT (HW): ");
            crate::raw_print::print_hex_bytes(&output);
            if output == expected {
                crate::raw_print::print_str(" PASS\n");
            } else {
                crate::raw_print::print_str(" FAIL\n");
                panic!("AES-128-ECB KAT failed — HW AES path broken");
            }

            // AES-128-CTR KAT — NIST SP800-38A F.5.1 (Vectors 1+2).
            // Validates the native CTR path: ALGOMODE=0x6, IV load,
            // HW counter increment between blocks, internal XOR. Key
            // is the same as ECB above so the same KEYVALID path is
            // exercised; IV is the F.5.1 counter; plaintext is F.5.1
            // block 1+2 concatenated.
            let ctr_key: [u8; 16] = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ];
            let ctr_iv: [u8; 16] = [
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
                0xfe, 0xff,
            ];
            let mut ctr_buf: [u8; 32] = [
                // Block 1 plaintext (F.5.1)
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a, // Block 2 plaintext
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                0x8e, 0x51,
            ];
            let ctr_expected: [u8; 32] = [
                // Block 1 ciphertext (F.5.1)
                0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
                0xb6, 0xce, // Block 2 ciphertext
                0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff,
                0xfd, 0xff,
            ];
            kat.init(&ctr_key, None);
            kat.ctr_xform(&ctr_iv, &mut ctr_buf);
            crate::raw_print::print_str("[UMBRASecureBoot] CTR KAT (HW): ");
            crate::raw_print::print_hex_bytes(&ctr_buf[0..16]);
            crate::raw_print::print_str(" ");
            crate::raw_print::print_hex_bytes(&ctr_buf[16..32]);
            if ctr_buf == ctr_expected {
                crate::raw_print::print_str(" PASS\n");
            } else {
                crate::raw_print::print_str(" FAIL\n");
                panic!("AES-128-CTR KAT failed — HW CTR path broken");
            }

            // AEAD trait surface check.
            // Compile-time: verifies that AesHardware satisfies the
            // Aead trait — associated consts, method signatures, and
            // AeadError variants all monomorphize. Runtime: confirms
            // the placeholder returns `NotYetImplemented`.
            {
                use drivers::aes::{Aead, AeadError};
                let mut aead_test = drivers::aes::AesHardware::new();
                let key = [0u8; <drivers::aes::AesHardware as Aead>::KEY_SIZE];
                let nonce = [0u8; <drivers::aes::AesHardware as Aead>::NONCE_SIZE];
                let ad = [0u8; 0];
                let pt = [0u8; 0];
                let mut ct_buf = [0u8; <drivers::aes::AesHardware as Aead>::TAG_SIZE];
                let seal_res = aead_test.seal(&key, &nonce, &ad, &pt, &mut ct_buf);
                crate::raw_print::print_str("[UMBRASecureBoot] AEAD surface: ");
                if seal_res == Err(AeadError::NotYetImplemented) {
                    crate::raw_print::print_str("OK (placeholder)\n");
                } else {
                    crate::raw_print::print_str("UNEXPECTED — GCM impl may have landed\n");
                }
            }
        }

        crate::GLOBAL_CRYPTO = Some(crate::crypto_impl::UmbraCryptoEngine::new(
            hash_driver,
            aes_driver,
        ));
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

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
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        crate::raw_print::print_str("[UMBRASecureBoot] Kernel Initialized\n");
    }
}
