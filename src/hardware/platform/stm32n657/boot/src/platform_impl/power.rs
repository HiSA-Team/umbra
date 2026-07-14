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

/// DEV-ONLY: open the Cortex-M55 debug access port and enable secure +
/// non-secure debug from the FSBL, mirroring embassy-boot-stm32. On a
/// closed/locked product state the Boot ROM leaves debug shut when booting
/// from flash; these two BSEC writes re-open it so GDB / STM32CubeProgrammer
/// can attach. On this BSEC-open Nucleo debug is already open, so it is
/// effectively a no-op — it exists for closed-part bring-up and parity with
/// the reference bootloader.
///
/// SECURITY: this DEFEATS debug isolation. It is gated behind the `dev_debug`
/// feature (injected only by `cargo xtask flash n657`) and MUST NEVER ship in
/// a production image.
///
/// BSEC base 0x5600_9000 (Secure). Both registers are write-once per cold
/// reset and persist until the next cold power-on (ST community: "How to allow
/// debugger to attach on STM32N6 when booting from flash"). Values + order are
/// taken verbatim from embassy-boot-stm32.
#[cfg(feature = "dev_debug")]
pub fn enable_dev_debug() {
    unsafe {
        // Open the debug access port to the Cortex-M55 (offset 0xE90).
        core::ptr::write_volatile(0x5600_9E90 as *mut u32, 0xB451_B400);
        // Enable the non-secure/secure debug (offset 0xE8C).
        core::ptr::write_volatile(0x5600_9E8C as *mut u32, 0xB451_B400);
    }
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
            // KAT moved post-share (issue #45): the AES key now arrives over
            // the SAES->CRYP DHUK shared bus. `provision_and_share_enc_key` runs
            // after `init_keys` (where enc_key exists), so a fixed-vector
            // SW-load KAT no longer applies — AesHardware has no SW key load.
            // A self-consistency KAT (CRYP-shared vs AesEmulated(enc_key))
            // follows in a later increment; for now the DHUK share itself is the
            // fail-closed gate (CRYP KEYVALID).

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

            // HW SHA-256 known-answer test: SHA-256("abc") must equal the FIPS-180-4
            // vector. Proves the HASH-peripheral digest is CORRECT (not merely
            // deterministic — the state-continuity round-trip alone can't tell the
            // difference). Fail-closed: a wrong digest silently corrupts the chained
            // measurement and the state roots that depend on it.
            {
                let mut kat = [0u8; 32];
                drivers::hash::Hash::new().sha256(b"abc", &mut kat);
                const SHA256_ABC: [u8; 32] = [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ];
                if kat == SHA256_ABC {
                    crate::raw_print::print_str("[UMBRASecureBoot] SHA-256 HW KAT: PASS\n");
                } else {
                    crate::raw_print::print_str("[UMBRASecureBoot] SHA-256 HW KAT: FAIL — halt\n");
                    loop {
                        core::hint::spin_loop();
                    }
                }
                // Non-zero => the HASH DCIS interrupt fired during the KAT (thread
                // context). The checkpoint (SVC handler) hits are inspectable via GDB
                // on `drivers::crypto_wait::HASH_IRQ_HITS`.
                crate::raw_print::print_str("[UMBRASecureBoot] HASH IRQ hits: ");
                crate::raw_print::print_hex(
                    drivers::crypto_wait::HASH_IRQ_HITS.load(core::sync::atomic::Ordering::SeqCst),
                );
                crate::raw_print::print_str("\n");
            }

            // issue #45: wrap the derived enc_key under DHUK and share it to
            // CRYP over the SAES silicon bus, so the AES key reaches CRYP off
            // the CPU register path. Runs here (after init_keys) because that is
            // where enc_key exists. Uses the first 16 bytes (AES-128) of the
            // 32-byte derived key. Fail-closed on CRYP KEYVALID inside.
            #[cfg(feature = "n657_aes_hw")]
            {
                let mut enc_key = [0u8; 16];
                enc_key.copy_from_slice(&k.enc_key[..16]);
                crate::dhuk_provision::provision_and_share_enc_key(&enc_key);

                // Self-consistency KAT (issue #45). No fixed NIST vector is
                // possible — enc_key is rebuild-random — so the SW AES is the
                // oracle: encrypt a known block via CRYP (DHUK-shared key) and
                // via AesEmulated(enc_key); equality proves CRYP's shared key
                // equals enc_key end-to-end. Fail-closed.
                use drivers::aes::AesEngine;
                let pt: [u8; 16] = [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ];
                let mut hw = drivers::aes::AesHardware::new();
                hw.init(&enc_key, None); // configure_ecb_shared; key arg ignored
                let mut hw_ct = [0u8; 16];
                hw.encrypt_block(&pt, &mut hw_ct);

                let mut sw = drivers::aes::AesEmulated::new();
                sw.init(&enc_key, None);
                let mut sw_ct = [0u8; 16];
                sw.encrypt_block(&pt, &mut sw_ct);

                crate::raw_print::print_str("[UMBRASecureBoot] DHUK KAT: ");
                if hw_ct == sw_ct {
                    crate::raw_print::print_str("PASS\n");
                } else {
                    crate::raw_print::print_str("FAIL\n");
                    panic!("DHUK self-consistency KAT failed — shared key != enc_key");
                }
            }
        }
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        crate::raw_print::print_str("[UMBRASecureBoot] Kernel Initialized\n");

        // Async prefetch engine self-test: kick a BACKGROUND copy and confirm the
        // DMA→TC-IRQ→PendSV chain fired on its own (hits ≥ 1) and the bytes match — the
        // install (cache maintenance) ran in PendSV, not inline. Dev diagnostic.
        let (pf_hits, pf_ok) = crate::prefetch::self_test();
        crate::raw_print::print_str("[UMBRASecureBoot] prefetch async: hits=");
        crate::raw_print::print_hex(pf_hits);
        crate::raw_print::print_str(if pf_ok { " bytes=OK\n" } else { " bytes=DIFF\n" });

        // Phase 2a: probe the RISAF data-read trap (safe-eviction primitive). Halts on the
        // fault — reveals which fault fires so the eviction-miss recovery can hook it.
        #[cfg(feature = "eviction_probe")]
        crate::prefetch::risaf_trap_probe();
    }
}
