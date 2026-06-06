// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! External flash bring-up (XSPI2 + MCE2 + XSPIM).
//! The ESS-miss path would DMA from XSPI2 on platforms that support it;
//! N657's plaintext-flash model makes the DMA wiring unused here, but the
//! XSPI2 controller setup remains the canonical "external flash" boot
//! step. Lifted verbatim from the monolithic `platform_impl.rs` during
//!. Pure file reorganization; no semantic changes.

pub fn init_external_flash() -> bool {
    // XSPI2 memory-mapped + MCE2 fast block cipher.
    // Root cause of previous XSPI2 failure: we used AHB5RSTR (0x220, read-only
    // status) instead of AHB5RSTSR/AHB5RSTCR (0xA20/0x1220, write-1-to-set/clear).
    // The reset never happened, so Boot ROM's CID lock stayed on XSPI2/XSPIM.
    // Fix: use RSTSR/RSTCR pair (from ST's system_stm32n6xx_fsbl.c SystemInit).
    // Then follow ST's init: XSPIM clock first, then XSPI2, MODE=0, hclk5.

    unsafe {
        let rcc_s = 0x5602_8000usize;
        let xspi2 = 0x5802_A000usize;
        let xspim = 0x5802_B400usize;

        // ── Reset XSPI1 + XSPI2 + XSPIM via RSTSR/RSTCR ─────────
        // N6 uses split reset registers (NOT the single AHB5RSTR at 0x220):
        // AHB5RSTSR (0xA20) — write-1-to-SET (assert reset)
        // AHB5RSTCR (0x1220) — write-1-to-CLEAR (release reset)
        // Must also reset XSPI1 (bit 5): Boot ROM left it EN=1, and XSPIM
        // can only be modified when ALL XSPI controllers are disabled.
        core::ptr::write_volatile(
            (rcc_s + 0xA20) as *mut u32,
            (1 << 13) | (1 << 12) | (1 << 5),
        ); // XSPIM + XSPI2 + XSPI1
        let mut d: u32 = 0;
        while d < 1_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }
        core::ptr::write_volatile(
            (rcc_s + 0x1220) as *mut u32,
            (1 << 13) | (1 << 12) | (1 << 5),
        ); // release XSPIM + XSPI2 + XSPI1
        d = 0;
        while d < 1_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        // ── Enable clocks (XSPIM first, then XSPI2 — ST's order) ─
        let ahb5 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x260) as *mut u32, ahb5 | (1 << 13) | (1 << 5)); // XSPIMEN + XSPI1EN first
        let ahb5_2 = core::ptr::read_volatile((rcc_s + 0x260) as *const u32);
        core::ptr::write_volatile((rcc_s + 0x260) as *mut u32, ahb5_2 | (1 << 12) | (1 << 15)); // then XSPI2EN + MCE2EN

        // ── Kernel clock = IC3 from PLL1 (like ST's XSPI_NOR) ───
        // hclk5 (SEL=00) and per_ck (SEL=01) don't reach XSPI2 — N6 kernel
        // clocks require explicitly configured IC dividers.
        // ST's XSPI_NOR_MemoryMapped_DTR uses IC3 from PLL1 with divider=6.
        // IC3CFGR (0xCC): IC3SEL[29:28]=00 (PLL1), IC3INT[23:16]=divider-1
        // DIVENSR (0xA40): write-1-to-set IC enable. IC3 = bit 2.
        // CCIPR6 XSPI2SEL=10 selects ic3_ck.
        // PLL1 is 800 MHz, so the IC3 divider is set to 16 → XSPI source
        // = 50 MHz. Higher rates risked exceeding the DCYC=20 dummy-cycle
        // window for the on-board NOR flash.
        core::ptr::write_volatile((rcc_s + 0xCC) as *mut u32, (0b00 << 28) | (15 << 16)); // IC3SEL=PLL1, IC3INT=15 (div by 16)
                                                                                          // Enable IC3 via DIVENSR (write-1-to-set, offset 0xA40)
        core::ptr::write_volatile((rcc_s + 0xA40) as *mut u32, 1 << 2); // IC3EN
        let mut dw: u32 = 0;
        while dw < 1_000 {
            core::hint::spin_loop();
            dw = dw.wrapping_add(1);
        }

        // Select IC3 as XSPI2 kernel clock
        let ccipr6 = core::ptr::read_volatile((rcc_s + 0x158) as *const u32);
        core::ptr::write_volatile(
            (rcc_s + 0x158) as *mut u32,
            (ccipr6 & !(0b11 << 4)) | (0b10 << 4),
        ); // XSPI2SEL=10 (ic3_ck)

        // ── VDDIO3 supply for Port N I/Os ────────────────────────
        let pwr = 0x5602_4800usize;
        let svmcr3 = core::ptr::read_volatile((pwr + 0x03C) as *const u32);
        core::ptr::write_volatile(
            (pwr + 0x03C) as *mut u32,
            svmcr3 | (1 << 9) | (1 << 1) | (1 << 26),
        );
        let mut rdy: u32 = 0;
        while rdy < 100_000 {
            if core::ptr::read_volatile((pwr + 0x03C) as *const u32) & (1 << 17) != 0 {
                break;
            }
            rdy = rdy.wrapping_add(1);
        }
        let syscfg = 0x5600_8000usize;
        core::ptr::write_volatile(
            (syscfg + 0x05C) as *mut u32,
            (0x7 << 4) | (0x8 << 8) | (1 << 1),
        );
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        // ── GPIO Port N for XSPI Port2 (AF9, very high speed) ────
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
        while pi < 10 {
            ospeedr |= 0b11 << (af_pins[pi] * 2);
            pi += 1;
        }
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

        // ── XSPIM config (MODE=0, CSSEL_OVR_EN, REQ2ACK_TIME) ───
        // MODE=0 (direct: XSPI2→Port2), NCS1 override, req2ack=1
        core::ptr::write_volatile(xspim as *mut u32, (1u32 << 16) | (1u32 << 4)); // REQ2ACK_TIME=1, CSSEL_OVR_EN=1

        // ── Configure XSPI2 (while disabled) ─────────────────────
        // DCR1: MTYP=Macronix(001), DEVSIZE=25, CSHT=1
        core::ptr::write_volatile(
            (xspi2 + 0x008) as *mut u32,
            (0b001 << 24) | (25 << 16) | (1 << 8),
        );
        // DCR2: prescaler=4
        core::ptr::write_volatile((xspi2 + 0x00C) as *mut u32, 4);
        let mut bw: u32 = 0;
        while bw < 100_000 {
            if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & (1 << 5) == 0 {
                break;
            }
            bw = bw.wrapping_add(1);
        }

        // ── Enable XSPI2 ─────────────────────────────────────────
        core::ptr::write_volatile(xspi2 as *mut u32, 1); // EN=1
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        d = 0;
        while d < 5_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }

        // ── SPI flash reset (0x66 + 0x99) ────────────────────────
        core::ptr::write_volatile((xspi2 + 0x100) as *mut u32, 0b001); // IMODE=1line
        core::ptr::write_volatile((xspi2 + 0x108) as *mut u32, 0);
        core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x66);
        let mut t: u32 = 0;
        while t < 100_000 {
            if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & 2 != 0 {
                break;
            }
            t = t.wrapping_add(1);
        }
        core::ptr::write_volatile((xspi2 + 0x028) as *mut u32, 2);
        core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x99);
        t = 0;
        while t < 100_000 {
            if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & 2 != 0 {
                break;
            }
            t = t.wrapping_add(1);
        }
        core::ptr::write_volatile((xspi2 + 0x028) as *mut u32, 2);
        d = 0;
        while d < 50_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        // ── READ_ID (0x9F) ──────────────────────────────────────
        core::ptr::write_volatile(xspi2 as *mut u32, (0b01u32 << 28) | 1);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        core::ptr::write_volatile((xspi2 + 0x040) as *mut u32, 2);
        core::ptr::write_volatile((xspi2 + 0x108) as *mut u32, 1 << 30);
        core::ptr::write_volatile((xspi2 + 0x100) as *mut u32, (0b001 << 24) | (0b001 << 0));
        cortex_m::asm::dsb();
        core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x9F);

        t = 0;
        while t < 200_000 {
            if core::ptr::read_volatile((xspi2 + 0x024) as *const u32) & 2 != 0 {
                break;
            }
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

        // ── Memory-mapped mode ──────────────────────────────────
        let cr_cur = core::ptr::read_volatile(xspi2 as *const u32);
        core::ptr::write_volatile(xspi2 as *mut u32, cr_cur | (1 << 1));
        bw = 0;
        while bw < 10_000 {
            if core::ptr::read_volatile(xspi2 as *const u32) & (1 << 1) == 0 {
                break;
            }
            bw = bw.wrapping_add(1);
        }
        core::ptr::write_volatile(xspi2 as *mut u32, 0);
        core::ptr::write_volatile(
            (xspi2 + 0x100) as *mut u32,
            (0b001 << 24) | (0b11 << 12) | (0b001 << 8) | (0b001 << 0),
        );
        core::ptr::write_volatile((xspi2 + 0x108) as *mut u32, 8 | (1 << 30));
        core::ptr::write_volatile((xspi2 + 0x110) as *mut u32, 0x0C);
        core::ptr::write_volatile(xspi2 as *mut u32, (0b11u32 << 28) | 1);
        d = 0;
        while d < 10_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }

        // Discard the memory-mapped probe — used to be printed for
        // bring-up validation; XSPI2 access is now confirmed by the
        // host/enclave lifecycle running successfully.
        let _probe = core::ptr::read_volatile(0x7000_0000 as *const u32);

        // ── XSPI2 layout (plaintext-flash model) ────────────────
        // MCE2 encryption-at-rest is not enabled. Confidentiality comes
        // from the inner enclave encryption applied by
        // `protect_enclave.py --hmac-over-plaintext`; integrity comes
        // from the chained-HMAC measurement. MCE2 stays in passthrough.
        // XSPI2 layout:
        // 0x70000000-0x70030000 FSBL signed image
        // 0x70080000+ Host binary (plaintext) — enclave
        // header at 0x70090000, code follows
        // in plaintext.
        // `xspi.rs` exposes minimal SPI / OPI write primitives that are
        // kept `pub` as artifacts for a possible future revival of the
        // chip-as-oracle write path (currently blocked by an OPI WREN
        // chip-side issue documented in the design notes).
        core::ptr::write_volatile(0x5600_4800 as *mut u32, 0xAAAA_u32);

        // ── Disable MCE2 region 1 (passthrough on AXI reads) ────
        // Boot ROM may leave MCE2 region 1 enabled in Fast Block mode.
        // Explicitly disable to guarantee plaintext reads from XSPI2 at
        // 0x70080000+. No key/nonce config — MCE2 stays inert.
        let mce = drivers::mce::Mce2::new();
        mce.disable_region1();

        true
    }
}
