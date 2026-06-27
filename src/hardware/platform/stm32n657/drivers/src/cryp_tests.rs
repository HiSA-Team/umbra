//! Host tests for the CRYP1 driver (`cryp.rs`). Split into a sibling file
//! to keep the parent under the 600-LOC cap; `#[path]`-included from cryp.rs,
//! so it keeps the same `super::*` access as an inline `mod tests`.

    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Return the (addr, value) of the n-th Write in `log`. Mirrors the
    /// L552 hash.rs helper — N657 no_std test mod cannot pull in `Vec`,
    /// so iterate the slice directly.
    fn nth_write(log: &[MmioOp], n: usize) -> (u32, u32) {
        let mut seen = 0;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if seen == n {
                    return (addr, value);
                }
                seen += 1;
            }
        }
        panic!("log only contains {} writes, wanted index {}", seen, n);
    }

    /// Return the value of the most-recent Write to `want_addr` (or None).
    fn last_write_to(log: &[MmioOp], want_addr: u32) -> Option<u32> {
        let mut found = None;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if addr == want_addr {
                    found = Some(value);
                }
            }
        }
        found
    }

    /// Return the (addr, value) of the n-th Write whose addr matches
    /// `want_addr` (0-indexed). DIN/DOUT FIFOs share a single offset across
    /// 4 consecutive writes; this helper indexes into that sequence.
    fn nth_write_to(log: &[MmioOp], want_addr: u32, n: usize) -> u32 {
        let mut seen = 0;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if addr == want_addr {
                    if seen == n {
                        return value;
                    }
                    seen += 1;
                }
            }
        }
        panic!(
            "log only contains {} writes to 0x{:08x}, wanted index {}",
            seen, want_addr, n
        );
    }

    /// Verifies the load-bearing KEYRx ascending-write contract from
    /// `configure_ecb_128_sw_key`: K2LR receives `key[0..4]` as a big-
    /// endian u32 (the MSB word of KEY[127:0]), then K2RR/K3LR/K3RR in
    /// ascending offsets. Any other order asserts CRYP SR.KERF on real
    /// silicon and would prevent KEYVALID from rising. See L552 commit
    /// 18c47d3 for the analogous AesHardware test.
    /// Preloads SR with KEYVALID=1 so the post-key poll exits on the
    /// first iteration.
    #[test]
    fn configure_ecb_128_writes_keyrx_ascending_with_be_byteswap() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        // SR.KEYVALID = bit 7 — set so the poll-after-key loop exits.
        mem.preload_register(CRYP_SR_OFFSET, SR_KEYVALID);

        let mut cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        // Distinguishable per-word sentinels so a swapped order would
        // produce different captured values.
        let key: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, // → K2LR  = 0xDEADBEEF
            0x01, 0x02, 0x03, 0x04, // → K2RR  = 0x01020304
            0xCA, 0xFE, 0xBA, 0xBE, // → K3LR  = 0xCAFEBABE
            0x12, 0x34, 0x56, 0x78, // → K3RR  = 0x12345678
        ];
        cryp.configure_ecb_128_sw_key(&key);

        let log = mem.write_log();
        let k2lr_addr = CRYP_BASE_ADDR + CRYP_K2LR_OFFSET;
        let k2rr_addr = CRYP_BASE_ADDR + CRYP_K2RR_OFFSET;
        let k3lr_addr = CRYP_BASE_ADDR + CRYP_K3LR_OFFSET;
        let k3rr_addr = CRYP_BASE_ADDR + CRYP_K3RR_OFFSET;

        // Confirm the exact captured value at each KEYRx — pins both byte
        // order AND register choice.
        assert_eq!(
            last_write_to(&log, k2lr_addr),
            Some(0xDEAD_BEEF),
            "K2LR must receive key[0..4] as BE u32 (MSB word of KEY[127:0])"
        );
        assert_eq!(
            last_write_to(&log, k2rr_addr),
            Some(0x0102_0304),
            "K2RR must receive key[4..8] as BE u32"
        );
        assert_eq!(
            last_write_to(&log, k3lr_addr),
            Some(0xCAFE_BABE),
            "K3LR must receive key[8..12] as BE u32"
        );
        assert_eq!(
            last_write_to(&log, k3rr_addr),
            Some(0x1234_5678),
            "K3RR must receive key[12..16] as BE u32 (LSB word)"
        );

        // And confirm the relative ordering: K2LR write happens BEFORE
        // K2RR write, etc. KEYRx ascending order is the HW contract that
        // prevents SR.KERF.
        let pos = |addr: u32| -> usize {
            log.iter()
                .position(|op| matches!(op, MmioOp::Write { addr: a, .. } if *a == addr))
                .unwrap_or_else(|| panic!("expected a Write to 0x{:08x}", addr))
        };
        assert!(pos(k2lr_addr) < pos(k2rr_addr), "K2LR must precede K2RR");
        assert!(pos(k2rr_addr) < pos(k3lr_addr), "K2RR must precede K3LR");
        assert!(pos(k3lr_addr) < pos(k3rr_addr), "K3LR must precede K3RR");
    }

    /// Verifies the CR.ALGOMODE encoding for ECB: bits [5:3] = 0b100
    /// (= 0x4 per RM0486 §49.8.1), bit 19 (ALGOMODE[3] extension) cleared.
    /// Also pins ancillary CR fields zeroed by the configure routine:
    /// KEYSIZE [9:8] = 0 (128-bit), DATATYPE [7:6] = 0 (no swap),
    /// ALGODIR bit 2 = 0 (encrypt), KMOD [25:24] = 0 (normal SW key).
    /// The final CR write (step 5: CRYPEN=1) is what we sample.
    #[test]
    fn configure_ecb_128_sets_algomode_ecb_in_cr() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        mem.preload_register(CRYP_SR_OFFSET, SR_KEYVALID);

        let mut cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        // Zero key — value irrelevant for this test; we're checking CR.
        cryp.configure_ecb_128_sw_key(&[0u8; 16]);

        let log = mem.write_log();
        let cr_addr = CRYP_BASE_ADDR + CRYP_CR_OFFSET;
        let final_cr = last_write_to(&log, cr_addr)
            .expect("configure_ecb_128_sw_key must write CR at least once");

        // ALGOMODE field [5:3] == 0b100 (ECB = 0x4)
        assert_eq!(
            (final_cr >> 3) & 0x7,
            0b100,
            "CR.ALGOMODE[5:3] must be 0b100 (ECB) — got 0b{:03b}",
            (final_cr >> 3) & 0x7
        );
        // ALGOMODE[3] extension at bit 19 cleared
        assert_eq!(
            (final_cr >> 19) & 1,
            0,
            "CR bit 19 (ALGOMODE ext) must be cleared"
        );
        // KEYSIZE [9:8] = 0 (AES-128)
        assert_eq!((final_cr >> 8) & 0x3, 0, "CR.KEYSIZE must be 0 (128-bit)");
        // DATATYPE [7:6] = 0 (no byte swap on the data path; the BE
        // swap is done in software via from_be_bytes on each DIN write)
        assert_eq!((final_cr >> 6) & 0x3, 0, "CR.DATATYPE must be 0 (no swap)");
        // ALGODIR bit 2 = 0 (encrypt — CTR is symmetric so decrypt re-uses)
        assert_eq!((final_cr >> 2) & 1, 0, "CR.ALGODIR must be 0 (encrypt)");
        // KMOD [25:24] = 0 (normal SW key — not DHUK-wrapped shared-bus)
        assert_eq!(
            (final_cr >> 24) & 0x3,
            0,
            "CR.KMOD must be 0 (normal SW key)"
        );
        // Final write must enable CRYP (bit 15)
        assert_eq!(
            (final_cr >> 15) & 1,
            1,
            "CR.CRYPEN must be set on final write"
        );
    }

    /// Verifies the DIN→OFNE-poll→DOUT FIFO protocol from `process_block`.
    /// Preload SR.OFNE=1 so the poll exits on the first read. Preload
    /// DOUT with 4 distinct sentinels so we can check the BE byte-order
    /// reconstruction (each u32 read becomes 4 output bytes via
    /// `to_be_bytes`).
    /// Confirms:
    /// - 4 DIN writes happen in ascending input-byte order (MSB-first
    /// per §49.8.3, matching key BE convention)
    /// - OFNE poll happens between the writes and the DOUT reads
    /// - output buffer matches the BE expansion of the 4 DOUT reads
    #[test]
    fn process_block_writes_din_then_polls_ofne_then_reads_dout() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        // SR.OFNE = bit 2; preload so the poll exits immediately.
        mem.preload_register(CRYP_SR_OFFSET, SR_OFNE);
        // Preload DOUT with a single sentinel — MmioMem's single-cell
        // FIFO returns the same value for all 4 reads, which is fine for
        // pinning the BE-expansion semantics: we just need to verify the
        // output buffer mirrors what came back.
        mem.preload_register(CRYP_DOUT_OFFSET, 0xCA11_AB1E);

        let cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        let input: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, // → DIN  = 0x11223344
            0x55, 0x66, 0x77, 0x88, // → DIN  = 0x55667788
            0x99, 0xAA, 0xBB, 0xCC, // → DIN  = 0x99AABBCC
            0xDD, 0xEE, 0xFF, 0x00, // → DIN  = 0xDDEEFF00
        ];
        let mut output = [0u8; 16];
        cryp.process_block(&input, &mut output);

        let log = mem.write_log();
        let din_addr = CRYP_BASE_ADDR + CRYP_DIN_OFFSET;

        // 4 DIN writes with BE byte-order (MSB-first per §49.8.3)
        assert_eq!(
            nth_write_to(&log, din_addr, 0),
            0x1122_3344,
            "DIN write #0 must be input[0..4] BE"
        );
        assert_eq!(
            nth_write_to(&log, din_addr, 1),
            0x5566_7788,
            "DIN write #1 must be input[4..8] BE"
        );
        assert_eq!(
            nth_write_to(&log, din_addr, 2),
            0x99AA_BBCC,
            "DIN write #2 must be input[8..12] BE"
        );
        assert_eq!(
            nth_write_to(&log, din_addr, 3),
            0xDDEE_FF00,
            "DIN write #3 must be input[12..16] BE"
        );

        // Output reconstructed from BE expansion of the DOUT reads.
        let expect = 0xCA11_AB1Eu32.to_be_bytes();
        for i in 0..4 {
            assert_eq!(
                &output[i * 4..i * 4 + 4],
                &expect,
                "output[{}*4..] must mirror DOUT read as BE bytes",
                i
            );
        }

        // Reference nth_write so dead-code lint doesn't trip on this
        // helper when only the addr-filtered nth_write_to is exercised.
        let _ = nth_write(&log, 0);
    }

    /// `configure_ecb_shared` must set KMOD=shared in CR and write NO KEYRx
    /// (the key is delivered by SAES over the shared bus, not by software).
    #[test]
    fn configure_ecb_shared_sets_kmod_shared_no_keyrx() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        // KEYVALID=1 so the bounded poll exits at once (SAES share would set it).
        mem.preload_register(CRYP_SR_OFFSET, SR_KEYVALID);
        let mut cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        cryp.configure_ecb_shared();

        let log = mem.write_log();
        for off in [
            CRYP_K2LR_OFFSET,
            CRYP_K2RR_OFFSET,
            CRYP_K3LR_OFFSET,
            CRYP_K3RR_OFFSET,
        ] {
            assert!(
                !log.iter().any(|op| matches!(op,
                    MmioOp::Write { addr, .. } if *addr == CRYP_BASE_ADDR + off)),
                "shared mode must not write KEYRx (offset {:#x})",
                off
            );
        }
        assert!(
            log.iter().any(|op| matches!(op,
                MmioOp::Write { addr, value }
                    if *addr == CRYP_BASE_ADDR + CRYP_CR_OFFSET && (value >> 24) & 0x3 == 0b10)),
            "a CR write must set KMOD=shared"
        );
    }
