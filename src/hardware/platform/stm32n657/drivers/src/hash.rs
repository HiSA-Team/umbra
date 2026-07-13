//! HASH driver for STM32N657 — HW SHA-256 + HW HMAC-SHA256 on the HASH peripheral
//! (Secure alias `0x5402_0400`, clock enabled at boot). Both `Hash::sha256` and
//! `Hash::hmac_sha256` drive the peripheral. Completion is polled on DCIS: a SHA-256
//! digest is bounded compute with no external dependency, so — unlike the SAES/DHUK
//! wait which could hang on an unpowered backup domain — a busy-poll is already
//! fail-safe. The file-local SW `Sha256` + `Sha256Engine` adapter are kept as the
//! host-testable `umbra_hal::Hash` trait backing (the HW path is method-only) and a
//! fallback; the SW path is a legacy artefact of the old RIFSC AHB3ENR.HASHEN blocker.
//! # Register map (RM0486 §28, verified empirically — layout differs from L5)
//! HASH_CR = base + 0x00 SHA-256 algo = bits 17+18 (ALGO[1:0] = 0b11),
//! MODE (HMAC) = bit 6, INIT = bit 2,
//! DATATYPE (byte-swap) = bits 5:4
//! HASH_DIN = base + 0x04 data input (32-bit LE words)
//! HASH_STR = base + 0x08 DCAL = bit 8, NBLW = bits 4:0
//! HASH_HR0..HR4 = base + 0x0C..0x1C first 5 digest words (BE)
//! HASH_SR = base + 0x24 DINIS = bit 0, DCIS = bit 1
//! HASH_HR5..HR7 = base + 0x324..0x32C last 3 digest words (NOT contiguous
//! with HR0–HR4 — same split-bank landmine as L552;
//! misreading them yields the correct first 160
//! bits and garbage for the last 96)
//! Keys are always ≤64 bytes (typically 32) so LKEY (bit 16) is never needed.

use peripheral_regs::{MmioAccess, RealMmio};

/// Secure-alias base address of the N657 HASH peripheral.
const HASH_BASE_ADDR: u32 = 0x5402_0400;

// Register offsets (relative to HASH_BASE_ADDR). HR5/HR6/HR7 live in a
// separate bank at +0x324 — DO NOT collapse into a stride from HR0.
const HASH_CR_OFFSET: u32 = 0x00;
const HASH_DIN_OFFSET: u32 = 0x04;
const HASH_STR_OFFSET: u32 = 0x08;
const HASH_HR_OFFSET: u32 = 0x0C; // HR0..HR4
const HASH_SR_OFFSET: u32 = 0x24;
const HASH_HR5_OFFSET: u32 = 0x324; // HR5..HR7 — split-bank landmine

// CR field encodings (see RM0486 §28 — N657 layout is NOT the L5 layout).
const CR_INIT_BIT: u8 = 2;
const CR_DMAE_BIT: u8 = 3; // DMA enable
const CR_MODE_HMAC_BIT: u8 = 6;
// SHA-256 = ALGO[1:0] = 0b11 → bits 17+18 in the N657 CR layout.
const CR_ALGO_SHA256: u32 = 0b11 << 17;
// DATATYPE = byte-swap (CR bits 5:4 = 0b10). SHA-256's message schedule
// processes bytes as big-endian u32 words; with LE CPU writes to DIN this
// datatype tells the peripheral to swap bytes before hashing. Without it,
// w[i] gets reversed and the digest is wrong.
const CR_DATATYPE_BYTE: u32 = 0b10 << 4;

const STR_DCAL_BIT: u8 = 8;
const SR_DINIS_MASK: u32 = 1 << 0;
const SR_DCIS_MASK: u32 = 1 << 1;

#[derive(Clone, Copy, PartialEq)]
pub enum Algorithm {
    SHA256,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DataType {
    Width8,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: H_INIT,
            buf: [0; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buf_len > 0 && self.buf_len + data.len() >= 64 {
            let fill = 64 - self.buf_len;
            let mut i: usize = 0;
            while i < fill {
                self.buf[self.buf_len + i] = data[i];
                i += 1;
            }
            self.compress(&self.buf.clone());
            self.buf_len = 0;
            offset = fill;
        }

        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            let mut i: usize = 0;
            while i < 64 {
                block[i] = data[offset + i];
                i += 1;
            }
            self.compress(&block);
            offset += 64;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            let mut i: usize = 0;
            while i < remaining {
                self.buf[self.buf_len + i] = data[offset + i];
                i += 1;
            }
            self.buf_len += remaining;
        }
    }

    fn finalize(mut self, digest: &mut [u8]) {
        let bit_len = self.total_len * 8;

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            let mut i = self.buf_len;
            while i < 64 {
                self.buf[i] = 0;
                i += 1;
            }
            self.compress(&self.buf.clone());
            self.buf_len = 0;
        }

        let mut i = self.buf_len;
        while i < 56 {
            self.buf[i] = 0;
            i += 1;
        }

        let len_bytes = bit_len.to_be_bytes();
        let mut j: usize = 0;
        while j < 8 {
            self.buf[56 + j] = len_bytes[j];
            j += 1;
        }
        self.compress(&self.buf.clone());

        let mut i: usize = 0;
        while i < 8 {
            let bytes = self.state[i].to_be_bytes();
            digest[i * 4] = bytes[0];
            digest[i * 4 + 1] = bytes[1];
            digest[i * 4 + 2] = bytes[2];
            digest[i * 4 + 3] = bytes[3];
            i += 1;
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        let mut i: usize = 0;
        while i < 16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
            self.state[5],
            self.state[6],
            self.state[7],
        );

        let mut i: usize = 0;
        while i < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
            i += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// HASH driver. The plain `start`/`update`/`finish` no-op surface is kept
/// for API parity with the L552 `Hash<M>`; production callers route to
/// `Hash::sha256` (SW) for unkeyed digests and `Hash::hmac_sha256` (HW
/// peripheral) for keyed HMAC.
/// Generic over the MMIO backend so
/// host tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Hash::new()` call site unchanged
/// at the source level — the firmware build monomorphises to
/// `Hash<RealMmio>` and inlines the volatile accesses exactly as before.
/// The HW HMAC path used by the CJ2 chained-measurement boot flow keeps
/// its register-write order byte-for-byte.
pub struct Hash<M: MmioAccess = RealMmio> {
    mmio: M,
}

pub struct HashContext;

impl Hash<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(HASH_BASE_ADDR),
        }
    }
}

impl<M: MmioAccess> Hash<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Hash::new()` which monomorphises to
    /// `Hash<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    pub fn start(&mut self, _alg: Algorithm, _dt: DataType, _key: Option<&[u8]>) -> HashContext {
        HashContext
    }

    pub fn update(&mut self, _ctx: &mut HashContext, _data: &[u8]) {}

    pub fn finish(&mut self, _ctx: HashContext, _digest: &mut [u8]) {}

    /// Hardware HMAC-SHA256 using the N657 HASH peripheral at 0x5402_0400
    /// (Secure alias).
    /// CJ2 (chained-measurement) boot path uses this — preserve the
    /// register-write order verbatim. The HASH state machine is sensitive
    /// to the CR→DINIS→DIN→STR(NBLW)→STR(NBLW|DCAL)→DINIS sequence at
    /// each of the three stages (inner key, message, outer key); reordering
    /// silently corrupts the digest.
    /// DMA-fed hardware SHA-256 (firmware only). Feeds the message to HASH_DIN via
    /// HPDMA1 channel 0 (REQSEL 13 = HASH_IN, burst-4, Secure channel) instead of CPU
    /// word writes; with MDMAT=0 the peripheral auto-triggers the final digest when the
    /// DMA completes. Returns the HPDMA channel status word for diagnosis (TCF = clean;
    /// DTEF/ULEF/USEF = error). Self-enables the HPDMA1 clock. `data` must live in
    /// DMA-reachable memory (AXISRAM or the memory-mapped XSPI2 window).
    #[cfg(target_arch = "arm")]
    pub fn sha256_dma(&mut self, data: &[u8], output: &mut [u8]) -> u32 {
        const HASH_DIN_ADDR: u32 = HASH_BASE_ADDR + HASH_DIN_OFFSET;
        const HASH_IN_REQSEL: u8 = 13; // HPDMA1_REQUEST_HASH_IN (CMSIS)
        const CH: u8 = 0;

        crate::hpdma::enable_clock(); // self-sufficient: don't rely on boot-time bring-up

        // NBLW (valid bits in the last word) must be programmed BEFORE the DMA is
        // enabled (RM0486 §50.4.9). CR: SHA-256, byte-swap DATATYPE (same as the CPU
        // path — HW-verified the DMA-fed digest matches CPU with this), INIT, DMAE=1
        // (MDMAT=0 so the final digest auto-triggers when the DMA finishes).
        let nblw = (8 * (data.len() % 4)) as u32;
        self.mmio.write(
            HASH_CR_OFFSET,
            CR_ALGO_SHA256 | CR_DATATYPE_BYTE | (1 << CR_INIT_BIT) | (1 << CR_DMAE_BIT),
        );
        while self.mmio.read(HASH_SR_OFFSET) & SR_DINIS_MASK == 0 {}
        self.mmio.write(HASH_STR_OFFSET, nblw);

        // Clean the source out of D-cache so the DMA reads the CPU's latest bytes.
        crate::hpdma::dcache_clean_range(data.as_ptr() as usize, data.len());

        let dma = crate::hpdma::Hpdma1::new();
        dma.set_channel_secure(CH); // Secure channel — else RIFSC drops writes to HASH
        dma.reset_channel(CH);
        let byte_count = ((data.len() + 3) & !3) as u32; // whole words
        dma.configure_mem_to_periph(CH, data.as_ptr() as u32, HASH_DIN_ADDR, byte_count, HASH_IN_REQSEL);
        dma.enable_channel(CH);
        let dma_sr = dma.wait_complete(CH, 4_000_000);
        dma.clear_flags(CH);

        // MDMAT=0 → DCAL auto-set at end of DMA → final digest. Wait DCIS then read.
        let mut budget = 2_000_000u32;
        while self.mmio.read(HASH_SR_OFFSET) & SR_DCIS_MASK == 0 && budget > 0 {
            budget -= 1;
        }
        self.read_digest(output);
        dma_sr
    }

    pub fn hmac_sha256(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) {
        // Step 1: configure CR — algo + HMAC mode + byte-swap + INIT
        self.mmio.write(
            HASH_CR_OFFSET,
            CR_ALGO_SHA256 | (1 << CR_MODE_HMAC_BIT) | CR_DATATYPE_BYTE | (1 << CR_INIT_BIT),
        );

        // Step 2: wait for DINIS (peripheral ready to accept inner key)
        while self.mmio.read(HASH_SR_OFFSET) & SR_DINIS_MASK == 0 {}

        // Step 3: feed inner key — RAW bytes only. The HASH peripheral in
        // HMAC mode handles ipad/opad XOR and key zero-padding to 64 bytes
        // internally. Feeding a 32-byte key + 32 zero bytes would make the
        // peripheral treat the input as a 64-byte key (BIT_NUMBER_OF_VALID
        // _BITS = 512), producing the wrong HMAC. Just push key words, set
        // NBLW for partial tail, then DCAL.
        self.feed_data(key);
        let key_nblw = (8 * (key.len() % 4)) as u32;
        self.mmio.write(HASH_STR_OFFSET, key_nblw);
        // trigger inner-key digest
        self.mmio
            .write(HASH_STR_OFFSET, key_nblw | (1u32 << STR_DCAL_BIT));
        // Step 4: wait for DINIS (inner-key processed, ready for message data)
        while self.mmio.read(HASH_SR_OFFSET) & SR_DINIS_MASK == 0 {}

        // Step 5: feed message data
        self.feed_data(data);
        let nblw = (8 * (data.len() % 4)) as u32;
        self.mmio.write(HASH_STR_OFFSET, nblw);
        // trigger data digest
        self.mmio
            .write(HASH_STR_OFFSET, nblw | (1u32 << STR_DCAL_BIT));
        // Step 6: wait for DINIS (inner hash done, ready for outer key)
        while self.mmio.read(HASH_SR_OFFSET) & SR_DINIS_MASK == 0 {}

        // Step 7: feed outer key — same raw bytes; peripheral re-uses for
        // the opad pass.
        self.feed_data(key);
        self.mmio.write(HASH_STR_OFFSET, key_nblw);
        // trigger outer-key+hash final digest
        self.mmio
            .write(HASH_STR_OFFSET, key_nblw | (1u32 << STR_DCAL_BIT));
        // Step 8: wait for DCIS (bit 1) — full HMAC digest complete
        while self.mmio.read(HASH_SR_OFFSET) & SR_DCIS_MASK == 0 {}

        // Step 9: read HR0..HR4 (contiguous bank, stride 4). HR registers
        // are big-endian — use to_be_bytes() to match standard digest byte
        // order.
        let mut i: u32 = 0;
        while i < 5 {
            let w = self.mmio.read(HASH_HR_OFFSET + i * 4);
            let bytes = w.to_be_bytes();
            let idx = (i as usize) * 4;
            output[idx..idx + 4].copy_from_slice(&bytes);
            i += 1;
        }
        // Step 10: read HR5..HR7 from the split bank (0x324..0x32C). NOT
        // contiguous with HR0..HR4 — same landmine as L552. Misreading
        // these yields correct first 160 bits and garbage for the last 96.
        let mut j: u32 = 0;
        while j < 3 {
            let w = self.mmio.read(HASH_HR5_OFFSET + j * 4);
            let bytes = w.to_be_bytes();
            let idx = (5 + j as usize) * 4;
            output[idx..idx + 4].copy_from_slice(&bytes);
            j += 1;
        }
    }

    /// Feed `data` bytes to the HASH DIN register as 32-bit LE words. Full
    /// 4-byte words are written directly; a trailing partial word (1-3
    /// bytes) is zero-extended to u32 — the caller MUST set STR.NBLW to
    /// indicate the number of valid bits in that last word.
    fn feed_data(&self, data: &[u8]) {
        let full_words = data.len() / 4;
        let mut i: usize = 0;
        while i < full_words {
            let w = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
            self.mmio.write(HASH_DIN_OFFSET, w);
            i += 1;
        }
        let tail = data.len() % 4;
        if tail > 0 {
            let mut w: u32 = 0;
            let base = full_words * 4;
            let mut k: usize = 0;
            while k < tail {
                w |= (data[base + k] as u32) << (k * 8);
                k += 1;
            }
            self.mmio.write(HASH_DIN_OFFSET, w);
        }
    }

    /// Hardware SHA-256 using the N657 HASH peripheral. Same register sequence as
    /// `hmac_sha256` minus the key stages (MODE = 0, plain hash): CR(ALGO | byte-swap
    /// | INIT) → wait DINIS → feed message → STR(NBLW) → STR(NBLW | DCAL) → wait
    /// digest → read HR0..HR7. Padding is done by the peripheral. Completion is
    /// interrupt-driven on the firmware target (`HASH_IRQHandler` posts the flag; its
    /// priority is raised above SVC so it preempts the SVC#2 checkpoint handler where
    /// the hot-path digests run) with a DCIS poll fail-safe; host tests poll DCIS.
    pub fn sha256(&mut self, data: &[u8], output: &mut [u8]) {
        // CR: SHA-256, hash mode (MODE=0), byte-swap, INIT.
        self.mmio.write(
            HASH_CR_OFFSET,
            CR_ALGO_SHA256 | CR_DATATYPE_BYTE | (1 << CR_INIT_BIT),
        );
        // Wait until the input buffer is ready to accept data.
        while self.mmio.read(HASH_SR_OFFSET) & SR_DINIS_MASK == 0 {}
        // Feed the message, set the valid-bits of the last word.
        self.feed_data(data);
        let nblw = (8 * (data.len() % 4)) as u32;
        self.mmio.write(HASH_STR_OFFSET, nblw);
        // Arm the DCIS interrupt just before triggering the final digest (DCAL) —
        // padding + length append are automatic.
        #[cfg(target_arch = "arm")]
        crate::crypto_wait::hash_arm();
        self.mmio
            .write(HASH_STR_OFFSET, nblw | (1u32 << STR_DCAL_BIT));
        self.wait_digest_done();
        self.read_digest(output);
    }

    /// Wait for the digest. Firmware: the HASH IRQ posts completion (DCIS-poll
    /// fail-safe inside `block_until_hash_done` so it can never hang). Host tests:
    /// poll DCIS on the mock (preloaded), keeping `sha256` host-testable.
    fn wait_digest_done(&self) {
        #[cfg(target_arch = "arm")]
        crate::crypto_wait::block_until_hash_done();
        #[cfg(not(target_arch = "arm"))]
        while self.mmio.read(HASH_SR_OFFSET) & SR_DCIS_MASK == 0 {}
    }

    /// Read the 256-bit digest into `output`: HR0..HR4 from the contiguous bank
    /// (0x0C) and HR5..HR7 from the split bank (0x324 — the same landmine as L552).
    /// HR registers are big-endian.
    fn read_digest(&self, output: &mut [u8]) {
        let mut i: u32 = 0;
        while i < 5 {
            let w = self.mmio.read(HASH_HR_OFFSET + i * 4);
            let idx = (i as usize) * 4;
            output[idx..idx + 4].copy_from_slice(&w.to_be_bytes());
            i += 1;
        }
        let mut j: u32 = 0;
        while j < 3 {
            let w = self.mmio.read(HASH_HR5_OFFSET + j * 4);
            let idx = (5 + j as usize) * 4;
            output[idx..idx + 4].copy_from_slice(&w.to_be_bytes());
            j += 1;
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// umbra-hal::Hash adapter.
// Wraps the file-local `Sha256` SW implementation, matching what the
// existing `Hash::sha256()` one-shot method uses. The N657 HW HASH
// peripheral at 0x5402_0400 IS reachable in FSBL mode (the `hmac_sha256`
// path above already drives it for HMAC-SHA256); migrating this adapter
// to the HW path is a perf-only follow-up — kernel call sites don't
// need to change once that lands.
// ────────────────────────────────────────────────────────────────────────────

/// SHA-256 engine implementing `umbra_hal::Hash`. Backed by the
/// file-local SW `Sha256`; can be switched to HW HASH (peripheral at
/// 0x5402_0400) as a perf upgrade without touching kernel callers.
/// Generic over the same `MmioAccess`
/// backend as the wrapped `Hash<M>` for cross-platform parity with the
/// L552 `Sha256Engine<M>`. The N657 implementation is currently pure SW
/// so the backend parameter is held in a `PhantomData` — when the HW
/// SHA-256 perf upgrade lands it can move into `inner` without touching
/// any call site.
pub struct Sha256Engine<M: MmioAccess = RealMmio> {
    inner: Option<Sha256>,
    _mmio: core::marker::PhantomData<M>,
}

impl Default for Sha256Engine<RealMmio> {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Engine<RealMmio> {
    pub fn new() -> Self {
        Self {
            inner: None,
            _mmio: core::marker::PhantomData,
        }
    }
}

impl<M: MmioAccess> Sha256Engine<M> {
    /// Adopt an externally-constructed `Hash` driver. Used by callers that
    /// also need direct access to the HMAC path (the HW HMAC-SHA256
    /// peripheral driver), since the trait surface only models non-keyed
    /// SHA-256.
    pub fn from_hash(_hw: Hash<M>) -> Self {
        // N657's `Hash` does no SW-side state for the unkeyed path (the
        // HW-HMAC path is method-only); we keep the same constructor
        // surface as the L552 adapter so the platform-specific
        // `UmbraCryptoEngine::new` code looks identical across platforms.
        Self {
            inner: None,
            _mmio: core::marker::PhantomData,
        }
    }
}

#[derive(Debug)]
pub enum Sha256Error {
    /// `update` / `finalize` called before `init`.
    NotInitialized,
}

impl<M: MmioAccess> umbra_hal::Hash for Sha256Engine<M> {
    type Error = Sha256Error;

    fn init(&mut self) -> Result<(), Self::Error> {
        self.inner = Some(Sha256::new());
        Ok(())
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let h = self.inner.as_mut().ok_or(Sha256Error::NotInitialized)?;
        h.update(input);
        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8; 32]) -> Result<(), Self::Error> {
        // `Sha256::finalize` consumes self; the adapter `.take()`s the
        // inner state so a subsequent `update` correctly fails until
        // `init` is called again (matches the trait's documented
        // contract).
        let h = self.inner.take().ok_or(Sha256Error::NotInitialized)?;
        h.finalize(output);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
