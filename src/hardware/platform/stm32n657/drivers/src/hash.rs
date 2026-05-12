//! HASH driver for STM32N657 — SOFTWARE SHA-256 implementation.
//!
//! The hardware HASH peripheral is available at 0x54020400 (Secure) but
//! requires AHB3ENR bit 1 (HASHEN) to be enabled. This module provides
//! a pure software SHA-256/HMAC-SHA256 as fallback.
//!
//! IMPORTANT: All loops use `while` instead of `for` ranges because
//! Rust nightly UB checks in core::iter::range panic on ARMv8-M.

#[derive(Clone, Copy, PartialEq)]
pub enum Algorithm { SHA256 }

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DataType { Width8 }

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self { state: H_INIT, buf: [0; 64], buf_len: 0, total_len: 0 }
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
            while i < 64 { self.buf[i] = 0; i += 1; }
            self.compress(&self.buf.clone());
            self.buf_len = 0;
        }

        let mut i = self.buf_len;
        while i < 56 { self.buf[i] = 0; i += 1; }

        let len_bytes = bit_len.to_be_bytes();
        let mut j: usize = 0;
        while j < 8 { self.buf[56 + j] = len_bytes[j]; j += 1; }
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
                block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]
            ]);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
            i += 1;
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (self.state[0], self.state[1], self.state[2], self.state[3],
             self.state[4], self.state[5], self.state[6], self.state[7]);

        let mut i: usize = 0;
        while i < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
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

/// Software HASH driver — API-compatible with the hardware Hash driver.
pub struct Hash;

pub struct HashContext;

impl Hash {
    pub fn new() -> Self { Hash }

    pub fn start(&mut self, _alg: Algorithm, _dt: DataType, _key: Option<&[u8]>) -> HashContext {
        HashContext
    }

    pub fn update(&mut self, _ctx: &mut HashContext, _data: &[u8]) {}

    pub fn finish(&mut self, _ctx: HashContext, _digest: &mut [u8]) {}

    /// Hardware HMAC-SHA256 using the N657 HASH peripheral at 0x5402_0400 (Secure alias).
    ///
    /// Register map (RM0486 §28 + verified empirically against the on-chip
    /// peripheral; the layout differs from L5's HASH in several places):
    ///   HASH_CR  = 0x5402_0400  SHA-256 algo = bits 17+18 (ALGO[1:0] = 0b11)
    ///   HASH_DIN = 0x5402_0404  data input (32-bit LE words)
    ///   HASH_STR = 0x5402_0408  bit 8 = DCAL, bits 4:0 = NBLW
    ///   HASH_SR  = 0x5402_0424  bit 0 = DINIS (ready), bit 1 = DCIS (digest done)
    ///   HASH_HR0..HR4 = 0x5402_040C..0x5402_041C  first 5 digest words (BE)
    ///   HASH_HR5..HR7 = 0x5402_0724..0x5402_072C  last 3 digest words (not contiguous with HR0-4)
    ///
    /// Keys are always 32 bytes (≤64) so LKEY (bit 16) is never needed.
    pub fn hmac_sha256(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) {
        let cr   = 0x5402_0400u32 as *mut u32;
        let din  = 0x5402_0404u32 as *mut u32;
        let str_ = 0x5402_0408u32 as *mut u32;
        let sr   = 0x5402_0424u32 as *const u32;
        let hr0  = 0x5402_040Cu32 as *const u32;
        let hr5  = 0x5402_0724u32 as *const u32;

        // SHA-256: bits 17+18 set (ALGO[1:0] = 0b11 in N657 CR layout)
        const ALGO_SHA256: u32 = 0b11 << 17;
        const MODE_HMAC:   u32 = 1 << 6;
        const INIT_BIT:    u32 = 1 << 2;
        const DCAL_BIT:    u32 = 1 << 8;
        // DATATYPE = byte-swap (CR bits 5:4 = 0b10). SHA-256's message
        // schedule processes bytes as big-endian u32 words; with LE CPU
        // writes to DIN this datatype tells the peripheral to swap bytes
        // before hashing. Without it, w[i] gets reversed and the digest
        // is wrong.
        const DATATYPE_BYTE: u32 = 0b10 << 4;

        unsafe {
            // Step 1: configure CR — algo + HMAC mode + byte-swap + INIT
            core::ptr::write_volatile(cr, ALGO_SHA256 | MODE_HMAC | DATATYPE_BYTE | INIT_BIT);

            // Step 2: wait for DINIS (peripheral ready to accept inner key)
            while core::ptr::read_volatile(sr) & 1 == 0 {}

            // Step 3: feed inner key — RAW bytes only. The HASH peripheral
            // in HMAC mode handles ipad/opad XOR and key zero-padding to
            // 64 bytes internally. Feeding a 32-byte key + 32 zero bytes
            // would make the peripheral treat the input as a 64-byte key
            // (BIT_NUMBER_OF_VALID_BITS = 512), producing the wrong HMAC.
            // Just push key words, set NBLW for partial tail, then DCAL.
            feed_data_n657(din, key);
            let key_nblw = (8 * (key.len() % 4)) as u32;
            core::ptr::write_volatile(str_, key_nblw);
            core::ptr::write_volatile(str_, key_nblw | DCAL_BIT); // trigger inner-key digest
            // Step 4: wait for DINIS (inner-key processed, ready for message data)
            while core::ptr::read_volatile(sr) & 1 == 0 {}

            // Step 5: feed message data
            feed_data_n657(din, data);
            let nblw = (8 * (data.len() % 4)) as u32;
            core::ptr::write_volatile(str_, nblw);
            core::ptr::write_volatile(str_, nblw | DCAL_BIT); // trigger data digest
            // Step 6: wait for DINIS (inner hash done, ready for outer key)
            while core::ptr::read_volatile(sr) & 1 == 0 {}

            // Step 7: feed outer key — same raw bytes; peripheral re-uses
            // for the opad pass.
            feed_data_n657(din, key);
            core::ptr::write_volatile(str_, key_nblw);
            core::ptr::write_volatile(str_, key_nblw | DCAL_BIT); // trigger outer-key+hash final digest
            // Step 8: wait for DCIS (bit 1) — full HMAC digest complete
            while core::ptr::read_volatile(sr) & 2 == 0 {}

            // Step 9: read HR0..HR4 (addresses 0x5402_040C..0x5402_041C, stride 4)
            // HR registers are big-endian — use to_be_bytes() to match standard digest byte order.
            let mut i: isize = 0;
            while i < 5 {
                let w = core::ptr::read_volatile(hr0.offset(i));
                let bytes = w.to_be_bytes();
                output[(i as usize) * 4..(i as usize) * 4 + 4].copy_from_slice(&bytes);
                i += 1;
            }
            // Step 10: read HR5..HR7 from 0x5402_0724..0x5402_072C (NOT contiguous with HR0-4)
            let mut j: isize = 0;
            while j < 3 {
                let w = core::ptr::read_volatile(hr5.offset(j));
                let bytes = w.to_be_bytes();
                let idx = (5 + j as usize) * 4;
                output[idx..idx + 4].copy_from_slice(&bytes);
                j += 1;
            }
        }
    }

    pub fn sha256(&mut self, data: &[u8], output: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize(output);
    }
}

/// Feed `data` bytes to the N657 HASH DIN register as 32-bit LE words.
/// Full 4-byte words are written directly; a trailing partial word (1-3 bytes)
/// is zero-extended to u32 — the caller must set STR.NBLW to indicate the
/// number of valid bits in that last word.
///
/// Safety: `din` must be a valid volatile write address (HASH_DIN = 0x5402_0404).
unsafe fn feed_data_n657(din: *mut u32, data: &[u8]) {
    let full_words = data.len() / 4;
    let mut i: usize = 0;
    while i < full_words {
        let w = u32::from_le_bytes([
            data[i * 4], data[i * 4 + 1], data[i * 4 + 2], data[i * 4 + 3],
        ]);
        core::ptr::write_volatile(din, w);
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
        core::ptr::write_volatile(din, w);
    }
}
