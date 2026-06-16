//! Software AES-128 with 4× 1 KB T-tables — the RISC-V counterpart of the L552
//! `AesEmulated` path (`drivers/src/aes/emulated.rs`). QEMU virt has no AES
//! peripheral, so the monitor decrypts enclave code in software, exactly like
//! L552 (which has no HW AES either).
//!
//! The core lives in this host-testable arch crate (rather than the riscv-only
//! monitor bin) so its FIPS-197 known-answer test runs in host CI; the monitor's
//! `aes.rs` re-exports [`Aes128`] and [`ctr_xcrypt`] from here.
//!
//! Only the **forward** cipher is implemented: enclave code is encrypted with
//! AES-128-CTR by `tools/protect_enclave.py --flat`, and CTR decryption reuses
//! the encrypt keystream (`ks = AES_encrypt(counter)`, `plain = cipher ^ ks`).
//! The counter
//! is incremented as a 128-bit big-endian integer to match OpenSSL's
//! `enc -aes-128-ctr` semantics (the signer's encryptor).
//!
//! The T-table trick folds SubBytes + ShiftRows + MixColumns of each round into
//! 4 table lookups + 4 XORs per output column. Tables are built once at
//! `Aes128::new` from the S-box — no large constant arrays in the image.

/// AES-128 forward cipher with precomputed T-tables.
pub struct Aes128 {
    sbox: [u8; 256],
    expanded_key: [u32; 44],
    t0: [u32; 256],
    t1: [u32; 256],
    t2: [u32; 256],
    t3: [u32; 256],
}

impl Aes128 {
    /// Build the S-box + T-tables and run the key schedule for `key`.
    pub fn new(key: &[u8; 16]) -> Self {
        let sbox = Self::generate_sbox();
        let (t0, t1, t2, t3) = Self::generate_t_tables(&sbox);
        let mut aes = Self {
            sbox,
            expanded_key: [0; 44],
            t0,
            t1,
            t2,
            t3,
        };
        aes.key_expansion(key);
        aes
    }

    fn generate_sbox() -> [u8; 256] {
        let mut sbox = [0u8; 256];
        let mut p = 1u8;
        let mut q = 1u8;
        loop {
            p = p ^ (p << 1) ^ (if (p & 0x80) != 0 { 0x1B } else { 0 });
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= if (q & 0x80) != 0 { 0x09 } else { 0 };
            let xformed = q
                ^ q.rotate_left(1)
                ^ q.rotate_left(2)
                ^ q.rotate_left(3)
                ^ q.rotate_left(4)
                ^ 0x63;
            sbox[p as usize] = xformed;
            if p == 1 {
                break;
            }
        }
        sbox[0] = 0x63;
        sbox
    }

    /// GF(2^8) multiply (the AES field, reduction polynomial 0x11B).
    fn gmul(a: u8, b: u8) -> u8 {
        let mut p = 0u8;
        let mut a = a;
        let mut b = b;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi = (a & 0x80) != 0;
            a <<= 1;
            if hi {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    /// Build the four T-tables from the S-box (little-endian byte packing,
    /// matching `emulated.rs`).
    fn generate_t_tables(sbox: &[u8; 256]) -> ([u32; 256], [u32; 256], [u32; 256], [u32; 256]) {
        let mut t0 = [0u32; 256];
        let mut t1 = [0u32; 256];
        let mut t2 = [0u32; 256];
        let mut t3 = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let s = sbox[i] as u32;
            let s2 = Self::gmul(sbox[i], 2) as u32;
            let s3 = Self::gmul(sbox[i], 3) as u32;
            t0[i] = s2 | (s << 8) | (s << 16) | (s3 << 24);
            t1[i] = s3 | (s2 << 8) | (s << 16) | (s << 24);
            t2[i] = s | (s3 << 8) | (s2 << 16) | (s << 24);
            t3[i] = s | (s << 8) | (s3 << 16) | (s2 << 24);
            i += 1;
        }
        (t0, t1, t2, t3)
    }

    fn rot_word(w: u32) -> u32 {
        w.rotate_left(8)
    }

    fn sub_word(&self, w: u32) -> u32 {
        let b0 = self.sbox[(w >> 24) as usize] as u32;
        let b1 = self.sbox[((w >> 16) & 0xFF) as usize] as u32;
        let b2 = self.sbox[((w >> 8) & 0xFF) as usize] as u32;
        let b3 = self.sbox[(w & 0xFF) as usize] as u32;
        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    fn key_expansion(&mut self, key: &[u8; 16]) {
        let mut i = 0;
        while i < 4 {
            self.expanded_key[i] = u32::from_be_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
            i += 1;
        }
        let rcon = [
            0x01u32, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        ];
        while i < 44 {
            let mut temp = self.expanded_key[i - 1];
            if i % 4 == 0 {
                temp = self.sub_word(Self::rot_word(temp)) ^ (rcon[(i / 4) - 1] << 24);
            }
            self.expanded_key[i] = self.expanded_key[i - 4] ^ temp;
            i += 1;
        }
    }

    /// Encrypt one 16-byte block (the T-table fast path). Identical algorithm to
    /// `AesEmulated::encrypt_block` on L552 (little-endian state columns,
    /// big-endian expanded key byte-swapped on use).
    pub fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        let mut s0 = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        let mut s1 = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
        let mut s2 = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
        let mut s3 = u32::from_le_bytes([input[12], input[13], input[14], input[15]]);

        s0 ^= self.expanded_key[0].swap_bytes();
        s1 ^= self.expanded_key[1].swap_bytes();
        s2 ^= self.expanded_key[2].swap_bytes();
        s3 ^= self.expanded_key[3].swap_bytes();

        let mut round = 1;
        while round < 10 {
            let n0 = self.t0[(s0 & 0xFF) as usize]
                ^ self.t1[((s1 >> 8) & 0xFF) as usize]
                ^ self.t2[((s2 >> 16) & 0xFF) as usize]
                ^ self.t3[((s3 >> 24) & 0xFF) as usize]
                ^ self.expanded_key[round * 4].swap_bytes();
            let n1 = self.t0[(s1 & 0xFF) as usize]
                ^ self.t1[((s2 >> 8) & 0xFF) as usize]
                ^ self.t2[((s3 >> 16) & 0xFF) as usize]
                ^ self.t3[((s0 >> 24) & 0xFF) as usize]
                ^ self.expanded_key[round * 4 + 1].swap_bytes();
            let n2 = self.t0[(s2 & 0xFF) as usize]
                ^ self.t1[((s3 >> 8) & 0xFF) as usize]
                ^ self.t2[((s0 >> 16) & 0xFF) as usize]
                ^ self.t3[((s1 >> 24) & 0xFF) as usize]
                ^ self.expanded_key[round * 4 + 2].swap_bytes();
            let n3 = self.t0[(s3 & 0xFF) as usize]
                ^ self.t1[((s0 >> 8) & 0xFF) as usize]
                ^ self.t2[((s1 >> 16) & 0xFF) as usize]
                ^ self.t3[((s2 >> 24) & 0xFF) as usize]
                ^ self.expanded_key[round * 4 + 3].swap_bytes();
            s0 = n0;
            s1 = n1;
            s2 = n2;
            s3 = n3;
            round += 1;
        }

        let fk0 = self.expanded_key[40].swap_bytes();
        let fk1 = self.expanded_key[41].swap_bytes();
        let fk2 = self.expanded_key[42].swap_bytes();
        let fk3 = self.expanded_key[43].swap_bytes();

        let n0 = (self.sbox[(s0 & 0xFF) as usize] as u32)
            | ((self.sbox[((s1 >> 8) & 0xFF) as usize] as u32) << 8)
            | ((self.sbox[((s2 >> 16) & 0xFF) as usize] as u32) << 16)
            | ((self.sbox[((s3 >> 24) & 0xFF) as usize] as u32) << 24);
        let n1 = (self.sbox[(s1 & 0xFF) as usize] as u32)
            | ((self.sbox[((s2 >> 8) & 0xFF) as usize] as u32) << 8)
            | ((self.sbox[((s3 >> 16) & 0xFF) as usize] as u32) << 16)
            | ((self.sbox[((s0 >> 24) & 0xFF) as usize] as u32) << 24);
        let n2 = (self.sbox[(s2 & 0xFF) as usize] as u32)
            | ((self.sbox[((s3 >> 8) & 0xFF) as usize] as u32) << 8)
            | ((self.sbox[((s0 >> 16) & 0xFF) as usize] as u32) << 16)
            | ((self.sbox[((s1 >> 24) & 0xFF) as usize] as u32) << 24);
        let n3 = (self.sbox[(s3 & 0xFF) as usize] as u32)
            | ((self.sbox[((s0 >> 8) & 0xFF) as usize] as u32) << 8)
            | ((self.sbox[((s1 >> 16) & 0xFF) as usize] as u32) << 16)
            | ((self.sbox[((s2 >> 24) & 0xFF) as usize] as u32) << 24);

        output[0..4].copy_from_slice(&(n0 ^ fk0).to_le_bytes());
        output[4..8].copy_from_slice(&(n1 ^ fk1).to_le_bytes());
        output[8..12].copy_from_slice(&(n2 ^ fk2).to_le_bytes());
        output[12..16].copy_from_slice(&(n3 ^ fk3).to_le_bytes());
    }
}

/// Increment a 16-byte counter block as a 128-bit big-endian integer (OpenSSL
/// `-aes-128-ctr` counter semantics).
fn inc_be(ctr: &mut [u8; 16]) {
    for i in (0..16).rev() {
        let (v, carry) = ctr[i].overflowing_add(1);
        ctr[i] = v;
        if !carry {
            break;
        }
    }
}

/// AES-128-CTR encrypt/decrypt in place (the two are identical). `iv` is the
/// initial 128-bit counter block. Matches `openssl enc -aes-128-ctr -iv <iv>`.
pub fn ctr_xcrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let aes = Aes128::new(key);
    let mut counter = *iv;
    let mut ks = [0u8; 16];
    let mut i = 0;
    while i < data.len() {
        aes.encrypt_block(&counter, &mut ks);
        let n = core::cmp::min(16, data.len() - i);
        for j in 0..n {
            data[i + j] ^= ks[j];
        }
        inc_be(&mut counter);
        i += 16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix B / C.1 known-answer test for AES-128 ECB
    /// (one block = one `encrypt_block`).
    #[test]
    fn fips197_kat() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expect = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let aes = Aes128::new(&key);
        let mut out = [0u8; 16];
        aes.encrypt_block(&pt, &mut out);
        assert_eq!(out, expect);
    }

    /// CTR round-trip: decrypt(encrypt(x)) == x, and CTR is its own inverse.
    #[test]
    fn ctr_roundtrip() {
        let key = [
            0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [0u8; 16];
        let original = *b"the quick brown fox jumps!!";
        let mut buf = original;
        ctr_xcrypt(&key, &iv, &mut buf);
        assert_ne!(buf, original); // actually encrypted
        ctr_xcrypt(&key, &iv, &mut buf);
        assert_eq!(buf, original); // round-trips
    }

    /// NIST SP 800-38A F.5.1 AES-128-CTR known-answer test (first block) — locks
    /// the CTR keystream + big-endian counter against the published vector, not
    /// just self-consistency.
    #[test]
    fn sp800_38a_ctr_kat() {
        let key = [
            0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let plaintext = [
            0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expect = [
            0x87u8, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
            0xb6, 0xce,
        ];
        let mut buf = plaintext;
        ctr_xcrypt(&key, &iv, &mut buf);
        assert_eq!(buf, expect);
    }
}
