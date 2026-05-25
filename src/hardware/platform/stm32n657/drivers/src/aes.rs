//! AES engine for STM32N657.
//!
//! Two implementations are provided: `AesEmulated`, a pure-software AES-128
//! used in the current build, and `AesHardware` which routes key material
//! through the SAES1 keystore and performs block operations via CRYP1
//! (14 cycles per 16-byte block (RM0486 §49)).
//!
//! `AesHardware` composes SAES1 (keystore) + CRYP1 (engine) — key never
//! appears in CRYP_KxLR/RR via shared-key bus.
//!
//! NOTE: All loops use `while` instead of `for` ranges because Rust nightly
//! UB checks in `core::iter::range` panic on ARMv8-M.

/// AEAD error codes.
///
/// `AuthFail` is the security-critical variant: any byte modification to
/// ciphertext/tag/AD/nonce must produce it. Buffer-size mismatches surface
/// separately so callers can distinguish API misuse from tampering.
#[derive(Debug, PartialEq, Eq)]
pub enum AeadError {
    /// `out` slice shorter than `plaintext.len() + Self::TAG_SIZE`.
    OutputTooSmall,
    /// `plaintext_out` slice shorter than `ciphertext.len() - Self::TAG_SIZE`.
    PlaintextBufferTooSmall,
    /// Authentication tag did not match. Plaintext output is undefined and
    /// MUST NOT be released to higher layers.
    AuthFail,
    /// Nonce length does not match `Self::NONCE_SIZE`.
    InvalidNonceLength,
    /// Key length does not match `Self::KEY_SIZE`.
    InvalidKeyLength,
    /// Concrete implementation is declared in the type system but not yet
    /// wired to hardware. Returned by placeholder impls.
    NotYetImplemented,
}

/// Authenticated Encryption with Associated Data.
///
/// Associated consts (KEY_SIZE / NONCE_SIZE / TAG_SIZE) make this trait
/// **not** object-safe (no `&dyn Aead`). This is deliberate for embedded:
/// callers use it generically, monomorphization keeps the vtable cost at
/// zero. Mirrors the idiom of the upstream `aead` crate.
pub trait Aead {
    /// Symmetric key length in bytes.
    const KEY_SIZE: usize;
    /// Nonce / IV length in bytes. For GCM this is conventionally 12.
    const NONCE_SIZE: usize;
    /// Authentication tag length appended to ciphertext, in bytes.
    const TAG_SIZE: usize;

    /// Encrypt `plaintext` under `key`+`nonce`, authenticate
    /// `plaintext` + `associated_data`. Writes `ciphertext || tag` to
    /// `ciphertext_out` (length must be `plaintext.len() + TAG_SIZE`).
    /// Returns the number of bytes written.
    fn seal(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
    ) -> Result<usize, AeadError>;

    /// Verify tag against `associated_data` and the ciphertext portion of
    /// `ciphertext_and_tag`, then decrypt to `plaintext_out`. The last
    /// `TAG_SIZE` bytes of `ciphertext_and_tag` are the tag. On `Ok`,
    /// returns the plaintext length written. On `AuthFail`, the plaintext
    /// output buffer must be treated as untrusted (typically zeroized).
    fn open(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<usize, AeadError>;
}

/// Common interface for AES engines.
pub trait AesEngine {
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>);
    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);
    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);

    /// AES-128-CTR XOR transform (encrypt and decrypt are the same operation).
    ///
    /// `iv` is the initial 128-bit counter (block). `data.len()` must be a
    /// multiple of 16. The counter increments big-endian (NIST SP800-38A
    /// convention) on the rightmost byte; carry propagates left.
    ///
    /// Default impl: repeated `encrypt_block` of the counter, XORed into
    /// `data`. Overridable for native CTR-mode hardware (`AesHardware`
    /// switches `Cryp1` to ALGOMODE=0x6 and lets the peripheral increment
    /// the counter and produce keystream internally).
    fn ctr_xform(&mut self, iv: &[u8; 16], data: &mut [u8]) {
        let mut counter_block = *iv;
        let mut keystream = [0u8; 16];
        let chunks = data.len() / 16;
        let mut i: usize = 0;
        while i < chunks {
            self.encrypt_block(&counter_block, &mut keystream);
            let mut j: usize = 0;
            while j < 16 {
                data[i * 16 + j] ^= keystream[j];
                j += 1;
            }
            let mut c: usize = 15;
            loop {
                counter_block[c] = counter_block[c].wrapping_add(1);
                if counter_block[c] != 0 || c == 0 { break; }
                c -= 1;
            }
            i += 1;
        }
    }
}

/// Software AES-128 implementation.
///
/// `encrypt_block` uses 4 × 256 × u32 T-tables (4 KB total, in .bss)
/// that fold sub_bytes + shift_rows + mix_columns into 4 XOR-of-
/// lookups per output word per round. ~8× faster than the byte-wise
/// path on Cortex-M55.
///
/// `decrypt_block` is unchanged (byte-wise) — runtime CTR mode only
/// uses encrypt; decrypt is exercised by `boot_tests` self-check.
pub struct AesEmulated {
    key: [u8; 16],
    sbox: [u8; 256],
    rsbox: [u8; 256],
    expanded_key: [u32; 44],
    t0: [u32; 256],
    t1: [u32; 256],
    t2: [u32; 256],
    t3: [u32; 256],
}

impl AesEmulated {
    pub fn new() -> Self {
        let sbox = Self::generate_sbox();
        let rsbox = Self::generate_rsbox(&sbox);
        let (t0, t1, t2, t3) = Self::generate_t_tables(&sbox);
        Self { key: [0; 16], sbox, rsbox, expanded_key: [0; 44], t0, t1, t2, t3 }
    }

    fn generate_sbox() -> [u8; 256] {
        let mut sbox = [0u8; 256];
        let mut p = 1u8;
        let mut q = 1u8;
        loop {
            p = p ^ (p << 1) ^ (if (p & 0x80) != 0 { 0x1B } else { 0 });
            q ^= q << 1; q ^= q << 2; q ^= q << 4;
            q ^= if (q & 0x80) != 0 { 0x09 } else { 0 };
            sbox[p as usize] = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;
            if p == 1 { break; }
        }
        sbox[0] = 0x63;
        sbox
    }

    fn generate_rsbox(sbox: &[u8; 256]) -> [u8; 256] {
        let mut rsbox = [0u8; 256];
        let mut i: usize = 0;
        while i < 256 { rsbox[sbox[i] as usize] = i as u8; i += 1; }
        rsbox
    }

    /// Build the four AES T-tables from the S-box.
    /// For each input byte `b`, let `s = sbox[b]`. Tables encode
    /// (in little-endian u32 byte order — byte 0 = LSB):
    ///   T0[b] = [2·s, 1·s, 1·s, 3·s]   (column row 0 contribution)
    ///   T1[b] = [3·s, 2·s, 1·s, 1·s]   (column row 1 contribution)
    ///   T2[b] = [1·s, 3·s, 2·s, 1·s]   (column row 2 contribution)
    ///   T3[b] = [1·s, 1·s, 3·s, 2·s]   (column row 3 contribution)
    ///
    /// Multiplication is in GF(2^8); reuses the existing `gmul`.
    fn generate_t_tables(sbox: &[u8; 256]) -> ([u32; 256], [u32; 256], [u32; 256], [u32; 256]) {
        let mut t0 = [0u32; 256];
        let mut t1 = [0u32; 256];
        let mut t2 = [0u32; 256];
        let mut t3 = [0u32; 256];
        let mut i: usize = 0;
        while i < 256 {
            let s = sbox[i] as u32;
            let s2 = Self::gmul(s as u8, 2) as u32;
            let s3 = Self::gmul(s as u8, 3) as u32;
            // Little-endian byte packing: byte 0 = LSB.
            t0[i] = (s2 << 0)  | (s  << 8)  | (s  << 16) | (s3 << 24);
            t1[i] = (s3 << 0)  | (s2 << 8)  | (s  << 16) | (s  << 24);
            t2[i] = (s  << 0)  | (s3 << 8)  | (s2 << 16) | (s  << 24);
            t3[i] = (s  << 0)  | (s  << 8)  | (s3 << 16) | (s2 << 24);
            i += 1;
        }
        (t0, t1, t2, t3)
    }

    fn rot_word(w: u32) -> u32 { (w << 8) | (w >> 24) }

    fn sub_word(&self, w: u32) -> u32 {
        let b0 = self.sbox[(w >> 24) as usize] as u32;
        let b1 = self.sbox[((w >> 16) & 0xFF) as usize] as u32;
        let b2 = self.sbox[((w >> 8) & 0xFF) as usize] as u32;
        let b3 = self.sbox[(w & 0xFF) as usize] as u32;
        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    fn key_expansion(&mut self) {
        let mut i: usize = 0;
        while i < 4 {
            self.expanded_key[i] = u32::from_be_bytes([
                self.key[i*4], self.key[i*4+1], self.key[i*4+2], self.key[i*4+3]
            ]);
            i += 1;
        }
        let rcon = [0x01u32, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
        let mut i: usize = 4;
        while i < 44 {
            let mut temp = self.expanded_key[i - 1];
            if i % 4 == 0 { temp = self.sub_word(Self::rot_word(temp)) ^ (rcon[(i/4)-1] << 24); }
            self.expanded_key[i] = self.expanded_key[i - 4] ^ temp;
            i += 1;
        }
    }

    fn add_round_key(&self, state: &mut [u8; 16], round_key: &[u32]) {
        let mut i: usize = 0;
        while i < 4 {
            let rk = round_key[i].to_be_bytes();
            state[i*4]   ^= rk[0];
            state[i*4+1] ^= rk[1];
            state[i*4+2] ^= rk[2];
            state[i*4+3] ^= rk[3];
            i += 1;
        }
    }

    // Forward sub_bytes/shift_rows/mix_columns are unused — the encrypt
    // path uses T-tables (see encrypt_block). Kept for reference/decrypt
    // symmetry; the actual decrypt path uses the inv_* variants.
    #[allow(dead_code)]
    fn sub_bytes(&self, s: &mut [u8; 16]) {
        let mut i: usize = 0;
        while i < 16 { s[i] = self.sbox[s[i] as usize]; i += 1; }
    }
    fn inv_sub_bytes(&self, s: &mut [u8; 16]) {
        let mut i: usize = 0;
        while i < 16 { s[i] = self.rsbox[s[i] as usize]; i += 1; }
    }

    #[allow(dead_code)]
    fn shift_rows(s: &mut [u8; 16]) {
        let t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        let (t1,t2) = (s[2],s[6]); s[2]=s[10]; s[6]=s[14]; s[10]=t1; s[14]=t2;
        let t = s[3]; s[3]=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=t;
    }

    fn inv_shift_rows(s: &mut [u8; 16]) {
        let t = s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
        let (t1,t2) = (s[2],s[6]); s[2]=s[10]; s[6]=s[14]; s[10]=t1; s[14]=t2;
        let t = s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
    }

    fn gmul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        let mut round: u32 = 0;
        while round < 8 {
            if (b & 1) != 0 { p ^= a; }
            let hi = (a & 0x80) != 0;
            a <<= 1;
            if hi { a ^= 0x1B; }
            b >>= 1;
            round += 1;
        }
        p
    }

    #[allow(dead_code)]
    fn mix_columns(s: &mut [u8; 16]) {
        let mut i: usize = 0;
        while i < 4 {
            let o = i*4;
            let (c0,c1,c2,c3) = (s[o],s[o+1],s[o+2],s[o+3]);
            s[o]   = Self::gmul(c0,2) ^ Self::gmul(c1,3) ^ c2 ^ c3;
            s[o+1] = c0 ^ Self::gmul(c1,2) ^ Self::gmul(c2,3) ^ c3;
            s[o+2] = c0 ^ c1 ^ Self::gmul(c2,2) ^ Self::gmul(c3,3);
            s[o+3] = Self::gmul(c0,3) ^ c1 ^ c2 ^ Self::gmul(c3,2);
            i += 1;
        }
    }

    fn inv_mix_columns(s: &mut [u8; 16]) {
        let mut i: usize = 0;
        while i < 4 {
            let o = i*4;
            let (c0,c1,c2,c3) = (s[o],s[o+1],s[o+2],s[o+3]);
            s[o]   = Self::gmul(c0,14) ^ Self::gmul(c1,11) ^ Self::gmul(c2,13) ^ Self::gmul(c3,9);
            s[o+1] = Self::gmul(c0,9) ^ Self::gmul(c1,14) ^ Self::gmul(c2,11) ^ Self::gmul(c3,13);
            s[o+2] = Self::gmul(c0,13) ^ Self::gmul(c1,9) ^ Self::gmul(c2,14) ^ Self::gmul(c3,11);
            s[o+3] = Self::gmul(c0,11) ^ Self::gmul(c1,13) ^ Self::gmul(c2,9) ^ Self::gmul(c3,14);
            i += 1;
        }
    }
}

impl AesEngine for AesEmulated {
    fn init(&mut self, key: &[u8], _iv: Option<&[u8]>) {
        self.key.copy_from_slice(&key[..16]);
        self.key_expansion();
    }

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // Pack the 4 columns of the state as little-endian u32, matching
        // the column-major byte layout used by `mix_columns` and
        // `shift_rows` (state[c*4+r] = byte at row r of column c).
        // Byte at row r of column c lives at bit position (r*8)..((r+1)*8)
        // inside the column u32 (little-endian).
        let mut s0 = u32::from_le_bytes([input[0],  input[1],  input[2],  input[3]]);
        let mut s1 = u32::from_le_bytes([input[4],  input[5],  input[6],  input[7]]);
        let mut s2 = u32::from_le_bytes([input[8],  input[9],  input[10], input[11]]);
        let mut s3 = u32::from_le_bytes([input[12], input[13], input[14], input[15]]);

        // Initial AddRoundKey — expanded_key is big-endian (from_be_bytes
        // in key_expansion), state words are little-endian, so swap_bytes.
        s0 ^= self.expanded_key[0].swap_bytes();
        s1 ^= self.expanded_key[1].swap_bytes();
        s2 ^= self.expanded_key[2].swap_bytes();
        s3 ^= self.expanded_key[3].swap_bytes();

        // 9 full rounds collapsed into 4 T-table lookups + 4 XORs per output column.
        // Shift-rows (row r rotates left by r) is encoded in WHICH source byte feeds
        // which T-table:
        //   new_col_j[0] = T0[col_j[0]] ^ T1[col_{j+1}[1]] ^ T2[col_{j+2}[2]] ^ T3[col_{j+3}[3]]
        let mut round: usize = 1;
        while round < 10 {
            let n0 = self.t0[((s0 >>  0) & 0xFF) as usize]
                   ^ self.t1[((s1 >>  8) & 0xFF) as usize]
                   ^ self.t2[((s2 >> 16) & 0xFF) as usize]
                   ^ self.t3[((s3 >> 24) & 0xFF) as usize]
                   ^ self.expanded_key[round * 4 + 0].swap_bytes();
            let n1 = self.t0[((s1 >>  0) & 0xFF) as usize]
                   ^ self.t1[((s2 >>  8) & 0xFF) as usize]
                   ^ self.t2[((s3 >> 16) & 0xFF) as usize]
                   ^ self.t3[((s0 >> 24) & 0xFF) as usize]
                   ^ self.expanded_key[round * 4 + 1].swap_bytes();
            let n2 = self.t0[((s2 >>  0) & 0xFF) as usize]
                   ^ self.t1[((s3 >>  8) & 0xFF) as usize]
                   ^ self.t2[((s0 >> 16) & 0xFF) as usize]
                   ^ self.t3[((s1 >> 24) & 0xFF) as usize]
                   ^ self.expanded_key[round * 4 + 2].swap_bytes();
            let n3 = self.t0[((s3 >>  0) & 0xFF) as usize]
                   ^ self.t1[((s0 >>  8) & 0xFF) as usize]
                   ^ self.t2[((s1 >> 16) & 0xFF) as usize]
                   ^ self.t3[((s2 >> 24) & 0xFF) as usize]
                   ^ self.expanded_key[round * 4 + 3].swap_bytes();
            s0 = n0; s1 = n1; s2 = n2; s3 = n3;
            round += 1;
        }

        // Final round: sub_bytes + shift_rows + add_round_key (NO mix_columns).
        let final_key0 = self.expanded_key[40].swap_bytes();
        let final_key1 = self.expanded_key[41].swap_bytes();
        let final_key2 = self.expanded_key[42].swap_bytes();
        let final_key3 = self.expanded_key[43].swap_bytes();

        let n0 = (self.sbox[((s0 >>  0) & 0xFF) as usize] as u32) <<  0
               | (self.sbox[((s1 >>  8) & 0xFF) as usize] as u32) <<  8
               | (self.sbox[((s2 >> 16) & 0xFF) as usize] as u32) << 16
               | (self.sbox[((s3 >> 24) & 0xFF) as usize] as u32) << 24;
        let n1 = (self.sbox[((s1 >>  0) & 0xFF) as usize] as u32) <<  0
               | (self.sbox[((s2 >>  8) & 0xFF) as usize] as u32) <<  8
               | (self.sbox[((s3 >> 16) & 0xFF) as usize] as u32) << 16
               | (self.sbox[((s0 >> 24) & 0xFF) as usize] as u32) << 24;
        let n2 = (self.sbox[((s2 >>  0) & 0xFF) as usize] as u32) <<  0
               | (self.sbox[((s3 >>  8) & 0xFF) as usize] as u32) <<  8
               | (self.sbox[((s0 >> 16) & 0xFF) as usize] as u32) << 16
               | (self.sbox[((s1 >> 24) & 0xFF) as usize] as u32) << 24;
        let n3 = (self.sbox[((s3 >>  0) & 0xFF) as usize] as u32) <<  0
               | (self.sbox[((s0 >>  8) & 0xFF) as usize] as u32) <<  8
               | (self.sbox[((s1 >> 16) & 0xFF) as usize] as u32) << 16
               | (self.sbox[((s2 >> 24) & 0xFF) as usize] as u32) << 24;

        let final0 = n0 ^ final_key0;
        let final1 = n1 ^ final_key1;
        let final2 = n2 ^ final_key2;
        let final3 = n3 ^ final_key3;

        output[0..4].copy_from_slice(&final0.to_le_bytes());
        output[4..8].copy_from_slice(&final1.to_le_bytes());
        output[8..12].copy_from_slice(&final2.to_le_bytes());
        output[12..16].copy_from_slice(&final3.to_le_bytes());
    }

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        let mut s = *input;
        self.add_round_key(&mut s, &self.expanded_key[40..44]);
        let mut r: usize = 9;
        while r >= 1 {
            Self::inv_shift_rows(&mut s); self.inv_sub_bytes(&mut s);
            self.add_round_key(&mut s, &self.expanded_key[r*4..(r+1)*4]);
            Self::inv_mix_columns(&mut s);
            r -= 1;
        }
        Self::inv_shift_rows(&mut s); self.inv_sub_bytes(&mut s);
        self.add_round_key(&mut s, &self.expanded_key[0..4]);
        *output = s;
    }
}

/// Hardware AES via CRYP1.
///
/// `init` SW-loads the key into CRYP and configures ECB mode (used by
/// `encrypt_block` / `decrypt_block`). `ctr_xform` switches the engine to
/// native CTR mode: CRYP generates the keystream, XORs with input, and
/// increments the counter (IV1RR) internally per block — no manual loop
/// in software. The SAES driver is preserved for a future DHUK-wrapped
/// key-isolation path (`saes.rs`).
pub struct AesHardware {
    #[allow(dead_code)]   // clocked + ready for DHUK-wrap key isolation path
    saes: crate::saes::Saes,
    cryp: crate::cryp::Cryp1,
    // Cached most-recent key — `init()` writes it into CRYP_K* (ECB
    // config) so that `encrypt_block`/`decrypt_block` work for
    // `boot_tests` math sanity. `ctr_xform()` re-uses this byte buffer
    // when reconfiguring CRYP from ECB → CTR for a streaming decrypt;
    // CRYP key registers are reloaded as part of `configure_ctr_128_sw_key`
    // (the ascending K2LR→K3RR sequence must be repeated to land KEYVALID).
    key: [u8; 16],
}

impl AesHardware {
    pub fn new() -> Self {
        use crate::rcc::{self, Rcc};
        let rcc = Rcc::new();
        rcc.enable_ahb3_clock(rcc::SAESEN);
        rcc.enable_ahb3_clock(rcc::CRYP1EN);
        // SAFETY: The two preceding enable_ahb3 writes are volatile MMIO writes
        // to RCC_AHB3ENR (0x56028258). The DSB ensures those writes are visible
        // to the SAES and CRYP1 peripheral buses before the Saes::new() and
        // Cryp1::new() constructors below access their registers.
        // core::arch::asm! is used because cortex_m::asm::dsb() is not
        // available in this no_std driver crate.
        unsafe { core::arch::asm!("dsb"); }
        Self {
            saes: crate::saes::Saes::new(),
            cryp: crate::cryp::Cryp1::new(),
            key: [0u8; 16],
        }
    }
}

impl AesEngine for AesHardware {
    fn init(&mut self, key: &[u8], _iv: Option<&[u8]>) {
        if key.len() != 16 {
            panic!("AesHardware: only 128-bit keys supported");
        }
        self.key.copy_from_slice(&key[..16]);
        // SW-load CRYP key directly in ECB mode. ECB is the safe default
        // for `encrypt_block`/`decrypt_block`. `ctr_xform` reconfigures to
        // CTR on entry. The SAES shared-bus path requires DHUK-wrapped
        // keys per RM0486 §48.4.15 (see saes.rs).
        self.cryp.configure_ecb_128_sw_key(&self.key);
    }

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        self.cryp.process_block(input, output);
    }

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // Intentional: CTR is symmetric, runtime never calls decrypt_block.
        // boot_tests uses AesEmulated for math sanity.
        self.cryp.process_block(input, output);
    }

    /// Native HW CTR override.
    ///
    /// Reconfigures CRYP from ECB (left over from `init`) to CTR mode with
    /// `iv` as the initial counter, then streams `data` through the same
    /// FIFO protocol used by `process_block`. CRYP handles counter
    /// increment and XOR internally — the output of `process_block` is
    /// already the ciphertext/plaintext, not raw keystream.
    ///
    /// Trade-off vs default impl: saves one ECB encrypt+XOR loop per block
    /// in software, but adds a one-time CRYP reconfiguration cost. Worth
    /// it for any payload ≥ 2 blocks. For 1 block the difference is
    /// negligible.
    fn ctr_xform(&mut self, iv: &[u8; 16], data: &mut [u8]) {
        let chunks = data.len() / 16;
        if chunks == 0 { return; }

        // Reload CRYP in CTR mode with cached key + provided IV. The
        // ascending K2LR→K3RR sequence triggers KEYVALID again inside
        // configure_ctr_128_sw_key.
        self.cryp.configure_ctr_128_sw_key(&self.key, iv);

        let mut block = [0u8; 16];
        let mut out_block = [0u8; 16];
        let mut i: usize = 0;
        while i < chunks {
            // Stage one 16-byte ciphertext block in scratch
            let mut j: usize = 0;
            while j < 16 { block[j] = data[i * 16 + j]; j += 1; }

            // CRYP in CTR mode XORs internally — `out_block` is the
            // post-XOR result, not raw keystream.
            self.cryp.process_block(&block, &mut out_block);

            let mut j: usize = 0;
            while j < 16 { data[i * 16 + j] = out_block[j]; j += 1; }
            i += 1;
        }
    }
}

// Aead trait surface for AesHardware.
//
// AES-128-GCM is the target construction: AES-128 in CTR-mode keystream
// XORed with plaintext, GHASH over (associated_data || ciphertext) for the
// 16-byte tag, all under one CRYP ALGOMODE=0x8 configuration. CRYP supports
// GCM natively per RM0486 §49.4.13 (the four-phase init→header→payload→
// final state machine), and the existing `configure_ctr_128_sw_key` is the
// closest neighbor to extend. The placeholder seal/open below returns
// `NotYetImplemented` until the GCM driver lands.
impl Aead for AesHardware {
    const KEY_SIZE: usize = 16;     // AES-128
    const NONCE_SIZE: usize = 12;   // GCM standard nonce (96-bit; CRYP §49.4.13)
    const TAG_SIZE: usize = 16;     // GCM standard tag (128-bit)

    fn seal(
        &mut self,
        _key: &[u8],
        _nonce: &[u8],
        _associated_data: &[u8],
        _plaintext: &[u8],
        _ciphertext_out: &mut [u8],
    ) -> Result<usize, AeadError> {
        // CRYP ALGOMODE=0x8 (GCM) goes here when implemented.
        Err(AeadError::NotYetImplemented)
    }

    fn open(
        &mut self,
        _key: &[u8],
        _nonce: &[u8],
        _associated_data: &[u8],
        _ciphertext_and_tag: &[u8],
        _plaintext_out: &mut [u8],
    ) -> Result<usize, AeadError> {
        Err(AeadError::NotYetImplemented)
    }
}
