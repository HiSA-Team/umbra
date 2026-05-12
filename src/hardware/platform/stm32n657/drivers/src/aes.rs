//! AES engine for STM32N657.
//!
//! Two implementations are provided: `AesEmulated`, a pure-software AES-128
//! used in the current build, and the CRYP1 hardware driver under `cryp.rs`
//! (skeleton — 11 cycles per 16-byte block once wired up).
//!
//! NOTE: All loops use `while` instead of `for` ranges because Rust nightly
//! UB checks in `core::iter::range` panic on ARMv8-M.

/// Common interface for AES engines.
pub trait AesEngine {
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>);
    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);
    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);
}

/// Software AES-128 implementation.
pub struct AesEmulated {
    key: [u8; 16],
    sbox: [u8; 256],
    rsbox: [u8; 256],
    expanded_key: [u32; 44],
}

impl AesEmulated {
    pub fn new() -> Self {
        let sbox = Self::generate_sbox();
        let rsbox = Self::generate_rsbox(&sbox);
        Self { key: [0; 16], sbox, rsbox, expanded_key: [0; 44] }
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

    fn sub_bytes(&self, s: &mut [u8; 16]) {
        let mut i: usize = 0;
        while i < 16 { s[i] = self.sbox[s[i] as usize]; i += 1; }
    }
    fn inv_sub_bytes(&self, s: &mut [u8; 16]) {
        let mut i: usize = 0;
        while i < 16 { s[i] = self.rsbox[s[i] as usize]; i += 1; }
    }

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
        let mut s = *input;
        self.add_round_key(&mut s, &self.expanded_key[0..4]);
        let mut r: usize = 1;
        while r < 10 {
            self.sub_bytes(&mut s); Self::shift_rows(&mut s); Self::mix_columns(&mut s);
            self.add_round_key(&mut s, &self.expanded_key[r*4..(r+1)*4]);
            r += 1;
        }
        self.sub_bytes(&mut s); Self::shift_rows(&mut s);
        self.add_round_key(&mut s, &self.expanded_key[40..44]);
        *output = s;
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
