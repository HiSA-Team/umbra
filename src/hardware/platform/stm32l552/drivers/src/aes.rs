// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
//
// STM32L5xxxx AES Driver
// This driver supports AES 128/256 hardware engine and emulated software implementation.

#[cfg(feature = "stm32l562")]
use peripheral_regs::*;
#[cfg(feature = "stm32l562")]
use crate::rcc::{self, Rcc};

#[cfg(feature = "stm32l562")]
const AES_BASE_ADDR: u32 = 0x520C0000; // Secure AES base address for STM32L562

// Registers
#[cfg(feature = "stm32l562")]
const AES_CR_BASE_OFFSET: u32 = 0x00;
#[cfg(feature = "stm32l562")]
const AES_SR_BASE_OFFSET: u32 = 0x04;
#[cfg(feature = "stm32l562")]
const AES_DINR_BASE_OFFSET: u32 = 0x08;
#[cfg(feature = "stm32l562")]
const AES_DOUTR_BASE_OFFSET: u32 = 0x0C;
#[cfg(feature = "stm32l562")]
const AES_KEYR0_BASE_OFFSET: u32 = 0x10;
#[cfg(feature = "stm32l562")]
const AES_KEYR1_BASE_OFFSET: u32 = 0x14;
#[cfg(feature = "stm32l562")]
const AES_KEYR2_BASE_OFFSET: u32 = 0x18;
#[cfg(feature = "stm32l562")]
const AES_KEYR3_BASE_OFFSET: u32 = 0x1C;
#[cfg(feature = "stm32l562")]
#[allow(dead_code)]
const AES_IVR0_BASE_OFFSET: u32 = 0x20;
#[cfg(feature = "stm32l562")]
#[allow(dead_code)]
const AES_IVR1_BASE_OFFSET: u32 = 0x24;
#[cfg(feature = "stm32l562")]
#[allow(dead_code)]
const AES_IVR2_BASE_OFFSET: u32 = 0x28;
#[cfg(feature = "stm32l562")]
#[allow(dead_code)]
const AES_IVR3_BASE_OFFSET: u32 = 0x2C;

/// Common interface for AES engines (Hardware and Emulated)
pub trait AesEngine {
    /// Initialize the engine with a key and optional IV.
    /// Only AES-128 is guaranteed to be supported by both implementations.
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>);
    
    /// Encrypt a single 128-bit block.
    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);
    
    /// Decrypt a single 128-bit block.
    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);
}

/// Hardware AES Driver for STM32L562
#[cfg(feature = "stm32l562")]
pub struct AesHardware {
    regs: *const u32,
    key: [u8; 16],
}

#[cfg(feature = "stm32l562")]
impl AesHardware {
    pub fn new() -> Self {
        let regs = AES_BASE_ADDR as *const u32;
        
        // Enable clock
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::AES);
        
        // Reset AES ??? (Optional, but good practice if RCC supports reset)
        
        Self { 
            regs,
            key: [0; 16] 
        }
    }
    
    fn wait_for_ccf(&self) {
        unsafe {
            loop {
                let sr = read_register(self.regs, AES_SR_BASE_OFFSET);
                if (sr & 0x1) != 0 { break; } // CCF: Computation Complete Flag
            }
        }
    }
    
    fn clear_ccf(&self) {
        unsafe { 
            set_register_bit(self.regs, AES_CR_BASE_OFFSET, 7); // CCFC: Computation Complete Flag Clear
        }
    }
}

#[cfg(feature = "stm32l562")]
impl AesEngine for AesHardware {
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>) {
        if key.len() != 16 {
            panic!("AesHardware: Only 128-bit keys supported for now");
        }
        
        self.key.copy_from_slice(key);

        unsafe {
             // Disable AES
            clear_register_bit(self.regs, AES_CR_BASE_OFFSET, 0); // EN bit
            
            // Set Mode to Encryption by default (00)
            let mut cr = read_register(self.regs, AES_CR_BASE_OFFSET);
            cr &= !((3 << 5) | (3 << 1)); // Clear CHMOD and DATATYPE
            cr &= !(3 << 3); // Encryption Mode
            write_register(self.regs, AES_CR_BASE_OFFSET, cr);

            // Write Key Initial
            write_register(self.regs, AES_KEYR0_BASE_OFFSET, u32::from_be_bytes(key[12..16].try_into().unwrap()));
            write_register(self.regs, AES_KEYR1_BASE_OFFSET, u32::from_be_bytes(key[8..12].try_into().unwrap()));
            write_register(self.regs, AES_KEYR2_BASE_OFFSET, u32::from_be_bytes(key[4..8].try_into().unwrap()));
            write_register(self.regs, AES_KEYR3_BASE_OFFSET, u32::from_be_bytes(key[0..4].try_into().unwrap()));

            if let Some(_iv_bytes) = iv {
                // TODO: IV support
            }
            
            // Enable AES
            set_register_bit(self.regs, AES_CR_BASE_OFFSET, 0);
        }
    }

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        unsafe {
            // Set Mode to Encryption (00).
            let mut cr = read_register(self.regs, AES_CR_BASE_OFFSET);
            
            // Always ensure Encryption Mode and Key are loaded (previous Decrypt might have dirtied them)
            // Ideally we check if mode changed, but Mode 11 overwrites key, so safe to reload.
             
            clear_register_bit(self.regs, AES_CR_BASE_OFFSET, 0); // Disable
            cr &= !(3 << 3); // Mode 00
            write_register(self.regs, AES_CR_BASE_OFFSET, cr);
            
             // Reload Key (because Decryption Mode 11 overwrites it)
            write_register(self.regs, AES_KEYR0_BASE_OFFSET, u32::from_be_bytes(self.key[12..16].try_into().unwrap()));
            write_register(self.regs, AES_KEYR1_BASE_OFFSET, u32::from_be_bytes(self.key[8..12].try_into().unwrap()));
            write_register(self.regs, AES_KEYR2_BASE_OFFSET, u32::from_be_bytes(self.key[4..8].try_into().unwrap()));
            write_register(self.regs, AES_KEYR3_BASE_OFFSET, u32::from_be_bytes(self.key[0..4].try_into().unwrap()));
            
            set_register_bit(self.regs, AES_CR_BASE_OFFSET, 0); // Enable
            
            // Write Data
            // Order: MSB first
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[0..4].try_into().unwrap()));
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[4..8].try_into().unwrap()));
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[8..12].try_into().unwrap()));
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[12..16].try_into().unwrap()));
            
            self.wait_for_ccf();
            
            // Read Data
            let d0 = read_register(self.regs, AES_DOUTR_BASE_OFFSET); // MSB
            let d1 = read_register(self.regs, AES_DOUTR_BASE_OFFSET);
            let d2 = read_register(self.regs, AES_DOUTR_BASE_OFFSET);
            let d3 = read_register(self.regs, AES_DOUTR_BASE_OFFSET); // LSB
            
            self.clear_ccf();
            
            output[0..4].copy_from_slice(&d0.to_be_bytes());
            output[4..8].copy_from_slice(&d1.to_be_bytes());
            output[8..12].copy_from_slice(&d2.to_be_bytes());
            output[12..16].copy_from_slice(&d3.to_be_bytes());
        }
    }

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
         unsafe {
             // Use Mode 11 (Key Derivation + Decryption)
             // This mode expects the ENCRYPTION KEY in the registers.
             // It derives automatically and then decrypts.
             // Warning: Overwrites registers with Derived Key.
             
            let mut cr = read_register(self.regs, AES_CR_BASE_OFFSET);
            
            clear_register_bit(self.regs, AES_CR_BASE_OFFSET, 0); // Disable
            cr &= !(3 << 3); 
            cr |= 3 << 3; // Set Mode 11 (Key Derivation + Decryption)
            write_register(self.regs, AES_CR_BASE_OFFSET, cr);

            // Reload original Encryption Key (Critical for Mode 11)
            write_register(self.regs, AES_KEYR0_BASE_OFFSET, u32::from_be_bytes(self.key[12..16].try_into().unwrap()));
            write_register(self.regs, AES_KEYR1_BASE_OFFSET, u32::from_be_bytes(self.key[8..12].try_into().unwrap()));
            write_register(self.regs, AES_KEYR2_BASE_OFFSET, u32::from_be_bytes(self.key[4..8].try_into().unwrap()));
            write_register(self.regs, AES_KEYR3_BASE_OFFSET, u32::from_be_bytes(self.key[0..4].try_into().unwrap()));
            
            set_register_bit(self.regs, AES_CR_BASE_OFFSET, 0); // Enable
            
            // Write Data (Ciphertext)
            // MBYTE Order: MSB first
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[0..4].try_into().unwrap()));
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[4..8].try_into().unwrap()));
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[8..12].try_into().unwrap()));
            write_register(self.regs, AES_DINR_BASE_OFFSET, u32::from_be_bytes(input[12..16].try_into().unwrap()));
            
            // Wait for Completion (Single CCF for Mode 11)
            self.wait_for_ccf();
            
            // Read Data (Plaintext)
            // First read is MSB
            let d0 = read_register(self.regs, AES_DOUTR_BASE_OFFSET); // MSB
            let d1 = read_register(self.regs, AES_DOUTR_BASE_OFFSET);
            let d2 = read_register(self.regs, AES_DOUTR_BASE_OFFSET);
            let d3 = read_register(self.regs, AES_DOUTR_BASE_OFFSET); // LSB
            
            self.clear_ccf();
            
            output[0..4].copy_from_slice(&d0.to_be_bytes());
            output[4..8].copy_from_slice(&d1.to_be_bytes());
            output[8..12].copy_from_slice(&d2.to_be_bytes());
            output[12..16].copy_from_slice(&d3.to_be_bytes());
         }
    }
}

/// Software AES-128 Emulated Driver.
///
/// `encrypt_block` uses 4 × 256 × u32 T-tables (4 KB total, in .bss)
/// that fold sub_bytes + shift_rows + mix_columns into 4 XOR-of-
/// lookups per output word per round. ~8× faster than the byte-wise
/// path on Cortex-M33.
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
        Self {
            key: [0; 16],
            sbox,
            rsbox,
            expanded_key: [0; 44],
            t0, t1, t2, t3,
        }
    }
    
    fn generate_sbox() -> [u8; 256] {
        let mut sbox = [0u8; 256];
        let mut p = 1u8;
        let mut q = 1u8;
        
        // Loop invariant: p * q == 1 in the Galois field
        loop {
            // Multiply p by 3 in polynomial field
            p = p ^ (p << 1) ^ (if (p & 0x80) != 0 { 0x1B } else { 0 });
            
            // Divide q by 3 (which is multiplication by 0xf6)
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= if (q & 0x80) != 0 { 0x09 } else { 0 };
            
            let xformed = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;
            sbox[p as usize] = xformed;
            
            if p == 1 { break; }
        }
        sbox[0] = 0x63;
        sbox
    }

    fn generate_rsbox(sbox: &[u8; 256]) -> [u8; 256] {
        let mut rsbox = [0u8; 256];
        for i in 0..256 {
            rsbox[sbox[i] as usize] = i as u8;
        }
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

    // Rotate word left by 8 bits
    fn rot_word(w: u32) -> u32 {
        (w << 8) | (w >> 24)
    }

    fn sub_word(&self, w: u32) -> u32 {
        let b0 = self.sbox[(w >> 24) as usize] as u32;
        let b1 = self.sbox[((w >> 16) & 0xFF) as usize] as u32;
        let b2 = self.sbox[((w >> 8) & 0xFF) as usize] as u32;
        let b3 = self.sbox[(w & 0xFF) as usize] as u32;
        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
    
    fn key_expansion(&mut self) {
        let mut i = 0;
        while i < 4 {
            self.expanded_key[i] = u32::from_be_bytes(self.key[i*4..(i+1)*4].try_into().unwrap());
            i += 1;
        }
        
        let rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
        
        while i < 44 {
            let mut temp = self.expanded_key[i-1];
            if i % 4 == 0 {
                temp = self.sub_word(Self::rot_word(temp)) ^ (rcon[(i/4)-1] as u32) << 24;
            }
            self.expanded_key[i] = self.expanded_key[i-4] ^ temp;
            i += 1;
        }
    }

    fn add_round_key(&self, state: &mut [u8; 16], round_key: &[u32]) {
        for i in 0..4 {
            let rk_bytes = round_key[i].to_be_bytes();
            for j in 0..4 {
                state[i*4 + j] ^= rk_bytes[j];
            }
        }
    }
    
    #[allow(dead_code)]  // forward AES round; ESS path is decrypt-only on L552
    fn sub_bytes(&self, state: &mut [u8; 16]) {
        for i in 0..16 {
            state[i] = self.sbox[state[i] as usize];
        }
    }

    fn inv_sub_bytes(&self, state: &mut [u8; 16]) {
        for i in 0..16 {
            state[i] = self.rsbox[state[i] as usize];
        }
    }

    #[allow(dead_code)]  // forward AES round; ESS path is decrypt-only on L552
    fn shift_rows(state: &mut [u8; 16]) {
        // Row 0 is unchanged
        // Row 1 rotated left by 1
        let temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
        // Row 2 rotated left by 2
        let temp1 = state[2]; let temp2 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = temp1; state[14] = temp2;
        // Row 3 rotated left by 3
        let temp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = temp;
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        // Row 0 is unchanged
        // Row 1 rotated right by 1
        let temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
        // Row 2 rotated right by 2
        let temp1 = state[2]; let temp2 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = temp1; state[14] = temp2;
        // Row 3 rotated right by 3
        let temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
    }

    fn gmul(a: u8, b: u8) -> u8 {
        let mut p = 0;
        let mut a = a;
        let mut b = b;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi_bit_set = (a & 0x80) != 0;
            a <<= 1;
            if hi_bit_set {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    #[allow(dead_code)]  // forward AES round; ESS path is decrypt-only on L552
    fn mix_columns(state: &mut [u8; 16]) {
        // Use column-major order indexing since state is byte array 128-bit linear
        // Standard AES defines state as column-major matrix of bytes. 
        // Our buffer is linear. Usually mapping is: 
        // 0  4  8 12
        // 1  5  9 13
        // 2  6 10 14
        // 3  7 11 15
        
        for i in 0..4 {
            let offset = i * 4;
            let c0 = state[offset];
            let c1 = state[offset+1];
            let c2 = state[offset+2];
            let c3 = state[offset+3];
            
            state[offset] = Self::gmul(c0, 2) ^ Self::gmul(c1, 3) ^ c2 ^ c3;
            state[offset+1] = c0 ^ Self::gmul(c1, 2) ^ Self::gmul(c2, 3) ^ c3;
            state[offset+2] = c0 ^ c1 ^ Self::gmul(c2, 2) ^ Self::gmul(c3, 3);
            state[offset+3] = Self::gmul(c0, 3) ^ c1 ^ c2 ^ Self::gmul(c3, 2);
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let offset = i * 4;
            let c0 = state[offset];
            let c1 = state[offset+1];
            let c2 = state[offset+2];
            let c3 = state[offset+3];
            
            state[offset] = Self::gmul(c0, 14) ^ Self::gmul(c1, 11) ^ Self::gmul(c2, 13) ^ Self::gmul(c3, 9);
            state[offset+1] = Self::gmul(c0, 9) ^ Self::gmul(c1, 14) ^ Self::gmul(c2, 11) ^ Self::gmul(c3, 13);
            state[offset+2] = Self::gmul(c0, 13) ^ Self::gmul(c1, 9) ^ Self::gmul(c2, 14) ^ Self::gmul(c3, 11);
            state[offset+3] = Self::gmul(c0, 11) ^ Self::gmul(c1, 13) ^ Self::gmul(c2, 9) ^ Self::gmul(c3, 14);
        }
    }
}

impl AesEngine for AesEmulated {
    fn init(&mut self, key: &[u8], _iv: Option<&[u8]>) {
        if key.len() != 16 {
            panic!("AesEmulated: Only 128-bit keys supported");
        }
        self.key.copy_from_slice(key);
        self.key_expansion();
    }

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // Pack the 4 columns of the state as little-endian u32, matching
        // the column-major byte layout used by `mix_columns` and
        // `shift_rows` (see comment at aes.rs:370-376).
        //   column 0 = bytes [0,1,2,3]   ← rows 0,1,2,3
        //   column 1 = bytes [4,5,6,7]
        //   column 2 = bytes [8,9,10,11]
        //   column 3 = bytes [12,13,14,15]
        // Byte at row r of column c lives at bit position (r*8)..((r+1)*8)
        // inside the column u32 (little-endian).
        let mut s0 = u32::from_le_bytes([input[0],  input[1],  input[2],  input[3]]);
        let mut s1 = u32::from_le_bytes([input[4],  input[5],  input[6],  input[7]]);
        let mut s2 = u32::from_le_bytes([input[8],  input[9],  input[10], input[11]]);
        let mut s3 = u32::from_le_bytes([input[12], input[13], input[14], input[15]]);

        // Initial AddRoundKey (XOR with first 4 expanded-key words).
        // expanded_key is big-endian per `key_expansion` (uses from_be_bytes),
        // but we work in little-endian state words — byte-swap on use.
        s0 ^= self.expanded_key[0].swap_bytes();
        s1 ^= self.expanded_key[1].swap_bytes();
        s2 ^= self.expanded_key[2].swap_bytes();
        s3 ^= self.expanded_key[3].swap_bytes();

        // 9 full rounds (sub_bytes + shift_rows + mix_columns + add_round_key)
        // collapsed into 4 T-table lookups + 4 XORs per output column.
        // The shift_rows pattern (row r rotates left by r) is encoded in
        // WHICH source byte feeds which T-table:
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
        // Apply S-box manually, with shift-rows index pattern, then XOR
        // last round key.
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

        // Unpack the 4 column u32s back to bytes (little-endian).
        output[0..4].copy_from_slice(&final0.to_le_bytes());
        output[4..8].copy_from_slice(&final1.to_le_bytes());
        output[8..12].copy_from_slice(&final2.to_le_bytes());
        output[12..16].copy_from_slice(&final3.to_le_bytes());
    }

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        let mut state = *input;
        
        self.add_round_key(&mut state, &self.expanded_key[40..44]);
        
        for round in (1..10).rev() {
            Self::inv_shift_rows(&mut state);
            self.inv_sub_bytes(&mut state);
            self.add_round_key(&mut state, &self.expanded_key[round*4..(round+1)*4]);
            Self::inv_mix_columns(&mut state);
        }
        
        Self::inv_shift_rows(&mut state);
        self.inv_sub_bytes(&mut state);
        self.add_round_key(&mut state, &self.expanded_key[0..4]);
        
        *output = state;
    }
}
