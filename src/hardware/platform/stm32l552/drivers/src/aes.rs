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

/// Software AES-128 Emulated Driver
pub struct AesEmulated {
    key: [u8; 16],
    // Expanded key could be cached here for performance
    sbox: [u8; 256],
    rsbox: [u8; 256],
    expanded_key: [u32; 44], 
}

impl AesEmulated {
    pub fn new() -> Self {
        let sbox = Self::generate_sbox();
        let rsbox = Self::generate_rsbox(&sbox);
        Self {
            key: [0; 16],
            sbox,
            rsbox,
            expanded_key: [0; 44],
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
        let mut state = *input;
        
        self.add_round_key(&mut state, &self.expanded_key[0..4]);
        
        for round in 1..10 {
            self.sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            self.add_round_key(&mut state, &self.expanded_key[round*4..(round+1)*4]);
        }
        
        self.sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        self.add_round_key(&mut state, &self.expanded_key[40..44]);
        
        *output = state;
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
