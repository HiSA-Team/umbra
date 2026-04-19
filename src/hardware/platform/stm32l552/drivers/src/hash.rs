// Author: Salvatore Bramante  <salvatore.bramante@imtlucca.it>
//
// STM32L5xxxx HASH Driver
// This driver supports HASH processor
//
// Description:
// Hash generator (HASH)
//

// Crates
use peripheral_regs::*;
use crate::rcc::Rcc;
use crate::rcc;
use core::cmp::min;

const HASH_BASE_ADDR: u32 = 0x520C0400; // Secure
type HashRegisters = u32;

// Registers
const HASH_CR_BASE_OFFSET: u32 = 0x00;
const HASH_DIN_BASE_OFFSET: u32 = 0x04;
const HASH_STR_BASE_OFFSET: u32 = 0x08;
const HASH_HR_BASE_OFFSET: u32 = 0x0C; // HASH_HR0
const HASH_IMR_BASE_OFFSET: u32 = 0x20;
const HASH_SR_BASE_OFFSET: u32 = 0x24; // HASH_SR
const HASH_CSR_BASE_OFFSET: u32 = 0xF8; // HASH_CSR0

const NUM_CONTEXT_REGS: usize = 54;
const HASH_BUFFER_LEN: usize = 132;
const DIGEST_BLOCK_SIZE: usize = 128;

///Hash algorithm selection
#[derive(Clone, Copy, PartialEq)]
pub enum Algorithm {
    /// SHA-1 Algorithm
    SHA1 = 0,
    /// MD5 Algorithm
    MD5 = 1,
    /// SHA-224 Algorithm
    SHA224 = 2,
    /// SHA-256 Algorithm
    SHA256 = 3,
}

/// Input data width selection
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DataType {
    ///32-bit data, no data is swapped.
    Width32 = 0,
    ///16-bit data, each half-word is swapped.
    Width16 = 1,
    ///8-bit data, all bytes are swapped.
    Width8 = 2,
    ///1-bit data, all bits are swapped.
    Width1 = 3,
}

type HmacKey<'k> = Option<&'k [u8]>;

/// Stores the state of the HASH peripheral for suspending/resuming
/// digest calculation.
#[derive(Clone)]
pub struct Context<'c> {
    first_word_sent: bool,
    key_sent: bool,
    buffer: [u8; HASH_BUFFER_LEN],
    buflen: usize,
    algo: Algorithm,
    format: DataType,
    imr: u32,
    str: u32,
    cr: u32,
    csr: [u32; NUM_CONTEXT_REGS],
    key: HmacKey<'c>,
}

pub struct Hash {
    regs: &'static mut HashRegisters,
}

impl Hash {
    pub fn new() -> Self {
        let regs = unsafe { &mut *(HASH_BASE_ADDR as *mut HashRegisters) };
        
        // Enable clock
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::Peripherals::HASH);

        // Reset
        unsafe { set_register_bit(regs as *mut u32 as *const u32, HASH_CR_BASE_OFFSET, 2); } // INIT bit

        Self { regs }
    }

    /// Starts computation of a new hash and returns the saved peripheral state.
    pub fn start<'c>(&mut self, algorithm: Algorithm, format: DataType, key: HmacKey<'c>) -> Context<'c> {
        // Define a context for this new computation.
        let mut ctx = Context {
            first_word_sent: false,
            key_sent: false,
            buffer: [0; HASH_BUFFER_LEN],
            buflen: 0,
            algo: algorithm,
            format: format,
            imr: 0,
            str: 0,
            cr: 0,
            csr: [0; NUM_CONTEXT_REGS],
            key,
        };

        // Set the data type in the peripheral.
        unsafe {
            let cr = read_register(self.regs, HASH_CR_BASE_OFFSET);
            let mask = !(3 << 4);
            let val = (ctx.format as u32) << 4;
            write_register(self.regs, HASH_CR_BASE_OFFSET, (cr & mask) | val);
        }

        // Select the algorithm.
        unsafe {
             let mut algo0 = false;
            let mut algo1 = false;
            if ctx.algo == Algorithm::MD5 || ctx.algo == Algorithm::SHA256 {
                algo0 = true;
            }
            if ctx.algo == Algorithm::SHA224 || ctx.algo == Algorithm::SHA256 {
                algo1 = true;
            }
            
            if algo0 { set_register_bit(self.regs, HASH_CR_BASE_OFFSET, 7); }
            else { clear_register_bit(self.regs, HASH_CR_BASE_OFFSET, 7); }

            if algo1 { set_register_bit(self.regs, HASH_CR_BASE_OFFSET, 18); }
            else { clear_register_bit(self.regs, HASH_CR_BASE_OFFSET, 18); }
        }

        // Configure HMAC mode if a key is provided.
        if let Some(key) = ctx.key {
             unsafe { set_register_bit(self.regs, HASH_CR_BASE_OFFSET, 6); } // MODE bit
            if key.len() > 64 {
                unsafe { set_register_bit(self.regs, HASH_CR_BASE_OFFSET, 16); } // LKEY bit
            }
        } else {
            unsafe { clear_register_bit(self.regs, HASH_CR_BASE_OFFSET, 6); }
        }

         unsafe { set_register_bit(self.regs, HASH_CR_BASE_OFFSET, 2); } // INIT bit

        // Store and return the state of the peripheral.
        self.store_context(&mut ctx);
        ctx
    }

    /// Restores the peripheral state using the given context,
    /// then updates the state with the provided data.
    /// Peripheral state is saved upon return.
    pub fn update<'c>(&mut self, ctx: &mut Context<'c>, input: &[u8]) {
        // Restore the peripheral state.
        self.load_context(&ctx);

        // Load the HMAC key if provided.
        if !ctx.key_sent {
            if let Some(key) = ctx.key {
                self.accumulate(key);
                unsafe { set_register_bit(self.regs, HASH_STR_BASE_OFFSET, 8); } // DCAL
                // Block waiting for digest.
                loop {
                    let sr = unsafe { read_register(self.regs, HASH_SR_BASE_OFFSET) };
                    if (sr & 1) != 0 { break; } // DINIS
                }
            }
            ctx.key_sent = true;
        }

        let mut data_waiting = input.len() + ctx.buflen;
        if data_waiting < DIGEST_BLOCK_SIZE || (data_waiting < ctx.buffer.len() && !ctx.first_word_sent) {
            // There isn't enough data to digest a block, so append it to the buffer.
            ctx.buffer[ctx.buflen..ctx.buflen + input.len()].copy_from_slice(input);
            ctx.buflen += input.len();
            self.store_context(ctx);
            return;
        }

        let mut ilen_remaining = input.len();
        let mut input_start = 0;

        // Handle first block.
        if !ctx.first_word_sent {
            let empty_len = ctx.buffer.len() - ctx.buflen;
            let copy_len = min(empty_len, ilen_remaining);
            // Fill the buffer.
            if copy_len > 0 {
                ctx.buffer[ctx.buflen..ctx.buflen + copy_len].copy_from_slice(&input[0..copy_len]);
                ctx.buflen += copy_len;
                ilen_remaining -= copy_len;
                input_start += copy_len;
            }
            self.accumulate(ctx.buffer.as_slice());
            data_waiting -= ctx.buflen;
            ctx.buflen = 0;
            ctx.first_word_sent = true;
        }

        if data_waiting < DIGEST_BLOCK_SIZE {
            // There isn't enough data remaining to process another block, so store it.
            ctx.buffer[0..ilen_remaining].copy_from_slice(&input[input_start..input_start + ilen_remaining]);
            ctx.buflen += ilen_remaining;
        } else {
            // First ingest the data in the buffer.
            let empty_len = DIGEST_BLOCK_SIZE - ctx.buflen;
            if empty_len > 0 {
                let copy_len = min(empty_len, ilen_remaining);
                ctx.buffer[ctx.buflen..ctx.buflen + copy_len]
                    .copy_from_slice(&input[input_start..input_start + copy_len]);
                ctx.buflen += copy_len;
                ilen_remaining -= copy_len;
                input_start += copy_len;
            }
            self.accumulate(&ctx.buffer[0..DIGEST_BLOCK_SIZE]);
            ctx.buflen = 0;

            // Move any extra data to the now-empty buffer.
            let leftovers = ilen_remaining % 64;
            if leftovers > 0 {
                ctx.buffer[0..leftovers].copy_from_slice(&input[input.len() - leftovers..input.len()]);
                ctx.buflen += leftovers;
                ilen_remaining -= leftovers;
            }

            // Hash the remaining data.
            self.accumulate(&input[input_start..input_start + ilen_remaining]);
        }

        // Save the peripheral context.
        self.store_context(ctx);
    }

    /// Computes a digest for the given context.
    /// The digest buffer must be large enough to accomodate a digest for the selected algorithm.
    /// The largest returned digest size is 128 bytes for SHA-512.
    /// Panics if the supplied digest buffer is too short.
    pub fn finish<'c>(&mut self, mut ctx: Context<'c>, digest: &mut [u8]) -> usize {
        // Restore the peripheral state.
        self.load_context(&ctx);

        // Hash the leftover bytes, if any.
        self.accumulate(&ctx.buffer[0..ctx.buflen]);
        ctx.buflen = 0;

        //Start the digest calculation.
        unsafe { set_register_bit(self.regs, HASH_STR_BASE_OFFSET, 8); } // DCAL

        // Load the HMAC key if provided.
        if let Some(key) = ctx.key {
             // Block waiting for data in ready.
            loop {
                let sr = unsafe { read_register(self.regs, HASH_SR_BASE_OFFSET) };
                if (sr & 1) != 0 { break; } // DINIS
            }
            self.accumulate(key);
             unsafe { set_register_bit(self.regs, HASH_STR_BASE_OFFSET, 8); } // DCAL
        }

        // Block until digest computation is complete.
         loop {
            let sr = unsafe { read_register(self.regs, HASH_SR_BASE_OFFSET) };
            if (sr & 2) != 0 { break; } // DCIS
        }

        // Return the digest.
        let digest_words = match ctx.algo {
            Algorithm::SHA1 => 5,
            Algorithm::MD5 => 4,
            Algorithm::SHA224 => 7,
            Algorithm::SHA256 => 8,
        };

        let digest_len_bytes = digest_words * 4;
        // Panics if the supplied digest buffer is too short.
        if digest.len() < digest_len_bytes {
            panic!("Digest buffer must be at least {} bytes long.", digest_words * 4);
        }

        let mut i = 0;
        while i < digest_words {
            let offset = if i < 5 {
                HASH_HR_BASE_OFFSET + (i as u32 * 4)
            } else {
                // HR5, HR6, HR7 found at 0x324, 0x328, 0x32C
                0x324 + ((i as u32 - 5) * 4)
            };
            let word = unsafe { read_register(self.regs, offset) };
            digest[(i * 4)..((i * 4) + 4)].copy_from_slice(word.to_be_bytes().as_slice());
            i += 1;
        }
        digest_len_bytes
    }

    /// Push data into the hash core.
    fn accumulate(&mut self, input: &[u8]) {
        // Set the number of valid bits.
        let num_valid_bits: u8 = (8 * (input.len() % 4)) as u8;
        
        unsafe {
            let str_val = read_register(self.regs, HASH_STR_BASE_OFFSET);
            let mask = !0x1F;
            let val = num_valid_bits as u32;
             write_register(self.regs, HASH_STR_BASE_OFFSET, (str_val & mask) | val);
        }

        let mut chunks = input.chunks_exact(4);
        for chunk in &mut chunks {
            let val = u32::from_ne_bytes(chunk.try_into().unwrap());
            unsafe { write_register(self.regs, HASH_DIN_BASE_OFFSET, val); }
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut word: [u8; 4] = [0; 4];
            word[0..rem.len()].copy_from_slice(rem);
            unsafe { write_register(self.regs, HASH_DIN_BASE_OFFSET, u32::from_ne_bytes(word)); }
        }
    }

    /// Save the peripheral state to a context.
    fn store_context<'c>(&mut self, ctx: &mut Context<'c>) {
        // Block waiting for data in ready.
        loop {
            let sr = unsafe { read_register(self.regs, HASH_SR_BASE_OFFSET) };
            if (sr & 1) != 0 { break; } // DINIS
        }

        // Store peripheral context.
        ctx.imr = unsafe { read_register(self.regs, HASH_IMR_BASE_OFFSET) };
        ctx.str = unsafe { read_register(self.regs, HASH_STR_BASE_OFFSET) };
        ctx.cr = unsafe { read_register(self.regs, HASH_CR_BASE_OFFSET) };
        let mut i = 0;
        while i < NUM_CONTEXT_REGS {
            ctx.csr[i] = unsafe { read_register(self.regs, HASH_CSR_BASE_OFFSET + (i as u32 * 4)) };
            i += 1;
        }
    }

    /// Restore the peripheral state from a context.
    fn load_context(&mut self, ctx: &Context) {
        // Restore the peripheral state from the context.
        unsafe {
             write_register(self.regs, HASH_IMR_BASE_OFFSET, ctx.imr);
             write_register(self.regs, HASH_STR_BASE_OFFSET, ctx.str);
             write_register(self.regs, HASH_CR_BASE_OFFSET, ctx.cr);
             set_register_bit(self.regs, HASH_CR_BASE_OFFSET, 2); // INIT
        }
        
        let mut i = 0;
        while i < NUM_CONTEXT_REGS {
             unsafe { write_register(self.regs, HASH_CSR_BASE_OFFSET + (i as u32 * 4), ctx.csr[i]); }
            i += 1;
        }
    }
}
