// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! HASH driver for STM32L5xxxx (Secure peripheral at `0x520C_0400`).
//! Supports SHA-1 / SHA-224 / SHA-256 / MD5 plain hashing and HMAC,
//! suspendable via a `Context` snapshot of the 54-word HASH_CSR bank.
//! # Output-register non-contiguity (HR5/HR6/HR7 are NOT at base + 5/6/7 × 4)
//! For SHA-256 the digest spans 8 words. HR0–HR4 are contiguous starting
//! at the regular `HASH_HR_BASE_OFFSET = 0x0C`. **HR5 / HR6 / HR7 live at
//! offsets `0x324 / 0x328 / 0x32C`** — a separate bank, not an extension
//! of the HR0–HR4 stride. The split-offset readout lives in `finish()`
//! (see the `if i < 5 {... } else { 0x324 +... }` branch). Auto-generated
//! register structs from the `stm32l5` PAC family encode this wrong; do
//! NOT trust PAC-based offsets here — verify against RM0438 §32.6 (HASH
//! register map) and the on-device readout. Misreading HR5–HR7 yields the
//! correct first 160 digest bits and garbage for the last 96.

// Crates
use crate::rcc;
use crate::rcc::Rcc;
use core::cmp::min;
use peripheral_regs::{MmioAccess, RealMmio};

const HASH_BASE_ADDR: u32 = 0x520C0400; // Secure
type HashRegisters = u32;

// Registers
const HASH_CR_BASE_OFFSET: HashRegisters = 0x00;
const HASH_DIN_BASE_OFFSET: HashRegisters = 0x04;
const HASH_STR_BASE_OFFSET: HashRegisters = 0x08;
const HASH_HR_BASE_OFFSET: HashRegisters = 0x0C; // HASH_HR0
const HASH_IMR_BASE_OFFSET: HashRegisters = 0x20;
const HASH_SR_BASE_OFFSET: HashRegisters = 0x24; // HASH_SR
const HASH_CSR_BASE_OFFSET: HashRegisters = 0xF8; // HASH_CSR0

// HR5 / HR6 / HR7 split-bank offsets (see module docs § "Output-register
// non-contiguity"). DO NOT collapse these into a stride from HR0_BASE.
const HASH_HR5_BASE_OFFSET: HashRegisters = 0x324;

const NUM_CONTEXT_REGS: usize = 54;
const HASH_BUFFER_LEN: usize = 132;
const DIGEST_BLOCK_SIZE: usize = 128;

/// Upper bound on HASH status-register spin polls. A SHA-256 digest of a
/// single block retires in well under a thousand bus cycles, so this cap is
/// orders of magnitude above any real completion latency — it is only ever
/// reached if the HASH peripheral is mis-clocked or wedged. On timeout the
/// driver returns [`HashError::Timeout`] instead of the former silent
/// `loop {}`; the crypto boundary maps it to `UmbraError::HashHardware`
/// (→ UART log + reset), so a wedged HASH surfaces a typed error rather than
/// freezing Secure boot before "Kernel Initialized".
const HASH_POLL_LIMIT: u32 = 5_000_000;

/// Failure modes of the raw `Hash` driver. HW-specific subtype that the
/// crypto boundary converts into `UmbraError::HashHardware` via `map_err`,
/// keeping the drivers crate free of the `umbra-error` dependency (see the
/// `umbra-error` crate docs § "HW-specific subtypes via From impls").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    /// A HASH_SR status flag never asserted within `HASH_POLL_LIMIT` polls.
    /// The `&'static str` names the wait site (e.g. `"finish/digest"`) so a
    /// panic-dump reader knows which stage of the digest pipeline wedged.
    Timeout(&'static str),
}

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
/// Note: `Context` is intentionally **NOT** generic over `MmioAccess`. It
/// carries only data (algo / format / cached CSR snapshot / pending HMAC
/// key) and never touches MMIO itself — every register access flows
/// through the owning `Hash<M>`.
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

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Hash::new()` call site unchanged at
/// the source level — the firmware build monomorphises to `Hash<RealMmio>`
/// and inlines the `volatile_register` accesses just like before.
pub struct Hash<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Hash<RealMmio> {
    pub fn new() -> Self {
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::HASH);

        let hash = Self {
            mmio: RealMmio::new(HASH_BASE_ADDR),
        };

        // Reset (INIT bit)
        hash.mmio.set_bit(HASH_CR_BASE_OFFSET, 2);

        hash
    }
}

impl<M: MmioAccess> Hash<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Hash::new()` which monomorphises to
    /// `Hash<RealMmio>` and inlines the volatile accesses. This test
    /// constructor deliberately skips the RCC `enable_clock` + INIT-bit
    /// reset that the production path needs — tests preload the mem CSR
    /// bank directly.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Starts computation of a new hash and returns the saved peripheral state.
    pub fn start<'c>(
        &mut self,
        algorithm: Algorithm,
        format: DataType,
        key: HmacKey<'c>,
    ) -> Result<Context<'c>, HashError> {
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
        let cr = self.mmio.read(HASH_CR_BASE_OFFSET);
        let mask = !(3u32 << 4);
        let val = (ctx.format as u32) << 4;
        self.mmio.write(HASH_CR_BASE_OFFSET, (cr & mask) | val);

        // Select the algorithm.
        let mut algo0 = false;
        let mut algo1 = false;
        if ctx.algo == Algorithm::MD5 || ctx.algo == Algorithm::SHA256 {
            algo0 = true;
        }
        if ctx.algo == Algorithm::SHA224 || ctx.algo == Algorithm::SHA256 {
            algo1 = true;
        }

        if algo0 {
            self.mmio.set_bit(HASH_CR_BASE_OFFSET, 7);
        } else {
            self.mmio.clear_bit(HASH_CR_BASE_OFFSET, 7);
        }

        if algo1 {
            self.mmio.set_bit(HASH_CR_BASE_OFFSET, 18);
        } else {
            self.mmio.clear_bit(HASH_CR_BASE_OFFSET, 18);
        }

        // Configure HMAC mode if a key is provided.
        if let Some(key) = ctx.key {
            self.mmio.set_bit(HASH_CR_BASE_OFFSET, 6); // MODE bit
            if key.len() > 64 {
                self.mmio.set_bit(HASH_CR_BASE_OFFSET, 16); // LKEY bit
            }
        } else {
            self.mmio.clear_bit(HASH_CR_BASE_OFFSET, 6);
        }

        self.mmio.set_bit(HASH_CR_BASE_OFFSET, 2); // INIT bit

        // Store and return the state of the peripheral.
        self.store_context(&mut ctx)?;
        Ok(ctx)
    }

    /// Restores the peripheral state using the given context,
    /// then updates the state with the provided data.
    /// Peripheral state is saved upon return.
    pub fn update<'c>(&mut self, ctx: &mut Context<'c>, input: &[u8]) -> Result<(), HashError> {
        // Restore the peripheral state.
        self.load_context(&ctx);

        // Load the HMAC key if provided.
        if !ctx.key_sent {
            if let Some(key) = ctx.key {
                self.accumulate(key);
                self.mmio.set_bit(HASH_STR_BASE_OFFSET, 8); // DCAL
                                                            // Block waiting for digest.
                self.wait_sr(1, "update/key")?; // DINIS
            }
            ctx.key_sent = true;
        }

        let mut data_waiting = input.len() + ctx.buflen;
        if data_waiting < DIGEST_BLOCK_SIZE
            || (data_waiting < ctx.buffer.len() && !ctx.first_word_sent)
        {
            // There isn't enough data to digest a block, so append it to the buffer.
            ctx.buffer[ctx.buflen..ctx.buflen + input.len()].copy_from_slice(input);
            ctx.buflen += input.len();
            self.store_context(ctx)?;
            return Ok(());
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
            ctx.buffer[0..ilen_remaining]
                .copy_from_slice(&input[input_start..input_start + ilen_remaining]);
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
                ctx.buffer[0..leftovers]
                    .copy_from_slice(&input[input.len() - leftovers..input.len()]);
                ctx.buflen += leftovers;
                ilen_remaining -= leftovers;
            }

            // Hash the remaining data.
            self.accumulate(&input[input_start..input_start + ilen_remaining]);
        }

        // Save the peripheral context.
        self.store_context(ctx)?;
        Ok(())
    }

    /// Computes a digest for the given context.
    /// The digest buffer must be large enough to accomodate a digest for the selected algorithm.
    /// The largest returned digest size is 128 bytes for SHA-512.
    /// Panics if the supplied digest buffer is too short.
    pub fn finish<'c>(
        &mut self,
        mut ctx: Context<'c>,
        digest: &mut [u8],
    ) -> Result<usize, HashError> {
        // Restore the peripheral state.
        self.load_context(&ctx);

        // Hash the leftover bytes, if any.
        self.accumulate(&ctx.buffer[0..ctx.buflen]);
        ctx.buflen = 0;

        // Start the digest calculation.
        self.mmio.set_bit(HASH_STR_BASE_OFFSET, 8); // DCAL

        // Load the HMAC key if provided.
        if let Some(key) = ctx.key {
            // Block waiting for data in ready.
            self.wait_sr(1, "finish/key")?; // DINIS
            self.accumulate(key);
            self.mmio.set_bit(HASH_STR_BASE_OFFSET, 8); // DCAL
        }

        // Block until digest computation is complete.
        self.wait_sr(2, "finish/digest")?; // DCIS

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
            panic!(
                "Digest buffer must be at least {} bytes long.",
                digest_words * 4
            );
        }

        let mut i = 0;
        while i < digest_words {
            // HR5/HR6/HR7 live at 0x324/0x328/0x32C — a separate bank from
            // HR0–HR4. See module docs § "Output-register non-contiguity".
            let offset = if i < 5 {
                HASH_HR_BASE_OFFSET + (i as u32 * 4)
            } else {
                HASH_HR5_BASE_OFFSET + ((i as u32 - 5) * 4)
            };
            let word = self.mmio.read(offset);
            digest[(i * 4)..((i * 4) + 4)].copy_from_slice(word.to_be_bytes().as_slice());
            i += 1;
        }
        Ok(digest_len_bytes)
    }

    /// Poll a HASH_SR status flag (`mask`) until set, bounded by
    /// `HASH_POLL_LIMIT`. Returns `Err(HashError::Timeout(site))` on overflow
    /// instead of spinning forever — a wedged HASH peripheral then surfaces a
    /// typed error the crypto boundary maps to `UmbraError::HashHardware`,
    /// rather than freezing Secure boot before "Kernel Initialized".
    fn wait_sr(&self, mask: u32, site: &'static str) -> Result<(), HashError> {
        let mut spins = 0u32;
        loop {
            if (self.mmio.read(HASH_SR_BASE_OFFSET) & mask) != 0 {
                return Ok(());
            }
            spins += 1;
            if spins >= HASH_POLL_LIMIT {
                return Err(HashError::Timeout(site));
            }
        }
    }

    /// Push data into the hash core.
    fn accumulate(&mut self, input: &[u8]) {
        // Set the number of valid bits.
        let num_valid_bits: u8 = (8 * (input.len() % 4)) as u8;

        let str_val = self.mmio.read(HASH_STR_BASE_OFFSET);
        let mask = !0x1Fu32;
        let val = num_valid_bits as u32;
        self.mmio
            .write(HASH_STR_BASE_OFFSET, (str_val & mask) | val);

        let mut chunks = input.chunks_exact(4);
        for chunk in &mut chunks {
            let val = u32::from_ne_bytes(chunk.try_into().unwrap());
            self.mmio.write(HASH_DIN_BASE_OFFSET, val);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut word: [u8; 4] = [0; 4];
            word[0..rem.len()].copy_from_slice(rem);
            self.mmio
                .write(HASH_DIN_BASE_OFFSET, u32::from_ne_bytes(word));
        }
    }

    /// Save the peripheral state to a context.
    fn store_context<'c>(&mut self, ctx: &mut Context<'c>) -> Result<(), HashError> {
        // Block waiting for data in ready.
        self.wait_sr(1, "store_context")?; // DINIS

        // Store peripheral context.
        ctx.imr = self.mmio.read(HASH_IMR_BASE_OFFSET);
        ctx.str = self.mmio.read(HASH_STR_BASE_OFFSET);
        ctx.cr = self.mmio.read(HASH_CR_BASE_OFFSET);
        let mut i = 0;
        while i < NUM_CONTEXT_REGS {
            ctx.csr[i] = self.mmio.read(HASH_CSR_BASE_OFFSET + (i as u32 * 4));
            i += 1;
        }
        Ok(())
    }

    /// Restore the peripheral state from a context.
    fn load_context(&mut self, ctx: &Context) {
        // Restore the peripheral state from the context. Write order matches
        // the RM0438 §32.4.5 suspend/resume sequence — IMR, STR, CR, then
        // INIT bit, then CSR bank. The HASH state machine is sensitive to
        // this ordering; do NOT reorder.
        self.mmio.write(HASH_IMR_BASE_OFFSET, ctx.imr);
        self.mmio.write(HASH_STR_BASE_OFFSET, ctx.str);
        self.mmio.write(HASH_CR_BASE_OFFSET, ctx.cr);
        self.mmio.set_bit(HASH_CR_BASE_OFFSET, 2); // INIT

        let mut i = 0;
        while i < NUM_CONTEXT_REGS {
            self.mmio
                .write(HASH_CSR_BASE_OFFSET + (i as u32 * 4), ctx.csr[i]);
            i += 1;
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// umbra-hal::Hash adapter.
// The driver's native API exposes `start` / `update` / `finish` with an
// explicit `Context` threaded by the caller (so the same peripheral can
// service multiple suspended computations). The `umbra-hal::Hash` trait
// presents the simpler `init` / `update(&mut self,..)` / `finalize` shape
// the kernel's chained-measurement code wants. `Sha256Engine` holds the
// context internally and delegates to the inherent methods — zero behavior
// change in the underlying HW driver.
// ────────────────────────────────────────────────────────────────────────────

/// SHA-256 engine implementing `umbra_hal::Hash`. Hard-codes
/// `Algorithm::SHA256` + `DataType::Width8` + non-HMAC, which is the
/// single configuration the kernel's chained measurement uses.
/// Generic over the same `MmioAccess`
/// backend as the wrapped `Hash<M>`. Default `M = RealMmio` keeps every
/// existing call site (`Sha256Engine::new()`, `Sha256Engine::from_hash(..)`,
/// `Sha256Engine::inner_mut()`) compiling unchanged.
pub struct Sha256Engine<M: MmioAccess = RealMmio> {
    hw: Hash<M>,
    ctx: Option<Context<'static>>,
}

impl Default for Sha256Engine<RealMmio> {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Engine<RealMmio> {
    pub fn new() -> Self {
        Self {
            hw: Hash::new(),
            ctx: None,
        }
    }
}

impl<M: MmioAccess> Sha256Engine<M> {
    /// Adopt an externally-constructed `Hash` driver. Used by callers that
    /// also need direct access to the HMAC path (`Hash::start` with a key),
    /// since the trait surface only models non-keyed SHA-256.
    pub fn from_hash(hw: Hash<M>) -> Self {
        Self { hw, ctx: None }
    }

    /// Borrow the underlying `Hash` driver. Used by `UmbraCryptoEngine::hmac`
    /// — HMAC needs the key-aware `Hash::start(.., Some(key))` API that
    /// the trait does not expose.
    pub fn inner_mut(&mut self) -> &mut Hash<M> {
        &mut self.hw
    }
}

#[derive(Debug)]
pub enum Sha256Error {
    /// `update` / `finalize` called before `init`.
    NotInitialized,
    /// The underlying `Hash` driver timed out on a HASH_SR poll
    /// (see [`HashError::Timeout`]). Surfaced through the trait so the
    /// crypto boundary maps it to `UmbraError::HashHardware`.
    HwTimeout,
}

impl<M: MmioAccess> umbra_hal::Hash for Sha256Engine<M> {
    type Error = Sha256Error;

    fn init(&mut self) -> Result<(), Self::Error> {
        // Reset to a fresh SHA-256 session. No HMAC key (None).
        self.ctx = Some(
            self.hw
                .start(Algorithm::SHA256, DataType::Width8, None)
                .map_err(|_| Sha256Error::HwTimeout)?,
        );
        Ok(())
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let ctx = self.ctx.as_mut().ok_or(Sha256Error::NotInitialized)?;
        self.hw
            .update(ctx, input)
            .map_err(|_| Sha256Error::HwTimeout)?;
        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8; 32]) -> Result<(), Self::Error> {
        let ctx = self.ctx.take().ok_or(Sha256Error::NotInitialized)?;
        // `finish` honours the HR5-7 offset split (see module docs §
        // "Output-register non-contiguity"); the trait does not need to
        // care about that landmine.
        self.hw
            .finish(ctx, output)
            .map_err(|_| Sha256Error::HwTimeout)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
