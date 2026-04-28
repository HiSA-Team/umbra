// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
//
// STM32L5xxxx OTFDEC Driver
// On-The-Fly Decryption Engine for external memories.

#[cfg(feature = "stm32l562")]
use peripheral_regs::*;
#[cfg(feature = "stm32l562")]
use crate::rcc::{self, Rcc};

#[cfg(feature = "stm32l562")]
const OTFDEC_BASE_ADDR: u32 = 0x520C5000; // Secure Base Address (SVD: 0x420C5000 -> 0x520C5000)

#[cfg(feature = "stm32l562")]
const OTFDEC_CR_OFFSET:  u32 = 0x000;
#[cfg(feature = "stm32l562")]
const OTFDEC_ISR_OFFSET: u32 = 0x300;
#[cfg(feature = "stm32l562")]
const OTFDEC_ICR_OFFSET: u32 = 0x304;

// Region 1 Offsets (Region 2, 3, 4 follow at +0x30 stride)
#[cfg(feature = "stm32l562")]
const REGION_STRIDE: u32 = 0x30;
#[cfg(feature = "stm32l562")]
const R1_CFGR_OFFSET: u32 = 0x20;
#[cfg(feature = "stm32l562")]
const R1_SADR_OFFSET: u32 = 0x24; // Start Address
#[cfg(feature = "stm32l562")]
const R1_EADR_OFFSET: u32 = 0x28; // End Address
#[cfg(feature = "stm32l562")]
const R1_NONCER0_OFFSET: u32 = 0x2C;
#[cfg(feature = "stm32l562")]
const R1_NONCER1_OFFSET: u32 = 0x30;
#[cfg(feature = "stm32l562")]
const R1_KEYR0_OFFSET: u32 = 0x34;
#[cfg(feature = "stm32l562")]
const R1_KEYR1_OFFSET: u32 = 0x38;
#[cfg(feature = "stm32l562")]
const R1_KEYR2_OFFSET: u32 = 0x3C;
#[cfg(feature = "stm32l562")]
const R1_KEYR3_OFFSET: u32 = 0x40;

#[cfg(feature = "stm32l562")]
pub struct OfdDriver {
    regs: *const u32,
}

#[cfg(not(feature = "stm32l562"))]
pub struct OfdDriver; 

#[derive(Clone, Copy)]
pub enum Region {
    Region1 = 0,
    Region2 = 1,
    Region3 = 2,
    Region4 = 3,
}

pub enum KeyMode {
    Instruction = 0,
    Data = 1,
    InstructionAndData = 2,
}

pub struct Config {
    pub start_addr: u32,
    pub end_addr:   u32,
    /// 64-bit nonce stored as a big-endian byte array: `nonce[0]` is
    /// the most-significant byte, `nonce[7]` the least-significant.
    /// `configure_region` maps `nonce[0..4]` → NONCER1 (high word)
    /// and `nonce[4..8]` → NONCER0 (low word).
    pub nonce:      [u8; 8],
    /// 128-bit AES key stored as a big-endian byte array: `key[0]` is
    /// the most-significant byte, `key[15]` the least-significant.
    /// `configure_region` maps `key[0..4]` → KEYR3 (most-significant
    /// 32-bit word) down to `key[12..16]` → KEYR0 (least-significant
    /// word), following the ST HAL convention where KEYR0 holds the
    /// LSW of the 128-bit key.
    pub key:        [u8; 16],
    pub mode:       KeyMode,
    pub enable:     bool,
}

#[cfg(feature = "stm32l562")]
impl OfdDriver {
    pub fn new() -> Self {
        let regs = OTFDEC_BASE_ADDR as *const u32;
        
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::OTFDEC);
        
        Self { regs }
    }
    
    pub fn configure_region(&mut self, region: Region, config: Config) {
        let region_idx = region as u32;
        let cfgr_off   = R1_CFGR_OFFSET    + region_idx * REGION_STRIDE;
        let sadr_off   = R1_SADR_OFFSET    + region_idx * REGION_STRIDE;
        let eadr_off   = R1_EADR_OFFSET    + region_idx * REGION_STRIDE;
        let nonce0_off = R1_NONCER0_OFFSET + region_idx * REGION_STRIDE;
        let nonce1_off = R1_NONCER1_OFFSET + region_idx * REGION_STRIDE;
        let key0_off   = R1_KEYR0_OFFSET   + region_idx * REGION_STRIDE;
        let key1_off   = R1_KEYR1_OFFSET   + region_idx * REGION_STRIDE;
        let key2_off   = R1_KEYR2_OFFSET   + region_idx * REGION_STRIDE;
        let key3_off   = R1_KEYR3_OFFSET   + region_idx * REGION_STRIDE;

        unsafe {
            // 1. Disable region.
            clear_register_bit(self.regs, cfgr_off, 0); // REG_EN

            if !config.enable {
                return;
            }

            // 2. MODE before KEY (MODE write clears KEY register per AN5281 §3.4).
            let mode_val: u32 = match config.mode {
                KeyMode::Instruction        => 0,
                KeyMode::Data               => 1,
                KeyMode::InstructionAndData => 2,
            };
            let mut cfgr = read_register(self.regs, cfgr_off);
            cfgr &= !(0b11 << 4);
            cfgr |=  mode_val << 4;
            write_register(self.regs, cfgr_off, cfgr);

            // 3. KEY (128-bit, written MSB-first per AN5281).
            write_register(self.regs, key0_off, u32::from_be_bytes(config.key[12..16].try_into().unwrap()));
            write_register(self.regs, key1_off, u32::from_be_bytes(config.key[ 8..12].try_into().unwrap()));
            write_register(self.regs, key2_off, u32::from_be_bytes(config.key[ 4.. 8].try_into().unwrap()));
            write_register(self.regs, key3_off, u32::from_be_bytes(config.key[ 0.. 4].try_into().unwrap()));

            // 4. NONCE (64-bit).
            write_register(self.regs, nonce0_off, u32::from_be_bytes(config.nonce[4..8].try_into().unwrap()));
            write_register(self.regs, nonce1_off, u32::from_be_bytes(config.nonce[0..4].try_into().unwrap()));

            // 5. Start / End addresses.
            write_register(self.regs, sadr_off, config.start_addr);
            write_register(self.regs, eadr_off, config.end_addr);

            // 6. Enable region.
            set_register_bit(self.regs, cfgr_off, 0); // REG_EN
        }
    }

    pub fn is_region_enabled(&self, region: Region) -> bool {
        let base = R1_CFGR_OFFSET + (region as u32 * REGION_STRIDE);
        unsafe {
            let val = read_register(self.regs, base);
            (val & 1) != 0
        }
    }

    /// Reads the OTFDEC Interrupt Status Register (ISR, offset 0x300).
    /// Bits: SEIF=0 (security error), XONEIF=1 (execute-only non-exec),
    /// KEIF=2 (key error). Used for bringup telemetry and fault diagnosis.
    pub fn isr(&self) -> u32 {
        unsafe { read_register(self.regs, OTFDEC_ISR_OFFSET) }
    }

    /// Clears all OTFDEC interrupt flags (SEIF | XONEIF | KEIF) via ICR (offset 0x304).
    pub fn icr_clear(&mut self) {
        unsafe { write_register(self.regs, OTFDEC_ICR_OFFSET, 0x7); }
    }

    /// Set or clear the ENC (encryption mode) bit in the OTFDEC CR register.
    ///
    /// Per STM32L562.svd OTFDEC1.CR: ENC is bit 0 (bitOffset=0, bitWidth=1).
    /// When ENC=1, OTFDEC operates in enciphering mode (plaintext in → ciphertext
    /// written to flash via OCTOSPI). When ENC=0, it operates in the default
    /// deciphering mode (ciphertext in flash → plaintext at AHB read time).
    ///
    /// Call this before `configure_region` so the region is enabled with the
    /// correct ENC state already in CR.
    pub fn set_enciphering(&mut self, enabled: bool) {
        unsafe {
            if enabled {
                set_register_bit(self.regs, OTFDEC_CR_OFFSET, 0);
            } else {
                clear_register_bit(self.regs, OTFDEC_CR_OFFSET, 0);
            }
        }
    }
}
