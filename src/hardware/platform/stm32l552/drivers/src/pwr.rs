// STM32L5xxxx PWR Driver
// This driver implements the Power control (PWR) peripheral present on STM32L5xxxx.
//
// Implements a minimal subset of PWR features needed by the other drivers.
#![allow(dead_code)]

// Crates
use peripheral_regs::*;
use crate::rcc::*;

const PWR_BASE_ADDR: u32 = 0x50007000; // Secure
type PwrRegisters = u32;

//   _____            _     _                
//  |  __ \          (_)   | |               
//  | |__) |___  __ _ _ ___| |_ ___ _ __ ___ 
//  |  _  // _ \/ _` | / __| __/ _ \ '__/ __|
//  | | \ \  __/ (_| | \__ \ ||  __/ |  \__ \
//  |_|  \_\___|\__, |_|___/\__\___|_|  |___/
//               __/ |                       
//              |___/                      
//
//
// TODO: Implement all registers
const PWR_CR1_BASE_OFFSET           : PwrRegisters = 0x00;
const PWR_CR2_BASE_OFFSET           : PwrRegisters = 0x04;
const PWR_CR3_BASE_OFFSET           : PwrRegisters = 0x08;
const PWR_CR4_BASE_OFFSET           : PwrRegisters = 0x0C;
const PWR_SR1_BASE_OFFSET           : PwrRegisters = 0x10;
const PWR_SR2_BASE_OFFSET           : PwrRegisters = 0x14;
const PWR_SCR_BASE_OFFSET           : PwrRegisters = 0x18;
const PWR_PUCRA_BASE_OFFSET         : PwrRegisters = 0x20;
const PWR_PDCRA_BASE_OFFSET         : PwrRegisters = 0x24;
const PWR_PUCRB_BASE_OFFSET         : PwrRegisters = 0x28;
const PWR_PDCRB_BASE_OFFSET         : PwrRegisters = 0x2C;
const PWR_PUCRC_BASE_OFFSET         : PwrRegisters = 0x30;
const PWR_PDCRC_BASE_OFFSET         : PwrRegisters = 0x34;

pub struct Pwr {
    regs: &'static mut PwrRegisters, 
}

impl Pwr {
    pub fn new() -> Self {
        let regs = unsafe { &mut *(PWR_BASE_ADDR as *mut PwrRegisters) };
        Self { regs }
    }
    
    pub fn enable_clock(&self) {
        let rcc = Rcc::new();
        rcc.enable_clock(peripherals::PWR);
    }
    
    pub fn enable_to_backup_domain(&self) {
        // DBP: Disable backup domain write protection,
        // Enable access to RTC and Backup Registers
        unsafe { set_register_bit(self.regs, PWR_CR1_BASE_OFFSET, 8); }

        // IOSB: Indicate that VDDIO2 is valid, needed for GPIOG[15:2]
        unsafe { set_register_bit(self.regs, PWR_CR2_BASE_OFFSET, 9); }
    }

    /// Set VOS = range 0 (Boost) in PWR_CR1.
    ///
    /// Required for SYSCLK > 80 MHz on STM32L5 (RM0438 §6.1.5).
    /// VOS field is bits [10:9] of PWR_CR1:
    ///   00 = reserved
    ///   01 = Range 1 (max 80 MHz)  ← reset default
    ///   10 = Range 2 (max 26 MHz)
    ///   00 with VOS field cleared = Range 0 boost (max 110 MHz)
    /// (RM0438 §6.4.1 — bit pattern is encoded as 00 = Range 0 / Boost.)
    ///
    /// After writing, polls PWR_SR2.VOSF (bit 10) until 0 (regulator
    /// settled at the new range). This must be called BEFORE raising
    /// SYSCLK above the previous VOS limit, otherwise the chip
    /// undervolts and hangs.
    pub fn set_vos_range_boost(&self) {
        // PWR_CR1.VOS bits [10:9]: clear to 00 = Range 0.
        // Safety: PWR_CR1 is the MMIO register at PWR_BASE + 0x00. Modifying
        // bits 10:9 changes voltage scaling; reset default is Range 1 (01).
        unsafe {
            let cr1 = read_register(self.regs, PWR_CR1_BASE_OFFSET);
            let new = cr1 & !(0b11 << 9);
            write_register(self.regs, PWR_CR1_BASE_OFFSET, new);
        }
        // Poll VOSF (PWR_SR2 bit 10) until 0 = regulator ready at new range.
        loop {
            // Safety: read-only readback of PWR_SR2.
            let sr2 = unsafe { read_register(self.regs, PWR_SR2_BASE_OFFSET) };
            if (sr2 & (1 << 10)) == 0 { break; }
        }
    }

    pub fn set_bit(&self, reg_offset: PwrRegisters, bit: u8) {
        unsafe { set_register_bit(self.regs, reg_offset, bit) }
    }
    pub fn clear_bit(&self, reg_offset: PwrRegisters, bit: u8) {
        unsafe { clear_register_bit(self.regs, reg_offset, bit) }
    }
}
