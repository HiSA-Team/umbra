

// STM32L5xxx Global TrustZone Controller

// Using Rust Naming conventions https://rust-lang.github.io/api-guidelines/naming.html
// Documentation is the STM32L552xx and STM32L562xx advanced Arm-based 32-bit MCUs rewference manual

//
// The Global TrustZone Controller enables the configuration of TrustZone security for programmable-security
// bus agents, such as on-chip RAM with secure blocks, AHB/APB peripherals with secure/privilege access,
// secure AHB masters, and off-chip memories with secure areas.
// 
// it includes the following three components, 
// 
// TZSC (TrustZone® Security Controller):
// 	    Manages the secure/privilege state of peripherals and controls the non-secure area size
// 	    for the watermark memory peripheral controller (MPCWM). It communicates secure statuses
// 	    to peripherals like RCC and GPIOs.
// 
// MPCBB (Block-Based Memory Protection Controller):
// 	    Regulates the secure states of 256-byte blocks within SRAM.
// 
// TZIC (TrustZone® Illegal Access Controller):
// 	    Monitors and reports illegal access events by generating secure interrupts to the NVIC.
//


// Crates
use peripheral_regs::*;
use kernel::common::memory_layout::MEMORY_BLOCK_SIZE;
use kernel::common::memory_layout::MemoryBlockList;
use kernel::common::memory_layout::MemoryBlockSecurityAttribute;
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;

//////////////////////////////////////////////////
//    ___                 _      _              //
//   |   \ ___ ___ __ _ _(_)_ __| |_ ___ _ _    //
//   | |) / -_|_-</ _| '_| | '_ \  _/ _ \ '_|   //
//   |___/\___/__/\__|_| |_| .__/\__\___/_|     //
//                         |_|                  //
//////////////////////////////////////////////////

const GTZC_BASE_ADDR: u32 = 0x40032400;
type GtzcRegisters = u32;

//////////////////////////////////////////////
//     ___             _            _       //
//    / __|___ _ _  __| |_ __ _ _ _| |_ ___ //
//   | (__/ _ \ ' \(_-<  _/ _` | ' \  _(_-< //
//    \___\___/_||_/__/\__\__,_|_||_\__/__/ //
//                                          //
//////////////////////////////////////////////

///////////////////////////////////
// TrustZone Security Controller //
///////////////////////////////////

// TBD

//////////////////////////////////////////////
// Block-based Memory Protection Controller //
//////////////////////////////////////////////

const GTZC_MPCBB1_BASE_OFFSET : u32 = 0x800;
const GTZC_MPCBB2_BASE_OFFSET : u32 = 0xC00;

// Memory Protection Controller 1/2 - Control Register
const _GTZC_MPCBB_CR_REG                 : u32 = 0x000;
const _GTZC_MPCBB_CR_LCK_FIELD           : u16 = 0x0100;
const _GTZC_MPCBB_CR_INVSECSTATE_FIELD   : u16 = 0x011e;
const _GTZC_MPCBB_CR_SRWILADIS           : u16 = 0x011f;
// Memory Protection Controller 1/2 - Lock Register
const _GTZC_MPCBB_LCKVTR1_REG            : u32 = 0x010;
// Memory Protection Controller 1/2 - Vector Register
const GTZC_MPCBB_VCTR_Y_REG             : u32 = 0x100;

/////////////////////////////////////////////
// TrustZone Security Interrupt Controller //
/////////////////////////////////////////////

// TBD


//////////////////////////////////////////////////////////////////////
//    ___            _                   _        _   _             //
//   |_ _|_ __  _ __| |___ _ __  ___ _ _| |_ __ _| |_(_)___ _ _     //
//    | || '  \| '_ \ / -_) '  \/ -_) ' \  _/ _` |  _| / _ \ ' \    //
//   |___|_|_|_| .__/_\___|_|_|_\___|_||_\__\__,_|\__|_\___/_||_|   //
//             |_|                                                  //
//////////////////////////////////////////////////////////////////////


/////////////////////////// 
// GTZC Peripheral Driver //
///////////////////////////

pub struct GtzcDriver {
    regs: &'static mut GtzcRegisters,
}

impl GtzcDriver {

    // Constructor
    pub fn new() -> Self {
        let regs = unsafe { &mut *(GTZC_BASE_ADDR as *mut GtzcRegisters) };
        Self { regs }
    }

    // The MPCBB sees memory as organized in blocks.
    // A block is 256 Bytes in size, A superblock is 256x32 = 8KB
    // SRAM1 is made of 192/8=24 super blocks, while SRAM2 has 8 superblocks

    // Currently unused, therefore commented
    /*pub unsafe fn set_memory_bank_security( &mut self, memory_bank_id : u8, secure_flag: u8 ) {

        // Disclaimer: SRAM sizes are hardcoded atm, they shall be taken from the linker script symbol
        let sram1_size : u32 = 24; 
        let sram2_size : u32 = 8; 

        let curr_bank_size = if memory_bank_id == 0 {sram1_size} else {sram2_size};

        for i in 0..curr_bank_size {
            self.set_memory_superblock_security(memory_bank_id, i as u8, secure_flag );
        }
    }

    pub unsafe fn set_memory_superblock_security( &mut self, memory_bank_id : u8, super_block_id : u8, secure_flag: u8 ) {
        
        let regs_base_address = self.regs as *const GtzcRegisters as *const u32;

        let mut block_reg_offset = GTZC_MPCBB_VCTR_Y_REG + (super_block_id as u32)*4;

        if memory_bank_id == 0 {
            block_reg_offset += GTZC_MPCBB1_BASE_OFFSET;
        } else {
            block_reg_offset += GTZC_MPCBB2_BASE_OFFSET;
        }

        let secure_data = if secure_flag == 0 {0x00000000} else {0xffffffff};
        write_register(regs_base_address, block_reg_offset, secure_data);

    }*/

    // This function sets block X in superblock Y security attribute
    pub unsafe fn set_memory_block_security( &mut self, memory_bank_id : u8, super_block_id : u8, block_id : u8, secure_flag: u8 ) {

        let regs_base_address = self.regs as *const GtzcRegisters as *const u32;

        let mut block_reg_offset = GTZC_MPCBB_VCTR_Y_REG + (super_block_id as u32)*4;

        if memory_bank_id == 0 {
            block_reg_offset += GTZC_MPCBB1_BASE_OFFSET;
        } else {
            block_reg_offset += GTZC_MPCBB2_BASE_OFFSET;
        }

        let block_bitmask = 1 << block_id;

        if secure_flag == 0 {
            clear_register_field(regs_base_address, block_reg_offset, 0x1f00, block_bitmask);
        } else {
            set_register_field(regs_base_address, block_reg_offset, 0x1f00, block_bitmask);
        }

    }

}


//////////////////////////////
//    _____         _ _     //
//   |_   _| _ __ _(_) |_   //
//     | || '_/ _` | |  _|  //  
//     |_||_| \__,_|_|\__|  //
//                          //
//////////////////////////////

impl MemorySecurityGuardTrait for GtzcDriver {

    fn memory_security_guard_init(&mut self) {
        // Let's enable secure reads/writes to non-secure pages
        let regs_base_address = self.regs as *const GtzcRegisters as *const u32;
        unsafe {
            write_register(regs_base_address, 0x800, 0x80000000);
            write_register(regs_base_address, 0xC00, 0x80000000);
        }
    }

    fn memory_security_guard_create(&mut self, memory_block_list: & MemoryBlockList) {

        /////////////////////////////////////////////////////////////////////
        // NOTES: Sanitizations and Error Handling are not implemented yet //
        /////////////////////////////////////////////////////////////////////

        // These are all placeholders and shall be replaced with linker script symbols
        let bank1_start = 0x20000000;
        let _bank1_end = 0x20030000;
        let _bank2_start = 0x20030000;
        let bank2_end = 0x20040000;

        // Get base and limit address for the region
        let mut region_base_address: u32 = MEMORY_BLOCK_SIZE*(memory_block_list.get_memory_block().get_block_base_address());

        // Does the requested region fall into the GTZC owned memory?
        if region_base_address < bank1_start || region_base_address >= bank2_end {
            // Ignore this region definition (NB: for future we will need some error/warning handling)
            return; 
        }

        // Identify the security attribute for the blocks
        let secure_flag: u8;
        match memory_block_list.get_memory_block().get_block_security_attribute() {
            MemoryBlockSecurityAttribute::Untrusted => { secure_flag = 0x0; }
            MemoryBlockSecurityAttribute::Trusted =>  { secure_flag = 0x1; }
            // This is a placeholder, since no TG are defined for the GTZC
            MemoryBlockSecurityAttribute::TrustedGateway => { return; }
        }

        // Compute Bank, Superblock and Block
        let gtzc_block_per_memory_block = MEMORY_BLOCK_SIZE / 256;
        let gtzc_block_num = memory_block_list.get_memory_block_list_size()*gtzc_block_per_memory_block;

        unsafe {
            for _i in 0..gtzc_block_num {

                // Parse block info from address
                let upper_address_id = (region_base_address >> 13) & 0x1f;
                let lower_address_id = (region_base_address >> 8) & 0x1f;

                let bank_id: u8;
                let super_block_id: u8;
                let block_id: u8;

                if (upper_address_id >> 3) != 0x3 {
                    // Bank 1 (first 24 superblocks)
                    bank_id = 0 as u8;
                    super_block_id = upper_address_id as u8;
                } else {
                    // Bank 2 (last 8 superblocks)
                    bank_id = 1 as u8;
                    super_block_id = (upper_address_id & 0x7) as u8;
                }

                block_id = lower_address_id as u8;

                // Set security for the block
                self.set_memory_block_security( bank_id, super_block_id, block_id, secure_flag );
                region_base_address += 256;
            }
            
        }
    }
}