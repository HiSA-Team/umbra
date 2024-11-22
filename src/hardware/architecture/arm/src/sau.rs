

// ARM Secure Attribution Unit

// Using Rust Naming conventions https://rust-lang.github.io/api-guidelines/naming.html

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

const SAU_BASE_ADDR: u32 = 0xE000EDD0;
type SauRegisters = u32;

//////////////////////////////////////////////
//     ___             _            _       //
//    / __|___ _ _  __| |_ __ _ _ _| |_ ___ //
//   | (__/ _ \ ' \(_-<  _/ _` | ' \  _(_-< //
//    \___\___/_||_/__/\__\__,_|_||_\__/__/ //
//                                          //
//////////////////////////////////////////////

//////////////////////////
// SAU Control Register //
//////////////////////////

const SAU_CTRL_REG          : u32 = 0x0;
// Lower byte is for the field starting bit, upper byte is for the length
const SAU_CTRL_ALLNS_FIELD  : u16 = 0x0101;
const SAU_CTRL_ENABLE_FIELD : u16 = 0x0100;

///////////////////////
// SAU Type Register //
///////////////////////

const SAU_TYPE_REG              : u32 = 0x4;
const _SAU_TYPE_SREGION_FIELD    : u16 = 0x0800;

///////////////////////////////
// SAU Region Numer Register //
///////////////////////////////

const SAU_RNR_REG           : u32 = 0x8;
const _SAU_RNR_REGION_FIELD  : u16 = 0x0800;

//////////////////////////////////////
// SAU Rebion Base Address Register //
//////////////////////////////////////

const SAU_RBAR_REG          : u32 = 0xC;
const _SAU_RBAR_BADDR_FIELD  : u16 = 0x1B05;

//////////////////////////
// SAU Control Register //
//////////////////////////

const SAU_RLAR_REG           : u32 = 0x10;
const _SAU_RLAR_LADDR_FIELD   : u16 = 0x1B05;
const _SAU_RLAR_NSC_FIELD     : u16 = 0x0101;
const SAU_RLAR_ENABLE_FIELD  : u16 = 0x0100;

//////////////////////////
// SAU Control Register //
//////////////////////////

const _SAU_SFSR_REG              : u32 = 0x14;
const _SAU_SFSR_LSERR_FIELD      : u16 = 0x0107;
const _SAU_SFSR_SFARVALID_FIELD  : u16 = 0x0106;
const _SAU_SFSR_LSPERR_FIELD     : u16 = 0x0105;
const _SAU_SFSR_INVTRAN_FIELD    : u16 = 0x0104;
const _SAU_SFSR_AUVIOL_FIELD     : u16 = 0x0103;
const _SAU_SFSR_INVER_FIELD      : u16 = 0x0102;
const _SAU_SFSR_INVIS_FIELD      : u16 = 0x0101;
const _SAU_SFSR_INVEP_FIELD      : u16 = 0x0100;

//////////////////////////
// SAU Control Register //
//////////////////////////

const _SAU_SFAR_REG  : u32 = 0x18;

//////////////////////////////////////////////////////////////////////
//    ___            _                   _        _   _             //
//   |_ _|_ __  _ __| |___ _ __  ___ _ _| |_ __ _| |_(_)___ _ _     //
//    | || '  \| '_ \ / -_) '  \/ -_) ' \  _/ _` |  _| / _ \ ' \    //
//   |___|_|_|_| .__/_\___|_|_|_\___|_||_\__\__,_|\__|_\___/_||_|   //
//             |_|                                                  //
//////////////////////////////////////////////////////////////////////

//////////////////////////////
// SAU Region Configuration //
//////////////////////////////

pub struct SauRegionConfig {
    base_addr   : u32,
    limit_addr  : u32,
    nsc         : u8,                    
    en          : u8,
    rnum        : u8
}

impl SauRegionConfig {

    pub fn new() -> Self {
        Self {
            base_addr   : 0x00000000,
            limit_addr  : 0x00000000,
            nsc         : 0x0,
            en          : 0x0,
            rnum        : 0x0
        }
    }

    // Getter and Setter for base_addr
    pub fn get_base_addr(&self) -> u32 {
        self.base_addr
    }

    pub fn set_base_addr(&mut self, value: u32) {
        self.base_addr = value;
    }

    // Getter and Setter for limit_addr
    pub fn get_limit_addr(&self) -> u32 {
        self.limit_addr
    }

    pub fn set_limit_addr(&mut self, value: u32) {
        self.limit_addr = value;
    }

    // Getter and Setter for nsc
    pub fn get_nsc(&self) -> u8 {
        self.nsc
    }

    pub fn set_nsc(&mut self, value: u8) {
        self.nsc = value;
    }

    // Getter and Setter for en
    pub fn get_en(&self) -> u8 {
        self.en
    }

    pub fn set_en(&mut self, value: u8) {
        self.en = value;
    }

    // Getter and Setter for rnum
    pub fn get_rnum(&self) -> u8 {
        self.rnum
    }

    pub fn set_rnum(&mut self, value: u8) {
        self.rnum = value;
    }
}

/////////////////////////// 
// SAU Peripheral Driver //
///////////////////////////

pub struct SauDriver {
    regs: &'static mut SauRegisters,
}

impl SauDriver {

    // Constructor
    pub fn new() -> Self {
        let regs = unsafe { &mut *(SAU_BASE_ADDR as *mut SauRegisters) };
        Self { regs }
    }

    // Initialize the SAU by cleaning all enable bits for SAU regions
    pub unsafe fn init(&mut self) {
        // By default, SAU regions are undefined at reset, we must clear them explicitly
        let regs_base_address = self.regs as *const SauRegisters as *const u32;
        let region_num : u8 = read_register(regs_base_address, SAU_TYPE_REG) as u8;

        for i in 0..region_num {
            // First, select the region
            write_register(regs_base_address, SAU_RNR_REG, i as u32);
            // Let's clear the region enable bit
            clear_register_field(regs_base_address, SAU_RLAR_REG, SAU_RLAR_ENABLE_FIELD, 0x1);
        }
        write_register(regs_base_address, SAU_RNR_REG, 0 as u32);
    }

    // Enable the SAU. By default, the whole memory map is IDAU defined (because of ALLNS)
    // Enabling the SAU disables the ALLNS behaviour, and enforces SAU one. If no region is
    // defined, and SAU is enabled, all CPU memory accesses are marked as secure.
    pub unsafe fn enable(&mut self) {

        let regs_base_address = self.regs as *const SauRegisters as *const u32;
        // Clear the ALLNS field (the whole memory map is secure as long as the SAU is disabled)
        clear_register_field(regs_base_address, SAU_CTRL_REG, SAU_CTRL_ALLNS_FIELD, 0x1);
        // Enable the SAU; ALLNS field will be ignored thereafter
        set_register_field(regs_base_address, SAU_CTRL_REG, SAU_CTRL_ENABLE_FIELD, 0x1); 
    }

    // Create a SAU region using a configuration.
    pub unsafe fn create_region(&mut self, config : &SauRegionConfig ) {

        let regs_base_address = self.regs as *const SauRegisters as *const u32;

        // The limit address that is passed from the configuration is the actual desired limit.
        // However, SAU regions must be at least 32 bytes in size, since last 5 bits are reserved
        // for NSC and enable bits.
        let limit_addr : u32 = (config.limit_addr & 0xffffffe0) | (config.nsc << 1) as u32 | (config.en) as u32; 

        // Select the region number. If a region already exists at that rnum, override it
        write_register(regs_base_address, SAU_RNR_REG, config.rnum as u32);
        write_register(regs_base_address, SAU_RBAR_REG, config.base_addr); 
        write_register(regs_base_address, SAU_RLAR_REG, limit_addr); 
    }

    // Search for a free region
    // NB - IT ASSUMES A FREE REGION ALWAYS EXIST, TO REFACTOR
    pub unsafe fn get_free_region(&mut self) -> u8 {
        let regs_base_address = self.regs as *const SauRegisters as *const u32;
        let region_num : u8 = read_register(regs_base_address, SAU_TYPE_REG) as u8;

        for i in 0..region_num {
            // First, select the region
            write_register(regs_base_address, SAU_RNR_REG, i as u32);
            // Let's read the region enable bit
            if (read_register(regs_base_address, SAU_RLAR_REG) & 0x1) == 0 {
                return i as u8;
            }
        }

        return 0 as u8;
    }

    // Delete Region
    // Get Sau Region Count
    // Get Sau Region

}

//////////////////////////////
//    _____         _ _     //
//   |_   _| _ __ _(_) |_   //
//     | || '_/ _` | |  _|  //  
//     |_||_| \__,_|_|\__|  //
//                          //
//////////////////////////////

impl MemorySecurityGuardTrait for SauDriver {

    fn memory_security_guard_init(&mut self) {
        unsafe { 
            self.init();
            self.enable();
        }
    }

    fn memory_security_guard_create(&mut self, memory_block_list: & MemoryBlockList) {

        let region_base_address: u32 = MEMORY_BLOCK_SIZE*(memory_block_list.get_memory_block().get_block_base_address());
        let region_limit_address: u32 = MEMORY_BLOCK_SIZE*(memory_block_list.get_memory_block_list_size()) + region_base_address;

        let security_attribute: u8;

        match memory_block_list.get_memory_block().get_block_security_attribute() {
            MemoryBlockSecurityAttribute::Untrusted => { security_attribute = 0x0; }
            MemoryBlockSecurityAttribute::Trusted =>  { return; } // This is a placeholder, since trusted regions definition in ARM are undefined
            MemoryBlockSecurityAttribute::TrustedGateway => { security_attribute = 0x1; }
        }

        unsafe {

            let region_num: u8 = self.get_free_region();
            let mut sau_region_config : SauRegionConfig = SauRegionConfig::new();

            sau_region_config.set_rnum(region_num as u8);
            sau_region_config.set_base_addr(region_base_address);
            sau_region_config.set_limit_addr(region_limit_address);
            sau_region_config.set_nsc(security_attribute);
            sau_region_config.set_en(0x1);
    
            self.create_region(&sau_region_config);
        }
    }
}