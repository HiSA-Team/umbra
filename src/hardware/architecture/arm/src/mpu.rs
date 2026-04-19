//////////////////////////////////////////////////////////////////
//                                                              //
// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>  //
//                                                              //
// Description:                                                 //
//      ARM Memory Protection Unit (MPU) Driver for Cortex-M33  //
//                                                              //
//////////////////////////////////////////////////////////////////

// Crates
use peripheral_regs::*;

//////////////////////////////////////////////////
//    __  __ ___ _   _                          //
//   |  \/  | _ \ | | |                         //
//   | |\/| |  _/ |_| |                         //
//   |_|  |_|_|  \___/                          //
//                                              //
//////////////////////////////////////////////////

const MPU_BASE_ADDR: u32 = 0xE000ED90;
type MpuRegisters = u32;

//////////////////////////////////////////////
//     ___             _            _       //
//    / __|___ _ _  __| |_ __ _ _ _| |_ ___ //
//   | (__/ _ \ ' \(_-<  _/ _` | ' \  _(_-< //
//    \___\___/_||_/__/\__\__,_|_||_\__/__/ //
//                                          //
//////////////////////////////////////////////

//////////////////////////
// MPU Type Register    //
//////////////////////////
const MPU_TYPE_REG              : u32 = 0x00;
const _MPU_TYPE_DREGION_FIELD    : u16 = 0x0808; // Number of MPU regions

//////////////////////////
// MPU Control Register //
//////////////////////////
const MPU_CTRL_REG              : u32 = 0x04;
const MPU_CTRL_PRIVDEFENA_FIELD : u16 = 0x0102; // Privileged default memory map enable
const _MPU_CTRL_HFNMIENA_FIELD   : u16 = 0x0101; // HardFault and NMI enable
const MPU_CTRL_ENABLE_FIELD     : u16 = 0x0100; // MPU enable

/////////////////////////////////
// MPU Region Number Register  //
/////////////////////////////////
const MPU_RNR_REG               : u32 = 0x08;

///////////////////////////////////////
// MPU Region Base Address Register  //
///////////////////////////////////////
const MPU_RBAR_REG              : u32 = 0x0C;
// Bits [31:5]: Base address (32-byte aligned)
// Bits [4:3]: SH (Shareability)
// Bits [2:1]: AP (Access Permissions)
// Bit [0]: XN (Execute Never)

/////////////////////////////////////////
// MPU Region Limit Address Register   //
/////////////////////////////////////////
const MPU_RLAR_REG              : u32 = 0x10;
// Bits [31:5]: Limit address (32-byte aligned)
// Bits [3:1]: AttrIndx (MAIR index)
// Bit [0]: EN (Region Enable)


//////////////////////////////////////////////
// MPU Memory Attribute Indirection Register//
//////////////////////////////////////////////
const MPU_MAIR0_REG             : u32 = 0x30;
const MPU_MAIR1_REG             : u32 = 0x34;


//////////////////////////////////////////////////////////////////////
//    ___            _                   _        _   _             //
//   |_ _|_ __  _ __| |___ _ __  ___ _ _| |_ __ _| |_(_)___ _ _     //
//    | || '  \| '_ \ / -_) '  \/ -_) ' \  _/ _` |  _| / _ \ ' \    //
//   |___|_|_|_| .__/_\___|_|_|_\___|_||_\__\__,_|\__|_\___/_||_|   //
//             |_|                                                  //
//////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy)]
pub enum MpuAccessPermission {
    RWPrivilegedOnly = 0b00,
    RWAny            = 0b01,
    ROPrivilegedOnly = 0b10,
    ROAny            = 0b11,
}

#[derive(Clone, Copy)]
pub enum MpuShareability {
    NonShareable   = 0b00,
    OuterShareable = 0b10,
    InnerShareable = 0b11,
}

#[derive(Clone, Copy)]
pub enum MpuExecuteNever {
    ExecutionPermitted = 0,
    ExecutionNever     = 1,
}

pub struct MpuRegionConfig {
    pub rnum: u8,
    pub base_addr: u32,
    pub limit_addr: u32,
    pub ap: MpuAccessPermission,
    pub sh: MpuShareability,
    pub xn: MpuExecuteNever,
    pub attr_index: u8,
    pub enable: bool,
}

impl MpuRegionConfig {
    pub fn new() -> Self {
        Self {
            rnum: 0,
            base_addr: 0,
            limit_addr: 0,
            ap: MpuAccessPermission::RWPrivilegedOnly,
            sh: MpuShareability::NonShareable,
            xn: MpuExecuteNever::ExecutionNever,
            attr_index: 0,
            enable: false,
        }
    }
}

///////////////////////////
// MPU Driver            //
///////////////////////////

pub struct MpuDriver {
    regs: &'static mut MpuRegisters,
}

impl MpuDriver {

    // Constructor
    pub fn new() -> Self {
        let regs = unsafe { &mut *(MPU_BASE_ADDR as *mut MpuRegisters) };
        Self { regs }
    }

    // Initialize MPU: Disable and clear all regions
    pub unsafe fn init(&mut self) {
        let regs_base_address = self.regs as *const MpuRegisters as *const u32;

        // Disable MPU
        self.disable();

        // Get number of regions
        let type_reg = read_register(regs_base_address, MPU_TYPE_REG);
        let dregion = (type_reg >> 8) & 0xFF;

        // Clear all regions
        for i in 0..dregion {
            write_register(regs_base_address, MPU_RNR_REG, i);
            write_register(regs_base_address, MPU_RBAR_REG, 0);
            write_register(regs_base_address, MPU_RLAR_REG, 0);
        }
    }

    pub unsafe fn enable(&mut self) {
        let regs_base_address = self.regs as *const MpuRegisters as *const u32;
        // Enable MPU with default memory map for privileged access (PRIVDEFENA)
        // This ensures that if no region matches and code is privileged, it uses default map.
        
        // Enable PRIVDEFENA (Bit 2)
        set_register_field(regs_base_address, MPU_CTRL_REG, MPU_CTRL_PRIVDEFENA_FIELD, 1);
        // Enable MPU (Bit 0)
        set_register_field(regs_base_address, MPU_CTRL_REG, MPU_CTRL_ENABLE_FIELD, 1);
    }

    pub unsafe fn disable(&mut self) {
        let regs_base_address = self.regs as *const MpuRegisters as *const u32;
        clear_register_bit(regs_base_address, MPU_CTRL_REG, 0);
    }

    // Configure Memory Attribute Indirection Registers (MAIR)
    // attr0..attr3 go to MAIR0, attr4..attr7 go to MAIR1
    // Each attribute is 8 bits.
    pub unsafe fn set_mair(&mut self, attr_idx: u8, attr_val: u8) {
        if attr_idx > 7 { return; }

        let regs_base_address = self.regs as *const MpuRegisters as *const u32;
        let reg_offset = if attr_idx < 4 { MPU_MAIR0_REG } else { MPU_MAIR1_REG };
        let shift = (attr_idx % 4) * 8;
        
        // Read-Modify-Write
        let mut val = read_register(regs_base_address, reg_offset);
        val &= !(0xFF << shift);
        val |= (attr_val as u32) << shift;
        write_register(regs_base_address, reg_offset, val);
    }

    pub unsafe fn configure_region(&mut self, config: &MpuRegionConfig) {
        let regs_base_address = self.regs as *const MpuRegisters as *const u32;

        // Select region
        write_register(regs_base_address, MPU_RNR_REG, config.rnum as u32);

        // MPU_RBAR: Base Address + SH + AP + XN
        let rbar = (config.base_addr & 0xFFFF_FFE0) 
                 | ((config.sh as u32) << 3)
                 | ((config.ap as u32) << 1)
                 | (config.xn as u32);
        
        write_register(regs_base_address, MPU_RBAR_REG, rbar);

        // MPU_RLAR: Limit Address + AttrIndx + EN
        // Limit Address in RLAR is bits [31:5] of the address.
        let rlar = (config.limit_addr & 0xFFFF_FFE0)
                 | ((config.attr_index as u32 & 0x7) << 1)
                 | (if config.enable { 1 } else { 0 });

        write_register(regs_base_address, MPU_RLAR_REG, rlar);
    }
}
