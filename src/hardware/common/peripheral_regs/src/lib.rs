
//////////////////////////////////////////////////////////
//    ____           _       _                    _     //
//   |  _ \ ___ _ __(_)_ __ | |__   ___ _ __ __ _| |    //
//   | |_) / _ \ '__| | '_ \| '_ \ / _ \ '__/ _` | |    //
//   |  __/  __/ |  | | |_) | | | |  __/ | | (_| | |    //
//   |_|   \___|_|  |_| .__/|_| |_|\___|_|  \__,_|_|    //
//    ____            |_|   _                           //
//   |  _ \ ___  __ _(_)___| |_ ___ _ __ ___            //
//   | |_) / _ \/ _` | / __| __/ _ \ '__/ __|           //
//   |  _ <  __/ (_| | \__ \ ||  __/ |  \__ \           //  
//   |_| \_\___|\__, |_|___/\__\___|_|  |___/           //
//              |___/                                   //
//////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                   //
//                                                                              //
// Description:                                                                 //    
//      This module offers fundamental functions for accessing                  //
//      peripheral registers. Supported operations include read, write,         //
//      clear, and set. It is the responsibility of the peripheral to           //
//      define the base address of the registers and apply offsets as needed.   //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////

#![crate_name = "peripheral_regs"]
#![crate_type = "rlib"]
#![no_std]

use core::ptr;

pub unsafe fn read_register(regs_base_address: *const u32, reg_offset: u32) -> u32 {
    let regs_base_address_u = regs_base_address as u32;
    let value = ptr::read_volatile((regs_base_address_u + reg_offset) as *const u32);
    return value;
}

pub unsafe fn write_register(regs_base_address: *const u32, reg_offset: u32, value: u32) {
    let regs_base_address_u = regs_base_address as u32;
    ptr::write_volatile((regs_base_address_u + reg_offset) as *mut u32, value);
}

pub unsafe fn set_register_bit(regs_base_address: *const u32, reg_offset: u32, bit: u8) {
    let reg_val = read_register(regs_base_address, reg_offset);
    write_register(regs_base_address, reg_offset, reg_val | (1 << bit));
}

pub unsafe fn clear_register_bit(regs_base_address: *const u32, reg_offset: u32, bit: u8) {
    let reg_val = read_register(regs_base_address, reg_offset);
    write_register(regs_base_address, reg_offset, reg_val & !(1 << bit));
}

pub unsafe fn set_register_field(regs_base_address: *const u32, reg_offset: u32, val: u16, mask: u32) {

    let field_size = val >> 8;
    let field_start = val & 0x00ff;

    for field_cnt in 0..field_size+1 {
        if ((mask >> field_cnt) & 0x1) == 1 {
            let curr_bit = (field_start + field_cnt) as u8;
            set_register_bit(regs_base_address, reg_offset, curr_bit);
        }
    }
}

pub unsafe fn clear_register_field(regs_base_address: *const u32, reg_offset: u32, val: u16, mask: u32) {
    
    let field_size = val >> 8;
    let field_start = val & 0x00ff;

    for field_cnt in 0..field_size+1 {
        if ((mask >> field_cnt) & 0x1) == 1 {
            let curr_bit = (field_start + field_cnt) as u8;
            clear_register_bit(regs_base_address, reg_offset, curr_bit);
        }
    }
}