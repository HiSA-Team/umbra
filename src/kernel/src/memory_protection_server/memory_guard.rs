

//////////////////////////////////////////////////////////////////
//                                                              //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>   //
//                                                              //
// Description (TBD)
//                                                              //
//////////////////////////////////////////////////////////////////

// The memory Guard module implements the methods to access the hardware-defined
// memory protection units implemented at a SoC level. Examples include the 
// Flash memory controllers, SRAM security controllers, CPU Memory protection units
// (e.g. SAU, Secure MPU, RISC-V PMP)

use crate::common::memory_layout::MemoryBlockList;

////////////////////////
// Memory Guard Trait //
////////////////////////

pub trait MemorySecurityGuardTrait {

    fn memory_security_guard_init(&mut self);
    // Create Region
    fn memory_security_guard_create(&mut self, memory_block_list: & MemoryBlockList);
    // Delete Region
    // Destroy

}

pub trait MemoryAccessGuardTrait {
    // TBD
}
