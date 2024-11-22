//////////////////////////////////////////////////////////////////////////////////////
//    __  __                                   _                            _       //
//   |  \/  | ___ _ __ ___   ___  _ __ _   _  | |    __ _ _   _  ___  _   _| |_     //
//   | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | | | |   / _` | | | |/ _ \| | | | __|    //
//   | |  | |  __/ | | | | | (_) | |  | |_| | | |__| (_| | |_| | (_) | |_| | |_     //
//   |_|  |_|\___|_| |_| |_|\___/|_|   \__, | |_____\__,_|\__, |\___/ \__,_|\__|    //
//                                     |___/              |___/                     //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                   //
//                                                                              //
// Description:                                                                 //    
//      Umbra sees memory as a set of logical blocks, called memory blocks.
//      
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////

pub const MEMORY_BLOCK_SIZE: u32 = 256;
pub const MEMORY_SUPER_BLOCK_SIZE: u32 = MEMORY_BLOCK_SIZE*16;

//////////////////
// Enumerations //
//////////////////
#[derive(Copy, Clone)]
pub enum MemoryBlockAccessAttribute {
    ReadOnly,
    ReadWrite,
    ReadExecutable
}

// A memory block can be either Trusted or Untrusted
// Some architectures supports also the TrustedGateway attribute 
// (e.g. TrustZone-M NSC)
#[derive(Copy, Clone)]
pub enum MemoryBlockSecurityAttribute {
    Untrusted,
    Trusted,
    TrustedGateway
}

/////////////////
// MemoryBlock //
/////////////////

#[derive(Copy, Clone)]
pub struct MemoryBlock {
    block_base_address: u32,
    block_access_attribute: MemoryBlockAccessAttribute,
    block_security_attribute: MemoryBlockSecurityAttribute
}

impl MemoryBlock {
    // Constructor for default values
    pub fn new() -> Self {
        Self {
            block_base_address: 0x0,
            block_access_attribute: MemoryBlockAccessAttribute::ReadOnly,
            block_security_attribute: MemoryBlockSecurityAttribute::Untrusted,
        }
    }

    // Constructor for custom values
    pub fn create( 
        block_base_address: u32,
        block_access_attribute: MemoryBlockAccessAttribute,
        block_security_attribute: MemoryBlockSecurityAttribute
    ) -> Self {

        Self {
            block_base_address,
            block_access_attribute,
            block_security_attribute
        }
    }

    ///////////////////////
    // Getters & Setters //
    ///////////////////////
    
    // Getter for block_base_address
    pub fn get_block_base_address(&self) -> u32 {
        self.block_base_address
    }

    // Setter for block_base_address
    pub fn set_block_base_address(&mut self, address: u32) {
        self.block_base_address = address;
    }

    // Getter for block_access_attribute
    pub fn get_block_access_attribute(&self) -> &MemoryBlockAccessAttribute {
        &self.block_access_attribute
    }

    // Setter for block_access_attribute
    pub fn set_block_access_attribute(&mut self, attribute: MemoryBlockAccessAttribute) {
        self.block_access_attribute = attribute;
    }

    // Getter for block_security_attribute
    pub fn get_block_security_attribute(&self) -> &MemoryBlockSecurityAttribute {
        &self.block_security_attribute
    }

    // Setter for block_security_attribute
    pub fn set_block_security_attribute(&mut self, attribute: MemoryBlockSecurityAttribute) {
        self.block_security_attribute = attribute;
    }

}

/////////////////////
// MemoryBlockList //
/////////////////////

// A memory block list is a contiguous list of MemoryBlocks
// That shares the same attributes

pub struct MemoryBlockList {
    memory_block: MemoryBlock,
    memory_block_list_size: u32
}

impl MemoryBlockList {
    // Constructor for default values
    pub fn new() -> Self {
        Self {
            memory_block: MemoryBlock::new(),
            memory_block_list_size: 0x0,
        }
    }

    // Constructor for custom values
    pub fn create( 
        memory_block: MemoryBlock,
        memory_block_list_size: u32
    ) -> Self {

        Self {
            memory_block,
            memory_block_list_size
        }
    }

    // Create a memory block list from a memory region
    pub fn create_from_range(
        base_addr: u32,
        limit_addr: u32
    ) -> Self {

        let mut memory_block = MemoryBlock::new();
        memory_block.set_block_base_address(base_addr/MEMORY_BLOCK_SIZE as u32);

        let mut memory_block_list_size = (limit_addr - base_addr)/MEMORY_BLOCK_SIZE as u32;

        // Check if the block_num must be ceiled or not
        if limit_addr & 0x000000ff != 0 {
            memory_block_list_size += 1;
        }

        Self {
            memory_block,
            memory_block_list_size,
        }
    }

    ///////////////////////
    // Getters & Setters //
    ///////////////////////

    // Getter for memory_block
    pub fn get_memory_block(&self) -> MemoryBlock {
        self.memory_block
    }

    // Setter for memory_block
    pub fn set_memory_block(&mut self, block: MemoryBlock) {
        self.memory_block = block;
    }

    // Getter for memory_block_list_size
    pub fn get_memory_block_list_size(&self) -> u32 {
        self.memory_block_list_size
    }

    // Setter for memory_block_list_size
    pub fn set_memory_block_list_size(&mut self, size: u32) {
        self.memory_block_list_size = size;
    }

    // Setter for memory_block_list attribute
    pub fn set_memory_block_security(&mut self, attribute: MemoryBlockSecurityAttribute) {
        let mut memory_block = self.get_memory_block();
        memory_block.set_block_security_attribute(attribute);
        self.set_memory_block(memory_block);
    }

}
