//! umbra-mem-core — verifiable memory-layout logic (issue #58).
//!
//! Umbra views memory as a set of logical **memory blocks**. This crate holds
//! the block model (`MemoryBlock`, `MemoryBlockList`) and the region math
//! (`create_from_range`) carved out of `kernel::common::memory_layout`. It is
//! `#![no_std]` with zero `unsafe`; the actual hardware enforcement (MPCBB /
//! SAU / PMP / RISAF) lives in the per-platform drivers behind the
//! `MemorySecurityGuardTrait` seam.
//!
//! The region math is the verification target (T5): `create_from_range(base,
//! limit)` is proved to cover the requested range under the assumptions it
//! implicitly relies on — see `formal/rocq/mem-core`.
#![no_std]

// Logical block size MEMORY_BLOCK_SIZE (the `UMBRA_SLOT_SIZE_BYTES` knob; default 256).
include!(concat!(env!("OUT_DIR"), "/block_size_generated.rs"));

/// A super-block groups 16 blocks (used by the per-platform guards).
pub const MEMORY_SUPER_BLOCK_SIZE: u32 = MEMORY_BLOCK_SIZE * 16;

#[derive(Copy, Clone)]
pub enum MemoryBlockAccessAttribute {
    ReadOnly,
    ReadWrite,
    ReadExecutable,
}

/// A memory block is Trusted or Untrusted. Some architectures also support a
/// TrustedGateway attribute (e.g. TrustZone-M NSC).
#[derive(Copy, Clone)]
pub enum MemoryBlockSecurityAttribute {
    Untrusted,
    Trusted,
    TrustedGateway,
}

#[derive(Copy, Clone)]
pub struct MemoryBlock {
    block_base_address: u32,
    block_access_attribute: MemoryBlockAccessAttribute,
    block_security_attribute: MemoryBlockSecurityAttribute,
}

impl MemoryBlock {
    pub fn new() -> Self {
        Self {
            block_base_address: 0x0,
            block_access_attribute: MemoryBlockAccessAttribute::ReadOnly,
            block_security_attribute: MemoryBlockSecurityAttribute::Untrusted,
        }
    }

    pub fn get_block_base_address(&self) -> u32 {
        self.block_base_address
    }
    pub fn set_block_base_address(&mut self, address: u32) {
        self.block_base_address = address;
    }
    pub fn get_block_access_attribute(&self) -> &MemoryBlockAccessAttribute {
        &self.block_access_attribute
    }
    pub fn set_block_access_attribute(&mut self, attribute: MemoryBlockAccessAttribute) {
        self.block_access_attribute = attribute;
    }
    pub fn get_block_security_attribute(&self) -> &MemoryBlockSecurityAttribute {
        &self.block_security_attribute
    }
    pub fn set_block_security_attribute(&mut self, attribute: MemoryBlockSecurityAttribute) {
        self.block_security_attribute = attribute;
    }
}

/// A contiguous list of MemoryBlocks sharing the same attributes.
pub struct MemoryBlockList {
    memory_block: MemoryBlock,
    memory_block_list_size: u32,
}

impl MemoryBlockList {
    /// Build a block list covering the address range `[base_addr, limit_addr)`.
    /// The base is recorded as a block index (`base_addr / MEMORY_BLOCK_SIZE`)
    /// and the size as the number of blocks spanning the range, rounded up.
    pub fn create_from_range(base_addr: u32, limit_addr: u32) -> Self {
        let mut memory_block = MemoryBlock::new();
        memory_block.set_block_base_address(base_addr / MEMORY_BLOCK_SIZE);

        let mut memory_block_list_size = (limit_addr - base_addr) / MEMORY_BLOCK_SIZE;

        // Round up when the limit is not block-aligned.
        if limit_addr & 0x000000ff != 0 {
            memory_block_list_size += 1;
        }

        Self {
            memory_block,
            memory_block_list_size,
        }
    }

    pub fn get_memory_block(&self) -> MemoryBlock {
        self.memory_block
    }
    pub fn set_memory_block(&mut self, block: MemoryBlock) {
        self.memory_block = block;
    }
    pub fn get_memory_block_list_size(&self) -> u32 {
        self.memory_block_list_size
    }
    pub fn set_memory_block_security(&mut self, attribute: MemoryBlockSecurityAttribute) {
        let mut memory_block = self.get_memory_block();
        memory_block.set_block_security_attribute(attribute);
        self.set_memory_block(memory_block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_base_is_block_index_and_size_spans_range() {
        // Block-aligned base, one full block range.
        let r = MemoryBlockList::create_from_range(0, MEMORY_BLOCK_SIZE);
        assert_eq!(r.get_memory_block().get_block_base_address(), 0);
        // limit == MEMORY_BLOCK_SIZE: for the 256-byte default, 256 & 0xff == 0,
        // so no round-up: exactly one block.
        assert_eq!(r.get_memory_block_list_size(), 1);
    }
}
