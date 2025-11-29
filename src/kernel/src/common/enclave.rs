//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>                      //
// Description:                                                                     //
//      Enclave data structures and header definitions                              //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

pub const EFB_SIZE: u32 = 256;
pub const UMBRA_HEADER_SIZE: u32 = 16;

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum EnclaveTrustLevel {
    Untrusted = 0,
    Trusted = 1,
}

/// Header EFB
/// 
/// 
///     +---------------------------+
///     |  magic (4 bytes)          |  
///     +---------------------------+
///     |  trust_level (1 byte)     |
///     +---------------------------+
///     |  reserved (1 byte)        |
///     +---------------------------+
///     |  efbc_size (2 bytes)      |
///     +---------------------------+
///     |  ess_blocks (2 bytes)     |
///     +---------------------------+
///     |  code_size (4 bytes)      | 
///     +---------------------------+
///     |  reserved (2 bytes)       |
///     +---------------------------+
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct UmbraEnclaveHeader {
    pub magic: u32,
    pub trust_level: u8,
    pub reserved0: u8,
    pub efbc_size: u16,
    pub ess_blocks: u16,
    pub code_size: u32,
    pub reserved1: u16,
}

impl UmbraEnclaveHeader {
    pub const MAGIC: u32 = 0x524D4255; // "UMBR" in little-endian

    pub unsafe fn from_address(addr: u32) -> Option<Self> {
        let header_ptr = addr as *const UmbraEnclaveHeader;
        let header = core::ptr::read_volatile(header_ptr);
        
        if header.magic == Self::MAGIC {
            Some(header)
        } else {
            None
        }
    }

    pub fn is_trusted(&self) -> bool {
        self.trust_level == EnclaveTrustLevel::Trusted as u8
    }

    pub fn code_offset(&self) -> u32 {
        UMBRA_HEADER_SIZE
    }

    pub fn efb_count(&self) -> u32 {
        (self.code_size + EFB_SIZE - 1) / EFB_SIZE
    }
}

#[derive(Copy, Clone)]
pub struct EnclaveDescriptor {
    pub id: u32,
    pub flash_base: u32,
    pub ram_base: u32,    
    pub code_size: u32,
    pub entry_point: u32,
    pub is_loaded: bool,
}

impl EnclaveDescriptor {
    pub fn new() -> Self {
        Self {
            id: 0,
            flash_base: 0,
            ram_base: 0,
            code_size: 0,
            entry_point: 0,
            is_loaded: false,
        }
    }
}