//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>                      //
// Description:                                                                     //
//      Enclave data structures and header definitions                              //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

pub const EFB_SIZE: u32 = 256;
pub const UMBRA_HEADER_SIZE: u32 = 48;

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
///     |  hmac (32 bytes)          |
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
    pub hmac: [u8; 32],
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

#[derive(Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum EnclaveState {
    Created    = 0,
    Ready      = 1,
    Running    = 2,
    Suspended  = 3,
    Terminated = 4,
    Faulted    = 5,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EnclaveContext {
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub psp: u32,
    pub lr: u32,
    pub control: u32,
    pub status: EnclaveState,
    pub result: u32,
}

impl EnclaveContext {
    pub const fn empty() -> Self {
        Self {
            r4: 0, r5: 0, r6: 0, r7: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            psp: 0, lr: 0, control: 0,
            status: EnclaveState::Created,
            result: 0,
        }
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