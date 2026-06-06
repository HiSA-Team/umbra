//////////////////////////////////////////////////////////
// ____ _ _ _ //
// | _ \ ___ _ __(_)_ __ | |__ ___ _ __ __ _| | //
// | |_) / _ \ '__| | '_ \| '_ \ / _ \ '__/ _` | | //
// | __/ __/ | | | |_) | | | | __/ | | (_| | | //
// |_| \___|_| |_|.__/|_| |_|\___|_| \__,_|_| //
// ____ |_| _ //
// | _ \ ___ __ _(_)___| |_ ___ _ __ ___ //
// | |_) / _ \/ _` | / __| __/ _ \ '__/ __| //
// | _ < __/ (_| | \__ \ || __/ | \__ \ //
// |_| \_\___|\__, |_|___/\__\___|_| |___/ //
// |___/ //
//////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
// //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it> //
// //
// Description: //
// This module offers fundamental functions for accessing //
// peripheral registers. Supported operations include read, write, //
// clear, and set. It is the responsibility of the peripheral to //
// define the base address of the registers and apply offsets as needed. //
// //
//////////////////////////////////////////////////////////////////////////////////

#![crate_name = "peripheral_regs"]
#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

use core::ptr;

/// # Safety
/// `regs_base_address + reg_offset` must point to a valid MMIO register,
/// 4-byte aligned, mapped Secure/NS consistently with the caller's view,
/// and not concurrently accessed by another context.
pub unsafe fn read_register(regs_base_address: *const u32, reg_offset: u32) -> u32 {
    let regs_base_address_u = regs_base_address as u32;
    ptr::read_volatile((regs_base_address_u + reg_offset) as *const u32)
}

/// # Safety
/// Same contract as [`read_register`]: the target address must be a valid,
/// aligned MMIO register accessible from the caller's security view.
pub unsafe fn write_register(regs_base_address: *const u32, reg_offset: u32, value: u32) {
    let regs_base_address_u = regs_base_address as u32;
    ptr::write_volatile((regs_base_address_u + reg_offset) as *mut u32, value);
}

/// # Safety
/// See [`read_register`] — issues an RMW pair on the same register.
pub unsafe fn set_register_bit(regs_base_address: *const u32, reg_offset: u32, bit: u8) {
    let reg_val = read_register(regs_base_address, reg_offset);
    write_register(regs_base_address, reg_offset, reg_val | (1 << bit));
}

/// # Safety
/// See [`read_register`] — issues an RMW pair on the same register.
pub unsafe fn clear_register_bit(regs_base_address: *const u32, reg_offset: u32, bit: u8) {
    let reg_val = read_register(regs_base_address, reg_offset);
    write_register(regs_base_address, reg_offset, reg_val & !(1 << bit));
}

/// # Safety
/// See [`read_register`] — RMW loop over `mask` bits within the register.
pub unsafe fn set_register_field(
    regs_base_address: *const u32,
    reg_offset: u32,
    val: u16,
    mask: u32,
) {
    let field_size = val >> 8;
    let field_start = val & 0x00ff;

    for field_cnt in 0..field_size + 1 {
        if ((mask >> field_cnt) & 0x1) == 1 {
            let curr_bit = (field_start + field_cnt) as u8;
            set_register_bit(regs_base_address, reg_offset, curr_bit);
        }
    }
}

/// # Safety
/// See [`read_register`] — RMW loop over `mask` bits within the register.
pub unsafe fn clear_register_field(
    regs_base_address: *const u32,
    reg_offset: u32,
    val: u16,
    mask: u32,
) {
    let field_size = val >> 8;
    let field_start = val & 0x00ff;

    for field_cnt in 0..field_size + 1 {
        if ((mask >> field_cnt) & 0x1) == 1 {
            let curr_bit = (field_start + field_cnt) as u8;
            clear_register_bit(regs_base_address, reg_offset, curr_bit);
        }
    }
}

/// typed MMIO accessor for host-testable drivers.
/// Drivers parameterise their structs as `Driver<M: MmioAccess = RealMmio>`.
/// On firmware build, `RealMmio` inlines to the existing volatile read/write
/// against `(base + offset) as *mut u32` — zero runtime cost. On host test,
/// `umbra_pal_test::mmio::MmioHandle` implements the same trait and records
/// each access into a log that tests can assert against.
/// The free functions above remain for the existing call sites that have
/// not yet migrated; new code should prefer the `MmioAccess` trait.
pub trait MmioAccess {
    /// Read a 32-bit register at `base + offset`.
    fn read(&self, offset: u32) -> u32;

    /// Write a 32-bit register at `base + offset`.
    fn write(&self, offset: u32, value: u32);

    /// Read-modify-write: set bit `bit` (0-31) at `base + offset`.
    fn set_bit(&self, offset: u32, bit: u8) {
        let v = self.read(offset);
        self.write(offset, v | (1u32 << bit));
    }

    /// Read-modify-write: clear bit `bit` (0-31) at `base + offset`.
    fn clear_bit(&self, offset: u32, bit: u8) {
        let v = self.read(offset);
        self.write(offset, v & !(1u32 << bit));
    }
}

/// Zero-cost real-hardware MMIO backend. The base address is held by value,
/// not as a `&'static mut Registers` reference, so multiple instances may
/// be constructed without violating Rust's borrow rules — discipline lives
/// with the driver author (which matches the existing pattern of letting
/// every peripheral driver materialise its own `&'static mut`).
#[derive(Clone, Copy)]
pub struct RealMmio {
    base: u32,
}

impl RealMmio {
    pub const fn new(base: u32) -> Self {
        Self { base }
    }
}

impl MmioAccess for RealMmio {
    fn read(&self, offset: u32) -> u32 {
        // SAFETY: caller guarantees `base + offset` is a valid MMIO address
        // for the peripheral. Inherited from the pre-existing free-function
        // pattern in this crate.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write(&self, offset: u32, value: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
}
