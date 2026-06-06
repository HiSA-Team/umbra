#![allow(dead_code)]
// STM32L5xxx Global TrustZone Controller

// Using Rust Naming conventions https://rust-lang.github.io/api-guidelines/naming.html
// Documentation is the STM32L552xx and STM32L562xx advanced Arm-based 32-bit MCUs rewference manual

// The Global TrustZone Controller enables the configuration of TrustZone security for programmable-security
// bus agents, such as on-chip RAM with secure blocks, AHB/APB peripherals with secure/privilege access,
// secure AHB masters, and off-chip memories with secure areas.
// it includes the following three components,
// TZSC (TrustZone® Security Controller):
// 	 Manages the secure/privilege state of peripherals and controls the non-secure area size
// 	 for the watermark memory peripheral controller (MPCWM). It communicates secure statuses
// 	 to peripherals like RCC and GPIOs.
// MPCBB (Block-Based Memory Protection Controller):
// 	 Regulates the secure states of 256-byte blocks within SRAM.
// TZIC (TrustZone® Illegal Access Controller):
// 	 Monitors and reports illegal access events by generating secure interrupts to the NVIC.

// Crates
use kernel::common::memory_layout::MemoryBlockList;
use kernel::common::memory_layout::MemoryBlockSecurityAttribute;
use kernel::common::memory_layout::MEMORY_BLOCK_SIZE;
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
use peripheral_regs::{
    clear_register_field, read_register, set_register_field, MmioAccess, RealMmio,
};

//////////////////////////////////////////////////
// ___ _ _ //
// | \ ___ ___ __ _ _(_)_ __| |_ ___ _ _ //
// | |) / -_|_-</ _| '_| | '_ \ _/ _ \ '_| //
// |___/\___/__/\__|_| |_|.__/\__\___/_| //
// |_| //
//////////////////////////////////////////////////

const GTZC_BASE_ADDR: u32 = 0x40032400;
// Secure alias of GTZC1; MPCBB VCTR registers are secure-only, so writes
// through the NS alias (0x40032400) from secure mode are silently ignored.
// `mpcbb_set_slot_secure` uses this directly.
const GTZC1_SEC_BASE_ADDR: u32 = 0x50032400;
type GtzcRegisters = u32;

//////////////////////////////////////////////
// ___ _ _ //
// / __|___ _ _ __| |_ __ _ _ _| |_ ___ //
// | (__/ _ \ ' \(_-< _/ _` | ' \ _(_-< //
// \___\___/_||_/__/\__\__,_|_||_\__/__/ //
// //
//////////////////////////////////////////////

///////////////////////////////////
// TrustZone Security Controller //
///////////////////////////////////

// TBD

//////////////////////////////////////////////
// Block-based Memory Protection Controller //
//////////////////////////////////////////////

const GTZC_MPCBB1_BASE_OFFSET: u32 = 0x800;
const GTZC_MPCBB2_BASE_OFFSET: u32 = 0xC00;

// Memory Protection Controller 1/2 - Control Register
const _GTZC_MPCBB_CR_REG: u32 = 0x000;
const _GTZC_MPCBB_CR_LCK_FIELD: u16 = 0x0100;
const _GTZC_MPCBB_CR_INVSECSTATE_FIELD: u16 = 0x011e;
const _GTZC_MPCBB_CR_SRWILADIS: u16 = 0x011f;
// Memory Protection Controller 1/2 - Lock Register
const _GTZC_MPCBB_LCKVTR1_REG: u32 = 0x010;
// Memory Protection Controller 1/2 - Vector Register
const GTZC_MPCBB_VCTR_Y_REG: u32 = 0x100;

// CR-register init value used by `memory_security_guard_init` —
// SRWILADIS (bit 31) = 1 → allow secure read/write to non-secure pages.
const GTZC_MPCBB_CR_INIT_VALUE: u32 = 0x80000000;

/////////////////////////////////////////////
// TrustZone Security Interrupt Controller //
/////////////////////////////////////////////

// TBD

//////////////////////////////////////////////////////////////////////
// ___ _ _ _ _ //
// |_ _|_ __ _ __| |___ _ __ ___ _ _| |_ __ _| |_(_)___ _ _ //
// | || ' \| '_ \ / -_) ' \/ -_) ' \ _/ _` | _| / _ \ ' \ //
// |___|_|_|_|.__/_\___|_|_|_\___|_||_\__\__,_|\__|_\___/_||_| //
// |_| //
//////////////////////////////////////////////////////////////////////

///////////////////////////
// GTZC Peripheral Driver //
///////////////////////////

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `GtzcDriver::new()` call site
/// unchanged at the source level — the firmware build monomorphises to
/// `GtzcDriver<RealMmio>` and inlines the volatile accesses through the
/// secure alias (`0x5003_2400`) exactly as before.
/// The driver instance covers the MPCBB-block configuration path; the
/// fault-handler-callable [`mpcbb_set_slot_secure`] free function below
/// remains pointer-based because the MemManage/SecureFault dispatch path
/// has no driver handle available.
pub struct GtzcDriver<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl GtzcDriver<RealMmio> {
    // Constructor — uses the secure alias so MPCBB VCTR writes take effect.
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(GTZC1_SEC_BASE_ADDR),
        }
    }
}

impl<M: MmioAccess> GtzcDriver<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `GtzcDriver::new()` which
    /// monomorphises to `GtzcDriver<RealMmio>` and inlines the volatile
    /// accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    // The MPCBB sees memory as organized in blocks.
    // A block is 256 Bytes in size, A superblock is 256x32 = 8KB
    // SRAM1 is made of 192/8=24 super blocks, while SRAM2 has 8 superblocks

    // This function sets block X in superblock Y security attribute.
    // Preserves the byte-identical register-write sequence of the
    // pre-migration implementation: the VCTR offset is computed exactly the
    // same way (base VCTR_Y + superblock*4 + bank-base) and the
    // set/clear of bit `block_id` goes through a read-modify-write that
    // matches `peripheral_regs::{set,clear}_register_bit`.
    pub fn set_memory_block_security(
        &mut self,
        memory_bank_id: u8,
        super_block_id: u8,
        block_id: u8,
        secure_flag: u8,
    ) {
        let mut block_reg_offset = GTZC_MPCBB_VCTR_Y_REG + (super_block_id as u32) * 4;

        if memory_bank_id == 0 {
            block_reg_offset += GTZC_MPCBB1_BASE_OFFSET;
        } else {
            block_reg_offset += GTZC_MPCBB2_BASE_OFFSET;
        }

        if secure_flag == 0 {
            self.mmio.clear_bit(block_reg_offset, block_id);
        } else {
            self.mmio.set_bit(block_reg_offset, block_id);
        }
    }
}

/// Flip a single 256 B SRAM slot's MPCBB security attribute without owning a
/// `GtzcDriver`. Callable from the MemManage/SecureFault dispatch path where
/// no driver handle is available.
/// `addr` may be either the NS alias (`0x200xxxxx`) or the secure alias
/// (`0x300xxxxx`); bits [17:13] (superblock) and [12:8] (block) are identical
/// across the two aliases. Only SRAM1 bank is implemented — EFBC lives there.
/// The hardware half of the `UmbraIntegrityFixValidator.pv`
/// ESS-miss path: when the Validator installs a block, the caller flips the
/// corresponding slot back to Secure; when eviction (or boot-time preload cap)
/// marks a slot unloaded, the caller flips it to NS so a subsequent secure
/// instruction fetch into it raises SecureFault INVEP.
/// # Ordering invariant for page-load (CRITICAL — caused the ndes / statemate crash)
/// When called as part of a DMA-driven page-load:
/// 1. **First** call this with `secure = false` to drop the slot to NS.
/// 2. **Then** issue the DMA transfer that populates the slot via the NS
/// alias.
/// 3. **Then** call this again with `secure = true` to re-lock.
/// Reversing steps 1↔2 (DMA before flip) makes GTZC silently drop the
/// transfer; the destination slot retains whatever stale SRAM bytes were
/// there at boot and the subsequent in-place AES decrypt produces garbage
/// from garbage. The ESS-miss-recovery path already satisfies this because
/// `evict_block` flipped the slot to NS at eviction time. The force-load
/// path in `umbra_enclave_create_imp` does NOT — those slots have never
/// been evicted — which is why `handle_ess_miss` had to start with an
/// explicit `mpcbb_set_slot_secure(addr, false); dsb(); isb()` (idempotent
/// for the recovery path, mandatory for force-load).
/// NOTE — kept as a free function on the secure-alias raw pointer because
/// MemManage/SecureFault dispatch (`handlers.rs`, `lifecycle.rs`,
/// `exit.rs`) calls it from contexts that have no driver handle. The
/// MmioAccess migration intentionally does NOT move this path through
/// the generic — it would force every fault handler to thread a
/// `GtzcDriver` reference through the dispatch table.
pub unsafe fn mpcbb_set_slot_secure(addr: u32, secure: bool) {
    let normalized = addr & 0xEFFF_FFFF;
    let upper = (normalized >> 13) & 0x1f;
    let lower = (normalized >> 8) & 0x1f;

    // Bank 1 (SRAM1, 24 superblocks) uses MPCBB1; bank 2 (SRAM2, 8 superblocks)
    // uses MPCBB2 and its superblock index is `upper & 0x7`.
    let (super_block_id, bank_offset) = if (upper >> 3) != 0x3 {
        (upper as u8, GTZC_MPCBB1_BASE_OFFSET)
    } else {
        ((upper & 0x7) as u8, GTZC_MPCBB2_BASE_OFFSET)
    };
    let block_id = lower as u8;

    let mut block_reg_offset = GTZC_MPCBB_VCTR_Y_REG + (super_block_id as u32) * 4;
    block_reg_offset += bank_offset;

    let regs_base_address = GTZC1_SEC_BASE_ADDR as *const u32;
    let block_bitmask = 1 << block_id;
    if secure {
        set_register_field(regs_base_address, block_reg_offset, 0x1f00, block_bitmask);
    } else {
        clear_register_field(regs_base_address, block_reg_offset, 0x1f00, block_bitmask);
    }
}

/// Like [`mpcbb_set_slot_secure`], but reads the MPCBB SECCFG register back
/// and verifies the targeted block bit actually flipped. Returns `true` on
/// success, `false` if the controller silently refused the write (e.g. the
/// MPCBB config is locked via `GTZC_MPCBB.CR.LCK`, or the block index decoded
/// out of the bank's range).
///
/// The plain setter is fire-and-forget by design (it is called from fault
/// dispatch contexts that cannot fail). This checked variant exists for the
/// ESS-miss install path, where a refused flip-to-NS would make the
/// subsequent NS-alias DMA silently drop — the 2026-05-24 `ndes`/`statemate`
/// landmine. The caller maps `false` to `UmbraError::MemProtectDenied`.
///
/// # Safety
/// Same contract as [`mpcbb_set_slot_secure`]: `addr` must be a valid SRAM
/// address whose MPCBB superblock/block decode is in range.
pub unsafe fn mpcbb_set_slot_secure_checked(addr: u32, secure: bool) -> bool {
    mpcbb_set_slot_secure(addr, secure);

    // Re-decode the same superblock/block coordinates the setter used and
    // read the SECCFG register back. `set/clear_register_field(.., 0x1f00,
    // 1 << block_id)` toggles exactly bit `block_id`, so the slot's secure
    // state is that single bit.
    let normalized = addr & 0xEFFF_FFFF;
    let upper = (normalized >> 13) & 0x1f;
    let lower = (normalized >> 8) & 0x1f;
    let (super_block_id, bank_offset) = if (upper >> 3) != 0x3 {
        (upper as u8, GTZC_MPCBB1_BASE_OFFSET)
    } else {
        ((upper & 0x7) as u8, GTZC_MPCBB2_BASE_OFFSET)
    };
    let block_id = lower as u8;
    let block_reg_offset = GTZC_MPCBB_VCTR_Y_REG + (super_block_id as u32) * 4 + bank_offset;
    let regs_base_address = GTZC1_SEC_BASE_ADDR as *const u32;

    let reg_val = read_register(regs_base_address, block_reg_offset);
    let bit_is_secure = ((reg_val >> block_id) & 1) == 1;
    bit_is_secure == secure
}

//////////////////////////////
// _____ _ _ //
// |_ _| _ __ _(_) |_ //
// | || '_/ _` | | _| //
// |_||_| \__,_|_|\__| //
// //
//////////////////////////////

impl<M: MmioAccess> MemorySecurityGuardTrait for GtzcDriver<M> {
    fn memory_security_guard_init(&mut self) {
        // Let's enable secure reads/writes to non-secure pages.
        // Writes MPCBB1_CR (offset 0x800) and MPCBB2_CR (offset 0xC00)
        // with SRWILADIS (bit 31) set — byte-identical to the pre-migration
        // sequence.
        self.mmio.write(0x800, GTZC_MPCBB_CR_INIT_VALUE);
        self.mmio.write(0xC00, GTZC_MPCBB_CR_INIT_VALUE);
    }

    fn memory_security_guard_create(&mut self, memory_block_list: &MemoryBlockList) {
        /////////////////////////////////////////////////////////////////////
        // NOTES: Sanitizations and Error Handling are not implemented yet //
        /////////////////////////////////////////////////////////////////////

        // These are all placeholders and shall be replaced with linker script symbols
        let bank1_start = 0x20000000;
        let _bank1_end = 0x20030000;
        let _bank2_start = 0x20030000;
        let bank2_end = 0x20040000;

        // Get base and limit address for the region
        let mut region_base_address: u32 = MEMORY_BLOCK_SIZE
            * (memory_block_list
                .get_memory_block()
                .get_block_base_address());

        // Does the requested region fall into the GTZC owned memory?
        if region_base_address < bank1_start || region_base_address >= bank2_end {
            // Ignore this region definition (NB: for future we will need some error/warning handling)
            return;
        }

        // Identify the security attribute for the blocks
        let secure_flag: u8;
        match memory_block_list
            .get_memory_block()
            .get_block_security_attribute()
        {
            MemoryBlockSecurityAttribute::Untrusted => {
                secure_flag = 0x0;
            }
            MemoryBlockSecurityAttribute::Trusted => {
                secure_flag = 0x1;
            }
            // This is a placeholder, since no TG are defined for the GTZC
            MemoryBlockSecurityAttribute::TrustedGateway => {
                return;
            }
        }

        // Compute Bank, Superblock and Block
        let gtzc_block_per_memory_block = MEMORY_BLOCK_SIZE / 256;
        let gtzc_block_num =
            memory_block_list.get_memory_block_list_size() * gtzc_block_per_memory_block;

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
            self.set_memory_block_security(bank_id, super_block_id, block_id, secure_flag);
            region_base_address += 256;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `memory_security_guard_init` issues two writes to the
    /// MPCBB CR registers at the documented offsets, both with the
    /// SRWILADIS bit (31) asserted. This is byte-identical to the
    /// pre-MmioAccess sequence — CJ3 confidentiality relies on the
    /// CR-register init order, so the test pins both the addresses and
    /// the value.
    #[test]
    fn memory_security_guard_init_writes_mpcbb1_then_mpcbb2_cr() {
        let mem = MmioMem::new(GTZC1_SEC_BASE_ADDR);
        let mut gtzc = GtzcDriver::<_>::new_with_mmio(mem.handle());
        gtzc.memory_security_guard_init();

        let log = mem.write_log();
        assert_eq!(log.len(), 2, "log = {:?}", log);

        match log[0] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, GTZC1_SEC_BASE_ADDR + 0x800);
                assert_eq!(value, GTZC_MPCBB_CR_INIT_VALUE);
            }
            _ => panic!("expected Write MPCBB1_CR at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, GTZC1_SEC_BASE_ADDR + 0xC00);
                assert_eq!(value, GTZC_MPCBB_CR_INIT_VALUE);
            }
            _ => panic!("expected Write MPCBB2_CR at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies `set_memory_block_security` performs a read-modify-write
    /// on the correct VCTR register (offset = VCTR_Y + superblock*4 +
    /// bank-base) that sets bit `block_id` for secure=1 and clears it for
    /// secure=0, preserving the other bits in the register. The address
    /// arithmetic is the load-bearing piece — getting it wrong on a heavy
    /// paper-app's MPCBB flip drops DMA writes silently (per the ndes /
    /// statemate post-mortem).
    #[test]
    fn set_memory_block_security_targets_correct_vctr_and_preserves_other_bits() {
        let mem = MmioMem::new(GTZC1_SEC_BASE_ADDR);

        // Bank 0 (SRAM1) → MPCBB1 base 0x800; superblock 3 → offset += 12.
        // VCTR_Y is 0x100. block_id 5 → bit 5.
        const BANK_ID: u8 = 0;
        const SUPER_BLOCK_ID: u8 = 3;
        const BLOCK_ID: u8 = 5;

        let expected_vctr_offset: u32 = 0x800 + 0x100 + (SUPER_BLOCK_ID as u32) * 4;
        let expected_vctr_addr: u32 = GTZC1_SEC_BASE_ADDR + expected_vctr_offset;

        // Preload with all-bits-set on some unrelated bits so the
        // preservation property is observable for both the set and clear
        // paths.
        const UNRELATED_BITS: u32 = 0xF000_0001;
        mem.preload_register(expected_vctr_offset, UNRELATED_BITS);

        let mut gtzc = GtzcDriver::<_>::new_with_mmio(mem.handle());

        // secure=1 → set bit BLOCK_ID via RMW.
        gtzc.set_memory_block_security(BANK_ID, SUPER_BLOCK_ID, BLOCK_ID, 1);
        // secure=0 → clear bit BLOCK_ID via RMW.
        gtzc.set_memory_block_security(BANK_ID, SUPER_BLOCK_ID, BLOCK_ID, 0);

        let log = mem.write_log();
        // set_bit = 1 Read + 1 Write
        // clear_bit = 1 Read + 1 Write
        assert_eq!(log.len(), 4, "log = {:?}", log);

        // Op 0: Read VCTR.
        match log[0] {
            MmioOp::Read { addr, .. } => assert_eq!(addr, expected_vctr_addr),
            _ => panic!("expected Read at position 0, got {:?}", log[0]),
        }
        // Op 1: Write VCTR with bit BLOCK_ID set + unrelated bits preserved.
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, expected_vctr_addr);
                assert_eq!(value, UNRELATED_BITS | (1u32 << BLOCK_ID));
            }
            _ => panic!("expected Write at position 1, got {:?}", log[1]),
        }
        // Op 2: Read VCTR (RMW for clear).
        match log[2] {
            MmioOp::Read { addr, .. } => assert_eq!(addr, expected_vctr_addr),
            _ => panic!("expected Read at position 2, got {:?}", log[2]),
        }
        // Op 3: Write VCTR with bit BLOCK_ID cleared back; unrelated bits
        // still preserved.
        match log[3] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, expected_vctr_addr);
                assert_eq!(value, UNRELATED_BITS);
            }
            _ => panic!("expected Write at position 3, got {:?}", log[3]),
        }
    }

    /// Verifies bank-id 1 routes to MPCBB2 (0xC00) rather than MPCBB1
    /// (0x800). SRAM2 bank attribution is the path used for EFBC fallback
    /// blocks — getting the bank dispatch wrong silently mis-attributes
    /// the slot.
    #[test]
    fn set_memory_block_security_bank1_uses_mpcbb2_offset() {
        let mem = MmioMem::new(GTZC1_SEC_BASE_ADDR);

        const BANK_ID: u8 = 1; // SRAM2 → MPCBB2 base 0xC00
        const SUPER_BLOCK_ID: u8 = 2;
        const BLOCK_ID: u8 = 0;

        let expected_vctr_offset: u32 = 0xC00 + 0x100 + (SUPER_BLOCK_ID as u32) * 4;
        let expected_vctr_addr: u32 = GTZC1_SEC_BASE_ADDR + expected_vctr_offset;

        let mut gtzc = GtzcDriver::<_>::new_with_mmio(mem.handle());
        gtzc.set_memory_block_security(BANK_ID, SUPER_BLOCK_ID, BLOCK_ID, 1);

        let log = mem.write_log();
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, expected_vctr_addr);
                assert_eq!(value, 1u32 << BLOCK_ID);
            }
            _ => panic!("expected Write at position 1, got {:?}", log[1]),
        }
    }
}
