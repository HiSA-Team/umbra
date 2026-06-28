//! Host-testable mirror of the two PMP worlds Umbra swaps per ring transition
//! (see `book/src/decisions/008-riscv-spmp-arbitration.md`). PMP cannot tell S
//! from U, so the trusted U-mode enclave is protected from the more-privileged
//! S-mode host only by which PMP context is live. This type asserts the two
//! invariants off-target:
//!   1. host-world denies the enclave (ESS) region;
//!   2. enclave-world denies the host region (and W^X within the enclave).

/// Access kind requested against a world.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    Exec,
}

/// One granted PMP region `[base, end)` with its permission bits.
#[derive(Clone, Copy)]
struct Grant {
    base: u32,
    end: u32,
    r: bool,
    w: bool,
    x: bool,
}

impl Grant {
    fn covers(&self, addr: u32, want: Access) -> bool {
        if addr < self.base || addr >= self.end {
            return false;
        }
        match want {
            Access::Read => self.r,
            Access::Write => self.w,
            Access::Exec => self.x,
        }
    }
}

/// The PMP context for one world: a small set of grants. Anything not covered is
/// denied (PMP default-deny for S/U once any rule set is active).
pub struct PmpWorld {
    grants: [Option<Grant>; 4],
    n: usize,
}

impl PmpWorld {
    pub const fn new() -> Self {
        PmpWorld {
            grants: [None; 4],
            n: 0,
        }
    }

    fn grant(mut self, base: u32, end: u32, r: bool, w: bool, x: bool) -> Self {
        debug_assert!(self.n < 4, "PmpWorld grant overflow");
        self.grants[self.n] = Some(Grant { base, end, r, w, x });
        self.n += 1;
        self
    }

    /// True iff some grant covers `addr` with at least `want`.
    pub fn allows(&self, addr: u32, want: Access) -> bool {
        self.grants.iter().flatten().any(|g| g.covers(addr, want))
    }
}

impl Default for PmpWorld {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the host-world context: the host region RWX, ESS denied.
pub fn host_world(host_base: u32, host_end: u32) -> PmpWorld {
    PmpWorld::new().grant(host_base, host_end, true, true, true)
}

/// Build the enclave-world context: ESS code R-X, enclave stack R-W, host denied.
pub fn enclave_world(ess_base: u32, ess_end: u32, stack_base: u32, stack_end: u32) -> PmpWorld {
    PmpWorld::new()
        .grant(ess_base, ess_end, true, false, true)
        .grant(stack_base, stack_end, true, true, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MONITOR: u32 = 0x8000_4000; // monitor .data (uncovered in both worlds)
    const HOST_BASE: u32 = 0x8010_0000;
    const HOST_END: u32 = 0x8020_0000;
    const ESS_BASE: u32 = 0x8020_0000;
    const ESS_END: u32 = 0x8021_0000;
    const STK_BASE: u32 = 0x8021_0000;
    const STK_END: u32 = 0x8022_0000;

    fn host() -> PmpWorld {
        host_world(HOST_BASE, HOST_END)
    }
    fn enc() -> PmpWorld {
        enclave_world(ESS_BASE, ESS_END, STK_BASE, STK_END)
    }

    #[test]
    fn host_world_denies_enclave_ess() {
        // The key S>U fence: the S-mode host cannot read decrypted enclave code.
        assert!(!host().allows(ESS_BASE, Access::Read));
        assert!(host().allows(HOST_BASE, Access::Read)); // its own region is fine
        assert!(host().allows(HOST_BASE, Access::Exec)); // host runs its own code (RWX)
    }

    #[test]
    fn enclave_world_denies_host_and_monitor() {
        assert!(!enc().allows(HOST_BASE, Access::Read));
        assert!(!enc().allows(MONITOR, Access::Read));
        assert!(enc().allows(ESS_BASE, Access::Exec)); // its own code runs
    }

    #[test]
    fn enclave_code_is_execute_not_write_wxor() {
        assert!(enc().allows(ESS_BASE, Access::Exec));
        assert!(!enc().allows(ESS_BASE, Access::Write)); // W^X
        assert!(enc().allows(STK_BASE, Access::Write)); // stack is writable
        assert!(!enc().allows(STK_BASE, Access::Exec)); // but not executable
    }

    #[test]
    fn grants_are_half_open() {
        assert!(host().allows(HOST_BASE, Access::Read)); // base included
        assert!(!host().allows(HOST_BASE - 1, Access::Read)); // below base excluded
        assert!(!host().allows(HOST_END, Access::Read)); // end excluded
    }

    #[test]
    fn empty_world_denies_everything() {
        let w = PmpWorld::new();
        assert!(!w.allows(HOST_BASE, Access::Read));
        assert!(!w.allows(ESS_BASE, Access::Exec));
    }
}
