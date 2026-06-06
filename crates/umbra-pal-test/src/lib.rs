//! Host-side test platform for the Umbra kernel.
//! Provides software stand-ins for the HAL traits ([`TestHash`] for
//! SHA-256) and an in-memory MMIO backend ([`mmio::MmioMem`] +
//! [`mmio::MmioHandle`]) so that driver `#[cfg(test)] mod tests` blocks
//! can exercise the register-write recipe of a
//! `Driver<M: MmioAccess = RealMmio>` without silicon attached.

// Re-export so existing call sites can keep `use umbra_pal_test::Hash`.
pub use umbra_hal::Hash;

/// SHA-256 backed by the `sha2` crate — matches the byte-for-byte output
/// of the L552 HW HASH and the N657 SW SHA-256 implementations.
#[derive(Default)]
pub struct TestHash {
    state: sha2::Sha256,
}

impl TestHash {
    pub fn new() -> Self {
        Self::default()
    }
}

impl umbra_hal::Hash for TestHash {
    type Error = core::convert::Infallible;

    fn init(&mut self) -> Result<(), Self::Error> {
        use sha2::Digest;
        self.state = sha2::Sha256::new();
        Ok(())
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        use sha2::Digest;
        self.state.update(input);
        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8; 32]) -> Result<(), Self::Error> {
        use sha2::Digest;
        let digest = self.state.clone().finalize();
        output.copy_from_slice(&digest);
        Ok(())
    }
}

/// Host-side MMIO simulation. Wraps an in-memory register-space
/// (HashMap) and records every read/write so tests can assert against
/// an expected register-write recipe.
/// Drivers wrap their MMIO accesses behind a generic handle that on
/// hardware resolves to `core::ptr::read_volatile` / `write_volatile`,
/// and on host resolves to [`mmio::MmioHandle`]. The log captures the
/// operation sequence so tests can assert the driver issued the right
/// register writes without needing real silicon.
pub mod mmio {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type RegMap = HashMap<u32, u32>;

    /// Single MMIO operation recorded in the log.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum MmioOp {
        Read { addr: u32, value: u32 },
        Write { addr: u32, value: u32 },
    }

    /// Cloneable handle to a shared in-memory register space. Drivers
    /// under test hold this and issue `read` / `write` against it.
    #[derive(Clone)]
    pub struct MmioHandle {
        pub base: u32,
        regs: Arc<Mutex<RegMap>>,
        log: Arc<Mutex<Vec<MmioOp>>>,
    }

    /// Owning view over an in-memory register space. Tests build this,
    /// hand a clone of [`MmioHandle`] to the driver, then call
    /// [`write_log`] to assert the issued operation sequence.
    /// [`write_log`]: MmioMem::write_log
    pub struct MmioMem {
        handle: MmioHandle,
    }

    impl MmioMem {
        pub fn new(base: u32) -> Self {
            Self {
                handle: MmioHandle {
                    base,
                    regs: Arc::new(Mutex::new(HashMap::new())),
                    log: Arc::new(Mutex::new(Vec::new())),
                },
            }
        }

        pub fn handle(&self) -> MmioHandle {
            self.handle.clone()
        }

        pub fn write_log(&self) -> Vec<MmioOp> {
            self.handle.log.lock().unwrap().clone()
        }

        /// Seed a register with a value before the driver runs — useful
        /// for simulating HW-side state like "peripheral ready" bits.
        pub fn preload_register(&self, addr_offset: u32, value: u32) {
            self.handle
                .regs
                .lock()
                .unwrap()
                .insert(self.handle.base + addr_offset, value);
        }
    }

    impl MmioHandle {
        pub fn read(&self, addr_offset: u32) -> u32 {
            let addr = self.base + addr_offset;
            let value = *self.regs.lock().unwrap().get(&addr).unwrap_or(&0);
            self.log.lock().unwrap().push(MmioOp::Read { addr, value });
            value
        }

        pub fn write(&self, addr_offset: u32, value: u32) {
            let addr = self.base + addr_offset;
            self.regs.lock().unwrap().insert(addr, value);
            self.log.lock().unwrap().push(MmioOp::Write { addr, value });
        }
    }

    // Bridge: MmioHandle satisfies the same MmioAccess contract as RealMmio.
    // Drivers parameterised as `Driver<M: MmioAccess = RealMmio>` accept this
    // handle in tests with no further plumbing.
    impl peripheral_regs::MmioAccess for MmioHandle {
        fn read(&self, offset: u32) -> u32 {
            MmioHandle::read(self, offset)
        }

        fn write(&self, offset: u32, value: u32) {
            MmioHandle::write(self, offset, value);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn write_then_read_round_trip() {
            let mem = MmioMem::new(0x4000_0000);
            let h = mem.handle();
            h.write(0x10, 0xDEAD_BEEF);
            assert_eq!(h.read(0x10), 0xDEAD_BEEF);
            assert_eq!(
                mem.write_log(),
                vec![
                    MmioOp::Write {
                        addr: 0x4000_0010,
                        value: 0xDEAD_BEEF
                    },
                    MmioOp::Read {
                        addr: 0x4000_0010,
                        value: 0xDEAD_BEEF
                    },
                ]
            );
        }

        #[test]
        fn preload_seeds_register() {
            let mem = MmioMem::new(0x4000_0000);
            mem.preload_register(0x04, 0x0000_0001);
            assert_eq!(mem.handle().read(0x04), 0x0000_0001);
        }
    }
}
