//! Secure-side kernel for STM32L552 — init, enclave enter / exit, lifecycle.
//! decomposition of the former 900-LOC `secure_kernel.rs`
//! into four submodules. The split is layered along ESS-block residency
//! lifetime rather than NSC boundary (NSC enter/exit live in
//! `kernel/asm/arm/nsc_veneers.s`, `api_impl.rs`, and `handlers.rs`):
//! - [`init`] — singleton bootstrap (struct, constants, key derivation,
//! measurement chain, SysTick, PC→block lookup,
//! `apply_relocs_to_block`).
//! - [`enter`] — block-into-residency at boot (BFS loader
//! `load_and_verify_block` + DMA scratch fetch
//! `fetch_block_to_scratch`).
//! - [`exit`] — block-out-of-residency runtime (UDF poisoning +
//! MPCBB flip in `evict_block`).
//! - [`lifecycle`] — runtime miss recovery (`handle_ess_miss` — full
//! fetch → validate → evict → install → relocate
//! cycle when MemManage IACCVIOL fires).
//! Every change in these submodules MUST preserve:
//! - **CJ2 chained-measurement invariant** — see `validator.rs` for the
//! chain semantics. Skipping or reordering the hash steps breaks the
//! root of trust.
//! - **ESS state-machine ordering** — see `kernel::common::ess` module
//! docs (#3 DMA→MPCBB flip ordering: `mpcbb_set_slot_secure(addr, false)`
//! MUST precede the DMA that populates the slot; reversing causes the
//! silent ndes / statemate failure).
//! - **Panic-policy delegation** — every failure path delegates to
//! `panic_policy::handle_fault()` (, see ADR
//! the panic-policy ADR). No raw `loop {}` or `panic!()` in
//! handlers; the policy module owns the reset-vs-halt choice.
//! - **SysTick reload sync** — `SYSTICK_RELOAD` and `startup.s::_svc_enter`'s
//! immediate must move together (see `drivers::rcc` docs).

pub mod enter;
pub mod exit;
pub mod init;
pub mod lifecycle;

pub use init::*;
