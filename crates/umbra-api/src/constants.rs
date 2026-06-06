//! Const layout — memory regions, block sizes, max-instance counts.
//! Stub for. Today these live in
//! `src/kernel/src/common/memory_layout.rs` and
//! `src/kernel/src/common/ess.rs`. Moving the platform-agnostic ones
//! here keeps the kernel from being the "single source of truth" for
//! every consumer.
//! Platform-specific constants (per-board memory map) stay
//! platform-feature-gated in the kernel; they can't live in a leaf API.
