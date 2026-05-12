//! ARMv8-M core register addresses (Private Peripheral Bus, 0xE000_xxxx).
//!
//! Single source of truth for MMIO pointers shared by the L552/L562/N657
//! boot crates and driver code. Naming follows the ARMv8-M Architecture
//! Reference Manual.
//!
//! All constants are `*mut u32`; callers wrap accesses in `unsafe {}` and
//! provide a `// SAFETY:` comment per `clippy::undocumented_unsafe_blocks`.

// ─── SCB: System Control Block (0xE000_ED00 …) ───────────────────────────────
pub const SCB_ICSR:   *mut u32 = 0xE000_ED04 as *mut u32;
pub const SCB_VTOR:   *mut u32 = 0xE000_ED08 as *mut u32;
/// Configuration & Control Register. M55 cache-enable bits live here:
/// bit 16 = DC, bit 17 = IC.
pub const SCB_CCR:    *mut u32 = 0xE000_ED14 as *mut u32;
pub const SCB_SHCSR:  *mut u32 = 0xE000_ED24 as *mut u32;
pub const SCB_CFSR:   *mut u32 = 0xE000_ED28 as *mut u32;
pub const SCB_HFSR:   *mut u32 = 0xE000_ED2C as *mut u32;
pub const SCB_MMFAR:  *mut u32 = 0xE000_ED34 as *mut u32;
pub const SCB_BFAR:   *mut u32 = 0xE000_ED38 as *mut u32;
/// Cache Size ID Register (read after writing CSSELR).
pub const SCB_CCSIDR: *mut u32 = 0xE000_ED80 as *mut u32;
/// Cache Size Selection Register.
pub const SCB_CSSELR: *mut u32 = 0xE000_ED84 as *mut u32;
/// Secure Fault Status Register (Armv8-M Security Extension).
pub const SCB_SFSR:   *mut u32 = 0xE000_EDE4 as *mut u32;
/// Secure Fault Address Register (Armv8-M Security Extension).
pub const SCB_SFAR:   *mut u32 = 0xE000_EDE8 as *mut u32;

// ─── SysTick (0xE000_E010 …) ─────────────────────────────────────────────────
pub const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
pub const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
pub const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

// ─── NVIC: Nested Vectored Interrupt Controller (0xE000_E100 …) ─────────────
pub const NVIC_ISER0: *mut u32 = 0xE000_E100 as *mut u32;
pub const NVIC_ISER1: *mut u32 = 0xE000_E104 as *mut u32;
/// Interrupt Target Non-Secure register N (Armv8-M Security Extension).
/// Each register covers 32 IRQs; bit i selects NS-target for IRQ (32·N + i).
pub const NVIC_ITNS0: *mut u32 = 0xE000_E380 as *mut u32;
pub const NVIC_ITNS1: *mut u32 = 0xE000_E384 as *mut u32;

// ─── MPU: Memory Protection Unit (0xE000_ED90 …) ─────────────────────────────
pub const MPU_TYPE: *mut u32 = 0xE000_ED90 as *mut u32;
pub const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
pub const MPU_RNR:  *mut u32 = 0xE000_ED98 as *mut u32;
pub const MPU_RBAR: *mut u32 = 0xE000_ED9C as *mut u32;
pub const MPU_RLAR: *mut u32 = 0xE000_EDA0 as *mut u32;

// ─── SAU: Security Attribution Unit (0xE000_EDD0 …) ──────────────────────────
pub const SAU_CTRL: *mut u32 = 0xE000_EDD0 as *mut u32;

// ─── DWT: Data Watchpoint and Trace (0xE000_1000 …) ──────────────────────────
pub const DWT_CTRL:   *mut u32 = 0xE000_1000 as *mut u32;
pub const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;

// ─── Debug (0xE000_EDFC) ─────────────────────────────────────────────────────
/// Debug Exception & Monitor Control Register. Bit 24 (TRCENA) gates the
/// DWT cycle counter on Cortex-M33/M55; must be set before DWT_CTRL.CYCCNTENA.
pub const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;

// ─── Cache maintenance (Cortex-M55 only, 0xE000_EF50 …) ──────────────────────
/// Invalidate I-cache all (write any value).
pub const ICIALLU:  *mut u32 = 0xE000_EF50 as *mut u32;
/// Invalidate D-cache by MVA to PoC.
pub const DCIMVAC:  *mut u32 = 0xE000_EF5C as *mut u32;
/// Invalidate D-cache by set/way (used during cache init).
pub const DCISW:    *mut u32 = 0xE000_EF60 as *mut u32;
/// Clean D-cache by MVA to PoC (does NOT invalidate).
pub const DCCMVAC:  *mut u32 = 0xE000_EF68 as *mut u32;
/// Clean+Invalidate D-cache by MVA to PoC (writes dirty lines then drops).
pub const DCCIMVAC: *mut u32 = 0xE000_EF70 as *mut u32;
