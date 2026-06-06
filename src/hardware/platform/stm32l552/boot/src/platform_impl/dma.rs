//! Dma channel reservation for the kernel-side ESS-miss path.
//!: per the submodule layout, the DMA channels
//! used by the ESS-miss recovery path (DMA1 channels 1-4 → NVIC IRQ
//! 29/30/31/32) are reserved by enabling the corresponding NVIC ISER
//! bits inside [`Stm32l5Platform::init_security_impl`] in
//! [`super::syscall_dispatch`].
//! The NVIC enables are kept inline at the original call site to
//! preserve byte-equivalence with the pre-split implementation — the
//! ordering vs the surrounding SAU/GTZC writes is load-bearing for the
//! L562 regression covered by commit `38fce6f`. This submodule
//! is the documented landing site for any future DMA channel allocator
//! or per-channel arbitration helper.
//! ## Channel map
//! | DMA controller | Channel | NVIC IRQ | User |
//! |----------------|---------|----------|----------------------------|
//! | DMA1 | 1 | 29 | ESS-miss path (HASH feed) |
//! | DMA1 | 2 | 30 | ESS-miss path (HASH feed) |
//! | DMA1 | 3 | 31 | ESS-miss path (HASH feed) |
//! | DMA1 | 4 | 32 | ESS-miss path (HASH feed) |
//! The DMA1/DMA2 peripheral clocks themselves are enabled in
//! [`super::boot::Stm32l5Platform::init_clocks_impl`] alongside the rest
//! of the bring-up sequence.
