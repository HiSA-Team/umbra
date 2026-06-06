//! Kernel panic handler — delegates to `common::panic_policy::handle`.
//! The UART log + reset/halt behaviour lives in `panic_policy` so every
//! fault path goes through one decision point (see ADR
//! the panic-policy ADR).
//! `#[panic_handler]` is bare-metal-only: under `cargo test` the test
//! harness pulls in `std` which already defines `panic_impl`, so the
//! attribute would collide. cfg-gates it on the same
//! `target_arch = "arm" + target_os = "none"` predicate `panic_policy`
//! uses internally, unlocking `cargo test -p kernel` host-side.

#[cfg(all(target_arch = "arm", target_os = "none"))]
use core::panic::PanicInfo;

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::common::panic_policy::handle(info)
}
