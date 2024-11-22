
use core::panic::PanicInfo;

// The reset vector, a pointer into the reset handler
// The reset function is defined in cortem crate ;)

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}




