/* STM32L552 chip-level memory regions (Non-Secure alias).
 *
 * Umbra Secure owns 0x08000000-0x0803FFFF (first 256 KB of flash) plus SRAM2
 * (0x20030000-0x2003FFFF, 64 KB). The host NS world gets the remainder:
 * 256 KB of flash at 0x08040000 + 192 KB of SRAM1 at 0x20000000. Per-board
 * layout.ld files carve these into sub-regions (FLASH_NS / APPS_NS / etc.).
 *
 * This file is NOT auto-included by cargo — the board crate's build.rs
 * stages it into its OUT_DIR. The chip crate has no build.rs so memory.x
 * is purely a reference the board author consumes by name.
 */

MEMORY
{
    FLASH_NS  (rx)  : ORIGIN = 0x08040000, LENGTH = 256K
    SRAM_NS   (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
}
