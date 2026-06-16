/* RISC-V (RV32) bare-metal Umbra host linker script — the U-mode host image.
 * Mirrors the STM32L552 host's `host.ld`, adapted to the QEMU memory map and to
 * the monitor's SPMP regions:
 *
 *   [0x8010_0000, 0x8014_0000)  host working region (code/rodata/data/bss/stack)
 *                               — the monitor maps this UMODE R|W|X.
 *   [0x8014_0000, 0x8014_1000)  the EMBEDDED enclave (48-byte `.app.enclave_header`
 *                               then `.app.enclave_code`, entry first) — the
 *                               monitor maps this SHARED R|X so S-mode can run it.
 *
 * The host stack tops out at the enclave base (0x8014_0000) and grows down. */
OUTPUT_ARCH(riscv)
ENTRY(_host_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x80100000, LENGTH = 1M
}

_host_app_address = 0x80140000;     /* fixed enclave base — known to the monitor */
_host_estack = _host_app_address;   /* host stack top (grows down into the region) */

SECTIONS {
  . = 0x80100000;

  .text : ALIGN(4) {
    KEEP(*(.text.init))      /* _host_start first */
    *(.text .text.*)
  } > RAM

  .rodata : ALIGN(4) {
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
  } > RAM

  .data : ALIGN(4) {
    _sdata = .;
    *(.data .data.* .sdata .sdata.*)
    _edata = .;
  } > RAM

  .bss (NOLOAD) : ALIGN(4) {
    _sbss = .;
    *(.bss .bss.* .sbss .sbss.* COMMON)
    _ebss = .;
  } > RAM

  /* Embedded enclave at the fixed app address. */
  ._enclave_header _host_app_address : ALIGN(4) {
    _enclave_start = .;
    KEEP(*(.app.enclave_header))
  } > RAM

  ._enclave_code : ALIGN(4) {
    _enclave_code_start = .;
    KEEP(*(.app.enclave_entry))    /* entry FIRST: lands at base + 48 */
    KEEP(*(.app.enclave_code))
    KEEP(*(.app.*))
    . = ALIGN(4);
    _enclave_code_end = .;         /* real code+data end (protect_enclave.py reads
                                      this for the block-split length, NOT the
                                      reserved padding below) */
    /* Reserve room for the protected blob: N 320-byte EFBC blocks + reloc table.
       1536 B covers up to 4 blocks; the pre-protect code is smaller. */
    . = _enclave_code_start + 0x600;
  } > RAM

  /DISCARD/ : { *(.eh_frame .eh_frame_hdr) }
}
