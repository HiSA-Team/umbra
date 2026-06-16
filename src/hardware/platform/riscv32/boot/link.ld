OUTPUT_ARCH(riscv)
ENTRY(_start)

/* QEMU `virt` RAM starts at 0x8000_0000. */
MEMORY {
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M
}

/* QEMU `virt` 16550 UART. */
PROVIDE(_uart_base = 0x10000000);

SECTIONS {
  . = 0x80000000;

  _stext = .;                /* start of monitor .text (ePMP self-lock base) */
  .text : ALIGN(4) {
    KEEP(*(.text.init))      /* _start must be first */
    *(.text .text.*)
  } > RAM
  . = ALIGN(4);
  _etext = .;                /* end of monitor .text (ePMP self-lock top) */

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

  /* Carve-outs for the U-mode host, the S-mode enclave, and the shared
     parameter window. PMP/SPMP grants are programmed against these symbols in
     later phases. */
  . = ALIGN(4096);
  _host_base = .;    .host    (NOLOAD) : ALIGN(4096) { . += 64K; } > RAM   _host_top   = .;
  _enc_base  = .;    .enclave (NOLOAD) : ALIGN(4096) { . += 64K; } > RAM   _enc_top    = .;
  _shared_base = .;  .shared  (NOLOAD) : ALIGN(4096) { . += 4K;  } > RAM   _shared_top = .;

  . = ALIGN(16);
  _stack_top = ORIGIN(RAM) + LENGTH(RAM);

  /DISCARD/ : { *(.eh_frame .eh_frame_hdr) }
}
