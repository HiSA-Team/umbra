OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY { RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 8M }
SECTIONS {
  . = 0x80000000;
  .text   : { KEEP(*(.text.init)) *(.text*) } > RAM
  .rodata : { *(.rodata*) } > RAM
  .data   : { *(.data*) } > RAM
  .bss    : { *(.bss*) *(COMMON) } > RAM
}
