# RISC-V (RV32) bare-metal Umbra host reset. The U-mode host enters here when
# the monitor `mret`s to it; sets the stack, zeroes .bss, and calls host_main.
.section .text.init
.globl _host_start
_host_start:
    la   sp, _host_estack
    la   t0, _sbss
    la   t1, _ebss
1:  bgeu t0, t1, 2f
    sw   zero, 0(t0)
    addi t0, t0, 4
    j    1b
2:  call host_main
3:  wfi
    j    3b
