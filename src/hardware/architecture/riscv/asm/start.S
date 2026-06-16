# RISC-V RV32 M-mode entry + trap plumbing for the Umbra monitor.
#
# Layout of the 144-byte trap frame (matches `trap::TrapFrame`, repr(C)):
#   off 4*n : x[n]   (x0 reserved at 0, unused)
#   off 128 : mepc
#   off 132 : mcause
#   off 136 : mtval
#   off 140 : mstatus
#
# The monitor's trap stack lives at `_stack_top`; `mscratch` holds it while the
# host/enclave run, so the trap entry can switch stacks with a single swap.

    .section .text.init
    .globl _start
_start:
    la   sp, _stack_top
    # zero .bss
    la   t0, _sbss
    la   t1, _ebss
1:  bgeu t0, t1, 2f
    sw   zero, 0(t0)
    addi t0, t0, 4
    j    1b
2:  call secure_boot
hang:
    wfi
    j    hang

# ── M-mode trap entry ───────────────────────────────────────────────────────
    .section .text
    .align 4
    .globl _mtrap_entry
_mtrap_entry:
    csrrw sp, mscratch, sp          # sp = M trap stack ; mscratch = trapped sp
    addi  sp, sp, -144
    sw    x1, 4(sp)
    csrr  x1, mscratch              # x1 = trapped sp (original x2)
    sw    x1, 8(sp)
    sw    x3, 12(sp)
    sw    x4, 16(sp)
    sw    x5, 20(sp)
    sw    x6, 24(sp)
    sw    x7, 28(sp)
    sw    x8, 32(sp)
    sw    x9, 36(sp)
    sw    x10, 40(sp)
    sw    x11, 44(sp)
    sw    x12, 48(sp)
    sw    x13, 52(sp)
    sw    x14, 56(sp)
    sw    x15, 60(sp)
    sw    x16, 64(sp)
    sw    x17, 68(sp)
    sw    x18, 72(sp)
    sw    x19, 76(sp)
    sw    x20, 80(sp)
    sw    x21, 84(sp)
    sw    x22, 88(sp)
    sw    x23, 92(sp)
    sw    x24, 96(sp)
    sw    x25, 100(sp)
    sw    x26, 104(sp)
    sw    x27, 108(sp)
    sw    x28, 112(sp)
    sw    x29, 116(sp)
    sw    x30, 120(sp)
    sw    x31, 124(sp)
    csrr  t0, mepc
    sw    t0, 128(sp)
    csrr  t0, mcause
    sw    t0, 132(sp)
    csrr  t0, mtval
    sw    t0, 136(sp)
    csrr  t0, mstatus
    sw    t0, 140(sp)

    mv    a0, sp                    # &mut TrapFrame
    call  rust_mtrap

    lw    t0, 140(sp)
    csrw  mstatus, t0
    lw    t0, 128(sp)
    csrw  mepc, t0
    lw    x1, 4(sp)
    lw    x3, 12(sp)
    lw    x4, 16(sp)
    # x5/t0 restored near the end (kept as scratch for the mscratch reset)
    lw    x6, 24(sp)
    lw    x7, 28(sp)
    lw    x8, 32(sp)
    lw    x9, 36(sp)
    lw    x10, 40(sp)
    lw    x11, 44(sp)
    lw    x12, 48(sp)
    lw    x13, 52(sp)
    lw    x14, 56(sp)
    lw    x15, 60(sp)
    lw    x16, 64(sp)
    lw    x17, 68(sp)
    lw    x18, 72(sp)
    lw    x19, 76(sp)
    lw    x20, 80(sp)
    lw    x21, 84(sp)
    lw    x22, 88(sp)
    lw    x23, 92(sp)
    lw    x24, 96(sp)
    lw    x25, 100(sp)
    lw    x26, 104(sp)
    lw    x27, 108(sp)
    lw    x28, 112(sp)
    lw    x29, 116(sp)
    lw    x30, 120(sp)
    lw    x31, 124(sp)
    la    t0, _stack_top            # reset mscratch = M trap stack for next trap
    csrw  mscratch, t0
    lw    t0, 20(sp)               # restore real x5/t0
    lw    x2, 8(sp)                # restore sp (target ring's sp) — last
    mret

# ── Initial hand-off into U-mode (boot → host). Does not return. ────────────
# extern "C" fn _enter_umode(entry: usize /*a0*/, sp: usize /*a1*/) -> !
    .globl _enter_umode
_enter_umode:
    li    t1, (3 << 11)            # mstatus.MPP mask (bits 12:11)
    csrc  mstatus, t1             # MPP = 00  -> mret drops to U-mode
    csrw  mepc, a0
    mv    sp, a1
    mret
