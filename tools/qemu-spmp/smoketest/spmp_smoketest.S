# Minimal M->S SPMP liveness spike for the SPMP RFC patchset.
#
# IMPORTANT — this patchset exposes SPMP via INDIRECT CSRs (Sscsrind/Smcsrind),
# NOT direct spmpcfg0/spmpaddr0. The real programming sequence (discovered by
# reading the patched target/riscv/{csr.c,cpu_bits.h}, 2026-06-07):
#   siselect (0x150) <- ISELECT_SPMP_BASE(0x100) + entry_index
#   sireg    (0x151) <-> spmpaddr[index]
#   sireg2   (0x152) <-> spmpcfg[index]
# Gating: at reset mpmpdeleg=64 => num_deleg_rules=0 => S sees nothing. M-mode
# must first write mpmpdeleg (0x316) < 64 to delegate SPMP rules to S
# (num_deleg_rules = 64 - mpmpdeleg). All CSRs by number (binutils lacks the
# non-ratified SPMP names).
#
# Build+run: GCC=/opt/homebrew/bin/riscv64-unknown-elf-gcc ./run.sh
.section .text.init
.globl _start
_start:
    li   sp, 0x80200000
    # permissive PMP so S/U can touch RAM (outer fence; liveness test only)
    li   t0, 0x1FFFFFFF
    csrw pmpaddr0, t0
    li   t1, 0x1F                  # NAPOT | X|W|R
    csrw pmpcfg0, t1
    # delegate SPMP rules to S: mpmpdeleg(0x316) = 32  => num_deleg_rules = 32
    li   t0, 32
    csrw 0x316, t0
    # drop to S-mode (mstatus.MPP = 01)
    li   t0, (1 << 11)
    csrs mstatus, t0
    la   t0, smode_entry
    csrw mepc, t0
    mret

smode_entry:
    # select SPMP entry index 0
    li   t0, 0x100                 # ISELECT_SPMP_BASE + 0
    csrw 0x150, t0                 # siselect
    # write spmpaddr[0] via sireg (0x151)
    li   t1, 0x20010000
    csrw 0x151, t1
    # write spmpcfg[0] via sireg2 (0x152): R|W|X|TOR-ish cfg byte
    li   t2, 0x0F
    csrw 0x152, t2
    # read back spmpcfg[0]
    csrr t3, 0x152                 # t3 = readback

    la   a0, msg
1:  lbu  a1, 0(a0)
    beqz a1, 2f
    li   a2, 0x10000000
3:  lb   a3, 5(a2)
    andi a3, a3, 0x20
    beqz a3, 3b
    sb   a1, 0(a2)
    addi a0, a0, 1
    j    1b
2:
    # emit low nibble of the spmpcfg readback as hex
    andi t4, t3, 0xF
    li   t5, 10
    blt  t4, t5, 7f
    addi t4, t4, 0x37
    j    8f
7:  addi t4, t4, 0x30
8:  li   a2, 0x10000000
9:  lb   a3, 5(a2)
    andi a3, a3, 0x20
    beqz a3, 9b
    sb   t4, 0(a2)
    li   a1, 0x0A
    sb   a1, 0(a2)
done:
    j done

.section .rodata
msg: .asciz "SPMP cfg[0] readback nibble=0x"
