# Phase 0 probe — DHUK availability on N657 Nucleo (BSEC-open dev silicon)
# Run: openocd -f openocd_scripts/stm32n6x.cfg &
#      arm-none-eabi-gdb -batch -nx -x tools/dhuk_probe.gdb
#
# WARNING: monitor reset halt resets the chip — do not run during an active firmware debug session.
#
# Key register bases (cross-check these against RM0486 before trusting reads):
#   BSEC base 0x54000000 (Secure alias) — to verify against RM §4 deep-read
#   RIFSC base 0x54024000 (Secure alias) — per src/hardware/platform/stm32n657/boot/src/platform_impl.rs:24
#   RCC_BASE 0x56028000 (Secure alias)  — per src/hardware/platform/stm32n657/drivers/src/rcc.rs:15
#   AHB3ENR offset 0x258                — per src/hardware/platform/stm32n657/drivers/src/rcc.rs:18

set pagination off
target extended-remote :3333
monitor reset halt

# BSEC base 0x54000000 (Secure alias — to verify against RM §4 deep-read)
# CPU halts in Secure state after monitor reset halt, so Secure alias is correct.
# HDPLSR is one of the lower offsets — typical Cortex-M ST layout
printf "=== BSEC_HDPLSR (expected HDPL=2 for OEM/Umbra) ===\n"
x/w 0x54000400

# RCC_BASE=0x56028000 (Secure) + AHB3ENR_OFFSET=0x258
# src/hardware/platform/stm32n657/drivers/src/rcc.rs:15 (RCC_BASE Secure)
# src/hardware/platform/stm32n657/drivers/src/rcc.rs:18 (AHB3ENR_OFFSET)
printf "=== AHB3ENR (expected CRYP1+SAES1 OFF before our enable) ===\n"
x/w 0x56028258

# RIFSC base 0x54024000 (Secure) + SECCFGR2 offset 0x18
# src/hardware/platform/stm32n657/boot/src/platform_impl.rs:24 (RIFSC base Secure)
printf "=== Current RIFSC_SECCFGR2 (CRYP1=bit 16 if RISUP 80; SAES TBD) ===\n"
x/w 0x54024018

monitor resume
detach
quit
