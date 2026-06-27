# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
#
# DHUK / Secure-crypto register probe on the N657 Nucleo (BSEC-open dev silicon).
#
# IMPORTANT — read before running:
#   The OLD version of this script did `monitor reset halt`, which lands the
#   CPU BEFORE the Boot ROM -> FSBL handoff. In that state RIF leaves SAES /
#   RIFSC / BSEC unclocked and unconfigured, so every read returned 0 /
#   "Failed to read memory" (see project_n657_rifsc_blocked memory). Peripheral
#   RISUP filtering is by security+privilege (NOT CID), so the fix is simply to
#   attach to the ALREADY-BOOTED FSBL from the Secure AP — no reset.
#
# Run (NO-RESET attach):
#   1. Boot the board: BOOT1=Flash-Boot, press RESET, confirm banner @115200.
#   2. openocd -f openocd_scripts/stm32n6x_attach.cfg &
#   3. arm-none-eabi-gdb -batch -nx -x tools/dhuk_probe.gdb
#
# PROVEN alternative (no GDB) — STM32CubeProgrammer HOTPLUG read on the running
# FSBL. This is the same SWD/HOTPLUG/ap=1 path flash_n657.sh uses to write the
# Secure register 0x5600_4100, so it reliably reaches Secure peripherals:
#   STM32_Programmer_CLI -c port=SWD mode=HOTPLUG ap=1 -r32 0x54021004 0x1   # SAES_SR
#   STM32_Programmer_CLI -c port=SWD mode=HOTPLUG ap=1 -r32 0x54024018 0x1   # RIFSC_SECCFGR2
#
# Verified addresses (do NOT add the unverified BSEC base back without checking
# the full RM register table — a wrong MMIO read BusFaults the target):
#   SAES1   base 0x5402_1000 (Secure)  — proven by the working AES KATs
#   RIFSC   base 0x5402_4000 (Secure)  — per project_n657_rifsc_register_map
#   SAES_SR        = base+0x04
#   RIFSC_SECCFGR2 = base+0x18  (SECCFGRx = 0x10 + 4*x; SAES=bit14, CRYP1=bit16)
#   RIFSC_RIMC_CR  = base+0xC00 (DAPCID[10:8], reset 0x710)

set pagination off
target extended-remote :3333

# Attach to the running FSBL — DO NOT reset.
monitor halt

printf "=== SAES_SR (bit7=KEYVALID, bit2=WRERRF, bit1=RDERRF, bit3=BSY) ===\n"
x/w 0x54021004

printf "=== RIFSC_SECCFGR2 (SAES=bit14, CRYP1=bit16 -> 1=Secure-only) ===\n"
x/w 0x54024018

printf "=== RIFSC_RIMC_CR (DAPCID at [10:8]; reset 0x710 -> DAP CID=7) ===\n"
x/w 0x54024c00

monitor resume
detach
quit
