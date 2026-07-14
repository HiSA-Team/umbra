# N657 source-level debug — loads BOTH symbol tables so functions resolve in
# every world the CPU can be in:
#   Secure FSBL/boot  @ 0x3418_xxxx   (this ELF, `file` below)
#   NS host           @ 0x2400_0100   ($HOST_APP.elf, add-symbol-file injected by xtask)
#   enclave code      @ 0x2401_0000+  (part of the NS host image)
#
# Usage (interactive — do NOT pass -batch):
#   1. Boot board: BOOT1=Flash-Boot, press RESET, confirm banner @115200.
#   2. pkill -x openocd; openocd -f openocd_scripts/stm32n6x_attach.cfg &
#   3. arm-none-eabi-gdb -nx -x tools/n657_debug.gdb
#      ^ -nx skips ~/.gdbinit (its Python breaks the Arm GDB build → harmless
#        "Scripting in the Python language is not supported" error otherwise).
#
# The NS host ELF is chosen automatically from HOST_APP by `cargo xtask flash n657` (it appends
# the add-symbol-file -ex), so two_enclaves / object_detection / freertos just work. Only a
# MANUAL `gdb -x` launch needs the -ex appended by hand (see the note further down).

set pagination off
set confirm off
set print pretty on

# Secure boot symbols (main executable). Use the WORKSPACE artifact — it is
# what flash_n657.sh flashes (target/.../umbra-n657-boot.bin) and its DWARF
# comp_dir is the repo root, so source paths resolve when gdb is launched from
# the repo root. Do NOT use the per-crate src/.../boot/target/.../boot ELF: it
# is a stale leftover (pre platform_impl.rs->platform_impl/ refactor) whose
# DWARF points at a source layout that no longer exists ("No such file").
file target/thumbv8m.main-none-eabi/release/umbra-n657-boot
# NS host symbols are injected by `cargo xtask flash n657` as a TRAILING
#   -ex "add-symbol-file host/stm32n657/$HOST_APP/bin/$HOST_APP.elf 0x24000100"
# (chosen from HOST_APP; .text VMA 0x24000100 for every N657 host). It runs AFTER this `file`
# so the boot symbols are not discarded. For a MANUAL launch (without xtask) append that -ex
# yourself, e.g. for two_enclaves:
#   arm-none-eabi-gdb -nx -x tools/n657_debug.gdb \
#     -ex "add-symbol-file host/stm32n657/two_enclaves/bin/two_enclaves.elf 0x24000100"

# Don't dive into stdlib/core internals on `step` (e.g. core::ptr::write_volatile
# -> ub_checks.rs). Use `n`/`next` to step over calls; `s`/`step` only enters
# functions you actually wrote — these skip rules keep it out of core/compiler
# builtins even when you do step.
skip -rfunction ^core::
skip -rfunction ^compiler_builtins::

# auto-hw + the gdb_breakpoint_override below are what make `n`/`s` work on the
# Secure FSBL (see the long note after `target ...`). `si` always works (HW
# single-step). If a step-over still misbehaves, walk with `si`/`ni`.
set breakpoint auto-hw on

target extended-remote :3333

# CRITICAL for stepping the Secure FSBL: `n`/`s` plant a temporary SW
# breakpoint (BKPT in RAM) at the return address. In Secure FSBL RAM the RIF
# ACCEPTS the write but silently drops it (RISUP/RISAF "ignore write / read 0"),
# so GDB thinks the bp is set, continues, and runs away to the NS idle loop.
# `si` works (HW single-step, no temp bp) but `n`/`s` don't. Forcing ALL GDB
# breakpoints (incl. step-resume) to HARDWARE fixes step-over (the M55 has 8 HW
# bps; step uses 1-2). If you hit "maximum breakpoints reached", delete unused
# bps. Restore with `monitor gdb_breakpoint_override disable` if ever needed.
monitor gdb_breakpoint_override hard

# ── Reset the micro and land at init_kernel ────────────────────────────────
# Reset on every gdb launch, re-run the boot through the Boot ROM -> FSBL, and
# stop INSIDE the real power::init_kernel with source. `hbreak power::init_kernel`
# (not bare `init_kernel`, which matches 2 locations -> "Duplicate Breakpoint"/
# "Cannot access" noise); HW bp because the FSBL is reloaded each boot so a soft
# bp would be overwritten. `monitor reset halt` is correct here (we WANT to
# re-run boot). From the prompt: `n`/`s` to step (HW bps forced above),
# finish / info locals / p <var>.
monitor reset halt
hbreak power::init_kernel
continue

# To instead inspect the post-boot NS-idle state, comment the three lines above
# and run `monitor halt; bt; info registers` by hand.
