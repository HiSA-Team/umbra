# STM32N657 two_enclaves host build.
#
# Phase 3.1: builds the host C application (host code ONLY — no embedded
# enclave) PLUS two SEPARATE standalone protected enclave blobs:
#
#     app/ammunition.bin   (TACLeBench "ammunition", ~60 blocks)
#     app/ndes.bin         (TACLeBench "ndes" DES,    ~20 blocks)
#
# Each blob is a minimal ELF containing only `._enclave_header` +
# `._enclave_code`, signed independently by tools/protect_enclave.py and then
# `objcopy --only-section`-extracted to a flat .bin. Both blobs link against
# the SAME EFBC runtime base (ORIGIN 0x0, PIC) so they overlay at 0x340E0000
# when the kernel loads each one at a time. Their FLASH locations differ
# (flashed by tools/flash_n657.sh at distinct XSPI2 offsets).
#
# The host src/main.c creates + runs BOTH sequentially: ammunition first, then
# ndes (see src/main.c). It knows each blob's flash address directly (no XSPI2
# NS scanning; RISAF12 blocks that).
#
# Mirrors the L552 multi-enclave pattern in host/stm32l552/taclebench/Makefile
# (each enclave a separate standalone .bin) but on the N657 partial-link +
# numeric-chain-fold toolchain.

PROGRAM_NAME = $(shell basename $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

CC_PREFIX = arm-none-eabi-
CC        = $(CC_PREFIX)gcc
LD        = $(CC_PREFIX)ld
OBJCOPY   = $(CC_PREFIX)objcopy
OBJDUMP   = $(CC_PREFIX)objdump

# M55 is a strict superset of M33 for Thumb-2+TrustZone (no Helium here),
# so we use cortex-m33 to match older arm-none-eabi-gcc toolchains.
COMMON_SRC_DIR = ../../common/src
COMMON_INC_DIR = ../../common/inc
INCS   = -Iinc -I$(COMMON_INC_DIR)
CFLAGS = -O0 -mcpu=cortex-m33 -mthumb -g -c \
         -ffreestanding -nostdlib -fno-builtin $(INCS)

# main.c creates BOTH enclaves alive and round-robins them; the N657 boot time-multiplexes the
# EFBC automatically (the `interenclave_overlay` feature is default-on in the boot crate, no flag
# needed). Always defined so this host always exercises the overlay.
CFLAGS += -DUMBRA_OVERLAY

# ── Enclave PIC flags ─────────────────────────────────────────────────────
# -fpic -mpic-data-is-text-relative: emit PC-relative loads for globals so
# .rodata/.data/.bss travel inside the image (the N657 loader copies each blob
# to a dynamically-allocated ESS address, not its link-time VMA — no runtime
# GOT/ABS relocator). -fvisibility=hidden suppresses GOT routing for symbols
# DEFINED in each TU. -fno-common gives globals real .data/.bss slots inside
# the image. -Os keeps the reachable image small (ammunition fits in ~60
# blocks; ndes ~20) inside the tight 16 KB EFBC window (MAX_EFBS(64) * 256).
# -ffunction-sections/-fdata-sections make every symbol separable so the
# partial-link --gc-sections drops the unreachable helpers (each enclave's
# own main()).
ENCLAVE_CFLAGS = -Os -mcpu=cortex-m33 -mthumb -g -c \
                 -ffreestanding -nostdlib -fno-builtin \
                 -fpic -mpic-data-is-text-relative -fvisibility=hidden \
                 -fno-common -ffunction-sections -fdata-sections \
                 -Wno-builtin-declaration-mismatch $(INCS)

ENCLAVE_PARTIAL_LD = linker/enclave_partial.ld
ENCLAVE_BLOB_LD    = linker/enclave_blob.ld
KEY                = ../../../tools/master_key.bin
PROTECT            = ../../../tools/protect_enclave.py

# protect_enclave.py env for N657:
#   UMBRA_CHAINED=1            -> chained-measurement layout (Meta 32 + CT 256 = 288 B/block)
#   UMBRA_ESS_MISS_RECOVERY=0  -> N657 boot crate has chained_measurement only
#   UMBRA_NUMERIC_FOLD=1       -> kernel folds ALL blocks in numeric order 0..N-1
#                                 (settings.sh sets this for N657; forced here so
#                                  the blob signs correctly even when the Makefile
#                                  is invoked from a bare shell)
PROTECT_ENV := UMBRA_CHAINED=1 UMBRA_ESS_MISS_RECOVERY=0 UMBRA_NUMERIC_FOLD=1
PROTECT_FLAGS := --hmac-over-plaintext

# ── Host (NS) — host code ONLY, no embedded enclave ───────────────────────
SRCS_HOST    = $(wildcard src/*.c)
SRCS_COMMON  = $(COMMON_SRC_DIR)/umbra_hex.c
HOST_OBJS = $(addprefix obj/, $(notdir $(SRCS_HOST:.c=.o))) \
            $(addprefix obj/, $(notdir $(SRCS_COMMON:.c=.o))) \
            obj/startup.o

# E.4c MCE2 region — default 4 MB at 0x70500000 (Path B-full).
ENCLAVE_REGION_SIZE ?= 0x00400000
ENCLAVE_DST_START   ?= 0x70500000

LDFLAGS = -nostdlib --discard-none \
          -T linker/memory.ld \
          -T linker/sections.ld
ifneq ($(ENCLAVE_REGION_SIZE),)
LDFLAGS += --defsym=ENCLAVE_REGION_SIZE=$(ENCLAVE_REGION_SIZE)
endif
ifneq ($(ENCLAVE_DST_START),)
LDFLAGS += --defsym=ENCLAVE_DST_START=$(ENCLAVE_DST_START)
endif

# `all` builds the host ELF/bin AND both standalone enclave blobs.
all: bin/$(PROGRAM_NAME).elf bin/$(PROGRAM_NAME).bin \
     app/ammunition.bin app/ndes.bin

# ── Host object rules ─────────────────────────────────────────────────────
obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

obj/%.o: $(COMMON_SRC_DIR)/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

obj/startup.o: src/startup.s
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

# Host ELF — pure NS host, no enclave embedded, so protect_enclave.py is NOT
# run on it (the ._enclave_header / ._enclave_code sections in sections.ld are
# empty here — the enclaves ship as separate blobs).
bin/$(PROGRAM_NAME).elf: $(HOST_OBJS)
	@mkdir -p bin
	$(LD) $(LDFLAGS) -o $@ $^

bin/$(PROGRAM_NAME).bin: bin/$(PROGRAM_NAME).elf
	$(OBJCOPY) -O binary $< $@
	@echo "[HOST] $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# ── Enclave 1: ammunition (arbitrary-precision integer arithmetic) ────────
# Multi-TU: arithm.c + ammunition.c + bits.c + ammunition_libc.c reference
# ammunition_overflow_bit / ammunition_result across TUs; the force-included
# inc/_disabled_ammunition/ammunition_hidden_visibility.h re-declares those two
# cross-TU globals hidden so the accesses stay PC-relative (no GOT). Sources
# vendored verbatim under app/_disabled_ammunition/ (referenced by explicit
# path so the src/*.c host wildcard never picks them up).
AMMU_DIR    = app/_disabled_ammunition
AMMU_INC    = inc/_disabled_ammunition
AMMU_HIDDEN = $(AMMU_INC)/ammunition_hidden_visibility.h
AMMU_OBJS   = obj/ammu_arithm.o obj/ammu_ammunition.o obj/ammu_bits.o \
              obj/ammu_ammunition_libc.o obj/ammu_ammunition_enclave.o

obj/ammu_arithm.o: $(AMMU_DIR)/arithm.c $(AMMU_HIDDEN)
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -I$(AMMU_INC) -include $(AMMU_HIDDEN) -o $@ $<
obj/ammu_ammunition.o: $(AMMU_DIR)/ammunition.c $(AMMU_HIDDEN)
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -I$(AMMU_INC) -include $(AMMU_HIDDEN) -o $@ $<
obj/ammu_bits.o: $(AMMU_DIR)/bits.c $(AMMU_HIDDEN)
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -I$(AMMU_INC) -include $(AMMU_HIDDEN) -o $@ $<
obj/ammu_ammunition_libc.o: $(AMMU_DIR)/ammunition_libc.c $(AMMU_HIDDEN)
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -I$(AMMU_INC) -include $(AMMU_HIDDEN) -o $@ $<
# Entry wrapper: no force-include (references none of the cross-TU globals).
obj/ammu_ammunition_enclave.o: $(AMMU_DIR)/ammunition_enclave.c
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -I$(AMMU_INC) -o $@ $<

# Partial-link the ammunition objects into one relocatable with exactly two
# sections (.app.enclave_code + .app.enclave_bss).
obj/enclave_combined_ammunition.o: $(AMMU_OBJS) $(ENCLAVE_PARTIAL_LD)
	@mkdir -p obj
	$(LD) -r --gc-sections -e enclave_entry -T $(ENCLAVE_PARTIAL_LD) \
	    -o $@ $(AMMU_OBJS)

# Header-only object + combined code -> standalone blob ELF.
obj/ammunition_header.o: blob_src/ammunition_header.c
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -o $@ $<

app/ammunition.elf: obj/ammunition_header.o obj/enclave_combined_ammunition.o $(ENCLAVE_BLOB_LD)
	@mkdir -p app
	$(LD) -nostdlib -T $(ENCLAVE_BLOB_LD) \
	    -o $@ obj/ammunition_header.o obj/enclave_combined_ammunition.o

app/ammunition.bin: app/ammunition.elf
	@echo "[SIGN] protect_enclave.py ammunition.elf"
	$(PROTECT_ENV) python3 $(PROTECT) $(PROTECT_FLAGS) $< blob_src/ammunition_header.c $(KEY) obj
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

ammunition: app/ammunition.bin

# ── Enclave 2: ndes (DES symmetric cipher) ────────────────────────────────
# Single-TU (ndes.c) with no cross-TU externs -> no force-include needed.
# ndes_libc.c supplies memcpy/memset that -Os synthesizes for ndes.c's
# volatile-array brace initializers.
NDES_OBJS = obj/ndes.o obj/ndes_enclave.o obj/ndes_libc.o

obj/ndes.o: app/ndes.c
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -o $@ $<
obj/ndes_enclave.o: app/ndes_enclave.c
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -o $@ $<
obj/ndes_libc.o: app/ndes_libc.c
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -o $@ $<

obj/enclave_combined_ndes.o: $(NDES_OBJS) $(ENCLAVE_PARTIAL_LD)
	@mkdir -p obj
	$(LD) -r --gc-sections -e enclave_entry -T $(ENCLAVE_PARTIAL_LD) \
	    -o $@ $(NDES_OBJS)

obj/ndes_header.o: blob_src/ndes_header.c
	@mkdir -p obj
	$(CC) $(ENCLAVE_CFLAGS) -o $@ $<

app/ndes.elf: obj/ndes_header.o obj/enclave_combined_ndes.o $(ENCLAVE_BLOB_LD)
	@mkdir -p app
	$(LD) -nostdlib -T $(ENCLAVE_BLOB_LD) \
	    -o $@ obj/ndes_header.o obj/enclave_combined_ndes.o

app/ndes.bin: app/ndes.elf
	@echo "[SIGN] protect_enclave.py ndes.elf"
	$(PROTECT_ENV) python3 $(PROTECT) $(PROTECT_FLAGS) $< blob_src/ndes_header.c $(KEY) obj
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

ndes: app/ndes.bin

clean:
	-rm -rf obj bin app/ammunition.elf app/ammunition.bin app/ndes.elf app/ndes.bin

dump-ammunition: app/ammunition.elf
	$(OBJDUMP) -D $<

dump-ndes: app/ndes.elf
	$(OBJDUMP) -D $<

.PHONY: all clean ammunition ndes dump-ammunition dump-ndes
