# Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
#
# Standalone Umbra enclave blobs from TACLeBench benchmarks.
#
# Each blob compiles + links upstream TACLeBench sources + a thin wrapper
# (header + entry) into a flat .bin signed by tools/protect_enclave.py and
# flashed at a free NS-flash slot scanned by the stm32l552/bare_metal host.
#
# Workflow (single uninterrupted sequence — see findings 2026-05-18 §
# "rebuild_all.sh rotates master_key.bin"):
#   1. ./rebuild_all.sh                         (generates K, builds kernel + host)
#   2. make -C host/stm32l552/taclebench        (signs blob with K)
#   3. $(FLASHER) -w app/recursion.bin 0x08079000  (flash blob)
#   4. ./debug.sh                               (run)
#
# Any ./rebuild_all.sh between steps 2 and 4 rotates K and invalidates
# the signed blob.

# Toolchain
CC      = arm-none-eabi-gcc
LD      = arm-none-eabi-ld
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump

# Paths
ROOT       = ../../..
TOOLS      = $(ROOT)/tools
TACLE      = lib/tacle-bench/bench/kernel
TACLE_SEQ  = lib/tacle-bench/bench/sequential
BLOB_SRC   = blob_src
LINKER_DIR = linker
APP_DIR    = app
OBJ_DIR    = obj

# -fpic + -mpic-data-is-text-relative: emit PC-relative loads for globals.
# Without -mpic-data-is-text-relative, ARM GCC defaults to r9 (Static Base)
# relative addressing — r9 is uninitialized at enclave entry, so every
# global read/write goes to absolute `garbage + offset` and faults.
# -fvisibility=hidden: suppress GOT references for non-static upstream
# symbols. -ffunction-sections / -fdata-sections: one input section per
# symbol so the linker can select what to include in `._enclave_code`.
# -nostdinc -nostdlib: TACLeBench upstream files don't require libc.
CFLAGS = -O0 -g -march=armv8-m.main -mthumb \
         -ffunction-sections -fdata-sections \
         -fpic -fvisibility=hidden -mpic-data-is-text-relative \
         -fno-builtin -nostdinc -nostdlib \
         -Wno-builtin-declaration-mismatch

LDFLAGS = -nostdlib --gc-sections -T $(LINKER_DIR)/enclave_blob.ld

KEY = $(TOOLS)/master_key.bin

# ----- recursion ----------------------------------

RECURSION_OBJS = $(OBJ_DIR)/recursion_blob.o $(OBJ_DIR)/recursion.o

$(OBJ_DIR)/recursion_blob.o: $(BLOB_SRC)/recursion_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/recursion.o: $(TACLE)/recursion/recursion.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_DIR)/recursion.elf: $(RECURSION_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(RECURSION_OBJS) -o $@

$(APP_DIR)/recursion.bin: $(APP_DIR)/recursion.elf
	@echo "[SIGN] protect_enclave.py recursion.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/recursion_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

recursion: $(APP_DIR)/recursion.bin

# ----- fac ---------------------------------------

FAC_OBJS = $(OBJ_DIR)/fac_blob.o $(OBJ_DIR)/fac.o

$(OBJ_DIR)/fac_blob.o: $(BLOB_SRC)/fac_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/fac.o: $(TACLE)/fac/fac.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_DIR)/fac.elf: $(FAC_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(FAC_OBJS) -o $@

$(APP_DIR)/fac.bin: $(APP_DIR)/fac.elf
	@echo "[SIGN] protect_enclave.py fac.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/fac_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

fac: $(APP_DIR)/fac.bin

# ----- insertsort  -

INSERTSORT_OBJS = $(OBJ_DIR)/insertsort_blob.o $(OBJ_DIR)/insertsort.o

$(OBJ_DIR)/insertsort_blob.o: $(BLOB_SRC)/insertsort_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/insertsort.o: $(TACLE)/insertsort/insertsort.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_DIR)/insertsort.elf: $(INSERTSORT_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(INSERTSORT_OBJS) -o $@

$(APP_DIR)/insertsort.bin: $(APP_DIR)/insertsort.elf
	@echo "[SIGN] protect_enclave.py insertsort.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/insertsort_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

insertsort: $(APP_DIR)/insertsort.bin

# ----- multi_block_test ------------------------
# Self-contained 2-block enclave to isolate "multi-block chain bug" from
# "insertsort-specific bug". No upstream tacle-bench dependency.

MULTI_OBJS = $(OBJ_DIR)/multi_block_test_blob.o

$(OBJ_DIR)/multi_block_test_blob.o: $(BLOB_SRC)/multi_block_test_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_DIR)/multi_block_test.elf: $(MULTI_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(MULTI_OBJS) -o $@

$(APP_DIR)/multi_block_test.bin: $(APP_DIR)/multi_block_test.elf
	@echo "[SIGN] protect_enclave.py multi_block_test.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/multi_block_test_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

multi_block_test: $(APP_DIR)/multi_block_test.bin

# ----- three_block_test  --------------------
# Same shape as multi_block_test but padded to 3 blocks. If this passes
# chained-measurement, multi-block-N>=3 works; insertsort failure is
# shape-specific. If this fails, the bug scales with chain length.

THREE_OBJS = $(OBJ_DIR)/three_block_test_blob.o

$(OBJ_DIR)/three_block_test_blob.o: $(BLOB_SRC)/three_block_test_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_DIR)/three_block_test.elf: $(THREE_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(THREE_OBJS) -o $@

$(APP_DIR)/three_block_test.bin: $(APP_DIR)/three_block_test.elf
	@echo "[SIGN] protect_enclave.py three_block_test.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/three_block_test_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

three_block_test: $(APP_DIR)/three_block_test.bin

# ----- prime ---------

PRIME_OBJS = $(OBJ_DIR)/prime_blob.o $(OBJ_DIR)/prime.o

$(OBJ_DIR)/prime_blob.o: $(BLOB_SRC)/prime_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/prime.o: $(TACLE)/prime/prime.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_DIR)/prime.elf: $(PRIME_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(PRIME_OBJS) -o $@

$(APP_DIR)/prime.bin: $(APP_DIR)/prime.elf
	@echo "[SIGN] protect_enclave.py prime.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/prime_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

prime: $(APP_DIR)/prime.bin

# Generic recipe for "canonical _init/_main/_return" benchmarks. Each
# expects $(BLOB_SRC)/<name>_blob.c (header + entry calling the triplet)
# and $(TACLE)/<name>/<name>.c (upstream source).
#
# Defined with `define / endef` so the rules can be instantiated per-benchmark
# without copy-pasting eight lines each.
define CANONICAL_BENCH_template

$(OBJ_DIR)/$(1)_blob.o: $$(BLOB_SRC)/$(1)_blob.c
	@mkdir -p $$(@D)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

$(OBJ_DIR)/$(1).o: $$(TACLE)/$(1)/$(1).c
	@mkdir -p $$(@D)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

$(APP_DIR)/$(1).elf: $(OBJ_DIR)/$(1)_blob.o $(OBJ_DIR)/$(1).o $$(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $$(@D)
	$$(LD) $$(LDFLAGS) $(OBJ_DIR)/$(1)_blob.o $(OBJ_DIR)/$(1).o -o $$@

$(APP_DIR)/$(1).bin: $(APP_DIR)/$(1).elf
	@echo "[SIGN] protect_enclave.py $(1).elf"
	python3 $$(TOOLS)/protect_enclave.py $$< $$(BLOB_SRC)/$(1)_blob.c $$(KEY) $$(OBJ_DIR)
	$$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $$< $$@
	@echo "[BLOB] $$@ ($$(shell wc -c < $$@ 2>/dev/null) bytes)"

$(1): $(APP_DIR)/$(1).bin

dump-$(1): $(APP_DIR)/$(1).elf
	$$(OBJDUMP) -d $$<

endef

$(eval $(call CANONICAL_BENCH_template,binarysearch))
$(eval $(call CANONICAL_BENCH_template,bsort))
$(eval $(call CANONICAL_BENCH_template,countnegative))
$(eval $(call CANONICAL_BENCH_template,complex_updates))

# ----- Sequential-bench benchmarks (paper Section §Evaluation) ---------
#
# Paper apps live in lib/tacle-bench/bench/sequential/ (one subdir each).
# Same canonical `_init/_main/_return` triplet pattern as kernel benches
# but sourced from the sequential path. Some apps have multiple .c files
# (dijkstra: dijkstra.c + input.c) and need a dedicated rule.

# Shared libc shim — provides memcpy/memset/memmove + ARM EABI aliases
# that GCC silently calls for aggregate initialisation and large-struct
# assignment. Linked into every sequential-bench enclave; unused entries
# are GC'd by `--gc-sections`. Stays static (no kernel API leak).
$(OBJ_DIR)/libc_shim.o: $(BLOB_SRC)/libc_shim.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

define SEQUENTIAL_BENCH_template

$(OBJ_DIR)/$(1)_blob.o: $$(BLOB_SRC)/$(1)_blob.c
	@mkdir -p $$(@D)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

$(OBJ_DIR)/$(1).o: $$(TACLE_SEQ)/$(1)/$(1).c
	@mkdir -p $$(@D)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

$(APP_DIR)/$(1).elf: $(OBJ_DIR)/$(1)_blob.o $(OBJ_DIR)/$(1).o $(OBJ_DIR)/libc_shim.o $$(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $$(@D)
	$$(LD) $$(LDFLAGS) $(OBJ_DIR)/$(1)_blob.o $(OBJ_DIR)/$(1).o $(OBJ_DIR)/libc_shim.o -o $$@

$(APP_DIR)/$(1).bin: $(APP_DIR)/$(1).elf
	@echo "[SIGN] protect_enclave.py $(1).elf"
	python3 $$(TOOLS)/protect_enclave.py $$< $$(BLOB_SRC)/$(1)_blob.c $$(KEY) $$(OBJ_DIR)
	$$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $$< $$@
	@echo "[BLOB] $$@ ($$(shell wc -c < $$@ 2>/dev/null) bytes)"

$(1): $(APP_DIR)/$(1).bin

dump-$(1): $(APP_DIR)/$(1).elf
	$$(OBJDUMP) -d $$<

endef

$(eval $(call SEQUENTIAL_BENCH_template,ndes))
$(eval $(call SEQUENTIAL_BENCH_template,statemate))

# dijkstra has an extra input.c that must be compiled and linked too.

DIJKSTRA_OBJS = $(OBJ_DIR)/dijkstra_blob.o $(OBJ_DIR)/dijkstra.o $(OBJ_DIR)/dijkstra_input.o $(OBJ_DIR)/libc_shim.o

$(OBJ_DIR)/dijkstra_blob.o: $(BLOB_SRC)/dijkstra_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/dijkstra.o: $(TACLE_SEQ)/dijkstra/dijkstra.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/dijkstra -c $< -o $@

$(OBJ_DIR)/dijkstra_input.o: $(TACLE_SEQ)/dijkstra/input.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/dijkstra -c $< -o $@

$(APP_DIR)/dijkstra.elf: $(DIJKSTRA_OBJS) $(OBJ_DIR)/libc_shim.o $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(DIJKSTRA_OBJS) -o $@

$(APP_DIR)/dijkstra.bin: $(APP_DIR)/dijkstra.elf
	@echo "[SIGN] protect_enclave.py dijkstra.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/dijkstra_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

dijkstra: $(APP_DIR)/dijkstra.bin

dump-dijkstra: $(APP_DIR)/dijkstra.elf
	$(OBJDUMP) -d $<

# ----- aux --------------------------------------------------------------

clean:
	rm -rf $(APP_DIR) $(OBJ_DIR)

dump-recursion: $(APP_DIR)/recursion.elf
	$(OBJDUMP) -d $<

dump-fac: $(APP_DIR)/fac.elf
	$(OBJDUMP) -d $<

dump-insertsort: $(APP_DIR)/insertsort.elf
	$(OBJDUMP) -d $<

dump-prime: $(APP_DIR)/prime.elf
	$(OBJDUMP) -d $<

dump-multi_block_test: $(APP_DIR)/multi_block_test.elf
	$(OBJDUMP) -d $<

dump-three_block_test: $(APP_DIR)/three_block_test.elf
	$(OBJDUMP) -d $<

# Working benchmarks (`all` only includes those proven to pass
# chained-measurement AND to terminate cleanly on hardware).

all: recursion fac prime binarysearch bsort countnegative

# Paper benchmarks (Section §Evaluation). NOT in `all` until validated
# on hardware end-to-end via tools/test_taclebench.sh. Build on demand:
#   make -C host/stm32l552/taclebench ndes dijkstra statemate
paper_apps: ndes dijkstra statemate

.PHONY: all paper_apps clean recursion fac insertsort prime \
        binarysearch bsort countnegative complex_updates \
        ndes dijkstra statemate \
        multi_block_test three_block_test \
        dump-recursion dump-fac dump-insertsort dump-prime \
        dump-binarysearch dump-bsort dump-countnegative dump-complex_updates \
        dump-ndes dump-dijkstra dump-statemate \
        dump-multi_block_test dump-three_block_test
.DEFAULT_GOAL := all
