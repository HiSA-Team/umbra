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
#
# KNOWN LIMITATION — runtime GOT relocation not supported.
#
# This toolchain is sufficient for benchmarks that access ONLY:
#   - local automatic variables (stack)
#   - direct global scalars / direct global arrays (PC-relative addressing
#     works for these via `-mpic-data-is-text-relative`)
#   - PC-relative branches
#
# It is NOT sufficient for benchmarks that access STATIC ARRAYS OF
# POINTERS, e.g. anagram's
#   `char const *anagram_dictionary[2279] = {"2nd", "abandon", ...};`
# or dijkstra/huff_dec/cjpeg_wrbmp that have similar pointer tables.
#
# GCC compiles such initialisers by storing COMPILE-TIME absolute
# addresses of the string literals into the array bytes, expecting a
# dynamic loader (or a static-PIE startup relocator) to walk the
# relocation table and add `runtime_base - compile_base` to each entry
# before main runs. We have neither — the enclave is a flat encrypted
# blob with no relocator, no `_start`. The first `dict[i]` deref at
# runtime treats the compile-time offset as a runtime address and
# MemManages with "addr outside any enclave".
#
# Confirmed FAILING on this build (2026-05-28):
#   - anagram   (`anagram_dictionary[2279]`)
#   - dijkstra, huff_dec, cjpeg_wrbmp (similar pointer-table patterns)
# Confirmed PASSING:
#   - bsort, countnegative, binarysearch, statemate, ndes, etc.
#     — these access globals as direct arrays / scalars, no pointer indirection.
#
# Workaround paths (not implemented yet):
#   (a) Per-bench rewrite to flat-table-of-offsets + base-address pattern
#   (b) Kernel-side static-PIE relocator: emit `.umbra_reloc` from the
#       blob signer, kernel walks it post-decrypt adding the runtime delta
#   (c) Per-enclave shim that runs at entry, fixes up the pointer tables
#       in-place using PC-relative computation
CFLAGS = -O0 -g -march=armv8-m.main -mthumb \
         -ffunction-sections -fdata-sections \
         -fpic -fvisibility=hidden -mpic-data-is-text-relative \
         -fno-builtin -nostdinc -nostdlib \
         -Wno-builtin-declaration-mismatch

# --emit-relocs: keep `.rel.*` sections in the linked ELF so
# protect_enclave.py can extract R_ARM_ABS32 entries (the static-PIE
# relocations for pointer arrays — anagram_dictionary[2279] etc.) and
# emit a .umbra_reloc table the kernel applies at block-install time.
# Required for benches that initialise `char const *table[]` patterns.
LDFLAGS = -nostdlib --gc-sections --emit-relocs -T $(LINKER_DIR)/enclave_blob.ld

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

# insertsort moved to CANONICAL_BENCH_template below (Tier-1 paper apps).

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

# libc_shim.o is linked into every kernel-bench ELF: with -fno-builtin,
# GCC can emit calls to `memset`/`memcpy` for aggregate initialisers
# even when the source doesn't reference them directly. md5 + crc were
# the first to trip on this. --gc-sections drops unused symbols so the
# .bin size is unchanged for benches that don't actually need libc.
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

$(eval $(call CANONICAL_BENCH_template,binarysearch))
$(eval $(call CANONICAL_BENCH_template,bsort))
$(eval $(call CANONICAL_BENCH_template,countnegative))
$(eval $(call CANONICAL_BENCH_template,complex_updates))

# Tier-1 kernel benches (paper-extension set §Evaluation). md5 + crc both
# return raw checksums (NOT 0-on-success); expected_r0 entries in
# tools/test_taclebench.sh are blank pending first-hardware-run discovery.
$(eval $(call CANONICAL_BENCH_template,md5))
$(eval $(call CANONICAL_BENCH_template,crc))
$(eval $(call CANONICAL_BENCH_template,insertsort))

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

# Tier-1 sequential benches (paper-extension set §Evaluation).
$(eval $(call SEQUENTIAL_BENCH_template,adpcm_dec))
$(eval $(call SEQUENTIAL_BENCH_template,petrinet))

# ----- anagram (multi-file with REDUCED dictionary) ---------------------
#
# Mentioned in the Umbra paper as the "uniform code access pattern" data
# point. Custom stdlib shim (anagram_stdlib.c) provides anagram_qsort/
# anagram_malloc/anagram_bzero without pulling in libc.
#
# REDUCTION: upstream anagram uses a 2279-word dictionary that compiles
# to ~40 KB plaintext at -O0, exceeding the 28 KB NS-flash slot at
# 0x08079000 (also exceeds the 16 KB linker reservation in
# enclave_blob.ld). We reduce DICTWORDS 2279 → 200 to target ~4 KB
# plaintext, matching the paper title "anagram_3974B". Two replacements:
#   (1) blob_src/anagram_input_small.c — committed; first 200 dict
#       entries + the achPhrase[3] verbatim from upstream.
#   (2) obj/anagram_small.c — generated by sed; identical to upstream
#       anagram.c except `#define anagram_DICTWORDS 2279` → 200.

ANAGRAM_OBJS = $(OBJ_DIR)/anagram_blob.o $(OBJ_DIR)/anagram.o \
               $(OBJ_DIR)/anagram_input.o $(OBJ_DIR)/anagram_stdlib.o \
               $(OBJ_DIR)/libc_shim.o

$(OBJ_DIR)/anagram_blob.o: $(BLOB_SRC)/anagram_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Generate the reduced-dictionary anagram.c (DICTWORDS=200).
$(OBJ_DIR)/anagram_small.c: $(TACLE_SEQ)/anagram/anagram.c
	@mkdir -p $(@D)
	sed 's|#define anagram_DICTWORDS 2279|#define anagram_DICTWORDS 200|' $< > $@

$(OBJ_DIR)/anagram.o: $(OBJ_DIR)/anagram_small.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/anagram -c $< -o $@

$(OBJ_DIR)/anagram_input.o: $(BLOB_SRC)/anagram_input_small.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/anagram -c $< -o $@

# Generate the reduced-heap anagram_stdlib.c. Upstream allocates an 18 KB
# BSS heap arena sized for the full 2279-word dictionary. With our 200
# words the live high-water mark is ~3 KB; we reserve 4 KB for headroom.
$(OBJ_DIR)/anagram_stdlib_small.c: $(TACLE_SEQ)/anagram/anagram_stdlib.c
	@mkdir -p $(@D)
	sed 's|#define ANAGRAM_HEAP_SIZE 18000|#define ANAGRAM_HEAP_SIZE 4000|' $< > $@

$(OBJ_DIR)/anagram_stdlib.o: $(OBJ_DIR)/anagram_stdlib_small.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/anagram -c $< -o $@

$(APP_DIR)/anagram.elf: $(ANAGRAM_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(ANAGRAM_OBJS) -o $@

$(APP_DIR)/anagram.bin: $(APP_DIR)/anagram.elf
	@echo "[SIGN] protect_enclave.py anagram.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/anagram_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

anagram: $(APP_DIR)/anagram.bin

dump-anagram: $(APP_DIR)/anagram.elf
	$(OBJDUMP) -d $<

# ----- cjpeg_wrbmp (multi-file: cjpeg_wrbmp.c + input.c) -------------
#
# Mentioned in the Umbra paper as the "good code locality" data point.
# Headers (jpeglib.h, jconfig.h, jmorecfg.h, jerror.h, cdjpeg.h, cderror.h)
# live in the bench dir → -I$(TACLE_SEQ)/cjpeg_wrbmp.

CJPEG_WRBMP_OBJS = $(OBJ_DIR)/cjpeg_wrbmp_blob.o $(OBJ_DIR)/cjpeg_wrbmp.o \
                   $(OBJ_DIR)/cjpeg_wrbmp_input.o $(OBJ_DIR)/libc_shim.o

$(OBJ_DIR)/cjpeg_wrbmp_blob.o: $(BLOB_SRC)/cjpeg_wrbmp_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/cjpeg_wrbmp.o: $(TACLE_SEQ)/cjpeg_wrbmp/cjpeg_wrbmp.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/cjpeg_wrbmp -c $< -o $@

$(OBJ_DIR)/cjpeg_wrbmp_input.o: $(TACLE_SEQ)/cjpeg_wrbmp/input.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TACLE_SEQ)/cjpeg_wrbmp -c $< -o $@

$(APP_DIR)/cjpeg_wrbmp.elf: $(CJPEG_WRBMP_OBJS) $(LINKER_DIR)/enclave_blob.ld
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) $(CJPEG_WRBMP_OBJS) -o $@

$(APP_DIR)/cjpeg_wrbmp.bin: $(APP_DIR)/cjpeg_wrbmp.elf
	@echo "[SIGN] protect_enclave.py cjpeg_wrbmp.elf"
	python3 $(TOOLS)/protect_enclave.py $< $(BLOB_SRC)/cjpeg_wrbmp_blob.c $(KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $< $@
	@echo "[BLOB] $@ ($(shell wc -c < $@ 2>/dev/null) bytes)"

cjpeg_wrbmp: $(APP_DIR)/cjpeg_wrbmp.bin

dump-cjpeg_wrbmp: $(APP_DIR)/cjpeg_wrbmp.elf
	$(OBJDUMP) -d $<

# ----- dijkstra-64 (reduced 64X64 graph) ----------------------------------
#
# Upstream dijkstra uses a 100X100 AdjMatrix (10 KB .rodata) + a 1000-
# entry QUEUE (16 KB .bss) → ~30 KB plaintext, exceeds our 28 KB
# NS-flash slot. We reduce to NUM_NODES=64, QUEUE_SIZE=640 to target
# ~16 KB plaintext (dijkstra-64; see Stage A Step 0c sizing notes).
#
# Three replacements:
#   (1) blob_src/dijkstra_input_small.c — committed; first 64 rows X
#       first 64 cols of the upstream matrix.
#   (2) blob_src/dijkstra_small_input.h — committed; pre-define guard
#       to defeat upstream input.h + NUM_NODES=64.
#   (3) obj/dijkstra_small.c — generated; sed on upstream dijkstra.c
#       to set QUEUE_SIZE 1000 → 640.

DIJKSTRA_OBJS = $(OBJ_DIR)/dijkstra_blob.o $(OBJ_DIR)/dijkstra.o $(OBJ_DIR)/dijkstra_input.o $(OBJ_DIR)/libc_shim.o

# -include forces blob_src/dijkstra_small_input.h to be processed before
# the source body — sets INPUT_H so the upstream input.h is skipped and
# defines NUM_NODES=64 before any code references it.
DIJKSTRA_CFLAGS = $(CFLAGS) -include $(BLOB_SRC)/dijkstra_small_input.h \
                  -I$(TACLE_SEQ)/dijkstra

$(OBJ_DIR)/dijkstra_blob.o: $(BLOB_SRC)/dijkstra_blob.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Generate the reduced-queue dijkstra.c (QUEUE_SIZE=640).
$(OBJ_DIR)/dijkstra_small.c: $(TACLE_SEQ)/dijkstra/dijkstra.c
	@mkdir -p $(@D)
	sed 's|#define QUEUE_SIZE 1000|#define QUEUE_SIZE 640|' $< > $@

$(OBJ_DIR)/dijkstra.o: $(OBJ_DIR)/dijkstra_small.c $(BLOB_SRC)/dijkstra_small_input.h
	@mkdir -p $(@D)
	$(CC) $(DIJKSTRA_CFLAGS) -c $< -o $@

$(OBJ_DIR)/dijkstra_input.o: $(BLOB_SRC)/dijkstra_input_small.c $(BLOB_SRC)/dijkstra_small_input.h
	@mkdir -p $(@D)
	$(CC) $(DIJKSTRA_CFLAGS) -c $< -o $@

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

# dump-insertsort emitted by CANONICAL_BENCH_template below.

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

# Tier-1 paper-extension benches — see "Tier 1" recommendation in the
# session log. md5 + crc return raw checksums; expected_r0 in
# tools/test_taclebench.sh must be filled in after first hardware run.
tier1_apps: insertsort crc md5 adpcm_dec petrinet

# §Evaluation full app set (PM scope: paper-fidelity + extensions). Used
# by the Stage A sweep harness. Includes paper-fidelity apps (anagram-200,
# cjpeg_wrbmp, statemate, ndes, dijkstra-64) plus Tier-1 extensions.
# susan excluded (~52 KB plaintext, exceeds 28 KB slot).
eval_apps: anagram cjpeg_wrbmp statemate ndes dijkstra \
           insertsort crc md5 adpcm_dec petrinet

.PHONY: all paper_apps tier1_apps eval_apps clean recursion fac insertsort prime \
        binarysearch bsort countnegative complex_updates \
        md5 crc adpcm_dec petrinet \
        anagram cjpeg_wrbmp ndes dijkstra statemate \
        multi_block_test three_block_test \
        dump-recursion dump-fac dump-insertsort dump-prime \
        dump-binarysearch dump-bsort dump-countnegative dump-complex_updates \
        dump-md5 dump-crc dump-adpcm_dec dump-petrinet \
        dump-anagram dump-cjpeg_wrbmp dump-ndes dump-dijkstra dump-statemate \
        dump-multi_block_test dump-three_block_test
.DEFAULT_GOAL := all
