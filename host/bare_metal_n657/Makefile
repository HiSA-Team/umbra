# STM32N657 NS bare-metal host build.
#
# Builds the host C application + the embedded enclave (app/), then runs
# tools/protect_enclave.py --hmac-over-plaintext to patch the chained-
# measurement HMAC into the .app.enclave_header section. The final .bin
# is flashed verbatim to XSPI2 0x70080000 by tools/flash_n657.sh.

PROGRAM_NAME = bare_metal_n657

CC_PREFIX = arm-none-eabi-
CC        = $(CC_PREFIX)gcc
LD        = $(CC_PREFIX)ld
OBJCOPY   = $(CC_PREFIX)objcopy
OBJDUMP   = $(CC_PREFIX)objdump

# M55 is a strict superset of M33 for Thumb-2+TrustZone (no Helium here),
# so we use cortex-m33 to match older arm-none-eabi-gcc toolchains.
# -ffreestanding: no hosted libc assumptions.
COMMON_SRC_DIR = ../common/src
COMMON_INC_DIR = ../common/inc
INCS   = -Iinc -I$(COMMON_INC_DIR)
CFLAGS = -O0 -mcpu=cortex-m33 -mthumb -g -c \
         -ffreestanding -nostdlib -fno-builtin $(INCS)

# E.4c MCE2 region — default 4 MB at 0x70500000 (Path B-full).
# To bump:
#   make ENCLAVE_REGION_SIZE=0x1000000 ENCLAVE_DST_START=0x71100000   # 16 MB
#   make ENCLAVE_REGION_SIZE=0x1800000 ENCLAVE_DST_START=0x71900000   # 24 MB
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

SRCS_HOST    = $(wildcard src/*.c)
SRCS_ENCLAVE = $(wildcard app/*.c)
SRCS_COMMON  = $(COMMON_SRC_DIR)/umbra_hex.c
OBJS = $(addprefix obj/, $(notdir $(SRCS_HOST:.c=.o))) \
       $(addprefix obj/, $(notdir $(SRCS_ENCLAVE:.c=.o))) \
       $(addprefix obj/, $(notdir $(SRCS_COMMON:.c=.o))) \
       obj/startup.o

# protect_enclave.py mode — N657 uses MCE2 (transparent decrypt on
# memory-mapped XSPI2 reads), the same on-the-fly model L562 uses with
# OTFDEC. So the HMAC is bound to the plaintext of each block.
PROTECT_ENCLAVE_FLAGS := --hmac-over-plaintext

all: bin/$(PROGRAM_NAME).elf bin/$(PROGRAM_NAME).bin

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

obj/%.o: app/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

obj/%.o: $(COMMON_SRC_DIR)/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

obj/startup.o: src/startup.s
	@mkdir -p obj
	$(CC) $(CFLAGS) -o $@ $<

bin/$(PROGRAM_NAME).elf: $(OBJS)
	@mkdir -p bin
	$(LD) $(LDFLAGS) -o $@ $^

bin/$(PROGRAM_NAME).bin: bin/$(PROGRAM_NAME).elf
	@echo "[PROTECT] Running protect_enclave.py on $<"
	@# N657 boot crate enables `chained_measurement` only (no
	@# `ess_miss_recovery`), so block layout is [Meta(32) | CT(256)]
	@# = 288B. Force UMBRA_ESS_MISS_RECOVERY=0 here in case
	@# rebuild_all.sh exported it for an L552/L562 run.
	@UMBRA_CHAINED=1 UMBRA_ESS_MISS_RECOVERY=0 \
	    python3 ../../tools/protect_enclave.py $(PROTECT_ENCLAVE_FLAGS) \
	    bin/$(PROGRAM_NAME).elf src/main.c ../../tools/master_key.bin obj
	$(OBJCOPY) -O binary $< $@

clean:
	-rm -rf obj bin

dump:
	$(OBJDUMP) -D bin/$(PROGRAM_NAME).elf

.PHONY: all clean dump
