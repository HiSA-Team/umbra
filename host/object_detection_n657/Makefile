# Object-detection enclave host for Umbra / STM32N657 — Phase G.2.b.
# Issue #38 NPU sub-project.
#
# M1.3 (link-fix): HAL pile dropped — FSBL does all platform init before
# jump_to_ns; the NS host needs only FreeRTOS + app/src + startup + NSC
# veneers (mirrors host/freertos_n657/ structure exactly).
#
# FreeRTOS-Kernel reused from host/freertos_arm/lib/ (no duplication).

################
# Program Name #
################

PROGRAM_NAME = $(shell basename $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

#####################
# Paths and Folders #
#####################

SRC_DIR     = src
APP_DIR     = app
INC_DIR     = inc
OBJ_DIR     = obj
STARTUP_DIR = src

# Shared host utilities (umbra_u32_to_hex + memset/memcpy stubs).
COMMON_SRC_DIR = ../common/src
COMMON_INC_DIR = ../common/inc

# FreeRTOS paths — submodule shared with host/freertos_arm/.
# V11.1.0: port files are in non_secure/ subdirectory.
FREERTOS_DIR    = ../freertos_arm/lib/FreeRTOS-Kernel
FREERTOS_PORT   = $(FREERTOS_DIR)/portable/GCC/ARM_CM33_NTZ/non_secure
FREERTOS_HEAP   = $(FREERTOS_DIR)/portable/MemMang

LD_SCRIPTS = linker/memory.ld linker/host.ld

#############
# Toolchain #
#############

CC_PREFIX   = arm-none-eabi-
CC          = $(CC_PREFIX)gcc
LD          = $(CC_PREFIX)ld
OBJDUMP     = $(CC_PREFIX)objdump
OBJCOPY     = $(CC_PREFIX)objcopy

# Cortex-M33 is a strict subset of M55 for non-Helium ARMv8-M Main code,
# matches the bare-metal N657 host build flags.
CFLAGS      = -O0 -mcpu=cortex-m33 -mthumb -g -c -ffreestanding -nostdlib -fno-builtin
CFLAGS     += -I$(SRC_DIR) -I$(INC_DIR) -I$(APP_DIR) -I$(COMMON_INC_DIR)
CFLAGS     += -I$(FREERTOS_DIR)/include -I$(FREERTOS_PORT)

# Device define (needed by FreeRTOS port headers).
CFLAGS     += -DSTM32N657xx

LDFLAGS     = -nostdlib $(addprefix -T,$(LD_SCRIPTS)) --discard-none --allow-multiple-definition

# libgcc provides the __aeabi_f{mul,add,sub,div,cmp*} softfloat routines
# the YOLO post-processor needs. Path resolved at make-time so it tracks
# the installed toolchain. (We don't enable the HW FPU because NS-side
# CPACR/NSACR setup is out of scope here; softfloat only adds tens of
# microseconds per inference for the post-process pass.)
LIBGCC      := $(shell $(CC_PREFIX)gcc -mcpu=cortex-m33 -mthumb -print-libgcc-file-name)

########
# Srcs #
########

# Application sources (src/ + app/).
APP_SRCS    = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(APP_DIR)/*.c)
APP_OBJS    = $(addprefix $(OBJ_DIR)/, $(notdir $(APP_SRCS:.c=.o)))

# Shared host utilities (linked into every host that needs them).
COMMON_SRCS = $(COMMON_SRC_DIR)/umbra_hex.c $(COMMON_SRC_DIR)/umbra_mem.c
COMMON_OBJS = $(addprefix $(OBJ_DIR)/, $(notdir $(COMMON_SRCS:.c=.o)))

# FreeRTOS sources
FREERTOS_SRCS = $(FREERTOS_DIR)/tasks.c \
                $(FREERTOS_DIR)/queue.c \
                $(FREERTOS_DIR)/list.c \
                $(FREERTOS_PORT)/port.c \
                $(FREERTOS_PORT)/portasm.c \
                $(FREERTOS_HEAP)/heap_4.c

FREERTOS_OBJS = $(addprefix $(OBJ_DIR)/freertos_, $(notdir $(FREERTOS_SRCS:.c=.o)))

ALL_OBJS = $(APP_OBJS) $(COMMON_OBJS) $(FREERTOS_OBJS) $(OBJ_DIR)/startup.o

RM      = rm -rf
MKDIR   = @mkdir -p $(@D)

###########
# Targets #
###########

all: bin/$(PROGRAM_NAME).bin

# App sources (src/ + app/)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "\n[OBJ]	Compiling $<"
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJ_DIR)/%.o: $(APP_DIR)/%.c
	@echo "\n[OBJ]	Compiling $<"
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

# Shared host utilities (host/common/)
$(OBJ_DIR)/%.o: $(COMMON_SRC_DIR)/%.c
	@echo "\n[OBJ]	Compiling $<"
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

# FreeRTOS core
$(OBJ_DIR)/freertos_tasks.o: $(FREERTOS_DIR)/tasks.c
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJ_DIR)/freertos_queue.o: $(FREERTOS_DIR)/queue.c
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJ_DIR)/freertos_list.o: $(FREERTOS_DIR)/list.c
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

# FreeRTOS port
$(OBJ_DIR)/freertos_port.o: $(FREERTOS_PORT)/port.c
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJ_DIR)/freertos_portasm.o: $(FREERTOS_PORT)/portasm.c
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

# FreeRTOS heap
$(OBJ_DIR)/freertos_heap_4.o: $(FREERTOS_HEAP)/heap_4.c
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

# Startup
$(OBJ_DIR)/startup.o: $(STARTUP_DIR)/startup.s
	@echo "\n[OBJ]	Assembling $<"
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

# Link
bin/$(PROGRAM_NAME).elf: $(ALL_OBJS)
	@echo "\n[ELF]	Linking $@"
	$(MKDIR)
	$(LD) -o $@ $^ $(LDFLAGS) $(LIBGCC)

# M1.2: run protect_enclave.py to patch chained-measurement HMAC into
# ._enclave_header (mirrors host/bare_metal_n657/ and host/freertos_n657/).
# N657 uses chained_measurement only (no ess_miss_recovery), block layout
# is [Meta(32)|CT(256)] = 288B. UMBRA_ESS_MISS_RECOVERY=0 forces this.
bin/$(PROGRAM_NAME).bin: bin/$(PROGRAM_NAME).elf
	@echo "\n[PROTECT] Running protect_enclave.py on $<"
	@UMBRA_CHAINED=1 UMBRA_ESS_MISS_RECOVERY=0 \
	    python3 ../../tools/protect_enclave.py --hmac-over-plaintext \
	    bin/$(PROGRAM_NAME).elf src/main.c ../../tools/master_key.bin obj
	@echo "\n[BIN]	Creating binary"
	$(OBJCOPY) -O binary bin/$(PROGRAM_NAME).elf bin/$(PROGRAM_NAME).bin

clean:
	-$(RM) obj
	-$(RM) bin

dump:
	$(OBJDUMP) -D bin/$(PROGRAM_NAME).elf

.PHONY: all clean dump
