# FreeRTOS NS host demo for Umbra / STM32N657.
# Runs a single FreeRTOS task that scans AXISRAM1 NS for enclave headers,
# creates each one via the umbra_enclave_create NSC veneer, and enters it under
# the Secure FSBL's SysTick preemption window.
#
# The FreeRTOS-Kernel submodule is shared with host/freertos_arm/.

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
CFLAGS     += -I$(SRC_DIR) -I$(INC_DIR) -I$(COMMON_INC_DIR)
CFLAGS     += -I$(FREERTOS_DIR)/include -I$(FREERTOS_PORT)

LDFLAGS     = -nostdlib $(addprefix -T,$(LD_SCRIPTS)) --discard-none --allow-multiple-definition

########
# Srcs #
########

# Application sources: host code under src/ + the enclave payload under app/.
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
	$(LD) -o $@ $^ $(LDFLAGS)

# F.3: enclave header present → patch chained-measurement HMAC via
# protect_enclave.py (mirrors bare_metal_n657/Makefile). N657 uses
# chained_measurement (288 B blocks = Meta(32)+CT(256)) — same flags.
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
