# FreeRTOS NS host demo for Umbra / STM32L552
# Issue #31 — https://github.com/HiSA-Team/umbra/issues/31

################
# Program Name #
################

PROGRAM_NAME = $(shell basename $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

#####################
# Paths and Folders #
#####################

SRC_DIR     = src
OBJ_DIR     = obj
APP_DIR     = app
INC_DIR     = inc
STARTUP_DIR = src

# FreeRTOS paths (V11.1.0: port files are in non_secure/ subdirectory)
FREERTOS_DIR    = lib/FreeRTOS-Kernel
FREERTOS_PORT   = $(FREERTOS_DIR)/portable/GCC/ARM_CM33_NTZ/non_secure
FREERTOS_HEAP   = $(FREERTOS_DIR)/portable/MemMang

LD_SCRIPTS = linker/memory.ld ../../linker/umbra.ld linker/host.ld

#############
# Toolchain #
#############

CC_PREFIX   = arm-none-eabi-
CC          = $(CC_PREFIX)gcc
LD          = $(CC_PREFIX)ld
OBJDUMP     = $(CC_PREFIX)objdump
OBJCOPY     = $(CC_PREFIX)objcopy

CFLAGS      = -O0 -march=armv8-m.main -g -c -save-temps=obj -fverbose-asm -Wa,-L
CFLAGS     += -I$(INC_DIR) -I$(SRC_DIR)
CFLAGS     += -I$(FREERTOS_DIR)/include -I$(FREERTOS_PORT)

LDFLAGS     = -nostdlib $(addprefix -T,$(LD_SCRIPTS)) --discard-none --allow-multiple-definition

########
# Srcs #
########

# Application sources
APP_SRCS    = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(APP_DIR)/*.c)
APP_OBJS    = $(addprefix $(OBJ_DIR)/, $(notdir $(APP_SRCS:.c=.o)))

# FreeRTOS sources
FREERTOS_SRCS = $(FREERTOS_DIR)/tasks.c \
                $(FREERTOS_DIR)/queue.c \
                $(FREERTOS_DIR)/list.c \
                $(FREERTOS_PORT)/port.c \
                $(FREERTOS_PORT)/portasm.c \
                $(FREERTOS_HEAP)/heap_4.c

FREERTOS_OBJS = $(addprefix $(OBJ_DIR)/freertos_, $(notdir $(FREERTOS_SRCS:.c=.o)))

ALL_OBJS = $(APP_OBJS) $(FREERTOS_OBJS) $(OBJ_DIR)/startup.o

RM      = rm -rf
MKDIR   = @mkdir -p $(@D)

###########
# Targets #
###########

all: bin/$(PROGRAM_NAME).bin

# App sources
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "\n[OBJ]	Compiling $<"
	$(MKDIR)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJ_DIR)/%.o: $(APP_DIR)/%.c
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

# Protect enclave + create binary
ifeq ($(MCU_VARIANT),stm32l562)
PROTECT_ENCLAVE_FLAGS := --hmac-over-plaintext
else
PROTECT_ENCLAVE_FLAGS :=
endif

bin/$(PROGRAM_NAME).bin: bin/$(PROGRAM_NAME).elf
	@echo "\n[BIN]	Creating binary"
	@python3 ../../tools/protect_enclave.py $(PROTECT_ENCLAVE_FLAGS) bin/$(PROGRAM_NAME).elf src/main.c ../../tools/master_key.bin obj
	$(OBJCOPY) -O binary bin/$(PROGRAM_NAME).elf bin/$(PROGRAM_NAME).bin

ifeq ($(MCU_VARIANT),stm32l562)
enclaves_plain.bin: bin/$(PROGRAM_NAME).bin
	$(OBJCOPY) -O binary \
		--only-section=._enclave_header \
		--only-section=._enclave_code \
		bin/$(PROGRAM_NAME).elf $@
endif

clean:
	-$(RM) obj
	-$(RM) bin

dump:
	$(OBJDUMP) -D bin/$(PROGRAM_NAME).elf

.PHONY: all clean dump
