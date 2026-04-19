# Author: Stefano Mercogliano 	<stefano.mercogliano@unina.it>
# Description:
#   This Makefile defines the project name and paths for the common Makefile.
#	Optionally, a user can define additional targets here.

################
# Program Name #
################

# $(MAKEFILE_LIST)			: Contains a list of all Makefiles parsed (This Makefile and common Makefile)
# $(first $(MAKEFILE_LIST))	: Extracts the first entry, which is the current Makefile.
# $(abspath ...)			: Converts the relative path of the Makefile to an absolute path.
# $(dir ...)				: Extracts the directory portion of the absolute path.
# $(shell basename ...)		: Extracts the last component of the directory path, which is the name of the directory containing the Makefile.
PROGRAM_NAME = $(shell basename $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

#####################
# Paths and Folders #
#####################

SRC_DIR		= src
OBJ_DIR		= obj
APP_DIR		= app
INC_DIR 	= inc 
STARTUP_DIR = src

LD_SCRIPTS = linker/memory.ld ../../linker/umbra.ld linker/host.ld 

#############
# Libraries #
#############

# Warning: libumbra.a contains veneer code with unresolved _imp references.
# The Host should NOT link it. Symbol addresses are provided via host.ld.
LIB_OBJ_LIST = #../../lib/libumbra.a
LIB_INC_LIST =

#############
# Toolchain #
#############

CC_PREFIX 	= arm-none-eabi-
CC 			= $(CC_PREFIX)gcc
LD 			= $(CC_PREFIX)ld
OBJDUMP 	= $(CC_PREFIX)objdump
OBJCOPY 	= $(CC_PREFIX)objcopy

CFLAGS 		= -O0 -march=armv8-m.main -g -c -save-temps=obj -fverbose-asm -Wa,-L
LDFLAGS 	= $(LIB_OBJ_LIST) -nostdlib $(addprefix -T,$(LD_SCRIPTS)) --discard-none
LIB_DIR		= lib 

########
# Misc #
########

SRCS_AUTO = $(wildcard src/*.c) $(wildcard app/*.c)
# Force app/fibonacci.c to the front of the link order. The `.app.enclave_code`
# section is concatenated in link order, and its byte at offset 0 is the
# enclave entry point (see `entry_point: ess_addr` in umbra_tee_create_imp).
# If counter.c sorts first alphabetically, counter_main becomes the entry and
# fibonacci/helpers end up dead code — which silently defeats the runtime
# ESS-miss fault test (tools/smoke_test_fault_runtime.sh UMBRA_ATTACK=hmac).
SRCS 	= app/fibonacci.c $(filter-out app/fibonacci.c,$(SRCS_AUTO))
OBJS 	= $(addprefix $(OBJ_DIR)/, $(notdir $(SRCS:.c=.o)))

RM      = rm -rf 					# Remove recursively command
MKDIR   = @mkdir -p $(@D) 			# Creates folders if not present

ENTRY_POINY ?= main

###############################################################################

###########
# Targets #
###########

all: bin/$(PROGRAM_NAME).bin

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "\n[OBJ]	Creating OBJs from src"
	$(MKDIR)
	$(CC) -o $@ $^ -I$(INC_DIR) $(LIB_INC_LIST) $(CFLAGS)

$(OBJ_DIR)/%.o: $(APP_DIR)/%.c
	@echo "\n[OBJ]	Creating OBJs from app"
	$(MKDIR)
	$(CC) -o $@ $^ -I$(INC_DIR) $(LIB_INC_LIST) $(CFLAGS)

obj/startup.o: 
	@echo "\n[OBJ]	Creating OBJs from $(STARTUP_DIR)/startup.s"
	$(MKDIR)
	$(CC) -o obj/startup.o $(STARTUP_DIR)/startup.s -I$(LIB_INC_LIST) $(CFLAGS)

bin/$(PROGRAM_NAME).elf: $(OBJS) obj/startup.o
	@echo "\n[ELF]	Creating elf file"
	$(MKDIR)
	$(LD) -o $@ $^ $(LDFLAGS)

ifeq ($(MCU_VARIANT),stm32l562)
PROTECT_ENCLAVE_FLAGS := --hmac-over-plaintext
else
PROTECT_ENCLAVE_FLAGS :=
endif

bin/$(PROGRAM_NAME).bin: bin/$(PROGRAM_NAME).elf
	@echo "\n[BIN]	Creating bin file"
	@python3 ../../tools/protect_enclave.py $(PROTECT_ENCLAVE_FLAGS) bin/$(PROGRAM_NAME).elf src/main.c ../../tools/master_key.bin obj
	$(OBJCOPY) -O binary bin/$(PROGRAM_NAME).elf bin/$(PROGRAM_NAME).bin

ifeq ($(MCU_VARIANT),stm32l562)
# Extract the post-protect_enclave.py enclave blob
# (header + code) as a flat binary suitable for CubeProgrammer --extload
# into OCTOSPI at 0x90000000. Section names are ._enclave_header /
# ._enclave_code (the leading underscore comes from the host linker script).
# This plaintext blob is flashed as-is; the L562 target uses the HAL
# target-as-oracle pattern (OTFDEC ENC-mode + OCTOSPI PP) to overwrite it
# with the real ciphertext in place on first boot. There is no offline
# encryptor.
enclaves_plain.bin: bin/$(PROGRAM_NAME).bin
	$(OBJCOPY) -O binary \
		--only-section=._enclave_header \
		--only-section=._enclave_code \
		bin/$(PROGRAM_NAME).elf $@
endif


debug: 
	$(GDB) bin/$(PROGRAM_NAME).elf
	
program_elf: 
	$(GDB) bin/$(PROGRAM_NAME).elf \
	-ex 'target extended-remote:3333' \
	-ex 'load bin/$(PROGRAM_NAME).elf' \
	-ex 'b ${ENTRY_POINY}' \
	-ex 'r' \

clean:
	-$(RM) obj
	-$(RM) bin

.PHONY: all clean

dump:
	$(OBJDUMP) -D bin/$(PROGRAM_NAME).elf

libdump:
	$(OBJDUMP) -f $(LIB_OBJ_LIST)


