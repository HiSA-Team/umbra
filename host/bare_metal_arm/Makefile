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

LD_SCRIPT 	= linker/host.ld 

#############
# Libraries #
#############

LIB_OBJ_LIST = lib/libumbra.a
LIB_INC_LIST =

#############
# Toolchain #
#############

CC_PREFIX 	= /opt/gcc-arm-none-eabi/bin/arm-none-eabi-
CC 			= $(CC_PREFIX)gcc
LD 			= $(CC_PREFIX)ld
OBJDUMP 	= $(CC_PREFIX)objdump
OBJCOPY 	= $(CC_PREFIX)objcopy

CFLAGS 		= -O0 -march=armv8-m.main -g -c
LDFLAGS 	= $(LIB_OBJ_LIST) -nostdlib -T$(LD_SCRIPT)
LIB_DIR		= lib 

########
# Misc #
########

SRCS 	= $(wildcard src/*.c) $(wildcard app/*.c)
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

bin/$(PROGRAM_NAME).bin: bin/$(PROGRAM_NAME).elf
	@echo "\n[BIN]	Creating bin file"
	$(OBJCOPY) -O binary bin/$(PROGRAM_NAME).elf bin/$(PROGRAM_NAME).bin


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


