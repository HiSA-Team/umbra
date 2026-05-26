# Builds the fibonacci enclave payload that lives at 0x08078000 of the Tock
# host image:
#   1. Compile src/header.c (this dir) + fibonacci.c (shared with bare_metal)
#   2. Link with linker/enclave.ld at 0x08078000
#   3. Run protect_enclave.py on the ELF (encrypt + HMAC + chain-measure)
#   4. Extract ._enclave_header + ._enclave_code as a flat .bin
# The parent Makefile then `objcopy --add-section`s the .bin into tock.elf.

CC_PREFIX := arm-none-eabi-
CC        := $(CC_PREFIX)gcc
LD        := $(CC_PREFIX)ld
OBJCOPY   := $(CC_PREFIX)objcopy
OBJDUMP   := $(CC_PREFIX)objdump

# Same flags as host/stm32l552/bare_metal/Makefile so the produced object
# code matches bare_metal's canonical enclave that protect_enclave.py was
# tuned against.
CFLAGS  := -O0 -march=armv8-m.main -g -c -save-temps=obj -fverbose-asm -Wa,-L
LDFLAGS := -nostdlib -T linker/enclave.ld --discard-none

FIBONACCI_C := ../../bare_metal/app/fibonacci.c
FIBONACCI_H_DIR := ../../bare_metal/inc

OBJ_DIR := obj
BIN_DIR := bin
ELF     := $(BIN_DIR)/enclave_payload.elf
BIN     := $(BIN_DIR)/enclave_payload.bin

# Link order matters: fibonacci first so its entry is at offset 0 of
# ._enclave_code.
OBJS := $(OBJ_DIR)/fibonacci.o $(OBJ_DIR)/header.o

MASTER_KEY := ../../../../tools/master_key.bin
PROTECT_PY := ../../../../tools/protect_enclave.py

.PHONY: all clean

all: $(BIN)

$(OBJ_DIR)/fibonacci.o: $(FIBONACCI_C)
	@mkdir -p $(OBJ_DIR)
	$(CC) -o $@ -c $< -I$(FIBONACCI_H_DIR) $(CFLAGS)

$(OBJ_DIR)/header.o: src/header.c
	@mkdir -p $(OBJ_DIR)
	$(CC) -o $@ -c $< $(CFLAGS)

$(ELF): $(OBJS) linker/enclave.ld
	@mkdir -p $(BIN_DIR)
	$(LD) -o $@ $(OBJS) $(LDFLAGS)

# protect_enclave.py rewrites the ELF in place: encrypts ._enclave_code and
# patches the header HMAC. We then extract both sections as a flat .bin.
$(BIN): $(ELF) $(MASTER_KEY)
	@echo "[enclave_payload] Encrypting + HMAC-signing fibonacci enclave"
	python3 $(PROTECT_PY) $(ELF) src/header.c $(MASTER_KEY) $(OBJ_DIR)
	$(OBJCOPY) -O binary \
	    --only-section=._enclave_header \
	    --only-section=._enclave_code \
	    $(ELF) $(BIN)
	@echo "[enclave_payload] Built $(BIN) ($$(wc -c < $(BIN)) bytes)"

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
