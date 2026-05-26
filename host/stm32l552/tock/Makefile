# Tock kernel + enclave_demo app → bin/tock.elf, matching the
# settings.sh HOST_ELF pattern (host/${MCU}/${HOST_APP}/bin/${HOST_APP}.elf).

BOARD_CRATE   := nucleo_l552ze_q_umbra
TARGET        := thumbv8m.main-none-eabi
BOARD_FEATURE := board_l552
APP_FLASH     := 0x08070000
APP_FLASH_LEN := 0x8000
# App RAM lives in 0x20010000-0x2001FFFF — the only NS-accessible 64 KB of
# SRAM. 0x20020000-0x2002FFFF is EFBC, GTZC-attributed Secure; NS writes
# there raise SecureFault.AUVIOL.
APP_RAM       := 0x20010000
APP_RAM_LEN   := 0x10000
APP_ARCH      := cortex-m33

ELF2TAB ?= elf2tab
OBJCOPY ?= arm-none-eabi-objcopy

APP_TARGET   := target/$(TARGET)/release/enclave_demo
APP_TBF      := $(APP_TARGET).tbf
IMAGE_DIR    := bin
IMAGE_OUT    := $(IMAGE_DIR)/tock.elf
BOARD_ELF    := target/$(TARGET)/release/$(BOARD_CRATE)
ENCLAVE_BIN  := enclave_payload/bin/enclave_payload.bin
ENCLAVE_ADDR := 0x08078000

.PHONY: all stage0-check board apps enclave image clean
.DEFAULT_GOAL := image

stage0-check:
	cargo build -p capsule_umbra
	cargo build -p enclave_demo --features=$(BOARD_FEATURE)

board:
	cargo build -p $(BOARD_CRATE) --release --target $(TARGET)

# `env -u LIBTOCK_PLATFORM` is mandatory: .cargo/config.toml sets
# LIBTOCK_PLATFORM as a workspace-wide default so bare `cargo check` resolves,
# but libtock-rs's build_scripts panics if both LIBTOCK_PLATFORM and
# LIBTOCK_LINKER_* are set together.
#
# elf2tab version pin: MUST be 0.10.x (NOT >= 0.11). Newer elf2tab emits a PIE
# TBF format that Tock master @ b35fad8 doesn't have a loader for; it would
# branch into the embedded ELF header and execute garbage. Install via:
#   cargo install elf2tab --version 0.10.0 --force
# --protected-region-size 128 = libtock-rs default `LIBTOCK_TBF_HEADER_SIZE`.
apps:
	env -u LIBTOCK_PLATFORM \
	    LIBTOCK_LINKER_FLASH=$(APP_FLASH) \
	    LIBTOCK_LINKER_FLASH_LENGTH=$(APP_FLASH_LEN) \
	    LIBTOCK_LINKER_RAM=$(APP_RAM) \
	    LIBTOCK_LINKER_RAM_LENGTH=$(APP_RAM_LEN) \
	    cargo build -p enclave_demo --release --features=$(BOARD_FEATURE) \
	        --target $(TARGET)
	mkdir -p target/tab
	$(ELF2TAB) \
	    --kernel-major 2 --kernel-minor 1 \
	    -n enclave_demo \
	    -o target/tab/enclave_demo.tab \
	    --stack 1024 \
	    --protected-region-size 128 \
	    $(APP_TARGET),$(APP_ARCH)

enclave: $(ENCLAVE_BIN)

$(ENCLAVE_BIN): enclave_payload/Makefile enclave_payload/src/header.c \
                enclave_payload/linker/enclave.ld \
                ../../../tools/master_key.bin
	$(MAKE) -C enclave_payload all

# The board's layout.ld leaves the ENCLAVE_NS region reserved (no section
# defined). objcopy --add-section injects the encrypted+signed enclave blob
# directly at $(ENCLAVE_ADDR), flagged ALLOC+LOAD+READONLY so it ends up in
# the flashable image.
$(IMAGE_OUT): board apps $(ENCLAVE_BIN)
	mkdir -p $(IMAGE_DIR)
	cp $(BOARD_ELF) $(IMAGE_OUT)
	$(OBJCOPY) --update-section .apps=$(APP_TBF) $(IMAGE_OUT)
	$(OBJCOPY) \
	    --add-section .enclave=$(ENCLAVE_BIN) \
	    --change-section-address .enclave=$(ENCLAVE_ADDR) \
	    --set-section-flags .enclave=alloc,load,readonly,contents \
	    $(IMAGE_OUT)

image: $(IMAGE_OUT)
all:   image

clean:
	cargo clean
	rm -rf target/tab $(IMAGE_DIR)
	$(MAKE) -C enclave_payload clean
