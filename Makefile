
# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
#		  Salvatore Bramante  <salvatore.bramante@imtlucca.it>
# Description:
#	this is umbra main makefile. It works in cooperation with settings.sh, which must be called as the first thing.
#	depending on the target platform and the host, configured by settings.sh,
#	it builds the secure boot ELF, but it does not support host building. Instead it is expecting
#	the host ELF path. You can program the target board, and debug it

########
# Misc #
########

CARGO_PATH_OPT = -Z unstable-options -C

#####################################################
#    ___                        ___           _   	#
#   / __| ___ __ _  _ _ _ ___  | _ ) ___  ___| |_ 	#
#   \__ \/ -_) _| || | '_/ -_) | _ \/ _ \/ _ \  _|	#
#   |___/\___\__|\_,_|_| \___| |___/\___/\___/\__|	#
#                                                 	#
#####################################################

# debug or release
BOOT_COMPILE_MODE = release
BOOT_ELF_MODE = $(if $(filter debug,$(BOOT_COMPILE_MODE)),, --release)
# The build output lives in the workspace target/ at ROOT_DIR; the boot
# binary name is BOOT_CRATE_NAME (umbra-l552-boot / umbra-n657-boot)
# exported by settings.sh.
BOOT_ELF_PATH = ${ROOT_DIR}/target/${TARGET_ARCH}/${BOOT_COMPILE_MODE}
BOOT_ELF_NAME = ${BOOT_CRATE_NAME}

#########
# Build #
#########

secureboot_check: 
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} check 

key_gen:
	@python3 tools/gen_key.py

generate_boot_measurements: key_gen
# HOST_APP carries the short app name (`bare_metal`, `freertos`,
# `object_detection`). Only the NPU object-detection host needs the
# bytecode + weights extraction step.
ifeq ($(HOST_APP),object_detection)
	@echo "[NPU] Extracting NPU bytecode + computing boot HMACs (using freshly-generated master key)..."
	@python3 tools/extract_bytecode.py \
		host/stm32n657/object_detection/Model/NUCLEO-N657X0-Q \
		host/stm32n657/object_detection/build
	@python3 tools/measure_blobs.py \
		tools/master_key.bin \
		host/stm32n657/object_detection/build/model_bytecode.bin \
		host/stm32n657/object_detection/Model/NUCLEO-N657X0-Q/network_data.xSPI2.bin \
		src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
else
	@# For non-obj-det hosts, write an all-zero stub so the boot crate still
	@# compiles. Overwrite unconditionally (the previous "only if missing"
	@# guard caused stale HMACs to survive across HOST_APP switches and
	@# broke obj-det boot HMAC verification at G.2.b).
	@echo "// Auto-generated stub — HOST_APP != object_detection" > src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
	@echo "pub const MODEL_BYTECODE_ADDR: u32 = 0;" >> src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
	@echo "pub const MODEL_BYTECODE_LEN: u32 = 0;" >> src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
	@echo "pub const MODEL_BYTECODE_HMAC: [u8; 32] = [0; 32];" >> src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
	@echo "pub const MODEL_WEIGHTS_ADDR: u32 = 0;" >> src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
	@echo "pub const MODEL_WEIGHTS_LEN: u32 = 0;" >> src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
	@echo "pub const MODEL_WEIGHTS_HMAC: [u8; 32] = [0; 32];" >> src/hardware/platform/stm32n657/boot/src/boot_measurements.rs
endif

secureboot_build: generate_boot_measurements
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} build ${BOOT_ELF_MODE} ${BOOT_FEATURES}
 
secureboot_bin: 
	@$(OBJCOPY) -O binary $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) $(BINPATH)/$(BOOT_ELF_NAME).bin
	@$(OBJCOPY) --extract-symbol $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) $(LIB_DIR)/libumbra.a
	
secureboot_clean:
	# `-p ${BOOT_CRATE_NAME}` is mandatory in workspace mode: without
	# it, `cargo clean` nukes the entire workspace target/ — including
	# any libkernel.a or freshly-built peer artefacts. See the same
	# comment on `umbra_clean` below.
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} clean -p ${BOOT_CRATE_NAME}

#############
# Dump Code #
#############

secureboot_objdump:
	@$(OBJDUMP) -D $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)

secureboot_elfdump:
	@readelf -S $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)

secureboot_hexdump:
	@hexdump -C $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME).bin

secureboot_cargodump:
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} objdump --bin $(BOOT_ELF_NAME) -- -d --no-show-raw-insn

#####################################
#    _   _       _             		#
#   | | | |_ __ | |__ _ _ __ _ 		#
#   | |_| | '  \| '_ \ '_/ _` |		#
#    \___/|_|_|_|_.__/_| \__,_|		#
#                              		#
#####################################

# debug or release
UMBRA_COMPILE_MODE = debug
UMBRA_LIB_MODE = $(if $(filter debug,$(UMBRA_COMPILE_MODE)),, --release)
# Kernel build output lives in the workspace target/ at ROOT_DIR (path
# mirrors BOOT_ELF_PATH above).
UMBRA_LIB_PATH = ${ROOT_DIR}/target/${TARGET_ARCH}/${UMBRA_COMPILE_MODE}

umbra_build:
	@${CARGO} ${CARGO_PATH_OPT} ${KERNEL_DIR} rustc ${UMBRA_LIB_MODE} --crate-type=staticlib
	@cp ${UMBRA_LIB_PATH}/libkernel.a ${LIB_DIR}/libumbra.a

umbra_clean:
	# `-p kernel` is mandatory in workspace mode: without it, `cargo
	# clean` nukes the entire workspace target/ — including the boot
	# binary just produced by `secureboot_build`, breaking the
	# sequenced rebuild flow.
	@${CARGO} ${CARGO_PATH_OPT} ${KERNEL_DIR} clean -p kernel;
	@rm -f lib/*

#################################################################
#    ___                                ___          _        	#
#   | _ \_ _ ___  __ _ _ _ __ _ _ __   |   \ _____ _(_)__ ___ 	#
#   |  _/ '_/ _ \/ _` | '_/ _` | '  \  | |) / -_) V / / _/ -_)	#
#   |_| |_| \___/\__, |_| \__,_|_|_|_| |___/\___|\_/|_\__\___|	#
#                |___/                                        	#
#################################################################

# Configure the target system security features
# Uses the flasher for stm32
enable_security:
	${FLASHER} ${CONNECT} ${SECURE_ENABLE};
	${FLASHER} ${CONNECT} ${OPTION_BYTES}

erase_all:
	${FLASHER} ${CONNECT} --erase all

# Open the backend (fixed to openocd)
openocd:
	${OPENOCD} -f ${OPENOCD_CONFIG}

# Program the secure boot first and the host then
# A backend (such as openocd) must be opened before doing this
program_elf: program_elf_boot program_elf_host

program_elf_boot:
	# `set pagination off` + `set confirm off` MUST come BEFORE any
	# command that may prompt — `add-symbol-file` (next target) asks
	# (y or n) per design unless confirm is disabled. Pagination off
	# prevents the `--More--` pause that hangs the GDB-as-loader path
	# inside a non-interactive shell.
	$(GDB) $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) \
	-ex 'set pagination off' \
	-ex 'set confirm off' \
	-ex 'target extended-remote:3333' \
	-ex 'load $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)' \
	-ex 'q'

program_elf_host:
	$(GDB) $(HOST_ELF) \
	-ex 'set pagination off' \
	-ex 'set confirm off' \
	-ex 'directory $(HOST_DIR)/src' \
	-ex 'directory $(HOST_DIR)/app' \
	-ex 'directory $(KERNEL_DIR)/src' \
	-ex 'directory $(SECBOOT_DIR)/src' \
	-ex 'directory $(PLATFORM_DIR)/drivers/src' \
	-ex 'directory $(HW_DIR)/architecture/arm/src' \
	-ex 'target extended-remote:3333' \
	-ex 'add-symbol-file $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) 0x08000000' \
	-ex 'b main' \
	-ex 'r' \
	-ex 'load $(HOST_ELF)' \
	-ex 'r' \
	-ex 'set confirm on'

##############
# Deprecated #
##############

# Program the secure boot and just debug it
program_elf_boot_stay: 
	$(GDB) $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) \
	-ex 'target extended-remote:3333' \
	-ex 'b secure_boot' \
	-ex 'set confirm off' \
	-ex 'r' \
	-ex 'load $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)' \
	-ex 'r' \
	-ex 'set confirm on'

# Program the system using the flasher (i.e. the flat binary)
# We expect the user to use GDB as a loader, but it is possible to
# load flat binaries using the platform flasher (if any)
program_target: enable_security
	${FLASHER} ${CONNECT} ${LOAD} $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME).bin ${TARGET_FLASH_START}

# Permanent path used to program the plaintext enclave
# blob into external OCTOSPI flash at 0x90000000 via STM32CubeProgrammer
# --extload. The L562 target then uses the HAL target-as-oracle cipher pass
# (OTFDEC ENC-mode + OCTOSPI PP) to overwrite it with the real ciphertext
# in place on first boot. There is no offline encryptor.
#
# IMPORTANT: erase OCTOSPI sectors 0-3 (the full 16 KB OTFDEC region)
# BEFORE writing the plaintext blob. Without this, sectors 1-3 keep
# stale ciphertext from a previous master_key — when the boot reads
# probe_word at 0x90000000 it gets garbage instead of the UBMR magic,
# falls into WARM path with the new OFD key, fails to decrypt, and
# infinite-spins in s2_fail. Surfaced once the xtask auto-rebuild UX
# made master_key rotation happen on every flash.
#
# Per-sector form (vs `--erase 0 3`) matches the L552 debug.sh wipe
# pattern that documented STM32_Programmer_CLI v2.19 multi-sector-range
# misbehavior.
program_enclaves_extload:
	$(MAKE) -C $(HOST_DIR) enclaves_plain.bin
	# Build a 16 KB padded blob covering the full OTFDEC region (sectors
	# 0-3 at 0x90000000-0x90003FFF). The previous per-sector
	# `--extload --erase N N` form silently no-op'd on STM32_Programmer_CLI
	# v2.19 with the L562 extloader — leaving sectors 1-3 with stale
	# ciphertext from a previous master_key, and the boot's WARM-path
	# decryption attempt with today's key failed (s2_fail). Padding the
	# download to 16 KB makes STM32_Programmer_CLI auto-erase all 4
	# sectors in its normal download-with-erase flow, which is documented
	# to work reliably across loaders.
	@tr '\0' '\377' < /dev/zero | head -c 16384 > $(HOST_DIR)/enclaves_plain_padded.bin
	@dd if=$(HOST_DIR)/enclaves_plain.bin of=$(HOST_DIR)/enclaves_plain_padded.bin conv=notrunc 2>/dev/null
	@ls -la $(HOST_DIR)/enclaves_plain_padded.bin
	$(FLASHER) $(CONNECT) --extload $(EXTLOAD_STLDR) \
		--download $(HOST_DIR)/enclaves_plain_padded.bin 0x90000000 -v

#########
# PHONY #
#########

.PHONY: all clean program_enclaves_extload