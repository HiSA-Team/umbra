
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
BOOT_ELF_PATH = ${SECBOOT_DIR}/target/${TARGET_ARCH}/${BOOT_COMPILE_MODE}
BOOT_ELF_NAME = boot

#########
# Build #
#########

secureboot_check: 
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} check 

secureboot_build:
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} build ${BOOT_ELF_MODE}
 
secureboot_clean:
	@${CARGO} ${CARGO_PATH_OPT} ${SECBOOT_DIR} clean 

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
UMBRA_LIB_PATH = ${KERNEL_DIR}/target/${TARGET_ARCH}/${UMBRA_COMPILE_MODE}

umbra_build:
	@${CARGO} ${CARGO_PATH_OPT} ${KERNEL_DIR} rustc ${UMBRA_LIB_MODE} --crate-type=staticlib 
	@mkdir -p ${LIB_DIR}
	@cp ${UMBRA_LIB_PATH}/libkernel.a ${LIB_DIR}/libumbra.a

umbra_clean:
	@${CARGO} ${CARGO_PATH_OPT} ${KERNEL_DIR} clean;
	@rm -f lib/*

#################################################################
#    ___                                ___          _        	#
#   | _ \_ _ ___  __ _ _ _ __ _ _ __   |   \ _____ _(_)__ ___ 	#
#   |  _/ '_/ _ \/ _` | '_/ _` | '  \  | |) / -_) V / / _/ -_)	#
#   |_| |_| \___/\__, |_| \__,_|_|_|_| |___/\___|\_/|_\__\___|	#
#                |___/                                        	#
#################################################################

########
# Misc #
########

# Configure the target system security features
# Uses the flasher for stm32
enable_security:
	${FLASHER} ${CONNECT} ${SECURE_ENABLE};
	${FLASHER} ${CONNECT} ${OPTION_BYTES}

erase_all:
	${FLASHER} ${CONNECT} --erase all

#################
# Debug Backend #
#################

# Open the backend (fixed to openocd)
run_openocd:
	${OPENOCD} -f ${OPENOCD_CONFIG}

run_openocd_async:
	@${OPENOCD} -f ${OPENOCD_CONFIG} > /dev/null 2>&1 &

kill_openocd:
	@if pgrep -x openocd > /dev/null; then pkill -x openocd; fi

######################
# Programming Target #
######################

# Enable all security features on the target device
prepare_target: enable_security erase_all
	${FLASHER} ${CONNECT} ${LOAD} $(HOST_ELF)

# Use GDB to program the secure boot (TODO: move this to a script)
program_secure_boot:
# Connect to the backend
	@echo "[PROGRAM] Running ${OPENOCD} in the background"
	${MAKE} run_openocd_async
# Prorgram through GDB
	@echo "[PROGRAM] Programming secure boot from $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)"
	$(GDB) $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) \
	-ex 'target extended-remote:3333' \
	-ex 'load $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)' \
	-ex 'set confirm off' \
	-ex 'q'
# Kill the backend
	@echo "[PROGRAM] Killing ${OPENOCD}"
	${MAKE} kill_openocd
	@echo "[PROGRAM] Secure boot flashed onto the board"

# Use board-specific flasher to program the host code
program_host:
	@echo "[PROGRAM] Programming host from $(HOST_ELF)"
	${FLASHER} ${CONNECT} ${LOAD} $(HOST_ELF) --verify
	@echo "[PROGRAM] Host flashed onto the board"

program_target:
	${MAKE} prepare_target
	${MAKE} program_secure_boot
	${MAKE} program_host


##################
# Running Target #
##################

# It is possible to run the elf including both symbols
# Otherwise, just load symbols for either the secure boot or the host
run_elf:
	$(GDB) $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) \
	-ex 'set confirm off' \
	-ex 'add-symbol-file $(HOST_ELF) 0x08040000' \
	-ex 'b main' \
	-ex 'set confirm on' \
	-ex 'target extended-remote:3333'

run_secure_boot_symbols: 
	$(GDB) $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) \
	-ex 'target extended-remote:3333' 

run_host_symbols: 
	$(GDB) $(HOST_ELF) \
	-ex 'target extended-remote:3333' 

#########
# PHONY #
#########

.PHONY: all program_target
