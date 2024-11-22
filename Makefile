
# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
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
 
secureboot_bin: 
	@$(OBJCOPY) -O binary $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) $(BINPATH)/$(BOOT_ELF_NAME).bin
	
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
	$(GDB) $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME) \
	-ex 'target extended-remote:3333' \
	-ex 'load $(BOOT_ELF_PATH)/$(BOOT_ELF_NAME)' \
	-ex 'set confirm off' \
	-ex 'q'

program_elf_host:
	$(GDB) $(HOST_ELF) \
	-ex 'target extended-remote:3333' \
	-ex 'b main' \
	-ex 'set confirm off' \
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

#########
# PHONY #
#########

.PHONY: all clean 