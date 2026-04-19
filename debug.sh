#!/bin/bash

if [ "$MCU_VARIANT" = "stm32l562" ]; then
    # Flash the plaintext enclave blob into OCTOSPI.
    # The L562 target uses the HAL target-as-oracle cipher pass
    # (OTFDEC ENC-mode + OCTOSPI PP) to overwrite it with the real
    # ciphertext in place on first boot. There is no offline encryptor.
    make program_enclaves_extload
fi

make program_elf_boot && make program_elf_host