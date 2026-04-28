#!/bin/bash

source ./settings.sh
export UMBRA_ESS_MISS_RECOVERY=1
make secureboot_clean && make secureboot_build && make umbra_clean && make umbra_build && cd ${HOST_DIR} && make clean && make && cd ${ROOT_DIR}