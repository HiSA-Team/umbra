#!/bin/bash

source ./settings.sh
export UMBRA_ESS_MISS_RECOVERY=1
make secureboot_clean && make secureboot_build && make umbra_clean && make umbra_build && cd host/bare_metal_arm && make clean && make && cd ../..