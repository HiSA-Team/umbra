#!/bin/bash
#
# Regenerate the YOLOv2 model for Umbra G.2.b inference.
#
# Difference vs the upstream generate-n6-model_NUCLEO-N657X0-Q.sh:
#   - Custom mpool (stm32n6-umbra.mpool) that omits AXIFLEXMEM (0x34000000)
#     and AXISRAM1 (0x34080000), which overlap with the Umbra host's code +
#     ESS region (0x34000000–0x340FFFFF). Without this, the original blob
#     emitted ~88 hardcoded 0x34xxxxxx scratch refs, several inside the
#     host range, and the NPU bus master would scribble over host memory
#     during inference.
#
#   - Custom neuralart profile (user_neuralart_umbra.json) pointing at the
#     restricted mpool. Same compiler options as upstream EXCEPT
#     `--cache-maintenance` is REMOVED. That flag emits sync points into
#     the bytecode where the EC halts and waits for the CPU's cache
#     invalidate callback before continuing. Our setup has activations
#     mapped as Device-nGnRnE (uncached) so cache maintenance is a no-op,
#     but the bytecode still emits the sync points — the inline-poll
#     loop spends ~9s acknowledging ~41M of them. Disabling
#     cache-maintenance should drop ack rate to per-epoch boundaries
#     (~1738 blocks ≈ thousands of acks) and bring inference to ~50ms.
#
# Output files end up in ./st_ai_output/ and are then copied to
# ../NUCLEO-N657X0-Q/ (the location the host build expects).

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "${SCRIPT_DIR}"

# Path to stedgeai. Default is the macOS install location; override via
# the STEDGEAI env var on Linux / Windows (e.g. an x86 box):
#   STEDGEAI=/path/to/Utilities/linux/stedgeai ./generate-umbra.sh
STEDGEAI="${STEDGEAI:-/Applications/ST/STEdgeAI_v2/2.0/Utilities/mac/stedgeai}"

if [ ! -x "${STEDGEAI}" ]; then
    echo "ERROR: stedgeai not found at ${STEDGEAI}"
    echo "       Set STEDGEAI env var to point at the binary."
    exit 1
fi

# NOTE on macOS Apple Silicon: stedgeai is x86_64; the bundled TensorFlow
# uses AVX which Rosetta 2 can't translate, so generate aborts immediately.
# Run this on a native x86 Linux/Windows machine instead.
#
# NOTE on the Linux 2.0 install (observed at /opt/ST/STEdgeAI/2.0/Utilities/
# configs/stm32n6.mdesc): the bundled stm32n6.mdesc is empty/corrupt and
# stedgeai dies with "machine description JSON ERROR: Unexpected end of
# string". The canonical mdesc from the macOS install is included in this
# bundle as `stm32n6.mdesc`. Replace the broken file before running:
#   sudo cp stm32n6.mdesc /opt/ST/STEdgeAI/2.0/Utilities/configs/stm32n6.mdesc

# Clean previous output.
rm -rf st_ai_output

"${STEDGEAI}" generate \
    --model quantized_tiny_yolo_v2_224_.tflite \
    --target stm32n6 \
    --st-neural-art default@user_neuralart_umbra.json \
    --input-data-type uint8 \
    --output-data-type int8

# Copy outputs into the host build directory.
DEST="${SCRIPT_DIR}/../NUCLEO-N657X0-Q"
echo
echo "Copying to ${DEST}/..."
mkdir -p "${DEST}"
cp st_ai_output/network.c            "${DEST}/"
cp st_ai_output/network_ecblobs.h    "${DEST}/"
cp st_ai_output/stai_network.c       "${DEST}/"
cp st_ai_output/stai_network.h       "${DEST}/"
cp st_ai_output/network_atonbuf.xSPI2.raw "${DEST}/network_data.xSPI2.bin"

echo
echo "[regen] done."
