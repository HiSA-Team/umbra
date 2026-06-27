#!/usr/bin/env bash
# Sign an N657 FSBL binary with a freshly-generated ECDSA-P256 keypair set,
# producing a v2.3-authenticated image. Keys are throwaway (regenerated every
# build, like master_key) and never committed. On the BSEC-open board the Boot
# ROM does NOT enforce the signature (needs the irreversible OTP close) — this
# is a validated signing PIPELINE, not runtime integrity. The signing tool
# self-verifies at sign time; we add a non-zero-signature assert to catch a
# silent regression to the unsigned (-of 0x80000000) path.
#
# Recipe verified 2026-06-25 against ST OEMuROT_Boot/STM32CubeIDE/postbuild.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IN_BIN="${1:?usage: sign_fsbl_n657.sh <in.bin> <out-trusted.bin>}"
OUT_BIN="${2:?usage: sign_fsbl_n657.sh <in.bin> <out-trusted.bin>}"

STM32CUBE_PROG_DIR="${STM32CUBE_PROG_DIR:-/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin}"
SIGNING_TOOL="${STM32_SIGNING_TOOL:-$STM32CUBE_PROG_DIR/STM32_SigningTool_CLI}"
KEYS_DIR="$HERE/.n657_signing_keys"
PW="umbra-dev-$$" # throwaway, never persisted beyond this build
FSBL_VERSION="${UMBRA_FSBL_VERSION:-1}" # anti-rollback image version (<=32); OTP-enforced only post-close

[ -x "$SIGNING_TOOL" ] || { echo "ERROR: STM32_SigningTool_CLI not found at $SIGNING_TOOL"; exit 1; }

# 1. Keygen: 8 fresh P-256 pairs; index 0 is the signer (password-encrypted PKCS#8).
rm -rf "$KEYS_DIR"; mkdir -p "$KEYS_DIR"
PUBS=()
for i in $(seq 0 7); do
  openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/k${i}_priv.pem" 2>/dev/null
  openssl ec -in "$KEYS_DIR/k${i}_priv.pem" -pubout -out "$KEYS_DIR/k${i}_pub.pem" 2>/dev/null
  PUBS+=("$KEYS_DIR/k${i}_pub.pem")
done
openssl pkcs8 -topk8 -in "$KEYS_DIR/k0_priv.pem" -out "$KEYS_DIR/k0_enc.pem" \
  -v2 aes-256-cbc -passout pass:"$PW" 2>/dev/null

# 2. Sign (v2.3, P-256, auth enabled = -of bit0). Entry point auto-extracts.
#    -align is REQUIRED: Umbra's N657 linker ORIGIN is 0x34180400 (the .rodata
#    fix left 0x400 for the header), so the payload must be padded to the 0x400
#    offset. Without it the code loads 0x400 too low and double-faults before
#    init_kernel. With -align the entry point extracts as 0x34180641 (the same
#    value the old -nk flow used).
"$SIGNING_TOOL" -bin "$IN_BIN" -hv 2.3 -a 1 \
  -pubk "${PUBS[@]}" -prvk "$KEYS_DIR/k0_enc.pem" -pwd "$PW" \
  -iv "$FSBL_VERSION" -la 0x34180000 -of 0x80000001 -t fsbl -align -o "$OUT_BIN" -s

# 3. Sanity: signature field (offset 0x04, 64 B) must be non-zero.
sig=$(xxd -s 4 -l 64 -p "$OUT_BIN" | tr -d '\n')
if [[ $sig =~ ^0+$ ]]; then
  echo "ERROR: signature field is all-zero — image is NOT signed (check -of flag)"; exit 1
fi
echo "[sign] signed FSBL: $OUT_BIN (sig starts ${sig:0:16}…)"
