#!/usr/bin/env bash
# Build the pinned Charon + Aeneas verification toolchain vendored as submodules
# under formal/toolchain/. Idempotent. Run this after
#   git submodule update --init formal/toolchain/aeneas formal/toolchain/charon
#
# The agent's PATH lacks the OCaml/Rust-nightly toolchains, so YOU run this.
# Pins: aeneas 8dd8bfb (tag nightly-2026.06.16), charon 6f058254 (its charon-pin).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHARON="$HERE/charon"
AENEAS="$HERE/aeneas"

if [ ! -e "$CHARON/Makefile" ] || [ ! -e "$AENEAS/Makefile" ]; then
  echo "error: submodules not checked out. Run:" >&2
  echo "  git submodule update --init formal/toolchain/aeneas formal/toolchain/charon" >&2
  exit 1
fi

# macOS BSD make is rejected by Charon's Makefile — need GNU make.
MAKE="${MAKE:-gmake}"
command -v "$MAKE" >/dev/null || { echo "error: '$MAKE' not found (brew install make)"; exit 1; }
OPAM_SWITCH="${OPAM_SWITCH:-aeneas}"   # OCaml 5.3.0 switch for Aeneas

echo ">> [1/3] building charon (Rust nightly-2026-06-01 + charon-ml OCaml)"
( cd "$CHARON" && "$MAKE" )                       # -> charon/bin/charon

echo ">> [2/3] wiring aeneas -> our pinned charon"
ln -sfn ../charon "$AENEAS/charon"                # aeneas wants ./charon/bin/charon at charon-pin

echo ">> [3/3] building aeneas (opam switch: $OPAM_SWITCH)"
eval "$(opam env --switch="$OPAM_SWITCH")"
( cd "$AENEAS" && "$MAKE" build-bin-dir )         # -> aeneas/bin/aeneas

echo
echo ">> done. Put the binaries on PATH for the extraction pipeline:"
echo "   export PATH=\"$AENEAS/bin:$CHARON/bin:\$PATH\""
echo "   charon --help | head -1 ; aeneas -version"
