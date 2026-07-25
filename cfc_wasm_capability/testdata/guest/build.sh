#!/usr/bin/env bash
#
# Builds the Phase 1a toy wasm component fixtures and copies the resulting
# WASI 0.2 components into ../ (oak/cfc_wasm_capability/testdata/), where they
# are checked in and consumed hermetically (via include_bytes!) by the crate
# tests and the cap-host-selftest binary.
#
# Requires the guest toolchain (NOT needed to build the host crate):
#   cargo install cargo-component            # tested with cargo-component 0.21
#   rustup target add wasm32-unknown-unknown
#
# We deliberately target wasm32-unknown-unknown, NOT the cargo-component default
# wasm32-wasip1. The wasip1 target splices in the preview1->preview2 adapter,
# which makes even a trivial component import the entire wasi:cli/io/filesystem/
# clocks surface. Targeting wasm32-unknown-unknown produces a component that
# imports EXACTLY what its WIT world declares (nothing for `compute`, only
# wasi:clocks/wall-clock for `compute_clock`) -- which is the confinement the
# capability model is about.
#
# Usage:  ./build.sh
set -euo pipefail

TARGET="wasm32-unknown-unknown"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
testdata="$(cd "$here/.." && pwd)"

build_one() {
  local crate="$1" outname="$2"
  echo ">>> building $crate"
  ( cd "$here/$crate" && cargo component build --release --target "$TARGET" )
  local wasm
  wasm="$(find "$here/$crate/target/$TARGET" -name '*.wasm' -path '*release*' \
            ! -path '*deps*' | head -n1)"
  if [[ -z "${wasm}" ]]; then
    echo "ERROR: no .wasm produced for $crate" >&2
    exit 1
  fi
  cp "$wasm" "$testdata/$outname"
  echo "    -> $testdata/$outname"
}

build_one compute       compute.wasm
build_one adapter       adapter.wasm
build_one compute_clock compute_clock.wasm
build_one concat        concat.wasm

echo
echo "Done. Verify each is a component (layer=01) with, if available:"
echo "  wasm-tools component wit $testdata/compute.wasm"
echo "  wasm-tools component wit $testdata/adapter.wasm"
echo "  wasm-tools component wit $testdata/compute_clock.wasm"
