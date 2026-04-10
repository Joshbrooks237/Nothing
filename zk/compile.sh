#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  compile.sh — Compile the Nothing settlement circuit with circom
#
#  Run from the zk/ directory:  bash compile.sh
#
#  Outputs into circuits/build/:
#    nothing_settle.r1cs   — the Rank-1 Constraint System (the circuit math)
#    nothing_settle_js/    — WASM witness generator
#    nothing_settle.sym    — symbol map for debugging
#
#  What the flags do:
#    --r1cs    output the constraint system (needed for Groth16 setup)
#    --wasm    output a WASM witness generator (runs in Node.js)
#    --sym     output a symbol file for debugging constraint names
#    -l        library include path (tells circom where node_modules are)
#    -o        output directory
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$SCRIPT_DIR/../circuits"
BUILD_DIR="$CIRCUIT_DIR/build"
NODE_MODS="$SCRIPT_DIR/node_modules"

echo "==> Checking prerequisites..."

# Check circom is installed
if ! command -v circom &>/dev/null; then
    echo ""
    echo "  circom not found.  Install it with:"
    echo "    curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh"
    echo "    cargo install circom"
    echo ""
    exit 1
fi

echo "    circom: $(circom --version)"

# Check node_modules exist
if [ ! -d "$NODE_MODS" ]; then
    echo ""
    echo "  node_modules not found.  Run:  cd zk && npm install"
    echo ""
    exit 1
fi

echo "==> Creating build directory: $BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Compiling circuit..."
circom "$CIRCUIT_DIR/nothing_settle.circom" \
    --r1cs \
    --wasm \
    --sym \
    -l "$NODE_MODS" \
    -o "$BUILD_DIR"

echo ""
echo "==> Done.  Outputs in $BUILD_DIR:"
ls -lh "$BUILD_DIR"
echo ""
echo "Next step: run  node zk/setup.js  to generate proving and verification keys."
