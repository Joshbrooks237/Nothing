#!/usr/bin/env bash
# setup.sh — bootstrap everything needed to build and run Nothing
#
# Run once:  bash setup.sh
#
# What this does:
#   1. Installs Rust (via rustup) if not present.
#   2. Installs Node.js dependencies for the CLI wrapper.
#   3. Compiles the Rust binary in release mode.
#
# After this completes, you can run:
#   ./nothing-core/target/release/nothing keygen
#   # or add nothing-core/target/release/ to your PATH, then:
#   nothing keygen

set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

section() { echo -e "\n${CYAN}${BOLD}▶ $1${RESET}"; }
ok()      { echo -e "${GREEN}✓ $1${RESET}"; }
warn()    { echo -e "${YELLOW}! $1${RESET}"; }

# ── 1. Rust ───────────────────────────────────────────────────────────────────

section "Checking for Rust..."

if command -v cargo &>/dev/null; then
  ok "Rust already installed: $(rustc --version)"
else
  warn "Rust not found.  Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  # Source cargo env for the rest of this script.
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  ok "Rust installed: $(rustc --version)"
fi

# ── 2. Node dependencies ──────────────────────────────────────────────────────

section "Installing Node.js CLI dependencies..."

if ! command -v node &>/dev/null; then
  warn "Node.js not found.  Please install Node.js 18+ from https://nodejs.org"
  warn "Skipping Node.js setup."
else
  ok "Node.js: $(node --version)"
  (cd "$(dirname "$0")/cli" && npm install)
  ok "CLI dependencies installed."
fi

# ── 3. Compile the Rust binary ────────────────────────────────────────────────

section "Compiling nothing-core (release build)..."
warn "This may take 2–5 minutes on first build while Cargo downloads dependencies."

(cd "$(dirname "$0")/nothing-core" && cargo build --release)

BIN="$(dirname "$0")/nothing-core/target/release/nothing"
ok "Binary compiled: $BIN"

# ── 4. Done ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Setup complete.${RESET}"
echo ""
echo "Add the binary to your PATH (paste this into your shell config):"
echo "  export PATH=\"\$PATH:$(realpath "$(dirname "$0")/nothing-core/target/release")\""
echo ""
echo "Or run directly:"
echo "  $BIN keygen"
echo ""
echo -e "${BOLD}Quick start:${RESET}"
echo "  # Terminal A"
echo "  nothing keygen"
echo "  nothing listen --port 7777"
echo ""
echo "  # Terminal B"
echo "  nothing mint --recipient <box-pubkey-from-A>"
echo "  nothing send /ip4/127.0.0.1/tcp/7777/p2p/<peer-id-from-A> <token>.nothing"
