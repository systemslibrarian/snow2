#!/usr/bin/env bash
set -euo pipefail

# Build WASM + run all Node-side tests in one command.
#
# Usage:  ./scripts/wasm_test.sh
#
# Prerequisites: Rust toolchain, wasm-pack, Node.js 18+

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Building WASM package ==="
cd "$REPO_ROOT/snow2_wasm"
wasm-pack build --target web --out-dir ../web_demo/pkg

echo ""
echo "=== Running WASM tests ==="
cd "$REPO_ROOT"
node web_demo/test_wasm.mjs

echo ""
echo "=== All WASM tests passed ==="
