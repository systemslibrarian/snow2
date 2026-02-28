# CI-RESULTS.md — SNOW2 Hostile Audit

**Commit:** `9e6678a` (main)
**Date:** 2026-02-28

---

## CI Workflow Files

### `.github/workflows/pages.yml`

**Purpose:** Deploy web demo to GitHub Pages
**Trigger:** push to `main`, manual dispatch

**Jobs:**

1. **build**
   - `ubuntu-latest`
   - Install Rust stable + `wasm32-unknown-unknown` target
   - Install `wasm-pack` via official installer
   - `wasm-pack build snow2_wasm --target web --out-dir ../web_demo/pkg`
   - Install Node.js 20
   - `node web_demo/test_wasm.mjs` (48 WASM tests)
   - Upload `web_demo/` as Pages artifact

2. **deploy**
   - `actions/deploy-pages@v4`

### Missing CI

- **No `cargo test` CI workflow exists.** The Rust test suite (143 tests) is not run in CI.
- **No `cargo clippy` CI step.**
- **No `cargo fmt --check` CI step.**
- **No fuzz CI.**
- **No adversarial test CI.**
- **`test_download_upload.mjs` is not run in CI** — only `test_wasm.mjs` is.

---

## Fresh Checkout Behavior

| Check | Result |
|---|---|
| `cargo build` | PASS — builds from clean checkout |
| `cargo test` | PASS — all 143 tests pass |
| `web_demo/pkg/` exists | NO — gitignored, must be built first |
| `node web_demo/test_wasm.mjs` (no build) | FAIL — clear error message added (pre-check) |
| `scripts/wasm_test.sh` | PASS — builds WASM then runs tests |
| `node web_demo/test_download_upload.mjs` (no build) | FAIL — clear error message added (pre-check) |

**WASM artifacts are gitignored.** A fresh checkout requires running `wasm-pack build` before WASM tests work. The `scripts/wasm_test.sh` script handles this. The test files now include a pre-check with a helpful error message.

---

## Recommendations

1. Add a `ci.yml` workflow that runs `cargo test`, `cargo clippy`, and `cargo fmt --check`.
2. Add `test_download_upload.mjs` to the Pages workflow.
3. Consider adding a nightly fuzz CI job (even 60s per target catches regressions).
