# TEST-RESULTS.md — SNOW2 Hostile Audit

**Commit:** `9e6678a` (main)
**Date:** 2026-02-28
**Rust:** nightly + stable toolchain present
**Environment:** Ubuntu 24.04 (devcontainer), 2 CPU threads

---

## Full `cargo test` — All Test Suites

**Command:** `cargo test 2>&1 | tee /tmp/snow2_test_results.txt`

| Test binary | Passed | Failed | Time |
|---|---|---|---|
| `src/lib.rs` (unit) | 3 | 0 | 0.01s |
| `src/main.rs` (unit) | 0 | 0 | 0.00s |
| `tests/cross_platform.rs` | 17 | 0 | 185.11s |
| `tests/negative_edge_cases.rs` | 33 | 0 | 79.18s |
| `tests/pepper_policy.rs` | 25 | 0 | 113.62s |
| `tests/pqc_roundtrip.rs` | 0 | 0 | 0.00s |
| `tests/robustness.rs` | 38 | 0 | 300.91s |
| `tests/roundtrip.rs` | 3 | 0 | 45.03s |
| `tests/websafe_zw_platform.rs` | 24 | 0 | 714.33s |
| Doc-tests | 0 | 0 | 0.00s |
| **TOTAL** | **143** | **0** | **~1438s** |

Result: **ALL PASS** (0 failures, 0 ignored)

---

## Adversarial Tests

**File:** `tests/adversarial.rs` (26 tests, added as part of this audit)

**Command:** `cargo test --test adversarial --no-run` → compiles clean.

Full run not executed in this pass (skipped by user request). Individual tests validated during development:
- `embed_with_hardened_kdf_roundtrips` — PASS (69.82s)
- `embed_rejects_payload_exceeding_bucket_limit` — PASS (3.40s)
- `crlf_carrier_preserves_cr_in_output` — PASS (10.88s)

Remaining 23 adversarial tests: compile-verified, not yet run as a full suite.

---

## WASM Tests

**Command:** `node web_demo/test_wasm.mjs`
**Result:** 48 passed, 0 failed

**Command:** `node web_demo/test_download_upload.mjs`
**Result:** 12 passed, 0 failed. Download → upload → decrypt flow verified.

---

## Linting

### `cargo clippy --all-targets`

Warnings (non-blocking, no errors):
- 11 warnings in `src/` (lib): `div_ceil` manual reimpl, no-effect ops, suffix stripping style
- 2 warnings in `src/main.rs`: too_many_arguments, manual char comparison
- 7 warnings in `tests/websafe_zw_platform.rs`: collapsible_str_replace style
- Several `struct update has no effect` in test files

**No clippy errors. All warnings are style/lint, not correctness.**

### `cargo fmt --check`

**20 files have formatting diffs.** List:
- `snow2_wasm/src/lib.rs`
- `src/config.rs`, `src/container.rs`, `src/crypto.rs`, `src/lib.rs`
- `src/main.rs`, `src/pqc.rs`, `src/secure_fs.rs`, `src/secure_mem.rs`
- `src/stego/classic_trailing.rs`, `src/stego/mod.rs`, `src/stego/websafe_zw.rs`
- All 8 test files in `tests/`

`cargo fmt` has not been applied. The codebase does not enforce formatting in CI.
