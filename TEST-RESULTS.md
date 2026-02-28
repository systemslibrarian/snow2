# TEST-RESULTS.md — SNOW2 Hostile Audit

**Commit:** post-`44dbbbc` (current session fixes applied)
**Date:** 2025-07-21
**Rust:** nightly + stable toolchain present
**Environment:** Ubuntu 24.04 (devcontainer), 2 CPU threads

---

## Full `cargo test` — All Test Suites

**Command:** `cargo test -- --test-threads=2`

| Test binary | Passed | Failed | Time |
|---|---|---|---|
| `src/lib.rs` (unit) | 3 | 0 | 0.07s |
| `src/main.rs` (unit) | 0 | 0 | 0.00s |
| `tests/adversarial.rs` | 26 | 0 | 481.13s |
| `tests/cross_platform.rs` | 17 | 0 | 189.17s |
| `tests/negative_edge_cases.rs` | 33 | 0 | 75.88s |
| `tests/pepper_policy.rs` | 25 | 0 | 107.30s |
| `tests/pqc_roundtrip.rs` | 0 | 0 | 0.00s |
| `tests/robustness.rs` | 38 | 0 | 313.96s |
| `tests/roundtrip.rs` | 3 | 0 | 44.01s |
| Doc-tests | 0 | 0 | 0.00s |
| **TOTAL** | **145** | **0** | **~1211s** |

Result: **ALL PASS** (0 failures, 0 ignored)

---

## Adversarial Tests

**File:** `tests/adversarial.rs` (26 tests, added as part of this audit)

**All 26 tests executed and passing.** Key results:
- `hardened_kdf_embed_wrong_password_fails` — PASS
- `hardened_kdf_embed_with_pepper_wrong_pepper_fails` — PASS
- `random_byte_corruption_classic_fails` — PASS (corrupts trailing whitespace channel, AEAD rejects)
- `random_byte_corruption_websafe_fails` — PASS (byte corruption → extraction fails)
- `embed_extract_symmetry_classic_small` — PASS (sizes 0,1,2,10,100,1000)
- `embed_extract_symmetry_websafe_small` — PASS (sizes 0,1,2,10,100,1000)
- `truncate_stego_at_various_points` — PASS (10/25/50/75% truncation)
- All 3 malformed v4 container tests — PASS
- All 3 KDF bounds validation tests — PASS

---

## WASM Tests

**Command:** `node web_demo/test_wasm.mjs`
**Result:** 48 passed, 0 failed

**Command:** `node web_demo/test_download_upload.mjs`
**Result:** 12 passed, 0 failed. Download → upload → decrypt flow verified.

---

## Linting

### `cargo clippy --all-targets -- -D warnings`

**PASS — zero warnings, zero errors.** All clippy issues fixed:
- `div_ceil` manual reimpl → `div_ceil()` method
- `repeat().take()` → `str::repeat()`
- `collapsible_str_replace` → chained `.replace()`
- `ends_with` + manual slice → `strip_suffix`
- Same-value push loop → `resize()`
- Loop variable indexing → `for (i, &item) in ...`
- `too_many_arguments` → `#[allow]` annotation
- `needless_update` in test struct init → removed `..Default::default()`
- `useless_asref` → `*line` dereference

### `cargo fmt --check`

**PASS — all files formatted.** `cargo fmt` applied to all source and test files.
