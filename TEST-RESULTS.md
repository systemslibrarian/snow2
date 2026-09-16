# TEST-RESULTS.md — SNOW2 Hostile Audit

**Commit:** post-`44dbbbc` (current session fixes applied)
**Date:** 2025-07-21
**Revised:** 2026-09-16 — table below re-measured; see the note on `pqc_roundtrip`.
**Rust:** nightly + stable toolchain present
**Environment:** Ubuntu 24.04 (devcontainer), 2 CPU threads

---

## Full `cargo test` — All Test Suites

**Command:** `cargo test --no-fail-fast -- --test-threads=2`

Re-measured 2026-09-16 (`--release`, macOS, 2 test threads):

| Test binary | Passed | Failed |
|---|---|---|
| `src/lib.rs` (unit) | 3 | 0 |
| `src/main.rs` (unit) | 0 | 0 |
| `tests/adversarial.rs` | 26 | 0 |
| `tests/cross_platform.rs` | 17 | 0 |
| `tests/negative_edge_cases.rs` | 35 | 0 |
| `tests/pepper_policy.rs` | 25 | 0 |
| `tests/robustness.rs` | 38 | 0 |
| `tests/roundtrip.rs` | 3 | 0 |
| `tests/steganalysis.rs` | 7 | 0 |
| `tests/websafe_zw_platform.rs` | 24 | 0 |
| Doc-tests | 0 | 0 |
| **TOTAL (default features)** | **178** | **0** |
| `tests/pqc_roundtrip.rs` (`--features pqc`) | 10 | 0 |
| **TOTAL (`--features pqc`)** | **188** | **0** |

Result: **ALL PASS** (0 failures, 0 ignored), in both feature configurations.

### Why the old table said `pqc_roundtrip | 0 | 0`

Because the suite was never built. `pqc_roundtrip.rs` is `#![cfg(feature = "pqc")]`,
and the run above it used default features, so the file compiled to an empty
binary and reported zero tests. A row of zeros was recorded as part of an
"ALL PASS" result.

What that zero was hiding, found on 2026-09-16:

1. `cargo test --features pqc` **did not compile.** `EmbedOptions` and
   `EmbedSecurityOptions` carry `#[cfg(feature = "pqc")]` fields, so every
   exhaustive struct literal in the integration tests failed with E0063 once
   the feature was enabled.
2. Once compiling, `test_pqc_roundtrip` **failed**: `embed --pqc-pk` died with
   "Password must not be empty." `embed_with_options` wrapped *every* container
   in the v4 outer AEAD, which is keyed by Argon2id over the password — but PQC
   mode is keypair-based and has no password. PQC embedding was broken
   end-to-end for as long as the v4 pipeline has existed.

Both are fixed, and CI now has a dedicated `Rust Tests (pqc feature)` job so a
feature-gated suite can no longer report zero and be counted as passing.

**Rule this file now follows:** a suite reporting 0 tests is an unverified
suite, not a passing one. Zero rows must be justified or removed.

### Suite runtime

The original table recorded ~1211s, dominated by Argon2id in unoptimized debug
dependencies (adversarial alone: 481s). `Cargo.toml` now sets
`[profile.dev.package."*"] opt-level = 2`, which optimizes dependencies while
leaving snow2's own code unoptimized so debug assertions and overflow checks
still apply. The adversarial suite now runs in **6.5s** in debug — a ~74x
improvement, and the reason the suite is cheap enough to keep running.

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
