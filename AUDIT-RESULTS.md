# AUDIT-RESULTS.md — SNOW2 Hostile Implementation Audit

**Commit:** `44dbbbc` → updated in current session (post-fix)
**Date:** 2025-07-21
**Auditor:** Automated hostile audit
**Evidence files:** `TEST-RESULTS.md`, `FUZZ-RESULTS.md`, `CI-RESULTS.md`, `ADVERSARIAL-RESULTS.md`

---

## 1. Outer-Layer Password/KDF Behavior

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| Outer layer uses `outer_profile()` not hardcoded `recommended()` | PASS | `src/lib.rs` lines 144-153, 209-213 |
| `outer_profile()` returns `recommended()` for params ≤ recommended bounds | PASS | `src/crypto.rs` `outer_profile()` method |
| `outer_profile()` returns `hardened()` for params above recommended | PASS | `src/crypto.rs` `outer_profile()` method |
| Extraction tries both profiles (recommended then hardened) | PASS | `src/lib.rs` `try_v4_extract()` lines 276-345 |
| Wrong password on hardened KDF fails | PASS | `tests/robustness.rs` `outer_layer_requires_correct_password` |
| Hardened KDF roundtrip works | PASS | `tests/robustness.rs` `embed_with_hardened_kdf_roundtrips` |
| Adversarial: wrong password on hardened profile | PASS | `tests/adversarial.rs` `hardened_kdf_embed_wrong_password_fails` |
| Adversarial: wrong pepper on hardened profile | PASS | `tests/adversarial.rs` `hardened_kdf_embed_with_pepper_wrong_pepper_fails` |
| Adversarial: outer profile boundary selection | PASS | `tests/adversarial.rs` tests #8, #9 |

---

## 2. Embed/Extract Size Safety

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| Oversized payload rejected with clear error | PASS | `tests/robustness.rs` `embed_rejects_payload_exceeding_bucket_limit` |
| Small payloads (0, 1, 2 bytes) roundtrip | PASS | `tests/adversarial.rs` `embed_extract_symmetry_*` |
| Boundary payload (V4_MAX_BUCKET) | PASS | `tests/robustness.rs` `embed_succeeds_for_payload_within_limit` |
| Carrier too small → error | PASS | `tests/robustness.rs` `classic_carrier_too_small` |
| Carrier soft cap (10 MiB) enforced | PASS | `src/lib.rs` `MAX_CARRIER_BYTES` check in both embed paths |
| Embed output always extractable | PASS | 169 tests pass including 17 cross-platform roundtrips |

---

## 3. CRLF/LF Correctness

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| LF carrier roundtrip | PASS | Multiple roundtrip tests use LF by default |
| CRLF carrier roundtrip | PASS | `tests/robustness.rs` `crlf_carrier_preserves_cr_in_output` |
| CRLF preservation in output | PASS | Same test asserts `crlf_count > 0` |
| Mixed line endings | PASS | `tests/adversarial.rs` `mixed_crlf_lf_cr_carrier_websafe` |
| Bare \\r carrier → clean failure | PASS | `tests/adversarial.rs` `bare_cr_only_carrier_classic` |
| Marker not appended after stray \\r | PASS | `tests/robustness.rs` `classic_no_marker_after_bare_cr` |
| Marker position relative to \\r | PASS | `tests/adversarial.rs` `classic_marker_position_relative_to_cr` |

---

## 4. Malformed Input Handling

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| Truncated hidden data | PASS | `tests/adversarial.rs` `truncate_stego_at_various_points` |
| Corrupted data channel (50 whitespace flips) | PASS | `tests/adversarial.rs` `random_byte_corruption_classic_fails` |
| Corrupted bytes (websafe) | PASS | `tests/adversarial.rs` `random_byte_corruption_websafe_fails` |
| Wrong mode | PASS | `tests/adversarial.rs` `classic_embed_websafe_extract_fails`, `websafe_embed_classic_extract_fails` |
| No hidden data | PASS | `tests/adversarial.rs` `extract_from_clean_text_*` |
| Too-small carrier | PASS | `tests/robustness.rs` `classic_carrier_too_small` |
| Malformed v4 container fields | PASS | `tests/adversarial.rs` `v4_container_*` (3 tests) |
| KDF param bounds validation | PASS | `tests/adversarial.rs` `kdf_params_*` (3 tests) |
| Corrupted ciphertext | PASS | `tests/negative_edge_cases.rs` (33 tests) |
| Invalid/legacy headers | PASS | `tests/robustness.rs` `legacy_container_*` tests |
| Fuzz: container parse | PASS | 591,930 runs, 0 crashes |
| Fuzz: v4 header | PASS | 752,488 runs, 0 crashes |
| Fuzz: outer AEAD | PASS | 116,860 runs, 0 crashes |
| Fuzz: bits_to_bytes | PASS | 111,215 runs, 0 crashes |
| Fuzz: CRLF mixed | PASS | 40,770 runs, 0 crashes |
| Fuzz: classic_extract | PASS | 1,455,240 runs, 0 crashes |
| Fuzz: extract_pipeline | PASS | 3,479 runs, 0 crashes |
| Fuzz: websafe_extract | PASS | 3,226,426 runs, 0 crashes |

---

## 5. Demo / WASM Behavior

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| WASM builds from repo root | PASS | `wasm-pack build snow2_wasm --target web --out-dir ../web_demo/pkg` |
| WASM test suite | PASS | `node web_demo/test_wasm.mjs` — 48 passed, 0 failed |
| Download/upload flow | PASS | `node web_demo/test_download_upload.mjs` — 12 passed, 0 failed |
| Fresh checkout: pre-check error | PASS | `test_wasm.mjs` and `test_download_upload.mjs` have pre-checks |
| README build instructions correct | PASS | `web_demo/README.md` updated with correct `--out-dir` path |
| Download button wired up | PASS | `web_demo/index.html` has button, `app.js` has handler |
| CSP headers present | PASS | WASM test verifies CSP meta tag |

---

## 6. Code Quality

**Verdict: PASS**

| Check | Result | Notes |
|---|---|---|
| `cargo clippy -- -D warnings` | **PASS** | Zero warnings across all targets |
| `cargo fmt --check` | **PASS** | All files formatted |
| `cargo build` | PASS | Clean build, no errors |
| `cargo build --release` | PASS | Release build available at `target/release/snow2` |

---

## 7. CI Coverage

**Verdict: PASS**

| Check | Result | Notes |
|---|---|---|
| `cargo test` in CI | **PASS** | `.github/workflows/ci.yml` — test job |
| `cargo clippy -- -D warnings` in CI | **PASS** | `.github/workflows/ci.yml` — check job |
| `cargo fmt --check` in CI | **PASS** | `.github/workflows/ci.yml` — check job |
| WASM build + test in CI | **PASS** | `.github/workflows/ci.yml` — wasm job + `pages.yml` |
| `test_download_upload.mjs` in CI | **PASS** | `.github/workflows/ci.yml` — wasm job |
| Fuzz in CI | N/A | Not enforced (requires nightly + long runtime) |

---

## Summary

| Area | Verdict |
|---|---|
| 1. Outer KDF | **PASS** |
| 2. Size safety | **PASS** |
| 3. CRLF/LF | **PASS** |
| 4. Malformed input | **PASS** |
| 5. Demo/WASM | **PASS** |
| 6. Code quality | **PASS** |
| 7. CI coverage | **PASS** |

### Resolved Since Initial Audit

1. **CI gap (was FAIL):** Added `.github/workflows/ci.yml` with `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, WASM build + both test scripts.
2. **Formatting (was FAIL):** `cargo fmt` applied to all 20 files. `fmt --check` now passes.
3. **Clippy (was WARN):** All clippy warnings fixed. `-D warnings` now passes clean.
4. **Adversarial tests (was COMPILE-VERIFIED):** All 26 tests executed and passing.
5. **Fuzz coverage (was 5/8):** All 8 fuzz targets run. ~6.6M total runs, 0 crashes.
