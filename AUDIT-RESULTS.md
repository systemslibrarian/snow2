# AUDIT-RESULTS.md — SNOW2 Hostile Implementation Audit

**Commit:** `9e6678a` (main)
**Date:** 2026-02-28
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
| Wrong password on hardened KDF fails | PASS | `tests/robustness.rs` `outer_layer_requires_correct_password` — passed |
| Hardened KDF roundtrip works | PASS | `tests/robustness.rs` `embed_with_hardened_kdf_roundtrips` — passed (69.82s) |
| Adversarial: wrong password on hardened profile | COMPILE-VERIFIED | `tests/adversarial.rs` `hardened_kdf_embed_wrong_password_fails` |
| Adversarial: wrong pepper on hardened profile | COMPILE-VERIFIED | `tests/adversarial.rs` `hardened_kdf_embed_with_pepper_wrong_pepper_fails` |
| Adversarial: outer profile boundary selection | COMPILE-VERIFIED | `tests/adversarial.rs` tests #8, #9 |

**Note:** Before commit `9e6678a`, both `embed()` and `embed_with_options()` hardcoded `KdfParams::recommended()` for the outer layer. This meant a user who configured `hardened()` KDF would still get `recommended()` Argon2 on the outer AEAD — a cheaper attack path. Fixed by introducing `outer_profile()`.

---

## 2. Embed/Extract Size Safety

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| Oversized payload rejected with clear error | PASS | `tests/robustness.rs` `embed_rejects_payload_exceeding_bucket_limit` — passed |
| Small payloads (0, 1, 2 bytes) roundtrip | COMPILE-VERIFIED | `tests/adversarial.rs` `embed_extract_symmetry_*` |
| Boundary payload (V4_MAX_BUCKET) | PASS | `tests/robustness.rs` `embed_succeeds_for_payload_within_limit` — passed |
| Carrier too small → error | PASS | `tests/robustness.rs` `classic_carrier_too_small` — passed |
| Carrier soft cap (10 MiB) enforced | PASS | `src/lib.rs` `MAX_CARRIER_BYTES` check in both embed paths |
| Embed output always extractable | PASS | 143 tests pass including 17 cross-platform roundtrips |

---

## 3. CRLF/LF Correctness

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| LF carrier roundtrip | PASS | Multiple roundtrip tests use LF by default |
| CRLF carrier roundtrip | PASS | `tests/robustness.rs` `crlf_carrier_preserves_cr_in_output` — passed |
| CRLF preservation in output | PASS | Same test asserts `crlf_count > 0` |
| Mixed line endings | COMPILE-VERIFIED | `tests/adversarial.rs` `mixed_crlf_lf_cr_carrier_websafe` |
| Bare \\r carrier → clean failure | COMPILE-VERIFIED | `tests/adversarial.rs` `bare_cr_only_carrier_classic` |
| Marker not appended after stray \\r | PASS | `tests/robustness.rs` `classic_no_marker_after_bare_cr` — passed |
| Marker position relative to \\r | COMPILE-VERIFIED | `tests/adversarial.rs` `classic_marker_position_relative_to_cr` |

---

## 4. Malformed Input Handling

**Verdict: PASS**

| Check | Result | Evidence |
|---|---|---|
| Truncated hidden data | COMPILE-VERIFIED | `tests/adversarial.rs` `truncate_stego_at_various_points` |
| Corrupted markers (50-byte random corruption) | COMPILE-VERIFIED | `tests/adversarial.rs` `random_byte_corruption_*` |
| Wrong mode | COMPILE-VERIFIED | `tests/adversarial.rs` `classic_embed_websafe_extract_fails`, `websafe_embed_classic_extract_fails` |
| No hidden data | COMPILE-VERIFIED | `tests/adversarial.rs` `extract_from_clean_text_*` |
| Too-small carrier | PASS | `tests/robustness.rs` `classic_carrier_too_small` — passed |
| Malformed v4 container fields | COMPILE-VERIFIED | `tests/adversarial.rs` `v4_container_*` (3 tests) |
| KDF param bounds validation | COMPILE-VERIFIED | `tests/adversarial.rs` `kdf_params_*` (3 tests) |
| Corrupted ciphertext | PASS | `tests/negative_edge_cases.rs` (33 tests) — all passed |
| Invalid/legacy headers | PASS | `tests/robustness.rs` `legacy_container_*` tests — passed |
| Fuzz: container parse | PASS | 591,930 runs, 0 crashes |
| Fuzz: v4 header | PASS | 752,488 runs, 0 crashes |
| Fuzz: outer AEAD | PASS | 116,860 runs, 0 crashes |
| Fuzz: bits_to_bytes | PASS | 111,215 runs, 0 crashes |
| Fuzz: CRLF mixed | PASS | 40,770 runs, 0 crashes |

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

| Check | Result | Notes |
|---|---|---|
| `cargo clippy` | WARN | 11 lib warnings (style only), 2 main warnings, 7 test warnings. No errors. |
| `cargo fmt --check` | FAIL | 20 files have formatting diffs. Not enforced in CI. |
| `cargo build` | PASS | Clean build, no errors |
| `cargo build --release` | PASS | Release build available at `target/release/snow2` |

---

## 7. CI Coverage

**Verdict: FAIL — Incomplete**

| Check | Result | Notes |
|---|---|---|
| `cargo test` in CI | **MISSING** | No CI workflow runs the Rust test suite |
| `cargo clippy` in CI | **MISSING** | No lint CI |
| `cargo fmt --check` in CI | **MISSING** | No format CI |
| WASM build + test in CI | PASS | `pages.yml` runs `wasm-pack build` + `test_wasm.mjs` |
| `test_download_upload.mjs` in CI | **MISSING** | Not included in Pages workflow |
| Fuzz in CI | **MISSING** | No fuzz CI |

---

## Summary

| Area | Verdict |
|---|---|
| 1. Outer KDF | **PASS** |
| 2. Size safety | **PASS** |
| 3. CRLF/LF | **PASS** |
| 4. Malformed input | **PASS** |
| 5. Demo/WASM | **PASS** |
| 6. Code quality | **WARN** (fmt not enforced) |
| 7. CI coverage | **FAIL** (no `cargo test` CI) |

### Open Items

1. **CI gap:** No `cargo test` or `cargo clippy` in any CI workflow. The 143-test Rust suite only runs locally.
2. **Formatting:** 20 files fail `cargo fmt --check`. Not security-relevant but indicates no formatting discipline.
3. **Adversarial tests:** 26 tests compile-verified but not yet executed as a full suite. Runtime verification pending.
4. **Fuzz coverage:** 3 of 8 fuzz targets not run in this audit session (`fuzz_classic_extract`, `fuzz_extract_pipeline`, `fuzz_websafe_extract`).
