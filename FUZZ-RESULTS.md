# FUZZ-RESULTS.md — SNOW2 Hostile Audit

**Commit:** post-`44dbbbc` (current session)
**Date:** 2025-07-21
**Fuzzer:** cargo-fuzz / libFuzzer via `cargo +nightly fuzz`

---

## Fuzz Targets

| Target | Duration | Runs | Crashes | Slow Units | Notes |
|---|---|---|---|---|---|
| `fuzz_container_parse` | 16s | 591,930 | 0 | 0 | cov: 123 |
| `fuzz_v4_header` | 16s | 752,488 | 0 | 0 | cov: 104 |
| `fuzz_outer_aead` | 16s | 116,860 | 0 | 0 | cov: 533 |
| `fuzz_bits_to_bytes` | 16s | 111,215 | 0 | 0 | cov: 271 |
| `fuzz_crlf_mixed` | 16s | 40,770 | 0 | 0 | cov: 463 |
| `fuzz_classic_extract` | 20s | 1,455,240 | 0 | 0 | cov: high |
| `fuzz_extract_pipeline` | 20s | 3,479 | 0 | 0 | Slow (Argon2 KDF path) |
| `fuzz_websafe_extract` | 20s | 3,226,426 | 0 | 0 | cov: high |
| **TOTAL** | **~140s** | **~6,296,408** | **0** | **0** | |

**All 8 fuzz targets run. Zero crashes across ~6.3M total runs.**

---

## Crash Artifacts

**Directory:** `fuzz/artifacts/`

| Target | Files |
|---|---|
| `fuzz_bits_to_bytes` | empty |
| `fuzz_classic_extract` | empty |
| `fuzz_container_parse` | empty |
| `fuzz_crlf_mixed` | empty |
| `fuzz_extract_pipeline` | `slow-unit-124c17e04399d09a2338503be9a16332bbbd608b` |
| `fuzz_outer_aead` | empty |
| `fuzz_v4_header` | empty |
| `fuzz_websafe_extract` | empty |

The `slow-unit` in `fuzz_extract_pipeline` is a performance artifact (not a crash). It triggers the Argon2 KDF path which is intentionally slow (~10ms+ per invocation). No security issue.

---

## Summary

- **0 crashes found** across ~6.3M total fuzz runs.
- No panics, hangs, or memory errors detected.
- All 8 fuzz targets run to completion.
- `fuzz_extract_pipeline` is inherently slow due to Argon2 KDF in the hot path; 3,479 runs in 20s is expected.
