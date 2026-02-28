# FUZZ-RESULTS.md — SNOW2 Hostile Audit

**Commit:** `9e6678a` (main)
**Date:** 2026-02-28
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
| `fuzz_classic_extract` | not run | — | — | — | Skipped (user request) |
| `fuzz_extract_pipeline` | not run | — | — | — | 1 slow-unit artifact exists from prior run |
| `fuzz_websafe_extract` | not run | — | — | — | Skipped (user request) |

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

The `slow-unit` in `fuzz_extract_pipeline` is a performance artifact (not a crash). It triggers the Argon2 KDF path which is intentionally slow. No security issue.

---

## Summary

- **0 crashes found** across ~1.6M total fuzz runs.
- No panics, hangs, or memory errors detected.
- 8 fuzz targets exist; 5 were run in this audit session, 3 skipped.
- The `fuzz_classic_extract`, `fuzz_extract_pipeline`, and `fuzz_websafe_extract` targets were not run during this session. Mark: **UNKNOWN** for those three.
