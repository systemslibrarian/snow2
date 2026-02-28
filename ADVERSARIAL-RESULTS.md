# ADVERSARIAL-RESULTS.md — SNOW2 Hostile Audit

**Commit:** `9e6678a` (main)
**Date:** 2026-02-28
**Test file:** `tests/adversarial.rs` (26 tests)

---

## Status

Tests compile (`cargo test --test adversarial --no-run` → OK).
Full suite not yet executed in a single pass (user requested skip).
Individual tests validated during development; compile-time correctness verified for all 26.

---

## Adversarial Test Inventory

| # | Case | Expected | Status |
|---|---|---|---|
| 1 | `one_byte_payload_classic_roundtrip` | 1-byte payload embeds and extracts | COMPILE-VERIFIED |
| 2 | `one_byte_payload_websafe_roundtrip` | 1-byte payload embeds and extracts | COMPILE-VERIFIED |
| 3 | `random_byte_corruption_classic_fails` | 50-byte corruption → extract fails | COMPILE-VERIFIED |
| 4 | `random_byte_corruption_websafe_fails` | 50-byte corruption → extract fails | COMPILE-VERIFIED |
| 5 | `repeated_extract_on_damaged_carrier_is_deterministic` | Damaged carrier → 5 identical errors | COMPILE-VERIFIED |
| 6 | `hardened_kdf_embed_wrong_password_fails` | Wrong password on hardened KDF → fails | COMPILE-VERIFIED |
| 7 | `hardened_kdf_embed_with_pepper_wrong_pepper_fails` | Wrong pepper on hardened KDF → fails | COMPILE-VERIFIED |
| 8 | `outer_profile_selection_boundary` | KDF at recommended bounds → uses recommended | COMPILE-VERIFIED |
| 9 | `outer_profile_selection_just_above_boundary` | KDF above recommended → uses hardened | COMPILE-VERIFIED |
| 10 | `embed_extract_symmetry_classic_small` | Sizes 0,1,2,10,100,1000 all roundtrip (classic) | COMPILE-VERIFIED |
| 11 | `embed_extract_symmetry_websafe_small` | Sizes 0,1,2,10,100,1000 all roundtrip (websafe) | COMPILE-VERIFIED |
| 12 | `bare_cr_only_carrier_classic` | Bare \\r carrier → embed fails cleanly | COMPILE-VERIFIED |
| 13 | `mixed_crlf_lf_cr_carrier_websafe` | Mixed endings carrier → roundtrip works | COMPILE-VERIFIED |
| 14 | `truncate_stego_at_various_points` | Truncated at 10/25/50/75% → extract fails | COMPILE-VERIFIED |
| 15 | `v4_container_with_zero_ciphertext` | Empty ciphertext → parse error | COMPILE-VERIFIED |
| 16 | `v4_container_m_cost_log2_overflow` | m_cost_log2=32 → parse error | COMPILE-VERIFIED |
| 17 | `v4_container_reserved_aead_bits` | Reserved AEAD bits → parse error | COMPILE-VERIFIED |
| 18 | `kdf_params_below_minimum_rejected` | 1 MiB m_cost → validation rejects | COMPILE-VERIFIED |
| 19 | `kdf_params_above_maximum_rejected` | 1 GiB m_cost → validation rejects | COMPILE-VERIFIED |
| 20 | `kdf_params_wrong_out_len_rejected` | out_len=64 → validation rejects | COMPILE-VERIFIED |
| 21 | `classic_embed_websafe_extract_fails` | Classic embed → websafe extract fails | COMPILE-VERIFIED |
| 22 | `websafe_embed_classic_extract_fails` | Websafe embed → classic extract fails | COMPILE-VERIFIED |
| 23 | `extract_from_clean_text_fails` | No hidden data → extract fails (classic) | COMPILE-VERIFIED |
| 24 | `extract_from_clean_text_websafe_fails` | No hidden data → extract fails (websafe) | COMPILE-VERIFIED |
| 25 | `crlf_carrier_preserves_crlf_in_output_after_roundtrip` | CRLF preserved + roundtrip works | COMPILE-VERIFIED |
| 26 | `classic_marker_position_relative_to_cr` | Marker before \\r, not after | COMPILE-VERIFIED |

---

## Coverage Gaps Addressed

| Gap | Before | After |
|---|---|---|
| 1-byte payload roundtrip | Not tested | Tests #1, #2 |
| Random multi-byte corruption | Not tested | Tests #3, #4 |
| Repeated extraction on damaged carrier | Not tested | Test #5 |
| Hardened KDF wrong-password | Not tested | Test #6 |
| Hardened KDF wrong-pepper | Not tested | Test #7 |
| Outer profile boundary selection | Not tested | Tests #8, #9 |
| Size 0 payload roundtrip | Not tested | Tests #10, #11 |
| Bare \\r carrier | Not tested | Test #12 |
| Mixed line-ending carrier | Not tested | Test #13 |
| Truncated stego at multiple points | Not tested | Test #14 |
| Malformed v4 container fields | Not tested | Tests #15, #16, #17 |
| KDF validation bounds | Not tested | Tests #18, #19, #20 |
| Cross-mode extraction | Not tested | Tests #21, #22 |
| Extraction from clean text | Not tested | Tests #23, #24 |
| CRLF preservation + roundtrip | Partially tested | Test #25 |
| Marker \\r position | Existed in robustness.rs | Test #26 (duplicate for audit) |

---

## Note

All 26 tests compile and are structurally correct. Full runtime execution is pending.
To run: `cargo test --test adversarial` (expect ~5-10 min due to hardened KDF tests).
