# ADVERSARIAL-RESULTS.md — SNOW2 Hostile Audit

**Commit:** post-`44dbbbc` (current session)
**Date:** 2025-07-21
**Test file:** `tests/adversarial.rs` (26 tests)

---

## Status

**All 26 tests executed and passing.**

```
cargo test --test adversarial -- --test-threads=2
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 481.13s
```

---

## Adversarial Test Inventory

| # | Case | Expected | Result |
|---|---|---|---|
| 1 | `one_byte_payload_classic_roundtrip` | 1-byte payload embeds and extracts | **PASS** |
| 2 | `one_byte_payload_websafe_roundtrip` | 1-byte payload embeds and extracts | **PASS** |
| 3 | `random_byte_corruption_classic_fails` | 50 whitespace-channel flips → AEAD rejects or garbled | **PASS** |
| 4 | `random_byte_corruption_websafe_fails` | 50-byte corruption → extract fails | **PASS** |
| 5 | `repeated_extract_on_damaged_carrier_is_deterministic` | Damaged carrier → 5 identical errors | **PASS** |
| 6 | `hardened_kdf_embed_wrong_password_fails` | Wrong password on hardened KDF → fails | **PASS** |
| 7 | `hardened_kdf_embed_with_pepper_wrong_pepper_fails` | Wrong pepper on hardened KDF → fails | **PASS** |
| 8 | `outer_profile_selection_boundary` | KDF at recommended bounds → uses recommended | **PASS** |
| 9 | `outer_profile_selection_just_above_boundary` | KDF above recommended → uses hardened | **PASS** |
| 10 | `embed_extract_symmetry_classic_small` | Sizes 0,1,2,10,100,1000 all roundtrip (classic) | **PASS** |
| 11 | `embed_extract_symmetry_websafe_small` | Sizes 0,1,2,10,100,1000 all roundtrip (websafe) | **PASS** |
| 12 | `bare_cr_only_carrier_classic` | Bare \\r carrier → embed fails cleanly | **PASS** |
| 13 | `mixed_crlf_lf_cr_carrier_websafe` | Mixed endings carrier → roundtrip works | **PASS** |
| 14 | `truncate_stego_at_various_points` | Truncated at 10/25/50/75% → no panic (error or valid) | **PASS** |
| 15 | `v4_container_with_zero_ciphertext` | Empty ciphertext → parse error | **PASS** |
| 16 | `v4_container_m_cost_log2_overflow` | m_cost_log2=32 → parse error | **PASS** |
| 17 | `v4_container_reserved_aead_bits` | Reserved AEAD bits → parse error | **PASS** |
| 18 | `kdf_params_below_minimum_rejected` | 1 MiB m_cost → validation rejects | **PASS** |
| 19 | `kdf_params_above_maximum_rejected` | 1 GiB m_cost → validation rejects | **PASS** |
| 20 | `kdf_params_wrong_out_len_rejected` | out_len=64 → validation rejects | **PASS** |
| 21 | `classic_embed_websafe_extract_fails` | Classic embed → websafe extract fails | **PASS** |
| 22 | `websafe_embed_classic_extract_fails` | Websafe embed → classic extract fails | **PASS** |
| 23 | `extract_from_clean_text_fails` | No hidden data → extract fails (classic) | **PASS** |
| 24 | `extract_from_clean_text_websafe_fails` | No hidden data → extract fails (websafe) | **PASS** |
| 25 | `crlf_carrier_preserves_crlf_in_output_after_roundtrip` | CRLF preserved + roundtrip works | **PASS** |
| 26 | `classic_marker_position_relative_to_cr` | Marker before \\r, not after | **PASS** |

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

## Notes

- Test #3 (`random_byte_corruption_classic_fails`) specifically corrupts the trailing-whitespace data channel (flips space↔tab on 50 lines). Random byte-level corruption of visible text does not affect the steganographic channel in classic trailing mode — this is by design.
- Test #14 (`truncate_stego_at_various_points`) accepts both error and success outcomes. Small payloads (22 bytes) fit within the first ~1% of a 5000-line carrier, so truncation at any tested percentage retains all embedded data.
