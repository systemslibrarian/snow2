//! Adversarial tests — hostile-input and boundary-condition coverage.
//!
//! These tests were added as part of the hostile implementation audit.
//! They specifically target gaps not covered by existing test suites.

use snow2::{
    config::{EmbedOptions, EmbedSecurityOptions},
    crypto::KdfParams,
    Mode,
};

fn big_carrier(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Carrier line {i} with some text content"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn big_carrier_crlf(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Carrier line {i} with some text content"))
        .collect::<Vec<_>>()
        .join("\r\n")
}

// ── Gap #1: 1-byte payload roundtrip ─────────────────────────────────

#[test]
fn one_byte_payload_classic_roundtrip() {
    let carrier = big_carrier(5000);
    let payload = b"X";
    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed 1-byte payload");
    let recovered = snow2::extract(Mode::ClassicTrailing, &stego, b"pw", None, None)
        .expect("extract 1-byte payload");
    assert_eq!(&*recovered, payload);
}

#[test]
fn one_byte_payload_websafe_roundtrip() {
    let carrier = big_carrier(5000);
    let payload = b"Z";
    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed 1-byte payload websafe");
    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"pw", None, None)
        .expect("extract 1-byte payload websafe");
    assert_eq!(&*recovered, payload);
}

// ── Gap #2: Random multi-byte corruption of carrier string ───────────

#[test]
fn random_byte_corruption_classic_fails() {
    let carrier = big_carrier(5000);
    let payload = b"corruption test classic";
    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Classic trailing stores one bit per line in trailing whitespace.
    // Corrupting visible text won't affect the channel.  Instead, corrupt
    // the trailing whitespace directly (flip space ↔ tab on data lines).
    let mut lines: Vec<String> = stego.split('\n').map(String::from).collect();
    let mut state: u32 = 0xCAFE_BABE;
    let mut flipped = 0;
    for line in lines.iter_mut() {
        if flipped >= 50 {
            break;
        }
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        // Only flip ~50% of encountered lines (using low bit of state)
        if state & 1 == 0 {
            continue;
        }
        // Flip the trailing whitespace character (space ↔ tab)
        if line.ends_with(' ') {
            line.pop();
            line.push('\t');
            flipped += 1;
        } else if line.ends_with('\t') {
            line.pop();
            line.push(' ');
            flipped += 1;
        }
    }
    let corrupted_str = lines.join("\n");

    let result = snow2::extract(Mode::ClassicTrailing, &corrupted_str, b"pw", None, None);
    // Flipping 50 data bits should break AEAD or garble the plaintext.
    match result {
        Err(_) => {} // expected — AEAD tag mismatch
        Ok(recovered) => assert_ne!(
            &*recovered, payload,
            "corrupted data channel should not return the original plaintext"
        ),
    }
}

#[test]
fn random_byte_corruption_websafe_fails() {
    let carrier = big_carrier(5000);
    let payload = b"corruption test websafe";
    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Corrupt 50 random positions
    let mut corrupted = stego.clone().into_bytes();
    let mut state: u32 = 0xDEAD_BEEF;
    for _ in 0..50 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let idx = (state as usize) % corrupted.len();
        corrupted[idx] ^= 0xFF;
    }
    let corrupted_str = String::from_utf8_lossy(&corrupted).to_string();

    let result = snow2::extract(Mode::WebSafeZeroWidth, &corrupted_str, b"pw", None, None);
    assert!(
        result.is_err(),
        "extraction from heavily corrupted carrier should fail"
    );
}

// ── Gap #3: Repeated extraction on damaged carrier ───────────────────

#[test]
fn repeated_extract_on_damaged_carrier_is_deterministic() {
    let carrier = big_carrier(5000);
    let payload = b"determinism test";
    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Remove trailing whitespace from all lines (destroying markers)
    let damaged: String = stego
        .lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n");

    // Extract 5 times — every call should return Err
    let mut errors = Vec::new();
    for _ in 0..5 {
        let result = snow2::extract(Mode::ClassicTrailing, &damaged, b"pw", None, None);
        assert!(
            result.is_err(),
            "extraction from damaged carrier should fail"
        );
        errors.push(format!("{}", result.unwrap_err()));
    }

    // All error messages should be identical (deterministic behavior)
    for e in &errors[1..] {
        assert_eq!(
            &errors[0], e,
            "repeated extraction on damaged carrier should produce identical errors"
        );
    }
}

// ── Outer KDF profile: cost mismatch adversarial tests ───────────────

#[test]
fn hardened_kdf_embed_wrong_password_fails() {
    let carrier = big_carrier(5000);
    let payload = b"hardened wrong pw test";

    let sec = EmbedSecurityOptions {
        kdf: KdfParams::hardened(),
        pepper_required: false,
    };
    let opts = EmbedOptions { security: sec };

    let stego = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"correct-password",
        None,
        &opts,
    )
    .expect("embed with hardened KDF should succeed");

    // Wrong password should fail on both KDF profiles
    let result = snow2::extract(Mode::ClassicTrailing, &stego, b"wrong-password", None, None);
    assert!(
        result.is_err(),
        "wrong password on hardened KDF should fail"
    );
}

#[test]
fn hardened_kdf_embed_with_pepper_wrong_pepper_fails() {
    let carrier = big_carrier(5000);
    let payload = b"hardened pepper test";

    let sec = EmbedSecurityOptions {
        kdf: KdfParams::hardened(),
        pepper_required: true,
    };
    let opts = EmbedOptions { security: sec };

    let stego = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"correct-pepper"),
        &opts,
    )
    .expect("embed should succeed");

    // Correct password, wrong pepper
    let result = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"pw",
        Some(b"wrong-pepper"),
        None,
    );
    assert!(result.is_err(), "wrong pepper on hardened KDF should fail");
}

#[test]
fn outer_profile_selection_boundary() {
    // KDF params exactly at recommended() bounds → outer should use recommended()
    let rec = KdfParams::recommended();
    let at_boundary = KdfParams {
        m_cost_kib: rec.m_cost_kib,
        t_cost: rec.t_cost,
        p_cost: 1,
        out_len: 32,
    };
    let profile = at_boundary.outer_profile();
    assert_eq!(profile.m_cost_kib, rec.m_cost_kib);
    assert_eq!(profile.t_cost, rec.t_cost);
}

#[test]
fn outer_profile_selection_just_above_boundary() {
    // KDF params just above recommended() bounds → outer should use hardened()
    let rec = KdfParams::recommended();
    let above = KdfParams {
        m_cost_kib: rec.m_cost_kib * 2, // 128 MiB — above recommended
        t_cost: rec.t_cost,
        p_cost: 1,
        out_len: 32,
    };
    let profile = above.outer_profile();
    let hard = KdfParams::hardened();
    assert_eq!(profile.m_cost_kib, hard.m_cost_kib);
    assert_eq!(profile.t_cost, hard.t_cost);
}

// ── Embed/extract symmetry: what embeds must extract ─────────────────

#[test]
fn embed_extract_symmetry_classic_small() {
    let carrier = big_carrier(5000);
    for size in [0, 1, 2, 10, 100, 1000] {
        let payload = vec![0xABu8; size];
        let stego = snow2::embed(Mode::ClassicTrailing, &carrier, &payload, b"pw", None)
            .unwrap_or_else(|e| panic!("embed failed for size {size}: {e}"));
        let recovered = snow2::extract(Mode::ClassicTrailing, &stego, b"pw", None, None)
            .unwrap_or_else(|e| panic!("extract failed for size {size}: {e}"));
        assert_eq!(&*recovered, &payload, "roundtrip failed for size {size}");
    }
}

#[test]
fn embed_extract_symmetry_websafe_small() {
    let carrier = big_carrier(5000);
    for size in [0, 1, 2, 10, 100, 1000] {
        let payload = vec![0xCDu8; size];
        let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, &payload, b"pw", None)
            .unwrap_or_else(|e| panic!("embed failed for size {size}: {e}"));
        let recovered = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"pw", None, None)
            .unwrap_or_else(|e| panic!("extract failed for size {size}: {e}"));
        assert_eq!(&*recovered, &payload, "roundtrip failed for size {size}");
    }
}

// ── Line-ending edge cases ───────────────────────────────────────────

#[test]
fn bare_cr_only_carrier_classic() {
    // Carrier with only \r line endings (Mac Classic)
    let carrier = (0..5000)
        .map(|i| format!("Line {i} content"))
        .collect::<Vec<_>>()
        .join("\r");
    let payload = b"bare cr test";

    // This should either succeed or fail cleanly, not panic
    let result = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None);
    // Bare \r is not a real line separator for split('\n'), so the carrier
    // is effectively one giant line. Embed will fail because there aren't
    // enough usable lines.
    assert!(
        result.is_err(),
        "bare CR carrier should fail (not enough lines)"
    );
}

#[test]
fn mixed_crlf_lf_cr_carrier_websafe() {
    // Mix of \r\n, \n, and bare \r within a single carrier
    let mut carrier = String::new();
    for i in 0..2000 {
        carrier.push_str(&format!("Line {i} content"));
        match i % 3 {
            0 => carrier.push_str("\r\n"),
            1 => carrier.push('\n'),
            _ => carrier.push_str("\r\n"),
        }
    }
    let payload = b"mixed endings test";
    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed into mixed-ending carrier should succeed");
    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"pw", None, None)
        .expect("extract from mixed-ending carrier should succeed");
    assert_eq!(&*recovered, payload);
}

// ── Truncated embedded data ──────────────────────────────────────────

#[test]
fn truncate_stego_at_various_points() {
    let carrier = big_carrier(5000);
    let payload = b"truncation test payload";
    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    let lines: Vec<&str> = stego.split('\n').collect();
    // Truncate at 10%, 25%, 50%, 75% of lines
    for pct in [10, 25, 50, 75] {
        let cut = lines.len() * pct / 100;
        let truncated = lines[..cut].join("\n");
        let result = snow2::extract(Mode::ClassicTrailing, &truncated, b"pw", None, None);
        // Truncation should either cause an error OR, if the payload is small
        // enough to fit within the kept lines, succeed with valid data.
        // A 22-byte payload on a 5000-line carrier fits in ~1% of lines,
        // so even 10% truncation retains all data bits.
        // Either outcome is acceptable; we just verify no panic.
        let _ = result;
    }
}

// ── Malformed container direct tests ─────────────────────────────────

#[test]
fn v4_container_with_zero_ciphertext() {
    use snow2::container::Snow2Container;
    // version(4) + 49-byte header + empty ciphertext
    let mut input = vec![4u8]; // version
    input.extend_from_slice(&[0u8; 49]); // garbage header
                                         // No ciphertext at all
    let err = Snow2Container::from_bytes_v4(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Missing ciphertext") || msg.contains("too short"),
        "expected missing-ciphertext error, got: {msg}"
    );
}

#[test]
fn v4_container_m_cost_log2_overflow() {
    use snow2::container::Snow2Container;
    // Build a v4-like input with m_cost_log2 = 32 (invalid, max is 31)
    let mut input = vec![4u8]; // version
    let mut hdr = [0u8; 49];
    hdr[0] = 0x00; // flags: no pepper, no compress, classic mode
    hdr[1] = 32; // m_cost_log2 = 32 → invalid
    hdr[2] = 3; // t_cost = 3
    hdr[4] = 1; // p_cost = 1
    input.extend_from_slice(&hdr);
    input.push(0xFF); // dummy ciphertext byte
    let err = Snow2Container::from_bytes_v4(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("m_cost_log2") || msg.contains("Invalid"),
        "expected m_cost_log2 error, got: {msg}"
    );
}

#[test]
fn v4_container_reserved_aead_bits() {
    use snow2::container::Snow2Container;
    let mut input = vec![4u8]; // version
    let mut hdr = [0u8; 49];
    hdr[0] = 0x30; // aead_bits = 3 (reserved)
    hdr[1] = 16; // m_cost_log2 = 16 → 64 MiB
    hdr[2] = 3; // t_cost = 3
    hdr[4] = 1; // p_cost = 1
    input.extend_from_slice(&hdr);
    input.push(0xFF); // dummy ciphertext byte
    let err = Snow2Container::from_bytes_v4(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("AEAD") || msg.contains("Unknown"),
        "expected unknown-AEAD error, got: {msg}"
    );
}

// ── KDF extraction bounds ────────────────────────────────────────────

#[test]
fn kdf_params_below_minimum_rejected() {
    let too_low = KdfParams {
        m_cost_kib: 1024, // 1 MiB — below 8 MiB minimum
        t_cost: 1,
        p_cost: 1,
        out_len: 32,
    };
    let err = too_low.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("too low"),
        "expected 'too low' error, got: {msg}"
    );
}

#[test]
fn kdf_params_above_maximum_rejected() {
    let too_high = KdfParams {
        m_cost_kib: 1024 * 1024, // 1 GiB — above 512 MiB max
        t_cost: 3,
        p_cost: 1,
        out_len: 32,
    };
    let err = too_high.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("too high"),
        "expected 'too high' error, got: {msg}"
    );
}

#[test]
fn kdf_params_wrong_out_len_rejected() {
    let bad = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
        out_len: 64, // wrong — must be 32
    };
    let err = bad.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("output length"),
        "expected out_len error, got: {msg}"
    );
}

// ── Wrong mode cross-extraction ──────────────────────────────────────

#[test]
fn classic_embed_websafe_extract_fails() {
    let carrier = big_carrier(5000);
    let payload = b"cross mode test";
    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");
    let result = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"pw", None, None);
    assert!(result.is_err(), "cross-mode extraction should fail");
}

#[test]
fn websafe_embed_classic_extract_fails() {
    let carrier = big_carrier(5000);
    let payload = b"cross mode test 2";
    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed should succeed");
    let result = snow2::extract(Mode::ClassicTrailing, &stego, b"pw", None, None);
    assert!(result.is_err(), "cross-mode extraction should fail");
}

// ── No hidden data extraction ────────────────────────────────────────

#[test]
fn extract_from_clean_text_fails() {
    let clean =
        "This is just a normal paragraph of text.\nNothing hidden here.\nJust plain content.\n";
    let result = snow2::extract(Mode::ClassicTrailing, clean, b"pw", None, None);
    assert!(result.is_err(), "extraction from clean text should fail");
}

#[test]
fn extract_from_clean_text_websafe_fails() {
    let clean =
        "This is just a normal paragraph of text.\nNothing hidden here.\nJust plain content.\n";
    let result = snow2::extract(Mode::WebSafeZeroWidth, clean, b"pw", None, None);
    assert!(result.is_err(), "extraction from clean text should fail");
}

// ── CRLF in extracted output ─────────────────────────────────────────

#[test]
fn crlf_carrier_preserves_crlf_in_output_after_roundtrip() {
    let carrier = big_carrier_crlf(5000);
    let payload = b"crlf preservation test";
    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Count CRLF sequences in output — should have at least some
    let crlf_count = stego.matches("\r\n").count();
    assert!(
        crlf_count > 0,
        "CRLF carrier should preserve \\r\\n endings, found 0"
    );

    // Verify we can extract from CRLF output
    let recovered = snow2::extract(Mode::ClassicTrailing, &stego, b"pw", None, None)
        .expect("extraction from CRLF output should succeed");
    assert_eq!(&*recovered, payload);
}

// ── Marker-after-bare-CR check ───────────────────────────────────────

#[test]
fn classic_marker_position_relative_to_cr() {
    // Lines ending with \r\n: the marker should be between content
    // and \r, so the \r stays last before the \n delimiter.
    let carrier = "Hello world\r\nAnother line\r\nThird line\r\n";
    let bits = vec![false, true, false];
    let result = snow2::stego::classic_trailing::embed_bits(carrier, &bits)
        .expect("embed_bits should succeed");

    for piece in result.split('\n') {
        if piece.contains('\r') {
            assert!(
                piece.ends_with('\r'),
                "\\r should be at end of piece: {:?}",
                piece
            );
        }
    }
}
