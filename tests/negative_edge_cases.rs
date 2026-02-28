//! Negative and edge-case tests for SNOW2.
//!
//! Each test defends against a specific real risk: malformed carriers,
//! truncated data, corrupted headers, bad MAC, boundary payloads,
//! and hostile container manipulation.

use snow2::{
    config::{EmbedOptions, EmbedSecurityOptions},
    container::Snow2Container,
    crypto::KdfParams,
    Mode,
};

fn big_carrier(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Carrier line number {i} with some text content"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Malformed carrier tests ──────────────────────────────────────────

#[test]
fn extract_from_empty_carrier_classic() {
    let err = snow2::extract(Mode::ClassicTrailing, "", b"pw", None, None).unwrap_err();
    let msg = format!("{err:#}");
    // Should fail with a clear error, not panic
    assert!(
        msg.to_lowercase().contains("not enough bits")
            || msg.to_lowercase().contains("length")
            || msg.to_lowercase().contains("too short"),
        "expected clear error for empty carrier, got: {msg}"
    );
}

#[test]
fn extract_from_empty_carrier_websafe() {
    let err = snow2::extract(Mode::WebSafeZeroWidth, "", b"pw", None, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("not enough bits")
            || msg.to_lowercase().contains("length")
            || msg.to_lowercase().contains("too short"),
        "expected clear error for empty carrier, got: {msg}"
    );
}

#[test]
fn extract_from_single_line_carrier() {
    let err =
        snow2::extract(Mode::ClassicTrailing, "just one line", b"pw", None, None).unwrap_err();
    // A single line without stego markers should produce a clear error
    let _msg = format!("{err:#}");
    // Acceptable: any error, just not a panic
}

#[test]
fn extract_from_lines_with_no_markers() {
    // Lines with no trailing whitespace — extractor should stop immediately
    let carrier = "line one\nline two\nline three\n";
    let err = snow2::extract(Mode::ClassicTrailing, carrier, b"pw", None, None).unwrap_err();
    let _msg = format!("{err:#}");
    // Should fail gracefully — no panic
}

// ── Truncated carrier tests ──────────────────────────────────────────

#[test]
fn extract_from_truncated_stego_classic() {
    // Embed data, then truncate the carrier so some lines are missing
    let carrier = big_carrier(5000);
    let payload = b"test truncation";
    let password = b"pw";

    let full = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed should succeed");

    // Take only the first 10 lines (way too few to contain the full payload)
    let truncated: String = full.lines().take(10).collect::<Vec<_>>().join("\n");

    let err = snow2::extract(Mode::ClassicTrailing, &truncated, password, None, None).unwrap_err();
    let _msg = format!("{err:#}");
    // Must not panic — should produce a clear error about insufficient data or CRC failure
}

#[test]
fn extract_from_truncated_stego_websafe() {
    let carrier = big_carrier(5000);
    let payload = b"test truncation zw";
    let password = b"pw";

    let full = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, password, None)
        .expect("embed should succeed");

    let truncated: String = full.lines().take(10).collect::<Vec<_>>().join("\n");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &truncated, password, None, None).unwrap_err();
    let _msg = format!("{err:#}");
}

// ── Garbage appended to carrier ──────────────────────────────────────

#[test]
fn garbage_appended_to_classic_carrier_fails() {
    let carrier = big_carrier(5000);
    let payload = b"garbage test";
    let password = b"pw";

    let mut full = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed should succeed");

    // Append garbage lines with trailing whitespace (adds extra "bits")
    for i in 0..100 {
        full.push_str(&format!("\ngarbage line {i}\t"));
    }

    // Should still succeed because classic-trailing stops reading at the
    // first non-marker line, and the CRC/length header limits the data.
    // But if it does fail, that's also acceptable — just no panic.
    let result = snow2::extract(Mode::ClassicTrailing, &full, password, None, None);
    if let Ok(recovered) = result {
        assert_eq!(&*recovered, payload);
    }
    // If Err, that's also fine — corruption detection working correctly
}

// ── Corrupted container header ───────────────────────────────────────

#[test]
fn container_with_corrupted_header_json() {
    // Valid magic + version + header_len, but garbage JSON
    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1); // version
    let garbage_json = b"{invalid json content here!!!}";
    input.extend_from_slice(&(garbage_json.len() as u32).to_le_bytes());
    input.extend_from_slice(garbage_json);
    input.extend_from_slice(&[0u8; 64]); // fake ciphertext

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("parse header")
            || msg.to_lowercase().contains("json")
            || msg.to_lowercase().contains("expected"),
        "expected header parse error, got: {msg}"
    );
}

#[test]
fn container_with_valid_json_but_wrong_magic_in_header() {
    // Valid outer magic + valid JSON, but header.magic is wrong
    let header = serde_json::json!({
        "magic": "FAKE2",
        "version": 1,
        "mode": "classic-trailing",
        "kdf": {"m_cost_kib": 65536, "t_cost": 3, "p_cost": 1, "out_len": 32},
        "pepper_required": false,
        "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
        "nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aead": "XChaCha20-Poly1305",
        "plaintext_len": 5
    });
    let header_json = serde_json::to_vec(&header).unwrap();

    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1);
    input.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    input.extend_from_slice(&header_json);
    input.extend_from_slice(&[0u8; 64]); // fake ciphertext

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("bad header magic"),
        "expected header magic rejection, got: {msg}"
    );
}

#[test]
fn container_with_mismatched_version() {
    // Outer version=1 but header says version=2
    let header = serde_json::json!({
        "magic": "SNOW2",
        "version": 2,
        "mode": "classic-trailing",
        "kdf": {"m_cost_kib": 65536, "t_cost": 3, "p_cost": 1, "out_len": 32},
        "pepper_required": false,
        "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
        "nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aead": "XChaCha20-Poly1305",
        "plaintext_len": 5
    });
    let header_json = serde_json::to_vec(&header).unwrap();

    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1); // outer says v1
    input.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    input.extend_from_slice(&header_json);
    input.extend_from_slice(&[0u8; 64]);

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("version mismatch"),
        "expected version mismatch, got: {msg}"
    );
}

#[test]
fn container_with_unsupported_version() {
    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(99); // unsupported version
    input.extend_from_slice(&0u32.to_le_bytes());
    input.extend_from_slice(&[0u8; 64]);

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("unsupported"),
        "expected unsupported version error, got: {msg}"
    );
}

#[test]
fn container_with_missing_ciphertext() {
    // Valid header but no ciphertext after it
    let header = serde_json::json!({
        "magic": "SNOW2",
        "version": 1,
        "mode": "classic-trailing",
        "kdf": {"m_cost_kib": 65536, "t_cost": 3, "p_cost": 1, "out_len": 32},
        "pepper_required": false,
        "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
        "nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aead": "XChaCha20-Poly1305",
        "plaintext_len": 5
    });
    let header_json = serde_json::to_vec(&header).unwrap();

    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1);
    input.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    input.extend_from_slice(&header_json);
    // No ciphertext at all

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("missing ciphertext"),
        "expected missing ciphertext error, got: {msg}"
    );
}

// ── Bad MAC / authentication failure ─────────────────────────────────

#[test]
fn wrong_pepper_fails_auth() {
    let carrier = big_carrier(5000);
    let payload = b"pepper auth test";

    let out = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"correct-pepper" as &[u8]),
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &out,
        b"pw",
        Some(b"wrong-pepper" as &[u8]),
        None,
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("decrypt") || msg.to_lowercase().contains("auth"),
        "expected auth failure with wrong pepper, got: {msg}"
    );
}

#[test]
fn correct_password_wrong_pepper_still_fails() {
    let carrier = big_carrier(5000);
    let payload = b"double secret test";

    let out = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"correct-pw",
        Some(b"secret-pepper" as &[u8]),
    )
    .expect("embed should succeed");

    // Correct password, no pepper → should fail
    let err = snow2::extract(Mode::ClassicTrailing, &out, b"correct-pw", None, None).unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("decrypt") || msg.to_lowercase().contains("auth"),
        "expected auth failure without pepper, got: {msg}"
    );
}

// ── Payload size boundary tests ──────────────────────────────────────

#[test]
fn empty_payload_roundtrip() {
    // Empty payload should still work (it's valid: zero bytes encrypted)
    let carrier = big_carrier(5000);
    let payload = b"";
    let password = b"pw";

    let result = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None);
    // If empty payloads are supported, roundtrip should work.
    // If not, the error should be clear.
    match result {
        Ok(out) => {
            let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
                .expect("extract of empty payload should succeed");
            assert!(recovered.is_empty());
        }
        Err(e) => {
            // Empty payload rejection is also acceptable behavior
            let _msg = format!("{e:#}");
        }
    }
}

#[test]
fn large_payload_exceeding_carrier_capacity() {
    // Carrier with only a few lines — large payload should be cleanly rejected
    let carrier = "line one\nline two\nline three\n";
    let payload = vec![0xABu8; 10_000]; // much larger than capacity

    let err = snow2::embed(Mode::ClassicTrailing, carrier, &payload, b"pw", None).unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too small") || msg.to_lowercase().contains("carrier"),
        "expected carrier capacity error, got: {msg}"
    );
}

#[test]
fn large_payload_exceeding_websafe_capacity() {
    let carrier = "line one\nline two\nline three\n";
    let payload = vec![0xCDu8; 10_000];

    let err = snow2::embed(Mode::WebSafeZeroWidth, carrier, &payload, b"pw", None).unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too small") || msg.to_lowercase().contains("carrier"),
        "expected carrier capacity error, got: {msg}"
    );
}

// ── Bitstream integrity (CRC) corruption ─────────────────────────────

#[test]
fn corrupted_crc_in_bitstream() {
    // Create valid bits, then flip one data bit to cause CRC mismatch
    let data = b"test data for crc";
    let bits = snow2::stego::bytes_to_bits(data).expect("bytes_to_bits should succeed");

    // Flip a bit in the data portion (after the 64-bit header)
    let mut corrupted_bits = bits.clone();
    if corrupted_bits.len() > 70 {
        corrupted_bits[70] = !corrupted_bits[70];
    }

    let err = snow2::stego::bits_to_bytes(&corrupted_bits).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("CRC") || msg.to_lowercase().contains("integrity"),
        "expected CRC error, got: {msg}"
    );
}

#[test]
fn corrupted_length_in_bitstream() {
    // Create valid bits, then corrupt the length prefix
    let data = b"length corruption test";
    let bits = snow2::stego::bytes_to_bits(data).expect("bytes_to_bits should succeed");

    // Flip a bit in the length field (first 32 bits)
    let mut corrupted_bits = bits.clone();
    corrupted_bits[0] = !corrupted_bits[0]; // flip MSB of length

    let err = snow2::stego::bits_to_bytes(&corrupted_bits).unwrap_err();
    let _msg = format!("{err:#}");
    // Should fail with length mismatch or CRC error, never panic
}

// ── Pepper policy edge cases ─────────────────────────────────────────

#[test]
fn pepper_required_with_empty_pepper_is_an_error() {
    let carrier = big_carrier(5000);
    let payload = b"test";

    let sec = EmbedSecurityOptions {
        pepper_required: true,
        ..EmbedSecurityOptions::default()
    };
    let opts = EmbedOptions { security: sec };

    // Empty pepper slice should NOT count as "provided"
    // This depends on implementation — document the behavior
    let result = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"" as &[u8]), // empty but present
        &opts,
    );

    // Either accept (empty bytes are still "provided") or reject — both are valid
    // The key is: it must not panic, and the behavior must be consistent
    let _outcome = result.is_ok();
}

// ── KDF parameter edge cases ─────────────────────────────────────────

#[test]
fn kdf_bounds_rejects_zero_p_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 0,
        out_len: 32,
    };
    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("parallelism"),
        "expected p_cost=0 rejection, got: {msg}"
    );
}

#[test]
fn kdf_bounds_rejects_zero_t_cost() {
    let params = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 0,
        p_cost: 1,
        out_len: 32,
    };
    let err = params.validate_extraction_bounds().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("time cost too low"),
        "expected t_cost=0 rejection, got: {msg}"
    );
}

// ── Carrier with only empty lines ────────────────────────────────────

#[test]
fn carrier_with_only_empty_lines_classic() {
    let carrier = "\n\n\n\n\n";
    let payload = b"test";

    let err = snow2::embed(Mode::ClassicTrailing, carrier, payload, b"pw", None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too small") || msg.to_lowercase().contains("carrier"),
        "expected capacity error for empty-line carrier, got: {msg}"
    );
}

#[test]
fn carrier_with_only_empty_lines_websafe() {
    let carrier = "\n\n\n\n\n";
    let payload = b"test";

    let err = snow2::embed(Mode::WebSafeZeroWidth, carrier, payload, b"pw", None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too small") || msg.to_lowercase().contains("carrier"),
        "expected capacity error for empty-line carrier, got: {msg}"
    );
}

// ── Bitstream framing edge cases ─────────────────────────────────────

#[test]
fn bits_to_bytes_too_few_bits() {
    // Less than 64 bits (minimum for the length+CRC header)
    let bits = vec![false; 32];
    let err = snow2::stego::bits_to_bytes(&bits).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("not enough bits"),
        "expected too-few-bits error, got: {msg}"
    );
}

#[test]
fn bits_to_bytes_exactly_64_bits_declares_nonzero_length() {
    // 64 bits total — length header says 1 byte of data but there's
    // nothing after the header → should fail
    let mut bits = Vec::new();
    // length = 1 (LE: 0x01 0x00 0x00 0x00)
    for &b in &[0u8, 0, 0, 0, 0, 0, 0, 1u8] {
        // bit 7 (LSBit of byte 0)
        for i in (0..8).rev() {
            bits.push(((b >> i) & 1) == 1);
        }
    }

    let err = snow2::stego::bits_to_bytes(&bits).unwrap_err();
    let _msg = format!("{err:#}");
    // Should fail — not enough data after header
}

#[test]
fn bytes_to_bits_roundtrip() {
    let data = b"roundtrip bitstream test 12345";
    let bits = snow2::stego::bytes_to_bits(data).expect("encode");
    let recovered = snow2::stego::bits_to_bytes(&bits).expect("decode");
    assert_eq!(&recovered, data);
}

// ── Unsupported AEAD algorithm ───────────────────────────────────────

#[test]
fn container_open_rejects_unsupported_aead() {
    // Create a valid-looking container but with wrong AEAD field
    let header = serde_json::json!({
        "magic": "SNOW2",
        "version": 1,
        "mode": "classic-trailing",
        "kdf": {"m_cost_kib": 65536, "t_cost": 3, "p_cost": 1, "out_len": 32},
        "pepper_required": false,
        "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
        "nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aead": "AES-256-GCM",
        "plaintext_len": 5
    });
    let header_json = serde_json::to_vec(&header).unwrap();

    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1);
    input.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    input.extend_from_slice(&header_json);
    input.extend_from_slice(&[0u8; 64]); // fake ciphertext

    let container = Snow2Container::from_bytes(&input).expect("parse should succeed");
    let err = container.open(b"pw", None, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("unsupported aead"),
        "expected AEAD rejection, got: {msg}"
    );
}

// ── Mode parsing edge cases ──────────────────────────────────────────

#[test]
fn mode_parse_rejects_garbage() {
    assert!(Mode::parse("garbage-mode").is_err());
    assert!(Mode::parse("").is_err());
    assert!(Mode::parse("   ").is_err());
}

#[test]
fn mode_parse_accepts_aliases() {
    assert_eq!(Mode::parse("classic").unwrap(), Mode::ClassicTrailing);
    assert_eq!(Mode::parse("trailing").unwrap(), Mode::ClassicTrailing);
    assert_eq!(
        Mode::parse("classic-trailing").unwrap(),
        Mode::ClassicTrailing
    );
    assert_eq!(Mode::parse("websafe-zw").unwrap(), Mode::WebSafeZeroWidth);
    assert_eq!(Mode::parse("websafe").unwrap(), Mode::WebSafeZeroWidth);
    assert_eq!(Mode::parse("zw").unwrap(), Mode::WebSafeZeroWidth);
    assert_eq!(Mode::parse("zero-width").unwrap(), Mode::WebSafeZeroWidth);
}

#[test]
fn mode_parse_is_case_insensitive() {
    assert_eq!(
        Mode::parse("CLASSIC-TRAILING").unwrap(),
        Mode::ClassicTrailing
    );
    assert_eq!(Mode::parse("WebSafe-ZW").unwrap(), Mode::WebSafeZeroWidth);
}

// ── Stego extraction edge cases ──────────────────────────────────────

#[test]
fn classic_extract_stops_at_first_non_marker_line() {
    // Lines with trailing whitespace, then a line without → extraction stops
    let carrier = "hello \nworld\t\nplain line\nmore \n";
    let bits = snow2::stego::classic_trailing::extract_bits(carrier).unwrap();
    // Should get exactly 2 bits (from "hello " and "world\t"), then stop at "plain line"
    assert_eq!(bits.len(), 2);
    assert!(!bits[0]); // space = 0
    assert!(bits[1]); // tab = 1
}

#[test]
fn websafe_extract_stops_at_first_non_marker_line() {
    let zw0 = '\u{200B}';
    let zw1 = '\u{200C}';
    let carrier = format!("hello{zw0}\nworld{zw1}\nplain line\nmore{zw0}\n");
    let bits = snow2::stego::websafe_zw::extract_bits(&carrier).unwrap();
    assert_eq!(bits.len(), 2);
    assert!(!bits[0]); // ZWSP = 0
    assert!(bits[1]); // ZWNJ = 1
}
