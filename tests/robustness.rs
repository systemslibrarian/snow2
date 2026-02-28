//! Robustness tests — exercising edge cases, corruption, bad inputs,
//! wrong credentials, and CRLF/LF handling for the SNOW2 library.

use snow2::{
    config::{EmbedOptions, EmbedSecurityOptions},
    container::Snow2Container,
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

// ── Issue #1: Outer password hardening ───────────────────────────────

#[test]
fn outer_layer_requires_correct_password() {
    let carrier = big_carrier(5000);
    let payload = b"outer password test";

    let stego = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"correct-pw",
        None,
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"wrong-pw",
        None,
        None,
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("decrypt")
            || msg.to_lowercase().contains("auth")
            || msg.to_lowercase().contains("wrong password"),
        "expected auth failure for wrong password, got: {msg}"
    );
}

#[test]
fn outer_layer_does_not_bind_pepper() {
    // When pepper is used during embed, extracting WITHOUT pepper should
    // still decrypt the outer layer and then fail with a clear "pepper is
    // required" error (not a generic AEAD failure).
    let carrier = big_carrier(6000);
    let payload = b"pepper test";

    let mut sec = EmbedSecurityOptions::default();
    sec.pepper_required = true;
    let opts = EmbedOptions { security: sec, ..Default::default() };

    let stego = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"my-pepper" as &[u8]),
        &opts,
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"pw",
        None, // no pepper
        None,
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("pepper is required"),
        "expected 'pepper is required' error, got: {msg}"
    );
}

#[test]
fn outer_and_inner_roundtrip_with_pepper() {
    let carrier = big_carrier(5000);
    let payload = b"both layers test";

    let stego = snow2::embed(
        Mode::WebSafeZeroWidth,
        &carrier,
        payload,
        b"pw",
        Some(b"pepper" as &[u8]),
    )
    .expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::WebSafeZeroWidth,
        &stego,
        b"pw",
        Some(b"pepper" as &[u8]),
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

// ── Issue #2: Embed/extract size limits ──────────────────────────────

#[test]
fn embed_rejects_payload_exceeding_bucket_limit() {
    let carrier = big_carrier(100_000);
    // A payload of ~65 KiB of incompressible data should hit the
    // V4_MAX_BUCKET guard after deflate + container overhead push the
    // padded bucket above 65 536 bytes.
    let mut payload = vec![0u8; 65_536];
    let mut state: u32 = 0xDEAD_BEEF;
    for b in payload.iter_mut() {
        // Simple xorshift32 PRNG — produces incompressible output.
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *b = state as u8;
    }

    let err = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        &payload,
        b"pw",
        None,
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too large"),
        "expected payload-too-large error, got: {msg}"
    );
}

#[test]
fn embed_succeeds_for_payload_within_limit() {
    let carrier = big_carrier(60_000);
    let payload = vec![0xCDu8; 1000]; // comfortably within limit

    let stego = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        &payload,
        b"pw",
        None,
    )
    .expect("embed of 1 KiB payload should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"pw",
        None,
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, &payload[..]);
}

#[test]
fn carrier_soft_cap_rejects_huge_carrier() {
    // Build a carrier larger than 10 MiB
    let line = "x".repeat(200);
    let lines: Vec<&str> = std::iter::repeat(line.as_str()).take(60_000).collect();
    let carrier = lines.join("\n"); // ~12 MiB+

    let err = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        b"test",
        b"pw",
        None,
    )
    .unwrap_err();

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("too large") || msg.to_lowercase().contains("mib"),
        "expected carrier size rejection, got: {msg}"
    );
}

// ── Issue #3: CRLF / LF handling ────────────────────────────────────

#[test]
fn crlf_carrier_classic_roundtrip() {
    let carrier = big_carrier_crlf(5000);
    let payload = b"CRLF classic test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed with CRLF carrier should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &stego, b"pw", None, None)
        .expect("extract from CRLF carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn crlf_carrier_websafe_roundtrip() {
    let carrier = big_carrier_crlf(5000);
    let payload = b"CRLF websafe test";

    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed with CRLF carrier should succeed");

    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"pw", None, None)
        .expect("extract from CRLF carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn mixed_crlf_lf_carrier_roundtrip() {
    // Some lines CRLF, others LF
    let mut carrier = String::new();
    for i in 0..5000 {
        carrier.push_str(&format!("Line {i} text"));
        if i % 3 == 0 {
            carrier.push_str("\r\n");
        } else {
            carrier.push('\n');
        }
    }

    let payload = b"mixed endings test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed with mixed endings should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &stego, b"pw", None, None)
        .expect("extract from mixed endings should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn crlf_carrier_preserves_cr_in_output() {
    // V4 pipeline needs ~960+ bits minimum (outer blob ≥ 120 bytes).
    // Classic mode = 1 bit/line, so we need well over 1000 lines.
    let carrier = big_carrier_crlf(5000);
    let payload = b"cr preserve test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // At least some lines should still end with \r\n
    let crlf_count = stego.matches("\r\n").count();
    assert!(
        crlf_count > 0,
        "CRLF output should preserve \\r\\n line endings, got 0 CRLF"
    );
}

#[test]
fn classic_no_marker_after_bare_cr() {
    // A line that ends with \r before \n should not have the marker
    // inserted between content and \r. The \r should stay last.
    let carrier = "Hello world\r\nAnother line\r\nThird line\r\n";
    let bits = vec![false, true, false];

    let result = snow2::stego::classic_trailing::embed_bits(carrier, &bits)
        .expect("embed_bits should succeed");

    // Check that no line ends with marker + \r\n (the marker should be
    // between the trimmed content and the \r).
    for line in result.split('\n') {
        if line.contains('\r') {
            // The \r should be at the very end of the line piece
            assert!(
                line.ends_with('\r'),
                "\\r should be at the end: {:?}",
                line
            );
        }
    }
}

// ── Robustness: truncated hidden data ────────────────────────────────

#[test]
fn truncated_carrier_fails_gracefully_classic() {
    let carrier = big_carrier(5000);
    let payload = b"truncation test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Keep only the first 20 lines
    let truncated: String = stego.lines().take(20).collect::<Vec<_>>().join("\n");

    let result = snow2::extract(Mode::ClassicTrailing, &truncated, b"pw", None, None);
    assert!(result.is_err(), "extraction from truncated carrier should fail");
}

#[test]
fn truncated_carrier_fails_gracefully_websafe() {
    let carrier = big_carrier(5000);
    let payload = b"truncation zw test";

    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    let truncated: String = stego.lines().take(20).collect::<Vec<_>>().join("\n");

    let result = snow2::extract(Mode::WebSafeZeroWidth, &truncated, b"pw", None, None);
    assert!(result.is_err(), "extraction from truncated carrier should fail");
}

// ── Robustness: corrupted markers ────────────────────────────────────

#[test]
fn corrupted_trailing_whitespace_fails() {
    let carrier = big_carrier(5000);
    let payload = b"marker corruption test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Strip all trailing whitespace from every line
    let corrupted: String = stego
        .lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n");

    let result = snow2::extract(Mode::ClassicTrailing, &corrupted, b"pw", None, None);
    assert!(result.is_err(), "extraction from stripped carrier should fail");
}

#[test]
fn corrupted_zw_chars_fails() {
    let carrier = big_carrier(5000);
    let payload = b"zw corruption test";

    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Strip all zero-width chars
    let corrupted = stego
        .replace('\u{200B}', "")
        .replace('\u{200C}', "");

    let result = snow2::extract(Mode::WebSafeZeroWidth, &corrupted, b"pw", None, None);
    assert!(result.is_err(), "extraction from stripped carrier should fail");
}

// ── Robustness: wrong password / wrong pepper / wrong mode ───────────

#[test]
fn wrong_password_classic() {
    let carrier = big_carrier(5000);
    let payload = b"wrong pw test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"right", None)
        .expect("embed should succeed");

    let err = snow2::extract(Mode::ClassicTrailing, &stego, b"wrong", None, None)
        .unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("decrypt") || msg.contains("auth") || msg.contains("password"),
        "expected auth failure, got: {msg}"
    );
}

#[test]
fn wrong_password_websafe() {
    let carrier = big_carrier(5000);
    let payload = b"wrong pw zw test";

    let stego = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, b"right", None)
        .expect("embed should succeed");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"wrong", None, None)
        .unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("decrypt") || msg.contains("auth") || msg.contains("password"),
        "expected auth failure, got: {msg}"
    );
}

#[test]
fn wrong_pepper_fails() {
    let carrier = big_carrier(5000);
    let payload = b"wrong pepper test";

    let stego = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        Some(b"correct" as &[u8]),
    )
    .expect("embed should succeed");

    let err = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"pw",
        Some(b"incorrect" as &[u8]),
        None,
    )
    .unwrap_err();

    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("decrypt") || msg.contains("auth"),
        "expected auth failure with wrong pepper, got: {msg}"
    );
}

#[test]
fn wrong_mode_fails() {
    let carrier = big_carrier(5000);
    let payload = b"wrong mode test";

    let stego = snow2::embed(Mode::ClassicTrailing, &carrier, payload, b"pw", None)
        .expect("embed should succeed");

    // Try to extract with the wrong mode
    let result = snow2::extract(Mode::WebSafeZeroWidth, &stego, b"pw", None, None);
    assert!(result.is_err(), "extracting with wrong mode should fail");
}

// ── Robustness: empty / too-small carrier ────────────────────────────

#[test]
fn empty_carrier_classic() {
    let err = snow2::extract(Mode::ClassicTrailing, "", b"pw", None, None).unwrap_err();
    let _ = format!("{err:#}");
}

#[test]
fn empty_carrier_websafe() {
    let err = snow2::extract(Mode::WebSafeZeroWidth, "", b"pw", None, None).unwrap_err();
    let _ = format!("{err:#}");
}

#[test]
fn too_small_carrier_classic() {
    let carrier = "one line\ntwo lines\n";
    let err = snow2::embed(Mode::ClassicTrailing, carrier, b"test", b"pw", None).unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("too small") || msg.contains("carrier") || msg.contains("too large"),
        "expected carrier too-small error, got: {msg}"
    );
}

#[test]
fn too_small_carrier_websafe() {
    let carrier = "one line\ntwo lines\n";
    let err = snow2::embed(Mode::WebSafeZeroWidth, carrier, b"test", b"pw", None).unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("too small") || msg.contains("carrier") || msg.contains("too large"),
        "expected carrier too-small error, got: {msg}"
    );
}

// ── Robustness: carrier with no hidden data ──────────────────────────

#[test]
fn extract_from_clean_carrier_classic() {
    let carrier = big_carrier(500);
    let result = snow2::extract(Mode::ClassicTrailing, &carrier, b"pw", None, None);
    assert!(result.is_err(), "extracting from clean carrier should fail");
}

#[test]
fn extract_from_clean_carrier_websafe() {
    let carrier = big_carrier(500);
    let result = snow2::extract(Mode::WebSafeZeroWidth, &carrier, b"pw", None, None);
    assert!(result.is_err(), "extracting from clean carrier should fail");
}

// ── Robustness: malformed container / version fields ─────────────────

#[test]
fn v4_container_with_bad_version_byte() {
    let bad = vec![99u8; 100]; // version=99, rest is garbage
    let result = Snow2Container::from_bytes_v4(&bad);
    assert!(result.is_err());
}

#[test]
fn v4_container_truncated_header() {
    // Just the version byte (4) and a few bytes — not enough for full header
    let mut bad = vec![4u8];
    bad.extend_from_slice(&[0u8; 10]);
    let result = Snow2Container::from_bytes_v4(&bad);
    assert!(result.is_err());
}

#[test]
fn v4_container_invalid_mode_bits() {
    // Build a minimal v4 blob with invalid mode bits (3 = reserved)
    let mut blob = vec![4u8]; // version
    let mut hdr = vec![0u8; 49];
    hdr[0] = 0x0C; // mode bits = 3 (invalid)
    hdr[1] = 16;   // m_cost_log2 = 16 (64 MiB)
    hdr[2] = 3;    // t_cost = 3
    hdr[4] = 1;    // p_cost = 1
    blob.extend_from_slice(&hdr);
    blob.extend_from_slice(&[0xAA; 32]); // fake ciphertext

    let result = Snow2Container::from_bytes_v4(&blob);
    assert!(result.is_err());
    let msg = format!("{:#}", result.unwrap_err()).to_lowercase();
    assert!(msg.contains("mode"), "expected mode error, got: {msg}");
}

#[test]
fn v4_container_too_short_for_ciphertext() {
    // Version + header only (50 bytes), but parser requires ≥51
    let mut blob = vec![4u8]; // version
    blob.extend_from_slice(&[0u8; 49]); // header

    let result = Snow2Container::from_bytes_v4(&blob);
    assert!(result.is_err());
    let msg = format!("{:#}", result.unwrap_err()).to_lowercase();
    assert!(
        msg.contains("too short"),
        "expected too-short error, got: {msg}"
    );
}

#[test]
fn legacy_container_bad_magic() {
    let err = Snow2Container::from_bytes(b"WRONG\x01\x00\x00\x00\x00...").unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(msg.contains("not a snow2"), "expected magic error, got: {msg}");
}

#[test]
fn legacy_container_truncated() {
    assert!(Snow2Container::from_bytes(b"").is_err());
    assert!(Snow2Container::from_bytes(b"SNOW").is_err());
    assert!(Snow2Container::from_bytes(b"SNOW2").is_err());
}

#[test]
fn legacy_container_oversized_header() {
    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1);
    input.extend_from_slice(&(2_000_000u32).to_le_bytes()); // 2 MB header
    input.extend_from_slice(&[0u8; 64]);

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("Header too large"), "got: {msg}");
}

#[test]
fn legacy_container_invalid_json_header() {
    let mut input = Vec::new();
    input.extend_from_slice(b"SNOW2");
    input.push(1);
    let bad_json = b"not json at all{{}}}}";
    input.extend_from_slice(&(bad_json.len() as u32).to_le_bytes());
    input.extend_from_slice(bad_json);
    input.extend_from_slice(&[0u8; 64]);

    let err = Snow2Container::from_bytes(&input).unwrap_err();
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("parse header") || msg.contains("json") || msg.contains("expected"),
        "expected parse error, got: {msg}"
    );
}

// ── Outer KDF profile tests ─────────────────────────────────────────

#[test]
fn outer_profile_returns_recommended_for_default_kdf() {
    use snow2::crypto::KdfParams;
    let rec = KdfParams::recommended();
    let profile = rec.outer_profile();
    assert_eq!(profile.m_cost_kib, rec.m_cost_kib);
    assert_eq!(profile.t_cost, rec.t_cost);
}

#[test]
fn outer_profile_returns_hardened_for_strong_kdf() {
    use snow2::crypto::KdfParams;
    let custom = KdfParams {
        m_cost_kib: 256 * 1024, // 256 MiB — exceeds recommended
        t_cost: 5,
        p_cost: 1,
        out_len: 32,
    };
    let profile = custom.outer_profile();
    let hard = KdfParams::hardened();
    assert_eq!(profile.m_cost_kib, hard.m_cost_kib);
    assert_eq!(profile.t_cost, hard.t_cost);
}

#[test]
fn outer_profile_returns_hardened_when_only_t_cost_exceeds() {
    use snow2::crypto::KdfParams;
    let rec = KdfParams::recommended();
    let custom = KdfParams {
        m_cost_kib: rec.m_cost_kib, // same memory
        t_cost: rec.t_cost + 1,     // but more iterations
        p_cost: 1,
        out_len: 32,
    };
    let profile = custom.outer_profile();
    let hard = KdfParams::hardened();
    assert_eq!(profile.m_cost_kib, hard.m_cost_kib);
    assert_eq!(profile.t_cost, hard.t_cost);
}

#[test]
fn embed_with_hardened_kdf_roundtrips() {
    // Embed with hardened KDF (outer layer should auto-select hardened profile).
    // Extract should try both profiles and find the hardened one.
    let carrier = big_carrier(5000);
    let payload = b"hardened kdf roundtrip";

    let sec = EmbedSecurityOptions {
        kdf: snow2::crypto::KdfParams::hardened(),
        pepper_required: false,
    };
    let opts = EmbedOptions { security: sec, ..Default::default() };

    let stego = snow2::embed_with_options(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        None,
        &opts,
    )
    .expect("embed with hardened KDF should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"pw",
        None,
        None,
    )
    .expect("extract should succeed even though outer uses hardened profile");

    assert_eq!(&*recovered, payload);
}

#[test]
fn embed_default_then_extract_still_works() {
    // Regression: default embed (recommended KDF) should still roundtrip
    // after the dual-profile extract change.
    let carrier = big_carrier(5000);
    let payload = b"default kdf roundtrip";

    let stego = snow2::embed(
        Mode::ClassicTrailing,
        &carrier,
        payload,
        b"pw",
        None,
    )
    .expect("embed should succeed");

    let recovered = snow2::extract(
        Mode::ClassicTrailing,
        &stego,
        b"pw",
        None,
        None,
    )
    .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}
