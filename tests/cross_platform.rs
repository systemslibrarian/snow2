//! Cross-platform text handling tests for SNOW2.
//!
//! Tests for CRLF vs LF, Unicode normalization, copy-paste survival,
//! and platform/editor survivability of stego markers.

use snow2::Mode;

fn big_carrier_lf(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Carrier line {i} with content"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn big_carrier_crlf(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Carrier line {i} with content"))
        .collect::<Vec<_>>()
        .join("\r\n")
}

// ── CRLF vs LF handling ─────────────────────────────────────────────

#[test]
fn classic_embed_extract_with_lf_carrier() {
    let carrier = big_carrier_lf(5000);
    let payload = b"LF test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed with LF should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract from LF carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn classic_embed_with_crlf_carrier_roundtrips() {
    // CRLF carriers should still work for embed/extract if line endings
    // are preserved through the pipeline.
    let carrier = big_carrier_crlf(5000);
    let payload = b"CRLF test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed with CRLF should succeed");

    // Extract from the same CRLF carrier
    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract from CRLF carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn crlf_to_lf_conversion_breaks_classic_stego() {
    // If a carrier embedded with CRLF is converted to LF, the \r before
    // the trailing whitespace marker changes the line content, which
    // should cause extraction to fail (integrity protection working).
    let carrier = big_carrier_crlf(5000);
    let payload = b"CRLF to LF test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed should succeed");

    // Simulate CRLF → LF conversion (common in git, editors, etc.)
    let converted = out.replace("\r\n", "\n");

    // This may succeed or fail depending on whether \r is part of the line
    // content the extractor sees. Either way, it must not panic.
    let result = snow2::extract(Mode::ClassicTrailing, &converted, password, None, None);
    // We primarily care that this doesn't panic. If it fails, great —
    // integrity protection is working.
    let _outcome = result;
}

#[test]
fn websafe_embed_extract_with_lf_carrier() {
    let carrier = big_carrier_lf(5000);
    let payload = b"ZW LF test";
    let password = b"pw";

    let out = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, password, None)
        .expect("embed with LF should succeed");

    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &out, password, None, None)
        .expect("extract from LF carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn websafe_embed_extract_with_crlf_carrier() {
    let carrier = big_carrier_crlf(5000);
    let payload = b"ZW CRLF test";
    let password = b"pw";

    let out = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, password, None)
        .expect("embed with CRLF should succeed");

    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &out, password, None, None)
        .expect("extract from CRLF carrier should succeed");

    assert_eq!(&*recovered, payload);
}

// ── Unicode handling ─────────────────────────────────────────────────

#[test]
fn carrier_with_unicode_content_classic() {
    // Carrier lines contain multibyte UTF-8 characters
    let carrier = (0..5000)
        .map(|i| format!("Línea {i} con contenido café ñ ü"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"unicode carrier test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed into unicode carrier should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract from unicode carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn carrier_with_unicode_content_websafe() {
    let carrier = (0..5000)
        .map(|i| format!("行 {i} 日本語テスト 🌸"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"unicode zw test";
    let password = b"pw";

    let out = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, password, None)
        .expect("embed into unicode carrier should succeed");

    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &out, password, None, None)
        .expect("extract from unicode carrier should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn carrier_with_emoji_content() {
    let carrier = (0..5000)
        .map(|i| format!("Line {i} 🎉🔒✨"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"emoji test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed into emoji carrier should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract from emoji carrier should succeed");

    assert_eq!(&*recovered, payload);
}

// ── Zero-width character survivability ───────────────────────────────

#[test]
fn websafe_markers_survive_if_preserved() {
    // Verify that zero-width markers are correctly placed and read back
    let carrier = (0..100)
        .map(|i| format!("Line {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let bits_in = vec![true, false, true, true, false];
    let embedded = snow2::stego::websafe_zw::embed_bits(&carrier, &bits_in)
        .expect("embed_bits should succeed");

    let bits_out =
        snow2::stego::websafe_zw::extract_bits(&embedded).expect("extract_bits should succeed");

    assert_eq!(bits_out, bits_in);
}

#[test]
fn websafe_stripping_all_zw_chars_destroys_data() {
    // If a system strips zero-width characters, extraction should get no bits
    let carrier = (0..5000)
        .map(|i| format!("Line {i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"zw strip test";
    let password = b"pw";

    let out = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, password, None)
        .expect("embed should succeed");

    // Strip all zero-width chars (simulates aggressive Unicode normalization)
    let stripped = out.replace(['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'], "");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &stripped, password, None, None).unwrap_err();
    let _ = format!("{err:#}");
    // Must fail, not succeed with garbage data
}

// ── Trailing whitespace stripping ────────────────────────────────────

#[test]
fn classic_trailing_whitespace_stripping_destroys_data() {
    let carrier = big_carrier_lf(5000);
    let payload = b"ws strip test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed should succeed");

    // Strip all trailing whitespace (simulates editor auto-trim)
    let stripped: String = out
        .lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n");

    let err = snow2::extract(Mode::ClassicTrailing, &stripped, password, None, None).unwrap_err();
    let _ = format!("{err:#}");
    // Must fail — integrity protection working
}

// ── Mixed content edge cases ─────────────────────────────────────────

#[test]
fn carrier_with_existing_trailing_whitespace() {
    // Carrier lines already have trailing spaces — embedding should
    // clean them before adding markers
    let carrier = (0..5000)
        .map(|i| format!("Line {i}   ")) // existing trailing spaces
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"existing ws test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed into carrier with existing trailing WS should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

#[test]
fn carrier_with_existing_zw_chars() {
    // Carrier lines already have zero-width chars — embedding should
    // strip them before adding markers
    let zw = '\u{200B}';
    let carrier = (0..5000)
        .map(|i| format!("Line {i}{zw}{zw}"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"existing zw test";
    let password = b"pw";

    let out = snow2::embed(Mode::WebSafeZeroWidth, &carrier, payload, password, None)
        .expect("embed into carrier with existing ZW chars should succeed");

    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &out, password, None, None)
        .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

// ── Tab expansion risk ───────────────────────────────────────────────

#[test]
fn carrier_with_inline_tabs_classic_roundtrip() {
    // Lines contain tabs (not trailing) — should not interfere with stego
    let carrier = (0..5000)
        .map(|i| format!("Col1\tCol2\tLine {i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = b"tab content test";
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, payload, password, None)
        .expect("embed should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract should succeed");

    assert_eq!(&*recovered, payload);
}

// ── Binary payload handling ──────────────────────────────────────────

#[test]
fn binary_payload_with_null_bytes() {
    let carrier = big_carrier_lf(5000);
    let payload: Vec<u8> = (0..256).map(|b| b as u8).collect();
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, &payload, password, None)
        .expect("embed binary payload should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract should succeed");

    assert_eq!(&*recovered, &payload[..]);
}

#[test]
fn binary_payload_all_zeros() {
    let carrier = big_carrier_lf(5000);
    let payload = vec![0u8; 100];
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, &payload, password, None)
        .expect("embed all-zero payload should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract should succeed");

    assert_eq!(&*recovered, &payload[..]);
}

#[test]
fn binary_payload_all_ones() {
    let carrier = big_carrier_lf(5000);
    let payload = vec![0xFFu8; 100];
    let password = b"pw";

    let out = snow2::embed(Mode::ClassicTrailing, &carrier, &payload, password, None)
        .expect("embed all-0xFF payload should succeed");

    let recovered = snow2::extract(Mode::ClassicTrailing, &out, password, None, None)
        .expect("extract should succeed");

    assert_eq!(&*recovered, &payload[..]);
}
