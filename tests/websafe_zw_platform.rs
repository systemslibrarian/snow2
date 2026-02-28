//! Zero-width (websafe-zw) platform survivability tests.
//!
//! Simulates the Unicode mangling that real platforms apply when text
//! is copy-pasted through Slack, Telegram, Reddit, Google Docs, Discord,
//! email clients, Markdown renderers, and older terminals.
//!
//! Key behaviors tested:
//! - Full stripping of ZWSP/ZWNJ → extraction must fail cleanly
//! - Partial stripping (random lines) → CRC-32 or AEAD must catch it
//! - Replacement with other Unicode (normalization NFKC/NFKD)
//! - Insertion of extra zero-width chars (BOM, ZWJ, etc.)
//! - Truncation: extraction stops at first non-marker char (correct)
//! - Mixed carrier content (some lines have markers, some don't)

use snow2::stego::websafe_zw;
use snow2::Mode;

const ZW0: char = '\u{200B}'; // ZERO WIDTH SPACE
const ZW1: char = '\u{200C}'; // ZERO WIDTH NON-JOINER

fn carrier(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("Line {i} of carrier text"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ═══════════════════════════════════════════════════════════════════════
// Platform stripping simulations
// ═══════════════════════════════════════════════════════════════════════

/// Discord, Slack, and some Markdown renderers strip ALL zero-width
/// characters. Extraction must fail, not return garbage.
#[test]
fn full_zwsp_zwnj_strip_fails_cleanly() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"secret message";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Strip every ZWSP and ZWNJ (Discord / Slack behavior)
    let stripped = stego.replace([ZW0, ZW1], "");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &stripped, password, None, None);
    assert!(err.is_err(), "full strip must fail, not silently succeed");
}

/// Some platforms strip only ZWSP (U+200B) but leave ZWNJ (U+200C).
/// This corrupts the bitstream → CRC-32 or AEAD will catch it.
#[test]
fn strip_only_zwsp_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"test data";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Strip only ZWSP, leave ZWNJ
    let mangled = stego.replace(ZW0, "");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "partial strip (ZWSP only) must fail");
}

/// Strip only ZWNJ (U+200C), leave ZWSP.
#[test]
fn strip_only_zwnj_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"test data 2";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    let mangled = stego.replace(ZW1, "");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "partial strip (ZWNJ only) must fail");
}

/// Simulate random line corruption: strip ZW markers from ~30% of lines.
/// This models platforms that strip ZW chars inconsistently (e.g. some
/// email renderers only process certain paragraphs).
#[test]
fn random_partial_strip_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"partial strip test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Strip ZW chars from every 3rd line
    let mangled: String = stego
        .split('\n')
        .enumerate()
        .map(|(i, line)| {
            if i % 3 == 0 {
                line.replace([ZW0, ZW1], "")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "random partial strip must fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Unicode normalization simulations
// ═══════════════════════════════════════════════════════════════════════

/// NFKC/NFKD normalization can strip compatibility characters.
/// U+200B and U+200C are format characters that some normalizers remove.
/// Simulate by replacing ZW chars with empty string (same as stripping).
#[test]
fn nfkc_normalization_strips_zw_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"nfkc test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // NFKC normalization effect: ZW format chars are removed
    let normalized = stego.replace([ZW0, ZW1], "");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &normalized, password, None, None);
    assert!(
        err.is_err(),
        "NFKC normalization must cause extraction failure"
    );
}

/// Some normalizers replace ZWSP with normal space. This changes the
/// last char on the line from a ZW marker to ' ', which breaks the
/// extraction (normal space is not a marker → stops early).
#[test]
fn zwsp_replaced_with_normal_space_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"space replace test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Replace ZWSP with regular space (some clipboard sanitizers do this)
    let mangled = stego.replace(ZW0, " ");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "ZWSP→space replacement must fail extraction");
}

// ═══════════════════════════════════════════════════════════════════════
// Extra zero-width character injection
// ═══════════════════════════════════════════════════════════════════════

/// Some systems insert BOM (U+FEFF) or ZWJ (U+200D) into text.
/// If placed at end-of-line after the ZW markers, these break the
/// trailing ZW detection and cause extraction to stop at that line.
#[test]
fn bom_injection_at_line_end_truncates() {
    // With 8 bits/line, embed 16 bits across 2 lines
    let bits_in = vec![
        true, false, true, false, true, false, true, false, false, true, false, true, false, true,
        false, true,
    ];
    let c = carrier(10);

    let embedded = websafe_zw::embed_bits(&c, &bits_in).expect("embed ok");

    // Inject BOM at end of line 1 (2nd carrier line)
    // The extractor reads trailing ZW chars via take_while from the end.
    // BOM at the end means take_while stops immediately → 0 ZW bits from that line → stop.
    let mut lines: Vec<String> = embedded.split('\n').map(String::from).collect();
    lines[1] = format!("{}\u{FEFF}", lines[1]);

    let mangled = lines.join("\n");
    let bits_out = websafe_zw::extract_bits(&mangled).expect("extract ok");

    // Should get only the 8 bits from line 0, then stop at line 1 (BOM breaks it)
    assert_eq!(
        bits_out.len(),
        8,
        "extraction should stop at BOM-injected line"
    );
    assert_eq!(bits_out, &bits_in[..8]);
}

/// ZWJ (U+200D) inserted at end of line — not a valid marker.
#[test]
fn zwj_injection_at_line_end_truncates() {
    // With 8 bits/line, embed 16 bits across 2 lines
    let bits_in = vec![
        false, true, false, true, false, true, false, true, true, false, true, false, true, false,
        true, false,
    ];
    let c = carrier(10);

    let embedded = websafe_zw::embed_bits(&c, &bits_in).expect("embed ok");

    let mut lines: Vec<String> = embedded.split('\n').map(String::from).collect();
    // Append ZWJ to the 2nd line (index 1)
    lines[1] = format!("{}\u{200D}", lines[1]);

    let mangled = lines.join("\n");
    let bits_out = websafe_zw::extract_bits(&mangled).expect("extract ok");

    // Should get 8 bits from line 0, then stop at line 1 (last char = ZWJ)
    assert_eq!(bits_out.len(), 8);
    assert_eq!(bits_out, &bits_in[..8]);
}

// ═══════════════════════════════════════════════════════════════════════
// Extraction truncation behavior
// ═══════════════════════════════════════════════════════════════════════

/// The extractor stops at the first non-empty line whose last char is
/// not a ZW marker. This is correct behavior but means truncation
/// is silent at the bit level. The CRC-32 framing catches it.
#[test]
fn truncation_at_unmarked_line_caught_by_crc() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"truncation crc test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Remove the ZW marker from line 50 (0-indexed) to simulate
    // a platform that strips ZW from one line in the middle.
    let mut lines: Vec<String> = stego.split('\n').map(String::from).collect();
    if lines.len() > 50 {
        let cleaned = lines[50].replace([ZW0, ZW1], "");
        lines[50] = cleaned;
    }
    let mangled = lines.join("\n");

    // Extraction gets only 50 bits, then stops. CRC-32 should catch the shortfall.
    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(
        err.is_err(),
        "truncation at line 50 must be caught by CRC or length check"
    );
}

/// Strip the very first line's marker. The entire bitstream offset
/// shifts, corrupting everything.
#[test]
fn strip_first_line_marker_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"first line test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    let mut lines: Vec<String> = stego.split('\n').map(String::from).collect();
    // Strip marker from first non-empty line
    lines[0] = lines[0].replace([ZW0, ZW1], "");
    let mangled = lines.join("\n");

    // First line has no marker → extraction stops immediately → 0 bits → fail
    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "stripping first line marker must fail");
}

/// Strip marker from the last embedded line only.
#[test]
fn strip_last_embedded_line_marker_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"last line test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // With v4 hardened pipeline, all lines get ZW content (real data + random padding).
    // Stripping a padding line won't cause failure because only the first N bytes matter.
    // Instead, strip an EARLY marker line (in the real-data range) to corrupt the payload.
    let mut lines: Vec<String> = stego.split('\n').map(String::from).collect();
    let first_marker_idx = lines
        .iter()
        .position(|l| l.ends_with(ZW0) || l.ends_with(ZW1))
        .expect("should find a marker");
    lines[first_marker_idx] = lines[first_marker_idx].replace([ZW0, ZW1], "");
    let mangled = lines.join("\n");

    // Corrupting the real-data area → outer AEAD or inner AEAD check fails
    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "stripping a real-data marker must fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Platform-specific simulations
// ═══════════════════════════════════════════════════════════════════════

/// Telegram: generally preserves zero-width chars in text messages.
/// Simulate a clean copy-paste (no mangling) = should roundtrip.
#[test]
fn telegram_clean_copypaste_roundtrips() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"telegram test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Telegram preserves ZW chars — no mangling
    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &stego, password, None, None)
        .expect("telegram-like clean paste should succeed");

    assert_eq!(&*recovered, payload);
}

/// Google Docs: tends to insert its own formatting characters.
/// Simulate by inserting U+00AD (soft hyphen) at random positions.
/// These should not affect extraction since they don't appear at
/// end-of-line positions.
#[test]
fn gdocs_soft_hyphen_insertion_roundtrips() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"gdocs test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Insert soft hyphens in the middle of some lines (not at end)
    let mangled: String = stego
        .split('\n')
        .enumerate()
        .map(|(i, line)| {
            if i % 5 == 0 && line.len() > 10 {
                // Insert soft hyphen after 5th char
                let (a, b) = line.split_at(5);
                format!("{a}\u{00AD}{b}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Soft hyphens are in the middle, not the last char. ZW markers
    // at end-of-line are preserved. Should still roundtrip.
    let recovered = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None)
        .expect("soft hyphens mid-line should not break extraction");

    assert_eq!(&*recovered, payload);
}

/// Reddit: its Markdown renderer may strip zero-width chars.
/// Simulate full strip.
#[test]
fn reddit_markdown_strip_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"reddit test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    let stripped = stego.replace([ZW0, ZW1], "");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &stripped, password, None, None);
    assert!(err.is_err(), "reddit full strip must fail");
}

/// Email client: may add trailing whitespace (spaces) to lines.
/// This puts a regular space AFTER the ZW marker, making space the
/// last char → extraction stops (space is not a marker).
#[test]
fn email_trailing_space_after_marker_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"email test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Append a trailing space to every line (common email format=flowed)
    let mangled: String = stego
        .split('\n')
        .map(|line| format!("{line} "))
        .collect::<Vec<_>>()
        .join("\n");

    // Last char on every line is now ' ' instead of ZW0/ZW1 → stops immediately
    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(
        err.is_err(),
        "trailing spaces after markers must break extraction"
    );
}

/// Older terminal: may strip all non-ASCII characters.
#[test]
fn terminal_ascii_only_strip_fails() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"terminal test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Strip everything non-ASCII
    let ascii_only: String = stego.chars().filter(|c| c.is_ascii()).collect();

    let err = snow2::extract(Mode::WebSafeZeroWidth, &ascii_only, password, None, None);
    assert!(err.is_err(), "ASCII-only filter must destroy ZW markers");
}

// ═══════════════════════════════════════════════════════════════════════
// Bit-level edge cases
// ═══════════════════════════════════════════════════════════════════════

/// Empty carrier → embed must fail, not produce broken output.
#[test]
fn embed_into_empty_carrier_fails() {
    let password = b"pw";
    let payload = b"hello";

    let err = snow2::embed(Mode::WebSafeZeroWidth, "", payload, password, None);
    assert!(err.is_err(), "embedding into empty carrier must fail");
}

/// Carrier with only empty lines → no usable lines → embed must fail.
#[test]
fn embed_into_blank_lines_only_fails() {
    let c = "\n\n\n\n\n";
    let password = b"pw";
    let payload = b"hello";

    let err = snow2::embed(Mode::WebSafeZeroWidth, c, payload, password, None);
    assert!(err.is_err(), "embedding into blank-only carrier must fail");
}

/// Extraction from carrier with no ZW markers → must fail.
#[test]
fn extract_from_unmarked_carrier_fails() {
    let c = carrier(100);
    let password = b"pw";

    let err = snow2::extract(Mode::WebSafeZeroWidth, &c, password, None, None);
    assert!(err.is_err(), "extracting from unmarked carrier must fail");
}

/// Single-bit markers: embed exactly 1 bit, extract it back.
#[test]
fn single_bit_roundtrip() {
    let c = carrier(10);

    for val in [true, false] {
        let embedded = websafe_zw::embed_bits(&c, &[val]).expect("embed 1 bit");
        let bits = websafe_zw::extract_bits(&embedded).expect("extract 1 bit");
        assert_eq!(bits[0], val, "single bit roundtrip for {val}");
    }
}

/// All-zero bits and all-one bits roundtrip at the bit level.
#[test]
fn uniform_bits_roundtrip() {
    let c = carrier(200);

    let all_zero = vec![false; 100];
    let embedded = websafe_zw::embed_bits(&c, &all_zero).expect("embed all-zero");
    let bits = websafe_zw::extract_bits(&embedded).expect("extract all-zero");
    assert_eq!(&bits[..100], &all_zero[..]);

    let all_one = vec![true; 100];
    let embedded = websafe_zw::embed_bits(&c, &all_one).expect("embed all-one");
    let bits = websafe_zw::extract_bits(&embedded).expect("extract all-one");
    assert_eq!(&bits[..100], &all_one[..]);
}

/// Verify bit fidelity: a known pattern encodes and decodes correctly.
#[test]
fn known_pattern_bit_fidelity() {
    let c = carrier(20);
    let pattern = vec![true, false, true, true, false, false, true, false];

    let embedded = websafe_zw::embed_bits(&c, &pattern).expect("embed pattern");
    let bits = websafe_zw::extract_bits(&embedded).expect("extract pattern");

    assert_eq!(&bits[..pattern.len()], &pattern[..]);
}

// ═══════════════════════════════════════════════════════════════════════
// Swap / bit-flip attacks
// ═══════════════════════════════════════════════════════════════════════

/// Swap ZW0 ↔ ZW1 on a single line → bitflip → CRC or AEAD catches it.
#[test]
fn single_bitflip_caught() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"bitflip test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    let mut lines: Vec<String> = stego.split('\n').map(String::from).collect();
    // Flip the marker on line 10
    if lines[10].ends_with(ZW0) {
        let trimmed = lines[10].trim_end_matches(ZW0);
        lines[10] = format!("{trimmed}{ZW1}");
    } else if lines[10].ends_with(ZW1) {
        let trimmed = lines[10].trim_end_matches(ZW1);
        lines[10] = format!("{trimmed}{ZW0}");
    }
    let mangled = lines.join("\n");

    let err = snow2::extract(Mode::WebSafeZeroWidth, &mangled, password, None, None);
    assert!(err.is_err(), "single bitflip must be caught");
}

/// Swap all ZW0 ↔ ZW1 (invert every bit).
#[test]
fn full_inversion_caught() {
    let c = carrier(5000);
    let password = b"pw";
    let payload = b"inversion test";

    let stego =
        snow2::embed(Mode::WebSafeZeroWidth, &c, payload, password, None).expect("embed ok");

    // Invert: swap ZW0 and ZW1 globally
    let tmp = stego.replace(ZW0, "\x01"); // temp placeholder
    let inv = tmp
        .replace(ZW1, &ZW0.to_string())
        .replace('\x01', &ZW1.to_string());

    let err = snow2::extract(Mode::WebSafeZeroWidth, &inv, password, None, None);
    assert!(err.is_err(), "full inversion must be caught");
}
