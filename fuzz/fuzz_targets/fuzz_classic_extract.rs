#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the classic-trailing stego extractor with arbitrary carrier text.
///
/// The extractor reads trailing whitespace from each line. Hostile carriers
/// may contain arbitrary Unicode, mixed line endings, or pathological line
/// counts. Must not panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = snow2::stego::classic_trailing::extract_bits(text);
    }
});
