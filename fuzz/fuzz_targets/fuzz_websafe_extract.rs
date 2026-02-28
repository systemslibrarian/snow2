#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the websafe-zw stego extractor with arbitrary carrier text.
///
/// The extractor reads trailing zero-width Unicode chars from each line.
/// Hostile carriers may contain arbitrary Unicode, mixed zero-width chars,
/// or pathological content. Must not panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = snow2::stego::websafe_zw::extract_bits(text);
    }
});
