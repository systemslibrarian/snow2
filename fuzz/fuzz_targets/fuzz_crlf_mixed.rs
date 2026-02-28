#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz stego extraction from carriers with mixed CRLF / LF line endings.
///
/// This converts raw fuzzer input to UTF-8 text and then transforms random
/// line endings to a mix of CRLF and LF before feeding into both stego
/// extractors. This ensures the \r-stripping logic never panics.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Convert ~50 % of \n to \r\n to create mixed endings
        let mixed: String = text
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if c == '\n' && i % 2 == 0 {
                    vec!['\r', '\n']
                } else {
                    vec![c]
                }
            })
            .collect();

        // Exercise classic-trailing with mixed endings
        let _ = snow2::stego::classic_trailing::extract_bits(&mixed);
        let _ = snow2::stego::classic_trailing::extract_all_bits(&mixed);

        // Exercise websafe-zw with mixed endings
        let _ = snow2::stego::websafe_zw::extract_bits(&mixed);
        let _ = snow2::stego::websafe_zw::extract_all_bits(&mixed);

        // Also exercise embed_bits with a handful of random bits
        let bits: Vec<bool> = data.iter().take(32).map(|b| b & 1 == 1).collect();
        if !bits.is_empty() {
            let _ = snow2::stego::classic_trailing::embed_bits(&mixed, &bits);
            let _ = snow2::stego::websafe_zw::embed_bits(&mixed, &bits);
        }
    }
});
