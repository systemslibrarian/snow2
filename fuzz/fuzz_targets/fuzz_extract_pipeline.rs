#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the full extract pipeline: stego extraction → bitstream decode → container parse.
///
/// This combines all untrusted-input parsers in the path an attacker controls.
/// Uses classic-trailing mode with a fixed password so the fuzzer can exercise
/// the full path up to (and including) AEAD authentication failure.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Exercise classic-trailing pipeline
        let _ = snow2::extract(
            snow2::Mode::ClassicTrailing,
            text,
            b"fuzz-password",
            None,
            None,
        );

        // Exercise websafe-zw pipeline
        let _ = snow2::extract(
            snow2::Mode::WebSafeZeroWidth,
            text,
            b"fuzz-password",
            None,
            None,
        );
    }
});
