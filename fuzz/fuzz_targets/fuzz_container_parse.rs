#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the SNOW2 container parser with arbitrary bytes.
///
/// This exercises both `from_bytes` (legacy v1/v2/v3) and `from_bytes_v4`
/// (hardened format) against malformed, truncated, corrupted, and hostile
/// inputs. The parsers must never panic — only return `Ok` or `Err`.
fuzz_target!(|data: &[u8]| {
    // Legacy parser (v1/v2/v3 — requires MAGIC header)
    let _ = snow2::container::Snow2Container::from_bytes(data);

    // V4 hardened parser (no magic bytes, 49-byte binary header)
    let _ = snow2::container::Snow2Container::from_bytes_v4(data);
});
