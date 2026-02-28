#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the SNOW2 container parser with arbitrary bytes.
///
/// This exercises `Snow2Container::from_bytes` against malformed, truncated,
/// corrupted, and hostile inputs. The parser must never panic — only return
/// `Ok` or `Err`.
fuzz_target!(|data: &[u8]| {
    let _ = snow2::container::Snow2Container::from_bytes(data);
});
