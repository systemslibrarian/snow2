#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the V4 container binary header parser with structured fuzzing.
///
/// Unlike fuzz_container_parse which feeds fully random bytes, this target
/// constructs blobs that *start* with a valid version byte (4) so the
/// parser actually enters the V4 header-decoding path. The fuzzer then
/// mutates the 49-byte header and trailing "ciphertext" to exercise
/// every bounds check, mode validation, and KDF-parameter validation.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Force version = 4 so we always exercise the V4 path
    let mut blob = Vec::with_capacity(1 + data.len());
    blob.push(4u8);
    blob.extend_from_slice(data);

    let _ = snow2::container::Snow2Container::from_bytes_v4(&blob);
});
