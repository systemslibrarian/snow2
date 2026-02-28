#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the bitstream decoder (`bits_to_bytes`) with arbitrary bit patterns.
///
/// The bitstream has a length prefix and CRC-32 checksum. Malformed inputs
/// should produce clear errors, not panics.
fuzz_target!(|data: &[u8]| {
    // Convert raw bytes to a bit vector (simulating what stego extraction produces)
    let bits: Vec<bool> = data.iter()
        .flat_map(|b| (0..8).rev().map(move |i| ((b >> i) & 1) == 1))
        .collect();

    let _ = snow2::stego::bits_to_bytes(&bits);
});
