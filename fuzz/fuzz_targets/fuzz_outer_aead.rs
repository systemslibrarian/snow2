#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the outer AEAD decryption path with corrupted ciphertext blobs.
///
/// This constructs outer-layer-shaped blobs (salt‖nonce‖ct+tag, ≥56 bytes)
/// and feeds them through `outer_open` with a fixed key. The goal is to
/// verify that the AEAD and key-derivation error paths never panic, even
/// for adversarial ciphertext.
fuzz_target!(|data: &[u8]| {
    // Need ≥ 56 bytes for a minimally valid outer envelope
    if data.len() < 56 {
        return;
    }

    // Build a ZeroizingKey via the public API
    let key = zeroize::Zeroizing::new([0xABu8; 32]);

    // Treat data as a raw outer blob and try to decrypt
    let _ = snow2::crypto::outer_open(&key, data);
});
