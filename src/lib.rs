//! SNOW2 core library.
//!
//! This crate provides the core primitives for SNOW2:
//! - Versioned container format (v1 classic, v2 PQC, v3 compact, v4 hardened)
//! - Modern crypto (Argon2id + XChaCha20-Poly1305)
//! - Optional hybrid post-quantum crypto (Kyber1024 + Dilithium5) via `pqc` feature
//! - Steganography embedding/extraction modes (classic-trailing, websafe-zw)
//! - Security policy config (KDF tuning, pepper-required policy)
//! - Secure memory handling (mlock + guard pages on native, zeroize on WASM)
//! - Steganalysis resistance: outer encryption, constant-size padding, full-carrier
//!   random fill, plaintext compression

pub mod config;
pub mod container;
pub mod crypto;
pub mod stego;
pub mod secure_mem;

#[cfg(not(target_arch = "wasm32"))]
pub mod secure_fs;

#[cfg(feature = "pqc")]
pub mod pqc;

use anyhow::{bail, Result};
use secure_mem::SecureVec;

use flate2::write::{DeflateEncoder, DeflateDecoder};
use flate2::Compression;
use std::io::Write;

/// Supported embedding/extraction modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ClassicTrailing,
    WebSafeZeroWidth,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "classic-trailing" | "classic" | "trailing" => Ok(Self::ClassicTrailing),
            "websafe-zw" | "websafe" | "zw" | "zero-width" | "zerowidth" => Ok(Self::WebSafeZeroWidth),
            _ => bail!("Unknown mode: {s}. Expected: classic-trailing | websafe-zw"),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::ClassicTrailing => "classic-trailing",
            Mode::WebSafeZeroWidth => "websafe-zw",
        }
    }
}

/// Compress bytes with deflate.
#[allow(dead_code)]
fn deflate_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Decompress deflate-compressed bytes (returns None if data is not valid deflate).
fn deflate_decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(Vec::new());
    decoder.write_all(data).ok()?;
    decoder.finish().ok()
}

// ── V4 hardened embed/extract pipeline ───────────────────────────────────
//
// These are the main entry points for the v4 pipeline:
//
// Embed:
//   plaintext → (optional deflate) → AEAD seal (v4 compact header as AAD)
//   → serialize container bytes → constant-size pad → outer AEAD encrypt
//   → raw bits → embed into carrier + random-fill ALL remaining lines
//
// Extract:
//   carrier → extract ALL bits (every line) → raw bytes → try v4 outer
//   decrypt (try each bucket size) → unpad → parse v4 container → AEAD
//   open → (optional inflate) → plaintext
//   If v4 fails → fall back to legacy (CRC framing + old formats)

/// Embed payload bytes into a carrier text using the chosen mode.
/// Returns the modified carrier text.
///
/// Uses the v4 hardened pipeline:
/// 1) Builds a SNOW2 v4 container (compress + encrypt + authenticate)
/// 2) Pads to constant-size bucket
/// 3) Outer-encrypts the padded container
/// 4) Converts to raw bits (no CRC framing)
/// 5) Embeds bits into carrier lines
/// 6) Random-fills ALL remaining carrier lines
pub fn embed(
    mode: Mode,
    carrier_text: &str,
    payload: &[u8],
    password: &[u8],
    pepper: Option<&[u8]>,
) -> Result<String> {
    let container = container::Snow2Container::seal(payload, password, pepper, mode)?;
    let container_bytes = container.to_bytes()?;

    // Constant-size padding: [real_len(4 LE)][container_bytes][random_pad]
    let inner_len = 4 + container_bytes.len();
    let bucket = container::pad_bucket(inner_len);
    let pad_len = bucket - inner_len;
    let random_pad = crypto::random_bytes(pad_len)?;

    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(container_bytes.len() as u32).to_le_bytes());
    padded.extend_from_slice(&container_bytes);
    padded.extend_from_slice(&random_pad);

    // Outer AEAD encrypt
    let outer_blob = crypto::outer_seal(password, &padded)?;

    // Raw bits (no CRC framing — outer AEAD provides integrity)
    let bits = stego::raw_bytes_to_bits(&outer_blob);

    // Embed + random-fill all remaining lines
    match mode {
        Mode::ClassicTrailing => stego::classic_trailing::embed_bits_with_padding(carrier_text, &bits),
        Mode::WebSafeZeroWidth => stego::websafe_zw::embed_bits_with_padding(carrier_text, &bits),
    }
}

/// Embed payload using explicit security options (KDF tuning, pepper-required).
pub fn embed_with_options(
    mode: Mode,
    carrier_text: &str,
    payload: &[u8],
    password: &[u8],
    pepper: Option<&[u8]>,
    opts: &config::EmbedOptions,
) -> Result<String> {
    let container =
        container::Snow2Container::seal_with_options(payload, password, pepper, mode, opts)?;
    let container_bytes = container.to_bytes()?;

    // Constant-size padding
    let inner_len = 4 + container_bytes.len();
    let bucket = container::pad_bucket(inner_len);
    let pad_len = bucket - inner_len;
    let random_pad = crypto::random_bytes(pad_len)?;

    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(container_bytes.len() as u32).to_le_bytes());
    padded.extend_from_slice(&container_bytes);
    padded.extend_from_slice(&random_pad);

    // Outer AEAD encrypt
    let outer_blob = crypto::outer_seal(password, &padded)?;

    // Raw bits (no CRC framing)
    let bits = stego::raw_bytes_to_bits(&outer_blob);

    // Embed + random-fill
    match mode {
        Mode::ClassicTrailing => stego::classic_trailing::embed_bits_with_padding(carrier_text, &bits),
        Mode::WebSafeZeroWidth => stego::websafe_zw::embed_bits_with_padding(carrier_text, &bits),
    }
}

/// Maximum bucket size for v4 extraction (64 KiB payloads).
const V4_MAX_BUCKET: usize = 65536;

/// Try v4 extraction: outer decrypt → unpad → parse → open.
///
/// Returns:
/// - `Ok(Some(plaintext))` — v4 container found and decrypted successfully
/// - `Ok(None)` — not a v4 container (all outer decrypts failed)
/// - `Err(e)` — v4 container found (outer decrypt succeeded) but inner
///   processing failed (e.g., wrong pepper, corrupted container)
fn try_v4_extract(
    raw_bytes: &[u8],
    password: &[u8],
    pepper: Option<&[u8]>,
    pqc_sk: Option<&[u8]>,
) -> Result<Option<SecureVec>> {
    // Outer blob layout: nonce(24) + ciphertext(bucket + 16)
    // So total = 24 + bucket + 16 = bucket + 40
    let mut bucket = 64;
    while bucket <= V4_MAX_BUCKET {
        let blob_len = bucket + 40; // 24 nonce + bucket data + 16 AEAD tag
        if blob_len > raw_bytes.len() {
            break; // Carrier doesn't have enough data for this bucket
        }

        let blob = &raw_bytes[..blob_len];
        if let Ok(padded) = crypto::outer_open(password, blob) {
            // ── Outer AEAD succeeded — this IS a v4 container ───────────
            // From here, any failure is a real error (wrong pepper,
            // corrupted data, etc.), NOT "wrong format". Propagate it.
            if padded.len() < 4 {
                bail!("V4 outer decryption produced too few bytes.");
            }
            let real_len = u32::from_le_bytes(
                padded[0..4]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("V4 inner length parse error"))?,
            ) as usize;
            if 4 + real_len > padded.len() {
                bail!(
                    "V4 inner length ({}) exceeds padded buffer ({}).",
                    real_len,
                    padded.len() - 4
                );
            }
            let container_bytes = &padded[4..4 + real_len];

            // Parse v4 container
            let container = container::Snow2Container::from_bytes_v4(container_bytes)?;
            let plaintext = container.open(password, pepper, pqc_sk)?;
            return Ok(Some(plaintext));
        }
        bucket += 64;
    }
    Ok(None)
}

/// Extract payload bytes from a carrier text using the chosen mode.
/// Returns the decrypted payload bytes.
///
/// Tries the v4 hardened pipeline first, then falls back to legacy formats.
pub fn extract(
    mode: Mode,
    carrier_text: &str,
    password: &[u8],
    pepper: Option<&[u8]>,
    pqc_sk: Option<&[u8]>,
) -> Result<SecureVec> {
    // ── V4 path: extract ALL bits, try outer decrypt ────────────────────
    let all_bits = match mode {
        Mode::ClassicTrailing => stego::classic_trailing::extract_all_bits(carrier_text),
        Mode::WebSafeZeroWidth => stego::websafe_zw::extract_all_bits(carrier_text),
    };
    let raw_bytes = stego::raw_bits_to_bytes(&all_bits);

    match try_v4_extract(&raw_bytes, password, pepper, pqc_sk) {
        Ok(Some(plaintext)) => return Ok(plaintext),
        Err(e) => return Err(e), // v4 found but inner failed (wrong pepper, etc.)
        Ok(None) => {}            // not v4 — fall through to legacy path
    }

    // ── Legacy path: CRC framing → old container formats ────────────────
    let legacy_result = (|| -> Result<SecureVec> {
        let bits = match mode {
            Mode::ClassicTrailing => stego::classic_trailing::extract_bits(carrier_text)?,
            Mode::WebSafeZeroWidth => stego::websafe_zw::extract_bits(carrier_text)?,
        };

        let raw_bytes = stego::bits_to_bytes(&bits)?;

        // Try deflate decompress (v3 containers); fall back to raw (v1)
        let container_bytes = deflate_decompress(&raw_bytes).unwrap_or(raw_bytes);

        let container = container::Snow2Container::from_bytes(&container_bytes)?;
        container.open(password, pepper, pqc_sk)
    })();

    match legacy_result {
        Ok(pt) => Ok(pt),
        Err(legacy_err) => {
            // Both v4 and legacy paths failed.
            // If we had enough raw data for the smallest v4 bucket (64 + 40 = 104 bytes)
            // and legacy failed on CRC/bitstream parsing (not crypto), the carrier
            // is almost certainly a v4 container with the wrong password.
            let smallest_v4_blob = 64 + 40; // smallest bucket + nonce + tag
            let msg = format!("{legacy_err:#}");
            if raw_bytes.len() >= smallest_v4_blob
                && (msg.contains("Not enough bits")
                    || msg.contains("CRC")
                    || msg.contains("length overflow")
                    || msg.contains("bit length overflow"))
            {
                bail!(
                    "AEAD decrypt/auth failed \
                     (wrong password, wrong pepper, or corrupted carrier)."
                );
            }
            // For crypto-level legacy errors (wrong password on old container),
            // or genuinely too-small carriers, propagate as-is.
            Err(legacy_err)
        }
    }
}