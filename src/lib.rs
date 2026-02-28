//! SNOW2 core library.
//!
//! This crate provides the core primitives for SNOW2:
//! - Versioned container format (v1 classic, v2 PQC)
//! - Modern crypto (Argon2id + XChaCha20-Poly1305)
//! - Optional hybrid post-quantum crypto (Kyber1024 + Dilithium5) via `pqc` feature
//! - Steganography embedding/extraction modes (classic-trailing, websafe-zw)
//! - Security policy config (KDF tuning, pepper-required policy)
//! - Secure memory handling (mlock + guard pages on native, zeroize on WASM)

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

/// Embed payload bytes into a carrier text using the chosen mode.
/// Returns the modified carrier text.
///
/// This function:
/// 1) Builds a SNOW2 container (encrypts + authenticates payload)
/// 2) Encodes container bytes into a bitstream
/// 3) Embeds that bitstream into the carrier using the selected stego mode
pub fn embed(
    mode: Mode,
    carrier_text: &str,
    payload: &[u8],
    password: &[u8],
    pepper: Option<&[u8]>,
) -> Result<String> {
    // Step 1: containerize (encrypt+auth)
    let container = container::Snow2Container::seal(payload, password, pepper, mode)?;

    // Step 2: bytes -> bits
    let bits = stego::bytes_to_bits(&container.to_bytes()?)?;

    // Step 3: embed bits
    match mode {
        Mode::ClassicTrailing => stego::classic_trailing::embed_bits(carrier_text, &bits),
        Mode::WebSafeZeroWidth => stego::websafe_zw::embed_bits(carrier_text, &bits),
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
    let bits = stego::bytes_to_bits(&container.to_bytes()?)?;

    match mode {
        Mode::ClassicTrailing => stego::classic_trailing::embed_bits(carrier_text, &bits),
        Mode::WebSafeZeroWidth => stego::websafe_zw::embed_bits(carrier_text, &bits),
    }
}

/// Extract payload bytes from a carrier text using the chosen mode.
/// Returns the decrypted payload bytes.
///
/// This function:
/// 1) Extracts a bitstream from carrier using the selected stego mode
/// 2) Bits -> bytes (container)
/// 3) Opens SNOW2 container (auth + decrypt)
pub fn extract(
    mode: Mode,
    carrier_text: &str,
    password: &[u8],
    pepper: Option<&[u8]>,
    pqc_sk: Option<&[u8]>,
) -> Result<SecureVec> {
    // Step 1: extract bits
    let bits = match mode {
        Mode::ClassicTrailing => stego::classic_trailing::extract_bits(carrier_text)?,
        Mode::WebSafeZeroWidth => stego::websafe_zw::extract_bits(carrier_text)?,
    };

    // Step 2: bits -> bytes
    let container_bytes = stego::bits_to_bytes(&bits)?;

    // Step 3: open container
    let container = container::Snow2Container::from_bytes(&container_bytes)?;
    container.open(password, pepper, pqc_sk)
}