use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::config::EmbedSecurityOptions;
use crate::crypto;
use crate::Mode;

const MAGIC: &[u8; 5] = b"SNOW2";
const VERSION: u8 = 1;

/// Versioned container header.
/// This header is authenticated (AAD) during encryption/decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snow2Header {
    /// "SNOW2"
    pub magic: String,
    /// container version (currently 1)
    pub version: u8,

    /// Stego mode used to embed the container (informational + authenticated)
    pub mode: String,

    /// KDF parameters used for Argon2id
    pub kdf: crypto::KdfParams,

    /// If true, pepper must be supplied during decrypt or open() fails.
    pub pepper_required: bool,

    /// Salt for password KDF (base64)
    pub salt_b64: String,

    /// AEAD nonce (base64). For XChaCha20-Poly1305 this is 24 bytes.
    pub nonce_b64: String,

    /// AEAD algorithm identifier
    pub aead: String,

    /// Plaintext length (informational + authenticated)
    pub plaintext_len: u64,
}

/// SNOW2 container:
/// [MAGIC(5)] [VERSION(1)] [HEADER_LEN u32 LE] [HEADER_JSON bytes] [CIPHERTEXT bytes]
///
/// Security model:
/// - HEADER_JSON is passed as AEAD AAD (authenticated, not encrypted)
/// - CIPHERTEXT is AEAD output (ciphertext + tag)
#[derive(Debug, Clone)]
pub struct Snow2Container {
    header: Snow2Header,
    ciphertext: Vec<u8>,
}

impl Snow2Container {
    /// Create a new container by encrypting a payload using provided security options.
    pub fn seal_with_options(
        plaintext: &[u8],
        password: &str,
        pepper: Option<&str>,
        mode: Mode,
        opts: &EmbedSecurityOptions,
    ) -> Result<Self> {
        if opts.pepper_required && pepper.is_none() {
            bail!("Pepper is required by policy, but no pepper was provided.");
        }

        // Generate per-message randomness
        let salt = crypto::random_bytes(16)?;
        let nonce = crypto::random_bytes(24)?; // XChaCha20-Poly1305 nonce length

        let header = Snow2Header {
            magic: String::from_utf8(MAGIC.to_vec()).expect("MAGIC is valid utf8"),
            version: VERSION,
            mode: mode.as_str().to_string(),
            kdf: opts.kdf.clone(),
            pepper_required: opts.pepper_required,
            salt_b64: STANDARD.encode(&salt),
            nonce_b64: STANDARD.encode(&nonce),
            aead: "XChaCha20-Poly1305".to_string(),
            plaintext_len: plaintext.len() as u64,
        };

        let header_json = serde_json::to_vec(&header).context("serialize header")?;

        // Derive key from password (+ optional pepper) and salt
        let salt_raw = STANDARD
            .decode(&header.salt_b64)
            .context("decode salt_b64")?;
        let key = crypto::derive_key(password, pepper, &salt_raw, &header.kdf)?;

        // AEAD seal: AAD = header_json
        let ciphertext = crypto::aead_seal(&key, &nonce, &header_json, plaintext)?;

        Ok(Self { header, ciphertext })
    }

    /// Backward-compatible helper: seal using recommended defaults (pepper optional).
    pub fn seal(
        plaintext: &[u8],
        password: &str,
        pepper: Option<&str>,
        mode: Mode,
    ) -> Result<Self> {
        let opts = EmbedSecurityOptions::default();
        Self::seal_with_options(plaintext, password, pepper, mode, &opts)
    }

    /// Open and decrypt a container.
    pub fn open(&self, password: &str, pepper: Option<&str>) -> Result<Vec<u8>> {
        if self.header.magic.as_bytes() != MAGIC {
            bail!("Not a SNOW2 container (bad magic).");
        }
        if self.header.version != VERSION {
            bail!(
                "Unsupported SNOW2 container version: {} (expected {}).",
                self.header.version,
                VERSION
            );
        }
        if self.header.aead != "XChaCha20-Poly1305" {
            bail!("Unsupported AEAD: {}", self.header.aead);
        }
        if self.header.pepper_required && pepper.is_none() {
            bail!("Pepper is required by this container, but none was provided.");
        }

        let header_json = serde_json::to_vec(&self.header).context("serialize header (aad)")?;
        let salt_raw = STANDARD
            .decode(&self.header.salt_b64)
            .context("decode salt_b64")?;
        let nonce = STANDARD
            .decode(&self.header.nonce_b64)
            .context("decode nonce_b64")?;

        if nonce.len() != 24 {
            bail!("Invalid nonce length: {} (expected 24).", nonce.len());
        }

        let key = crypto::derive_key(password, pepper, &salt_raw, &self.header.kdf)?;
        let plaintext = crypto::aead_open(&key, &nonce, &header_json, &self.ciphertext)?;

        if plaintext.len() as u64 != self.header.plaintext_len {
            bail!(
                "Decrypted length mismatch (got {}, expected {}).",
                plaintext.len(),
                self.header.plaintext_len
            );
        }

        Ok(plaintext)
    }

    pub fn header(&self) -> &Snow2Header {
        &self.header
    }

    /// Serialize container to bytes (for stego embedding).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let header_json = serde_json::to_vec(&self.header).context("serialize header")?;
        let header_len: u32 = header_json
            .len()
            .try_into()
            .context("header too large")?;

        let mut out = Vec::with_capacity(5 + 1 + 4 + header_json.len() + self.ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&header_json);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Parse container from bytes (after stego extraction).
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        if input.len() < 5 + 1 + 4 {
            bail!("Input too short to be a SNOW2 container.");
        }

        let magic = &input[0..5];
        if magic != MAGIC {
            bail!("Not a SNOW2 container (bad magic).");
        }

        let version = input[5];
        if version != VERSION {
            bail!(
                "Unsupported SNOW2 container version: {} (expected {}).",
                version,
                VERSION
            );
        }

        let header_len = u32::from_le_bytes(
            input[6..10]
                .try_into()
                .expect("slice length checked"),
        ) as usize;

        let header_start = 10;
        let header_end = header_start + header_len;
        if input.len() < header_end {
            bail!("Truncated SNOW2 header.");
        }

        let header_json = &input[header_start..header_end];
        let header: Snow2Header = serde_json::from_slice(header_json).context("parse header")?;

        if header.magic.as_bytes() != MAGIC {
            bail!("Bad header magic.");
        }
        if header.version != VERSION {
            bail!("Bad header version.");
        }

        let ciphertext = input[header_end..].to_vec();
        if ciphertext.is_empty() {
            bail!("Missing ciphertext.");
        }

        Ok(Self { header, ciphertext })
    }
}