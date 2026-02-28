use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::config::{EmbedOptions, EmbedSecurityOptions};
use crate::crypto::{self};
use crate::secure_mem::SecureVec;
use crate::Mode;
use subtle::ConstantTimeEq;

#[cfg(feature = "pqc")]
use pqcrypto_traits::{sign::DetachedSignature, kem::PublicKey as KemPublicKey, sign::PublicKey as SignPublicKey};


const MAGIC: &[u8; 5] = b"SNOW2";
const VERSION: u8 = 1;
const PQC_VERSION: u8 = 2;

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

    /// Post-quantum public keys (only in PQC containers)
    #[cfg(feature = "pqc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_kyber_pk_b64: Option<String>,
    #[cfg(feature = "pqc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_dilithium_pk_b64: Option<String>,
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
    #[cfg(feature = "pqc")]
    pqc_signature: Option<Vec<u8>>,
}

impl Snow2Container {
    /// Create a new container by encrypting a payload using provided security options.
    pub fn seal_with_options(
        plaintext: &[u8],
        password: &[u8],
        pepper: Option<&[u8]>,
        mode: Mode,
        opts: &EmbedOptions,
    ) -> Result<Self> {
        #[cfg(feature = "pqc")]
        if opts.security.pqc_enabled {
            return Self::seal_pqc(plaintext, mode, opts);
        }

        Self::seal_classic(plaintext, password, pepper, mode, &opts.security)
    }

    fn seal_classic(
        plaintext: &[u8],
        password: &[u8],
        pepper: Option<&[u8]>,
        mode: Mode,
        opts: &EmbedSecurityOptions,
    ) -> Result<Self> {
        if opts.pepper_required && pepper.is_none() {
            bail!("Pepper is required by policy, but no pepper was provided.");
        }

        // Validate KDF params at embed time so we never create a container
        // that our own extractor would reject.
        opts.kdf.validate_extraction_bounds()?;

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
            #[cfg(feature = "pqc")]
            pqc_kyber_pk_b64: None,
            #[cfg(feature = "pqc")]
            pqc_dilithium_pk_b64: None,
        };

        let header_json = serde_json::to_vec(&header).context("serialize header")?;

        // Derive key from password (+ optional pepper) and salt
        let salt_raw = STANDARD
            .decode(&header.salt_b64)
            .context("decode salt_b64")?;
        let key = crypto::derive_key(password, pepper, &salt_raw, &header.kdf)?;

        // AEAD seal: AAD = header_json
        let ciphertext = crypto::aead_seal(&key, &nonce, &header_json, plaintext)?;

        Ok(Self {
            header,
            ciphertext,
            #[cfg(feature = "pqc")]
            pqc_signature: None,
        })
    }

    #[cfg(feature = "pqc")]
    fn seal_pqc(
        plaintext: &[u8],
        mode: Mode,
        opts: &EmbedOptions,
    ) -> Result<Self> {
        let pq_pk = opts.pqc_keys.pk.as_ref().context("PQC public key is required for PQC seal.")?;

        let header = Snow2Header {
            magic: String::from_utf8(MAGIC.to_vec()).expect("MAGIC is valid utf8"),
            version: PQC_VERSION,
            mode: mode.as_str().to_string(),
            kdf: opts.security.kdf.clone(),
            pepper_required: false, // PQC mode does not use passwords
            salt_b64: String::new(),
            nonce_b64: String::new(),
            aead: "HYBRID-Kyber1024-XChaCha20-Poly1305".to_string(),
            plaintext_len: plaintext.len() as u64,
            pqc_kyber_pk_b64: Some(STANDARD.encode(pq_pk.kyber_pk.as_bytes())),
            pqc_dilithium_pk_b64: Some(STANDARD.encode(pq_pk.dilithium_pk.as_bytes())),
        };

        let header_json = serde_json::to_vec(&header).context("serialize header")?;

        let (kyber_ct, classic_ct) =
            crate::pqc::hybrid_encrypt(plaintext, &pq_pk.kyber_pk, &header_json)?;

        // The final ciphertext is: [kyber_ct_len u16 LE | kyber_ct | classic_ct]
        let mut ciphertext = Vec::with_capacity(2 + kyber_ct.len() + classic_ct.len());
        ciphertext.extend_from_slice(&(kyber_ct.len() as u16).to_le_bytes());
        ciphertext.extend_from_slice(&kyber_ct);
        ciphertext.extend_from_slice(&classic_ct);

        // Sign the whole thing
        let pq_sk = opts.pqc_keys.sk.as_ref().context("PQC secret key is required for PQC seal.")?;
        let signature = crate::pqc::sign(&ciphertext, &pq_sk.dilithium_sk);

        Ok(Self {
            header,
            ciphertext,
            pqc_signature: Some(signature.as_bytes().to_vec()),
        })
    }

    /// Backward-compatible helper: seal using recommended defaults (pepper optional).
    pub fn seal(
        plaintext: &[u8],
        password: &[u8],
        pepper: Option<&[u8]>,
        mode: Mode,
    ) -> Result<Self> {
        let opts = EmbedOptions::default();
        Self::seal_with_options(plaintext, password, pepper, mode, &opts)
    }

    /// Open and decrypt a container.
    pub fn open(
        &self,
        password: &[u8],
        pepper: Option<&[u8]>,
        _pqc_sk: Option<&[u8]>,
    ) -> Result<SecureVec> {
        // SECURITY: Constant-time magic check
        if self.header.magic.as_bytes().ct_eq(MAGIC).unwrap_u8() != 1 {
            bail!("Not a SNOW2 container (bad magic).");
        }

        #[cfg(feature = "pqc")]
        if self.header.version == PQC_VERSION {
            let sk = _pqc_sk.context("PQC container requires a secret key (--pqc-sk).")?;
            return self.open_pqc(sk);
        }

        if self.header.version != VERSION {
            bail!(
                "Unsupported SNOW2 container version: {} (expected {}).",
                self.header.version,
                VERSION
            );
        }
        // SECURITY: Constant-time AEAD check
        if self
            .header
            .aead
            .as_bytes()
            .ct_eq(b"XChaCha20-Poly1305")
            .unwrap_u8()
            != 1
        {
            bail!("Unsupported AEAD: {}", self.header.aead);
        }
        if self.header.pepper_required && pepper.is_none() {
            bail!("Pepper is required by this container, but none was provided.");
        }

        // SECURITY: Validate KDF parameters from the (untrusted) container
        // header before doing any expensive work. This prevents DoS via
        // absurd memory/time cost values.
        self.header.kdf.validate_extraction_bounds()?;

        let header_json = serde_json::to_vec(&self.header).context("serialize header (aad)")?;
        let salt_raw = STANDARD
            .decode(&self.header.salt_b64)
            .context("decode salt_b64")?;
        let nonce = STANDARD
            .decode(&self.header.nonce_b64)
            .context("decode nonce_b64")?;

        // Validate decoded lengths before passing to crypto primitives.
        if salt_raw.len() < 16 {
            bail!("Salt too short: {} bytes (expected 16).", salt_raw.len());
        }
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

    #[cfg(feature = "pqc")]
    fn open_pqc(&self, sk_bytes: &[u8]) -> Result<SecureVec> {
        use crate::pqc::{PqSecretKey};

        let sig = self
            .pqc_signature
            .as_ref()
            .context("PQC container is missing signature.")?;

        let dilithium_pk_b64 = self
            .header
            .pqc_dilithium_pk_b64
            .as_ref()
            .context("PQC header is missing Dilithium public key.")?;
        let dilithium_pk_bytes = STANDARD
            .decode(dilithium_pk_b64)
            .context("Failed to decode Dilithium public key")?;
        let dilithium_pk =
            crate::pqc::DilithiumPublicKey::from_bytes(&dilithium_pk_bytes)?;

        // Verify signature over the ciphertext first
        crate::pqc::verify(&self.ciphertext, sig, &dilithium_pk)?;

        // The ciphertext is: [kyber_ct_len u16 LE | kyber_ct | classic_ct]
        if self.ciphertext.len() < 2 {
            bail!("Truncated PQC ciphertext (missing length).");
        }
        let kyber_ct_len = u16::from_le_bytes(self.ciphertext[0..2].try_into().unwrap()) as usize;
        let kyber_ct_end = 2 + kyber_ct_len;
        if self.ciphertext.len() < kyber_ct_end {
            bail!("Truncated PQC ciphertext (missing Kyber ciphertext).");
        }
        let kyber_ct = &self.ciphertext[2..kyber_ct_end];
        let classic_ct = &self.ciphertext[kyber_ct_end..];

        // Reconstruct secret key from bytes
        let sk = PqSecretKey::from_bytes(sk_bytes)?;

        let header_json = serde_json::to_vec(&self.header).context("serialize header (aad)")?;

        // Decrypt
        let plaintext =
            crate::pqc::hybrid_decrypt(kyber_ct, classic_ct, &sk.kyber_sk, &header_json)?;

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

        let _sig_overhead = {
            #[cfg(feature = "pqc")]
            { self.pqc_signature.as_ref().map(|s| s.len() + 2).unwrap_or(0) }
            #[cfg(not(feature = "pqc"))]
            { 0usize }
        };
        let mut out = Vec::with_capacity(
            5 + 1 + 4 + header_json.len() + self.ciphertext.len() + _sig_overhead,
        );
        out.extend_from_slice(MAGIC);
        out.push(self.header.version);
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&header_json);

        #[cfg(feature = "pqc")]
        if let Some(sig) = &self.pqc_signature {
            out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            out.extend_from_slice(sig);
        }

        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Parse container from bytes (after stego extraction).
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        if input.len() < 5 + 1 + 4 {
            bail!("Input too short to be a SNOW2 container.");
        }

        let magic = &input[0..5];
        if magic.ct_eq(MAGIC).unwrap_u8() != 1 {
            bail!("Not a SNOW2 container (bad magic).");
        }

        let version = input[5];
        if version != VERSION && version != PQC_VERSION {
            bail!(
                "Unsupported SNOW2 container version: {} (expected {} or {}).",
                version,
                VERSION,
                PQC_VERSION
            );
        }

        let header_len = u32::from_le_bytes(
            input[6..10]
                .try_into()
                .expect("slice length checked"),
        ) as usize;

        // SECURITY: Cap header length to prevent absurdly large JSON
        // allocations from a malicious container. 64 KiB is far more
        // than any legitimate header will ever need.
        const MAX_HEADER_LEN: usize = 64 * 1024;
        if header_len > MAX_HEADER_LEN {
            bail!(
                "Header too large: {} bytes (max {}).",
                header_len,
                MAX_HEADER_LEN
            );
        }

        let header_start = 10;
        let header_end = header_start + header_len;
        if input.len() < header_end {
            bail!("Truncated SNOW2 header.");
        }

        let header_json = &input[header_start..header_end];
        let header: Snow2Header = serde_json::from_slice(header_json).context("parse header")?;

        if header.magic.as_bytes().ct_eq(MAGIC).unwrap_u8() != 1 {
            bail!("Bad header magic.");
        }
        if header.version != version {
            bail!("Header version mismatch.");
        }

        let ciphertext_start = header_end;
        #[cfg(feature = "pqc")]
        let mut ciphertext_start = ciphertext_start;
        #[cfg(feature = "pqc")]
        let mut pqc_signature: Option<Vec<u8>> = None;
        #[cfg(not(feature = "pqc"))]
        let _pqc_signature: Option<Vec<u8>> = None;

        #[cfg(feature = "pqc")]
        if version == PQC_VERSION {
            if input.len() < header_end + 2 {
                bail!("Truncated PQC signature length.");
            }
            let sig_len = u16::from_le_bytes(
                input[header_end..header_end + 2]
                    .try_into()
                    .expect("slice length checked"),
            ) as usize;
            ciphertext_start += 2;
            let sig_end = ciphertext_start + sig_len;
            if input.len() < sig_end {
                bail!("Truncated PQC signature.");
            }
            pqc_signature = Some(input[ciphertext_start..sig_end].to_vec());
            ciphertext_start = sig_end;
        }

        let ciphertext = input[ciphertext_start..].to_vec();
        if ciphertext.is_empty() {
            bail!("Missing ciphertext.");
        }

        Ok(Self {
            header,
            ciphertext,
            #[cfg(feature = "pqc")]
            pqc_signature,
        })
    }
}