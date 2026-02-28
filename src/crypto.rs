use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::secure_mem::SecureVec;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// A key that will be zeroized on drop.
pub type ZeroizingKey = Zeroizing<[u8; 32]>;

// ── Extraction-side KDF safety bounds ─────────────────────────────────────
//
// These constants define the maximum Argon2id parameters an extractor will
// accept from an untrusted container header. Without these bounds, a
// malicious embedder could set m_cost_kib = u32::MAX and force the
// extractor to allocate ~4 TiB of RAM, causing denial-of-service.
//
// The bounds are deliberately generous (well beyond any reasonable
// interactive use-case) so that legitimate containers are never rejected.
// They exist purely to prevent abuse.

/// Maximum Argon2 memory cost accepted during extraction: 512 MiB.
///
/// This is generous enough for any reasonable interactive use-case
/// while preventing practical DoS from hostile containers requesting
/// multi-GiB allocations.
pub const KDF_MAX_M_COST_KIB: u32 = 512 * 1024; // 512 MiB in KiB

/// Maximum Argon2 time cost accepted during extraction: 64 iterations.
pub const KDF_MAX_T_COST: u32 = 64;

/// Maximum Argon2 parallelism accepted during extraction: 16 lanes.
pub const KDF_MAX_P_COST: u32 = 16;

/// The only supported derived-key length. Fixed to 32 bytes
/// (XChaCha20-Poly1305 key size).
pub const KDF_REQUIRED_OUT_LEN: u32 = 32;

/// Minimum Argon2 memory cost: 8 MiB in KiB (prevents trivially weak KDF).
pub const KDF_MIN_M_COST_KIB: u32 = 8 * 1024;

/// Minimum Argon2 time cost: 1 iteration.
pub const KDF_MIN_T_COST: u32 = 1;

/// HKDF info labels for domain-separated key expansion.
const HKDF_LABEL_AEAD_KEY: &[u8] = b"snow2/aead-key";
const HKDF_LABEL_PEPPER_BINDING: &[u8] = b"snow2/pepper-binding";
const HKDF_LABEL_OUTER_KEY: &[u8] = b"snow2/outer-key";

/// Argon2id parameters (authenticated in the container header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub m_cost_kib: u32,
    /// Iterations/time cost.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
    /// Derived key length in bytes.
    pub out_len: u32,
}

impl KdfParams {
    /// Reasonable defaults for interactive use.
    pub fn recommended() -> Self {
        Self {
            m_cost_kib: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 1,
            out_len: 32,
        }
    }

    /// Hardened profile: stronger defaults for high-value secrets.
    ///
    /// Uses more memory and iterations than `recommended()`. Suitable for
    /// protecting long-term secrets where a few extra seconds of KDF time
    /// are acceptable.
    pub fn hardened() -> Self {
        Self {
            m_cost_kib: 256 * 1024, // 256 MiB
            t_cost: 4,
            p_cost: 1,
            out_len: 32,
        }
    }

    /// Validate that these parameters fall within the extraction-side safety
    /// bounds. Returns `Ok(())` if acceptable, or an error describing which
    /// bound was violated.
    ///
    /// This **must** be called before using untrusted KDF parameters read
    /// from a container header.
    pub fn validate_extraction_bounds(&self) -> Result<()> {
        if self.out_len != KDF_REQUIRED_OUT_LEN {
            bail!(
                "Unsupported KDF output length: {} (expected {}).",
                self.out_len,
                KDF_REQUIRED_OUT_LEN
            );
        }
        if self.m_cost_kib > KDF_MAX_M_COST_KIB {
            bail!(
                "KDF memory cost too high: {} KiB (max {} KiB / {} MiB). \
                 This container may be malicious.",
                self.m_cost_kib,
                KDF_MAX_M_COST_KIB,
                KDF_MAX_M_COST_KIB / 1024
            );
        }
        if self.m_cost_kib < KDF_MIN_M_COST_KIB {
            bail!(
                "KDF memory cost too low: {} KiB (min {} KiB / {} MiB). \
                 This container may have been created with dangerously weak settings.",
                self.m_cost_kib,
                KDF_MIN_M_COST_KIB,
                KDF_MIN_M_COST_KIB / 1024
            );
        }
        if self.t_cost > KDF_MAX_T_COST {
            bail!(
                "KDF time cost too high: {} (max {}). \
                 This container may be malicious.",
                self.t_cost,
                KDF_MAX_T_COST
            );
        }
        if self.t_cost < KDF_MIN_T_COST {
            bail!(
                "KDF time cost too low: {} (min {}).",
                self.t_cost,
                KDF_MIN_T_COST
            );
        }
        if self.p_cost > KDF_MAX_P_COST {
            bail!(
                "KDF parallelism too high: {} (max {}). \
                 This container may be malicious.",
                self.p_cost,
                KDF_MAX_P_COST
            );
        }
        if self.p_cost < 1 {
            bail!("KDF parallelism must be at least 1.");
        }
        Ok(())
    }
}

/// Secure random bytes from OS RNG.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).map_err(|e| anyhow!("getrandom failed: {:?}", e))?;
    Ok(out)
}

/// Derive an AEAD key using Argon2id with HKDF domain separation.
///
/// Two-stage derivation:
/// 1. **Argon2id**: derives a 32-byte master secret from `password` + `salt`
/// 2. **HKDF-SHA256 Expand**: domain-separates the master secret into the
///    AEAD key, optionally binding the pepper as HKDF salt.
///
/// This structure avoids ambiguity from concatenating password and pepper
/// directly, and makes each derived key's purpose explicit via HKDF labels.
///
/// # Arguments
///
/// - `password` — user-supplied password (must not be empty)
/// - `pepper` — optional second secret ("signal key"), not stored in the container
/// - `salt` — per-message random salt (at least 8 bytes)
/// - `params` — Argon2id tuning parameters
pub fn derive_key(
    password: &[u8],
    pepper: Option<&[u8]>,
    salt: &[u8],
    params: &KdfParams,
) -> Result<ZeroizingKey> {
    let master = derive_master_secret(password, salt, params)?;
    hkdf_expand_key(&master, pepper, HKDF_LABEL_AEAD_KEY)
}

/// Derive both inner AEAD key and outer AEAD key from a single Argon2id run.
///
/// Returns `(inner_key, outer_key)`.  Both keys pay the full Argon2 cost,
/// preventing the outer layer from being a cheap password oracle.
pub fn derive_key_pair(
    password: &[u8],
    pepper: Option<&[u8]>,
    salt: &[u8],
    params: &KdfParams,
) -> Result<(ZeroizingKey, ZeroizingKey)> {
    let master = derive_master_secret(password, salt, params)?;
    let inner = hkdf_expand_key(&master, pepper, HKDF_LABEL_AEAD_KEY)?;
    // Outer key is password-only (no pepper binding).  This ensures that
    // extraction can always decrypt the outer layer before seeing the
    // container's pepper_required flag, producing a clear error message
    // when pepper is missing instead of a generic AEAD failure.
    let outer = hkdf_expand_key(&master, None, HKDF_LABEL_OUTER_KEY)?;
    Ok((inner, outer))
}

/// Derive only the outer key from a pre-computed Argon2 master secret.
///
/// The outer key is password-only (no pepper binding).  This lets the
/// extraction pipeline decrypt the outer layer without knowing the pepper,
/// inspect the container's `pepper_required` flag, and produce a clear
/// error message when the pepper is missing.
pub fn derive_outer_key_from_master(
    master: &Zeroizing<[u8; 32]>,
) -> Result<ZeroizingKey> {
    hkdf_expand_key(master, None, HKDF_LABEL_OUTER_KEY)
}

/// Derive only the inner key from a pre-computed Argon2 master secret.
pub fn derive_inner_key_from_master(
    master: &Zeroizing<[u8; 32]>,
    pepper: Option<&[u8]>,
) -> Result<ZeroizingKey> {
    hkdf_expand_key(master, pepper, HKDF_LABEL_AEAD_KEY)
}

/// Stage 1: Argon2id(password, salt) → 32-byte master secret.
pub fn derive_master_secret(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    if password.is_empty() {
        bail!("Password must not be empty.");
    }
    if salt.len() < 8 {
        bail!("Salt too short.");
    }
    if params.out_len != 32 {
        bail!("Unsupported out_len {} (expected 32).", params.out_len);
    }

    let out_len_usize: usize = params
        .out_len
        .try_into()
        .map_err(|_| anyhow!("out_len does not fit usize: {}", params.out_len))?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(out_len_usize),
    )
    .map_err(|e| anyhow!("invalid Argon2 params: {:?}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut master_secret = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, &mut *master_secret)
        .map_err(|e| anyhow!("Argon2id derive failed: {:?}", e))?;

    Ok(master_secret)
}

/// Stage 2: HKDF-SHA256 domain-separated expansion from master secret.
fn hkdf_expand_key(
    master_secret: &Zeroizing<[u8; 32]>,
    pepper: Option<&[u8]>,
    label: &[u8],
) -> Result<ZeroizingKey> {
    // HKDF salt = pepper (if present), binding the pepper cryptographically
    // without concatenation ambiguity.
    // HKDF IKM  = master_secret from Argon2id
    // HKDF info = domain label
    //
    // If pepper is provided, we also mix in a pepper-binding label to create
    // a truly distinct derivation path.
    let hkdf_salt = pepper.unwrap_or(b"");
    let hkdf_info = if pepper.is_some() {
        let mut info = Vec::with_capacity(label.len() + HKDF_LABEL_PEPPER_BINDING.len());
        info.extend_from_slice(label);
        info.extend_from_slice(HKDF_LABEL_PEPPER_BINDING);
        info
    } else {
        label.to_vec()
    };

    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), master_secret.as_ref());
    let mut key = ZeroizingKey::new([0u8; 32]);
    hk.expand(&hkdf_info, &mut *key)
        .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;

    Ok(key)
}

/// AEAD seal using XChaCha20-Poly1305.
pub fn aead_seal(
    key: &ZeroizingKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != 24 {
        bail!("Invalid nonce length: {} (expected 24).", nonce.len());
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let n = XNonce::from_slice(nonce);

    let ct = cipher
        .encrypt(n, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow!("AEAD encrypt failed: {:?}", e))?;

    Ok(ct)
}

/// AEAD open using XChaCha20-Poly1305.
pub fn aead_open(
    key: &ZeroizingKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecureVec> {
    if nonce.len() != 24 {
        bail!("Invalid nonce length: {} (expected 24).", nonce.len());
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let n = XNonce::from_slice(nonce);

    let mut pt = cipher
        .decrypt(n, Payload { msg: ciphertext, aad })
        .map_err(|e| {
            anyhow!(
                "AEAD decrypt/auth failed (wrong key, wrong pepper, or modified carrier): {:?}",
                e
            )
        })?;
    let sv = SecureVec::from_slice(&pt);
    // Zeroize the intermediate Vec to avoid leaving plaintext in unlocked memory.
    pt.zeroize();
    sv
}

// ── Outer encryption layer ───────────────────────────────────────────────
//
// The outer layer makes the entire embedded bitstream indistinguishable
// from uniformly random bytes. This defeats byte-distribution and
// entropy-based steganalysis.
//
// Key derivation: Both inner and outer keys are derived from a single
// Argon2id master secret via HKDF with distinct domain labels.  This
// prevents the outer layer from being a cheap password oracle.
//
// Wire format: salt(16) || nonce(24) || ciphertext+tag
//
// The salt is stored in the clear (standard practice — salts are not
// secret).  During extraction, the salt is read first so Argon2 runs
// only once, then outer decryption is tried for each candidate bucket
// size (cheap XChaCha20 operations).
//
// Cipher: XChaCha20-Poly1305 (same as inner, independent key).

/// Outer AEAD overhead: 16-byte salt + 24-byte nonce + 16-byte AEAD tag = 56.
pub const OUTER_OVERHEAD: usize = 16 + 24 + 16;

/// Outer AEAD seal: encrypt + authenticate with Argon2-derived outer key.
/// Returns `salt(16) || nonce(24) || ciphertext+tag`.
///
/// The outer key is derived from the same Argon2 master secret as the
/// inner key, using a different HKDF domain label ("snow2/outer-key").
pub fn outer_seal(
    password: &[u8],
    pepper: Option<&[u8]>,
    salt: &[u8],
    params: &KdfParams,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (_inner, outer_key) = derive_key_pair(password, pepper, salt, params)?;
    let nonce_bytes = random_bytes(24)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(outer_key.as_ref()));
    let n = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(n, Payload { msg: plaintext, aad: b"" })
        .map_err(|e| anyhow!("Outer AEAD encrypt failed: {:?}", e))?;

    let mut out = Vec::with_capacity(16 + 24 + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Outer AEAD seal using a pre-computed outer key (avoids double Argon2).
/// Returns `salt(16) || nonce(24) || ciphertext+tag`.
pub fn outer_seal_with_key(
    outer_key: &ZeroizingKey,
    salt: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce_bytes = random_bytes(24)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(outer_key.as_ref()));
    let n = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(n, Payload { msg: plaintext, aad: b"" })
        .map_err(|e| anyhow!("Outer AEAD encrypt failed: {:?}", e))?;

    let mut out = Vec::with_capacity(16 + 24 + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Outer AEAD open: split salt + nonce, decrypt + verify.
/// Input: `salt(16) || nonce(24) || ciphertext+tag`.
/// Returns plaintext on success, error on failure (wrong password or corruption).
pub fn outer_open(outer_key: &ZeroizingKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < OUTER_OVERHEAD {
        bail!("Outer blob too short ({} bytes, need at least {}).", blob.len(), OUTER_OVERHEAD);
    }
    // salt is bytes [0..16] — already used by caller to derive the key
    let nonce = &blob[16..40];
    let ct = &blob[40..];

    let cipher = XChaCha20Poly1305::new(Key::from_slice(outer_key.as_ref()));
    let n = XNonce::from_slice(nonce);

    let pt = cipher
        .decrypt(n, Payload { msg: ct, aad: b"" })
        .map_err(|_| {
            anyhow!("Outer decryption failed (wrong password or no hidden message).")
        })?;

    Ok(pt)
}

/// Extract the 16-byte Argon2 salt from the beginning of a v4 outer blob.
/// Returns `None` if the blob is too short.
pub fn outer_extract_salt(blob: &[u8]) -> Option<&[u8]> {
    if blob.len() >= OUTER_OVERHEAD {
        Some(&blob[..16])
    } else {
        None
    }
}