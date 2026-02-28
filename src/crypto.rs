use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use crate::secure_mem::SecureVec;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroizing};

/// A key that will be zeroized on drop.
pub type ZeroizingKey = Zeroizing<[u8; 32]>;

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
    /// Reasonable defaults for interactive use in 2026.
    pub fn recommended() -> Self {
        Self {
            // 64 MiB
            m_cost_kib: 64 * 1024,
            // 3 iterations
            t_cost: 3,
            // 1 lane
            p_cost: 1,
            // 32 bytes for XChaCha20-Poly1305 key
            out_len: 32,
        }
    }
}

/// Secure random bytes from OS RNG.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).map_err(|e| anyhow!("getrandom failed: {:?}", e))?;
    Ok(out)
}

/// Derive an AEAD key using Argon2id from:
/// - password (required)
/// - optional pepper (not stored; extra "Signal Key")
/// - salt (per-message random)
pub fn derive_key(
    password: &[u8],
    pepper: Option<&[u8]>,
    salt: &[u8],
    params: &KdfParams,
) -> Result<ZeroizingKey> {
    if password.is_empty() {
        bail!("Password must not be empty.");
    }
    if salt.len() < 8 {
        bail!("Salt too short.");
    }
    if params.out_len != 32 {
        bail!("Unsupported out_len {} (expected 32).", params.out_len);
    }

    // password || 0x00 || pepper (if present)
    let mut pw = Zeroizing::new(Vec::with_capacity(
        password.len() + 1 + pepper.map(|p| p.len()).unwrap_or(0),
    ));
    pw.extend_from_slice(password);
    pw.push(0u8);
    if let Some(p) = pepper {
        pw.extend_from_slice(p);
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

    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(&pw, salt, &mut *out)
        .map_err(|e| anyhow!("Argon2id derive failed: {:?}", e))?;

    Ok(out)
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

    let pt = cipher
        .decrypt(n, Payload { msg: ciphertext, aad })
        .map_err(|e| {
            anyhow!(
                "AEAD decrypt/auth failed (wrong key, wrong pepper, or modified carrier): {:?}",
                e
            )
        })?;
    SecureVec::from_slice(&pt)
}