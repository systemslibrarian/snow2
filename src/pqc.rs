//! Post-Quantum Cryptography additions for SNOW2.
//!
//! This module implements hybrid encryption and signing using Kyber1024 and
//! Dilithium5, respectively. This is provided as an optional feature flag `pqc`.
//!
//! The container format is extended to support post-quantum keys and signatures.

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::{
    kem::{
        Ciphertext as KemCiphertext, PublicKey as KemPublicKey,
        SecretKey as KemSecretKey, SharedSecret as KemSharedSecret,
    },
    sign::{
        DetachedSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey,
    },
};
use sha2::Sha256;

use crate::crypto::ZeroizingKey;
use crate::secure_mem::SecureVec;

// Re-export for convenience in other modules
pub use pqcrypto_dilithium::dilithium5::{
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
pub use pqcrypto_kyber::kyber1024::{
    Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
};

pub const KYBER_PUBLIC_KEY_SIZE: usize = kyber1024::public_key_bytes();
pub const DILITHIUM_PUBLIC_KEY_SIZE: usize = dilithium5::public_key_bytes();
pub const PQC_PUBLIC_KEY_SIZE: usize = KYBER_PUBLIC_KEY_SIZE + DILITHIUM_PUBLIC_KEY_SIZE;

pub const KYBER_SECRET_KEY_SIZE: usize = kyber1024::secret_key_bytes();
pub const DILITHIUM_SECRET_KEY_SIZE: usize = dilithium5::secret_key_bytes();
pub const PQC_SECRET_KEY_SIZE: usize = KYBER_SECRET_KEY_SIZE + DILITHIUM_SECRET_KEY_SIZE;

/// A container for a post-quantum public key.
pub struct PqPublicKey {
    pub(crate) kyber_pk: KyberPublicKey,
    pub(crate) dilithium_pk: DilithiumPublicKey,
}

impl std::fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqPublicKey").finish_non_exhaustive()
    }
}

impl PqPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PQC_PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "Invalid PQC public key length: got {}, expected {}",
                bytes.len(),
                PQC_PUBLIC_KEY_SIZE
            ));
        }
        let (kyber_bytes, dilithium_bytes) = bytes.split_at(KYBER_PUBLIC_KEY_SIZE);
        Ok(Self {
            kyber_pk: KemPublicKey::from_bytes(kyber_bytes)
                .map_err(|_| anyhow!("Invalid Kyber public key bytes"))?,
            dilithium_pk: SignPublicKey::from_bytes(dilithium_bytes)
                .map_err(|_| anyhow!("Invalid Dilithium public key bytes"))?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PQC_PUBLIC_KEY_SIZE);
        bytes.extend_from_slice(self.kyber_pk.as_bytes());
        bytes.extend_from_slice(self.dilithium_pk.as_bytes());
        bytes
    }
}

/// Magic bytes for encrypted PQC secret key files.
///
/// Format (v1): `[SNOW2EK\0 (8)][version (1)][salt (16)][nonce (24)][AEAD ciphertext]`
///
/// Legacy (v0): `[SNOW2EK\0 (8)][salt (16)][nonce (24)][AEAD ciphertext]`
/// (no version byte — salt starts immediately after magic)
const ENCRYPTED_SK_MAGIC: &[u8; 8] = b"SNOW2EK\0";

/// Current encrypted-SK format version.
const ENCRYPTED_SK_VERSION: u8 = 1;

/// A container for a post-quantum secret key.
pub struct PqSecretKey {
    pub(crate) kyber_sk: KyberSecretKey,
    pub(crate) dilithium_sk: DilithiumSecretKey,
}

impl std::fmt::Debug for PqSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqSecretKey").finish_non_exhaustive()
    }
}

impl PqSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PQC_SECRET_KEY_SIZE {
            return Err(anyhow!(
                "Invalid PQC secret key length: got {}, expected {}",
                bytes.len(),
                PQC_SECRET_KEY_SIZE
            ));
        }
        let (kyber_bytes, dilithium_bytes) = bytes.split_at(KYBER_SECRET_KEY_SIZE);
        Ok(Self {
            kyber_sk: KemSecretKey::from_bytes(kyber_bytes)
                .map_err(|_| anyhow!("Invalid Kyber secret key bytes"))?,
            dilithium_sk: SignSecretKey::from_bytes(dilithium_bytes)
                .map_err(|_| anyhow!("Invalid Dilithium secret key bytes"))?,
        })
    }

    /// Serialize the secret key to bytes.
    ///
    /// **WARNING**: The caller is responsible for zeroizing the returned Vec
    /// when done. Prefer `to_zeroizing_bytes()` to get auto-zeroizing output.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PQC_SECRET_KEY_SIZE);
        bytes.extend_from_slice(self.kyber_sk.as_bytes());
        bytes.extend_from_slice(self.dilithium_sk.as_bytes());
        bytes
    }

    /// Serialize the secret key to a zeroize-on-drop buffer.
    pub fn to_zeroizing_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.to_bytes())
    }

    /// Encrypt the secret key with a password for secure on-disk storage.
    ///
    /// Uses Argon2id key derivation + XChaCha20-Poly1305 AEAD.
    ///
    /// Output format (v1): `[SNOW2EK\0 (8)][version=1 (1)][salt (16)][nonce (24)][ciphertext+tag]`
    pub fn encrypt(&self, password: &[u8]) -> Result<Vec<u8>> {
        use zeroize::Zeroize;

        let salt = crate::crypto::random_bytes(16)?;
        let kdf = crate::crypto::KdfParams::recommended();
        let key = crate::crypto::derive_key(password, None, &salt, &kdf)?;

        let nonce = crate::crypto::random_bytes(24)?;
        let mut plaintext = self.to_bytes();
        // AAD includes magic + version so downgrade attacks are detected.
        let mut aad = Vec::with_capacity(9);
        aad.extend_from_slice(ENCRYPTED_SK_MAGIC);
        aad.push(ENCRYPTED_SK_VERSION);
        let ciphertext =
            crate::crypto::aead_seal(&key, &nonce, &aad, &plaintext)?;
        // Zeroize the plaintext secret key bytes immediately after encryption.
        plaintext.zeroize();

        let mut out = Vec::with_capacity(8 + 1 + 16 + 24 + ciphertext.len());
        out.extend_from_slice(ENCRYPTED_SK_MAGIC);
        out.push(ENCRYPTED_SK_VERSION);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt an encrypted secret key file.
    ///
    /// Supports both v1 (versioned) and legacy v0 (un-versioned) formats.
    pub fn decrypt(encrypted: &[u8], password: &[u8]) -> Result<Self> {
        if encrypted.len() < 8 + 1 + 16 + 24 {
            return Err(anyhow!("Encrypted key file too short."));
        }

        let magic = &encrypted[0..8];
        if magic != ENCRYPTED_SK_MAGIC {
            return Err(anyhow!(
                "Not an encrypted SNOW2 secret key (bad magic). Is this an unencrypted key?"
            ));
        }

        let version = encrypted[8];
        let (salt, nonce, ciphertext, aad) = match version {
            ENCRYPTED_SK_VERSION => {
                // v1: [magic(8)][version(1)][salt(16)][nonce(24)][ct]
                let salt = &encrypted[9..25];
                let nonce = &encrypted[25..49];
                let ct = &encrypted[49..];
                let mut aad = Vec::with_capacity(9);
                aad.extend_from_slice(ENCRYPTED_SK_MAGIC);
                aad.push(ENCRYPTED_SK_VERSION);
                (salt, nonce, ct, aad)
            }
            _ => {
                return Err(anyhow!(
                    "Unsupported encrypted SK version: {}. \
                     You may need a newer version of snow2.",
                    version
                ));
            }
        };

        let kdf = crate::crypto::KdfParams::recommended();
        let key = crate::crypto::derive_key(password, None, salt, &kdf)?;

        let plaintext =
            crate::crypto::aead_open(&key, nonce, &aad, ciphertext)?;

        Self::from_bytes(&plaintext)
    }

    /// Load a secret key file, auto-detecting encrypted vs unencrypted format.
    ///
    /// If the file starts with the `SNOW2EK\0` magic, it is treated as encrypted
    /// and `password` is required. Otherwise, the raw bytes are parsed directly.
    pub fn load(bytes: &[u8], password: Option<&[u8]>) -> Result<Self> {
        if bytes.len() >= 8 && bytes[0..8] == *ENCRYPTED_SK_MAGIC {
            let password = password.ok_or_else(|| {
                anyhow!("Secret key is encrypted; a password is required (--sk-password).")
            })?;
            Self::decrypt(bytes, password)
        } else {
            Self::from_bytes(bytes)
        }
    }

    /// Check whether a byte slice looks like an encrypted secret key file.
    pub fn is_encrypted(bytes: &[u8]) -> bool {
        bytes.len() >= 8 && bytes[0..8] == *ENCRYPTED_SK_MAGIC
    }
}

/// Generate a new post-quantum keypair.
pub fn keypair() -> (PqPublicKey, PqSecretKey) {
    let (kyber_pk, kyber_sk) = kyber1024::keypair();
    let (dilithium_pk, dilithium_sk) = dilithium5::keypair();

    (
        PqPublicKey {
            kyber_pk,
            dilithium_pk,
        },
        PqSecretKey {
            kyber_sk,
            dilithium_sk,
        },
    )
}

/// Hybrid encryption: Kyber1024 + XChaCha20.
///
/// The `shared_secret` from Kyber is used as input to an HKDF to derive the
/// XChaCha20 key.
pub fn hybrid_encrypt(
    plaintext: &[u8],
    kyber_pk: &KyberPublicKey,
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (shared_secret, ciphertext) = kyber1024::encapsulate(kyber_pk);

    // Derive a classic key from the Kyber shared secret.
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = ZeroizingKey::new([0u8; 32]);
    hk.expand(b"snow2-kyber-xchacha20", &mut *okm)
        .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;

    let nonce = crate::crypto::random_bytes(24)?;
    let classic_ciphertext = crate::crypto::aead_seal(&okm, &nonce, aad, plaintext)?;

    // Prepend nonce to ciphertext
    let mut final_ciphertext = Vec::with_capacity(nonce.len() + classic_ciphertext.len());
    final_ciphertext.extend_from_slice(&nonce);
    final_ciphertext.extend_from_slice(&classic_ciphertext);

    Ok((ciphertext.as_bytes().to_vec(), final_ciphertext))
}

/// Hybrid decryption.
pub fn hybrid_decrypt(
    kyber_ciphertext: &[u8],
    classic_ciphertext_with_nonce: &[u8],
    kyber_sk: &KyberSecretKey,
    aad: &[u8],
) -> Result<SecureVec> {
    let shared_secret = kyber1024::decapsulate(
        &KemCiphertext::from_bytes(kyber_ciphertext)
            .map_err(|_| anyhow!("Invalid Kyber ciphertext length"))?,
        kyber_sk,
    );

    // Derive the classic key
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = ZeroizingKey::new([0u8; 32]);
    hk.expand(b"snow2-kyber-xchacha20", &mut *okm)
        .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;

    // Extract nonce
    if classic_ciphertext_with_nonce.len() < 24 {
        return Err(anyhow!("Ciphertext too short to contain a nonce."));
    }
    let (nonce, classic_ciphertext) = classic_ciphertext_with_nonce.split_at(24);

    crate::crypto::aead_open(&okm, nonce, aad, classic_ciphertext)
}

/// Sign a message with Dilithium5.
pub fn sign(message: &[u8], sk: &DilithiumSecretKey) -> impl DetachedSignature {
    dilithium5::detached_sign(message, sk)
}

/// Verify a Dilithium5 signature.
pub fn verify(message: &[u8], signature_bytes: &[u8], pk: &DilithiumPublicKey) -> Result<()> {
    let signature = dilithium5::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| anyhow!("Invalid Dilithium signature length"))?;
    dilithium5::verify_detached_signature(&signature, message, pk)
        .map_err(|_| anyhow!("Dilithium verification failed"))
}

