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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PQC_SECRET_KEY_SIZE);
        bytes.extend_from_slice(self.kyber_sk.as_bytes());
        bytes.extend_from_slice(self.dilithium_sk.as_bytes());
        bytes
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

