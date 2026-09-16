#[cfg(feature = "pqc")]
use crate::pqc::{PqPublicKey, PqSecretKey};
use serde::{Deserialize, Serialize};

use crate::crypto::KdfParams;

/// Security-related options that control how a container is created.
///
/// These are authenticated in the header (directly or indirectly via header fields),
/// so the extractor can enforce the same policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedSecurityOptions {
    /// Argon2id parameters (memory/time/parallelism/output length).
    pub kdf: KdfParams,

    /// If true, a pepper is REQUIRED to decrypt.
    /// (Without it, extraction must fail.)
    pub pepper_required: bool,

    /// If true, use post-quantum hybrid encryption.
    #[cfg(feature = "pqc")]
    pub pqc_enabled: bool,
}

#[cfg(feature = "pqc")]
#[derive(Debug, Default)]
pub struct PqKeys {
    pub pk: Option<PqPublicKey>,
    pub sk: Option<PqSecretKey>,
}

#[derive(Debug, Default)]
pub struct EmbedOptions {
    pub security: EmbedSecurityOptions,
    #[cfg(feature = "pqc")]
    pub pqc_keys: PqKeys,
}

impl EmbedOptions {
    /// Construct from security options alone, leaving feature-gated fields
    /// (`pqc_keys`) at their default.
    ///
    /// Prefer this over `EmbedOptions { security }`: that literal only
    /// compiles when the `pqc` feature is off, which is why the integration
    /// tests would not build under `--features pqc`.
    pub fn new(security: EmbedSecurityOptions) -> Self {
        Self {
            security,
            #[cfg(feature = "pqc")]
            pqc_keys: PqKeys::default(),
        }
    }
}

impl Default for EmbedSecurityOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::recommended(),
            pepper_required: false,
            #[cfg(feature = "pqc")]
            pqc_enabled: false,
        }
    }
}

impl EmbedSecurityOptions {
    /// Construct from the fields that exist in every build configuration.
    ///
    /// Feature-gated fields (`pqc_enabled`) take their default value.  Prefer
    /// this over a struct literal: a literal must name every field that is
    /// currently compiled in, so it stops compiling the moment a `#[cfg]`
    /// field is added or `--features pqc` is toggled.  That is precisely what
    /// broke `cargo test --features pqc`.
    pub fn new(kdf: KdfParams, pepper_required: bool) -> Self {
        Self {
            kdf,
            pepper_required,
            #[cfg(feature = "pqc")]
            pqc_enabled: false,
        }
    }

    /// Convenience: strict mode expects a pepper.
    pub fn strict_with_pepper() -> Self {
        Self {
            pepper_required: true,
            ..Default::default()
        }
    }

    /// Hardened profile: stronger KDF + mandatory pepper.
    ///
    /// Intended for protecting high-value or long-lived secrets where a
    /// few extra seconds of KDF time are acceptable.
    pub fn hardened() -> Self {
        Self {
            kdf: KdfParams::hardened(),
            pepper_required: true,
            #[cfg(feature = "pqc")]
            pqc_enabled: false,
        }
    }
}
