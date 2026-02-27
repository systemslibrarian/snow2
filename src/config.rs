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
}

impl Default for EmbedSecurityOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::recommended(),
            pepper_required: false,
        }
    }
}

impl EmbedSecurityOptions {
    /// Convenience: strict mode expects a pepper.
    pub fn strict_with_pepper() -> Self {
        Self {
            kdf: KdfParams::recommended(),
            pepper_required: true,
        }
    }
}