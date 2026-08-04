//! # vault-core
//!
//! Zero-knowledge cryptographic engine and encrypted vault backend for KeyVault.
//!
//! ## Security properties
//!
//! - Master password → **Argon2id** (64 MiB, t=3, p=4) → Master Key (MK)
//! - Record encryption: **AES-256-GCM** or **XChaCha20-Poly1305** with unique IV
//! - Sensitive key material is **zeroized** on drop
//! - Platform secure-key wrappers (DPAPI / Keychain / KeyStore bridges)
//! - Local SQL schema designed for SQLCipher; fields encrypted under MK
//!
//! UI layers (Tauri / Flutter / extensions) must only talk to this crate via
//! FFI or the local vault daemon — never reimplement crypto in JS/Dart.

#![deny(unsafe_op_in_unsafe_fn)]
// Public API is documented at the module and primary type level; field-level
// docs are expanded as the FFI surface stabilizes in Phase 2.
#![allow(missing_docs)]

pub mod error;
pub mod kdf;
pub mod password;
pub mod secure_key;
pub mod vault_crypto;
pub mod vault_db;

pub use error::{VaultError, VaultResult};
pub use kdf::{
    derive_master_key, derive_master_key_with_fresh_params, KdfParams, MasterKey, ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, MASTER_KEY_LEN,
};
pub use password::{
    generate_password, score_password, EntropyScore, PasswordPolicy, MAX_PASSWORD_LEN,
    MIN_PASSWORD_LEN,
};
pub use secure_key::{
    protect_account_key, protect_key, unprotect_account_key, unprotect_key, AccountKey,
    BiometricUnlock, WrappedKeyBlob,
};
pub use vault_crypto::{
    create_key_verifier, decrypt, encrypt, unwrap_key, verify_master_key, wrap_key, CipherAlgorithm,
    DEFAULT_CIPHER, ENVELOPE_VERSION,
};
pub use vault_db::{Vault, VaultItem, SCHEMA_SQL, SCHEMA_VERSION};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library health probe used by the daemon and CI.
pub fn health_check() -> HealthStatus {
    HealthStatus {
        ok: true,
        version: VERSION,
        schema_version: SCHEMA_VERSION,
        argon2_memory_kib: ARGON2_MEMORY_KIB,
        argon2_iterations: ARGON2_ITERATIONS,
        argon2_parallelism: ARGON2_PARALLELISM,
        default_cipher: format!("{DEFAULT_CIPHER:?}"),
    }
}

/// Serializable health payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    /// Always true when the library loaded successfully.
    pub ok: bool,
    /// Crate semver.
    pub version: &'static str,
    /// Vault SQL schema version.
    pub schema_version: i32,
    /// Argon2 memory parameter (KiB).
    pub argon2_memory_kib: u32,
    /// Argon2 time cost.
    pub argon2_iterations: u32,
    /// Argon2 parallelism.
    pub argon2_parallelism: u32,
    /// Default AEAD algorithm name.
    pub default_cipher: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok() {
        let h = health_check();
        assert!(h.ok);
        assert_eq!(h.argon2_memory_kib, 64 * 1024);
        assert_eq!(h.argon2_iterations, 3);
        assert_eq!(h.argon2_parallelism, 4);
    }
}
