//! Error types for the vault cryptographic core.

use thiserror::Error;

/// Primary error type returned by vault-core public APIs.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("authentication failed (wrong master password or corrupted vault)")]
    AuthenticationFailed,

    #[error("vault is locked")]
    VaultLocked,

    #[error("vault is already unlocked")]
    VaultAlreadyUnlocked,

    #[error("vault already exists at path")]
    VaultAlreadyExists,

    #[error("vault not found")]
    VaultNotFound,

    #[error("item not found: {0}")]
    ItemNotFound(String),

    #[error("invalid password policy: {0}")]
    InvalidPasswordPolicy(String),

    #[error("secure enclave / OS keystore error: {0}")]
    SecureStore(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<rusqlite::Error> for VaultError {
    fn from(value: rusqlite::Error) -> Self {
        VaultError::Database(value.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(value: serde_json::Error) -> Self {
        VaultError::Serialization(value.to_string())
    }
}

/// Convenient result alias for vault-core.
pub type VaultResult<T> = Result<T, VaultError>;
