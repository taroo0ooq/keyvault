//! Argon2id key derivation (zero-knowledge master key).
//!
//! Parameters (mandatory product policy):
//! - Memory: 64 MiB
//! - Iterations (time cost): 3
//! - Parallelism: 4
//! - Output: 32-byte Master Key (MK)

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};

/// Argon2id memory cost in kibibytes (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id time cost (iterations).
pub const ARGON2_ITERATIONS: u32 = 3;
/// Argon2id parallelism (lanes).
pub const ARGON2_PARALLELISM: u32 = 4;
/// Derived master key length in bytes.
pub const MASTER_KEY_LEN: usize = 32;
/// Salt length in bytes (128-bit).
pub const SALT_LEN: usize = 16;

/// 32-byte master key material. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_LEN],
}

impl MasterKey {
    /// Wrap existing key bytes (must be exactly 32 bytes of high-entropy material).
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw key bytes. Callers must not copy out of this slice into
    /// long-lived plaintext storage.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.bytes
    }

    /// Constant-time equality check.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// Parameters used to re-derive the master key for unlock.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Create product-default Argon2id parameters with a fresh random salt.
    pub fn generate() -> VaultResult<Self> {
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Ok(Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
            salt,
        })
    }

    fn argon2(&self) -> VaultResult<Argon2<'static>> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(MASTER_KEY_LEN),
        )
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Derive a 32-byte master key from the master password using Argon2id.
///
/// The master password is never logged and is only used as a temporary input
/// buffer for the KDF. Prefer clearing caller-owned password buffers after use.
pub fn derive_master_key(password: &str, params: &KdfParams) -> VaultResult<MasterKey> {
    if password.is_empty() {
        return Err(VaultError::InvalidInput(
            "master password must not be empty".into(),
        ));
    }
    if params.salt.len() < 8 {
        return Err(VaultError::KeyDerivation(
            "salt must be at least 8 bytes".into(),
        ));
    }

    let argon2 = params.argon2()?;
    let salt = SaltString::encode_b64(&params.salt)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let hash = password_hash
        .hash
        .ok_or_else(|| VaultError::KeyDerivation("argon2 produced empty hash".into()))?;

    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() < MASTER_KEY_LEN {
        return Err(VaultError::KeyDerivation(format!(
            "argon2 output too short: {}",
            hash_bytes.len()
        )));
    }

    let mut key = [0u8; MASTER_KEY_LEN];
    key.copy_from_slice(&hash_bytes[..MASTER_KEY_LEN]);
    Ok(MasterKey::from_bytes(key))
}

/// Derive a key and return both the key and the params (for vault creation).
pub fn derive_master_key_with_fresh_params(password: &str) -> VaultResult<(MasterKey, KdfParams)> {
    let params = KdfParams::generate()?;
    let key = derive_master_key(password, &params)?;
    Ok((key, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_salt() {
        let params = KdfParams {
            memory_kib: 8 * 1024, // faster for unit tests
            iterations: 1,
            parallelism: 1,
            salt: b"fixed-salt-16b!!".to_vec(),
        };
        let a = derive_master_key("correct horse battery staple", &params).unwrap();
        let b = derive_master_key("correct horse battery staple", &params).unwrap();
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn different_passwords_yield_different_keys() {
        let params = KdfParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
            salt: b"fixed-salt-16b!!".to_vec(),
        };
        let a = derive_master_key("password-one", &params).unwrap();
        let b = derive_master_key("password-two", &params).unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn different_salts_yield_different_keys() {
        let mut p1 = KdfParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
            salt: b"aaaaaaaaaaaaaaaa".to_vec(),
        };
        let mut p2 = p1.clone();
        p2.salt = b"bbbbbbbbbbbbbbbb".to_vec();
        let a = derive_master_key("same-password", &p1).unwrap();
        let b = derive_master_key("same-password", &p2).unwrap();
        assert!(!a.ct_eq(&b));
        p1.salt.zeroize();
        p2.salt.zeroize();
    }

    #[test]
    fn empty_password_rejected() {
        let params = KdfParams::generate().unwrap();
        assert!(matches!(
            derive_master_key("", &params),
            Err(VaultError::InvalidInput(_))
        ));
    }

    #[test]
    fn master_key_debug_redacts() {
        let key = MasterKey::from_bytes([0xAB; 32]);
        let s = format!("{:?}", key);
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("AB"));
    }

    #[test]
    fn generate_params_use_product_defaults() {
        let p = KdfParams::generate().unwrap();
        assert_eq!(p.memory_kib, ARGON2_MEMORY_KIB);
        assert_eq!(p.iterations, ARGON2_ITERATIONS);
        assert_eq!(p.parallelism, ARGON2_PARALLELISM);
        assert_eq!(p.salt.len(), SALT_LEN);
    }
}
