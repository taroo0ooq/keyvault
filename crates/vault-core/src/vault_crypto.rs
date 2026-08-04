//! Record-level vault encryption: AES-256-GCM and XChaCha20-Poly1305.
//!
//! Each record uses a unique nonce/IV. Ciphertext layout:
//!   `version (1) || algorithm (1) || nonce (N) || ciphertext+tag`

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{VaultError, VaultResult};
use crate::kdf::{MasterKey, MASTER_KEY_LEN};

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Supported AEAD algorithms for vault records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CipherAlgorithm {
    Aes256Gcm = 1,
    XChaCha20Poly1305 = 2,
}

impl CipherAlgorithm {
    pub fn from_u8(v: u8) -> VaultResult<Self> {
        match v {
            1 => Ok(Self::Aes256Gcm),
            2 => Ok(Self::XChaCha20Poly1305),
            _ => Err(VaultError::Crypto(format!("unknown algorithm id {v}"))),
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }
}

/// Default product cipher for new records.
pub const DEFAULT_CIPHER: CipherAlgorithm = CipherAlgorithm::Aes256Gcm;

/// Encrypt plaintext under the master key with a unique random nonce.
///
/// Optional associated data (`aad`) is authenticated but not encrypted
/// (e.g. record UUID, schema version).
pub fn encrypt(
    key: &MasterKey,
    plaintext: &[u8],
    aad: &[u8],
    algorithm: CipherAlgorithm,
) -> VaultResult<Vec<u8>> {
    let mut nonce = vec![0u8; algorithm.nonce_len()];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = match algorithm {
        CipherAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            let n = AesNonce::from_slice(&nonce);
            cipher
                .encrypt(
                    n,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::Crypto("AES-GCM encrypt failed".into()))?
        }
        CipherAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            let n = XNonce::from_slice(&nonce);
            cipher
                .encrypt(
                    n,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::Crypto("XChaCha20-Poly1305 encrypt failed".into()))?
        }
    };

    let mut out = Vec::with_capacity(2 + nonce.len() + ciphertext.len());
    out.push(ENVELOPE_VERSION);
    out.push(algorithm as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    nonce.zeroize();
    Ok(out)
}

/// Decrypt an envelope produced by [`encrypt`].
pub fn decrypt(key: &MasterKey, envelope: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>> {
    if envelope.len() < 2 + 12 + 16 {
        return Err(VaultError::Crypto("envelope too short".into()));
    }
    let version = envelope[0];
    if version != ENVELOPE_VERSION {
        return Err(VaultError::Crypto(format!(
            "unsupported envelope version {version}"
        )));
    }
    let algorithm = CipherAlgorithm::from_u8(envelope[1])?;
    let nonce_len = algorithm.nonce_len();
    let header = 2 + nonce_len;
    if envelope.len() < header + 16 {
        return Err(VaultError::Crypto("envelope truncated".into()));
    }
    let nonce = &envelope[2..header];
    let ciphertext = &envelope[header..];

    let plaintext = match algorithm {
        CipherAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            let n = AesNonce::from_slice(nonce);
            cipher
                .decrypt(
                    n,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::AuthenticationFailed)?
        }
        CipherAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            let n = XNonce::from_slice(nonce);
            cipher
                .decrypt(
                    n,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::AuthenticationFailed)?
        }
    };

    Ok(plaintext)
}

/// Derive a verifier blob used to validate the master password without
/// storing the master key. Encrypts a fixed magic under MK.
const VERIFIER_MAGIC: &[u8] = b"KEYVAULT_MK_VERIFY_V1";

pub fn create_key_verifier(key: &MasterKey) -> VaultResult<Vec<u8>> {
    encrypt(key, VERIFIER_MAGIC, b"verifier", DEFAULT_CIPHER)
}

pub fn verify_master_key(key: &MasterKey, verifier: &[u8]) -> VaultResult<()> {
    let plain = decrypt(key, verifier, b"verifier")?;
    if plain.as_slice() != VERIFIER_MAGIC {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(())
}

/// Wrap an account key (AK) under the master key for biometric/PIN unlock path.
pub fn wrap_key(wrapping_key: &MasterKey, key_to_wrap: &[u8; MASTER_KEY_LEN]) -> VaultResult<Vec<u8>> {
    encrypt(
        wrapping_key,
        key_to_wrap,
        b"wrapped-key",
        DEFAULT_CIPHER,
    )
}

pub fn unwrap_key(
    wrapping_key: &MasterKey,
    wrapped: &[u8],
) -> VaultResult<[u8; MASTER_KEY_LEN]> {
    let plain = decrypt(wrapping_key, wrapped, b"wrapped-key")?;
    if plain.len() != MASTER_KEY_LEN {
        return Err(VaultError::Crypto("unwrapped key wrong length".into()));
    }
    let mut out = [0u8; MASTER_KEY_LEN];
    out.copy_from_slice(&plain);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MasterKey;

    fn test_key() -> MasterKey {
        MasterKey::from_bytes([0x42; 32])
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = test_key();
        let pt = b"secret password entry";
        let ct = encrypt(&key, pt, b"item-1", CipherAlgorithm::Aes256Gcm).unwrap();
        let out = decrypt(&key, &ct, b"item-1").unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn xchacha_roundtrip() {
        let key = test_key();
        let pt = b"another secret";
        let ct = encrypt(&key, pt, b"aad", CipherAlgorithm::XChaCha20Poly1305).unwrap();
        let out = decrypt(&key, &ct, b"aad").unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn unique_nonce_per_encrypt() {
        let key = test_key();
        let a = encrypt(&key, b"same", b"", DEFAULT_CIPHER).unwrap();
        let b = encrypt(&key, b"same", b"", DEFAULT_CIPHER).unwrap();
        assert_ne!(a, b, "ciphertexts must differ due to random nonces");
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let other = MasterKey::from_bytes([0x99; 32]);
        let ct = encrypt(&key, b"data", b"", DEFAULT_CIPHER).unwrap();
        assert!(matches!(
            decrypt(&other, &ct, b""),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let ct = encrypt(&key, b"data", b"aad-a", DEFAULT_CIPHER).unwrap();
        assert!(matches!(
            decrypt(&key, &ct, b"aad-b"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn verifier_roundtrip() {
        let key = test_key();
        let v = create_key_verifier(&key).unwrap();
        assert!(verify_master_key(&key, &v).is_ok());
        let bad = MasterKey::from_bytes([1; 32]);
        assert!(verify_master_key(&bad, &v).is_err());
    }

    #[test]
    fn wrap_unwrap_account_key() {
        let mk = test_key();
        let ak = [0x77u8; 32];
        let wrapped = wrap_key(&mk, &ak).unwrap();
        let unwrapped = unwrap_key(&mk, &wrapped).unwrap();
        assert_eq!(unwrapped, ak);
    }

    #[test]
    fn truncated_envelope_rejected() {
        let key = test_key();
        assert!(decrypt(&key, &[1, 1, 2, 3], b"").is_err());
    }
}
