//! Platform secure-key wrappers (OS enclave / keystore bridges).
//!
//! - Windows: DPAPI (`CryptProtectData` / `CryptUnprotectData`)
//! - macOS: Keychain Services stub interface (Phase 2 binds Security.framework)
//! - Android/iOS: KeyStore / Secure Enclave bridge points for FFI
//!
//! Account Key (AK) material is wrapped so biometrics/PIN can release it
//! without retaining the long-term Master Key (MK) in process memory.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};
use crate::kdf::MASTER_KEY_LEN;

/// Opaque wrapped key blob stored on disk / in OS keystore.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WrappedKeyBlob {
    pub platform: String,
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for WrappedKeyBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKeyBlob")
            .field("platform", &self.platform)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// In-memory account key cleared on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccountKey {
    bytes: [u8; MASTER_KEY_LEN],
}

impl AccountKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKey([REDACTED])")
    }
}

/// Protect key material using the best available OS mechanism.
pub fn protect_key(plaintext: &[u8]) -> VaultResult<WrappedKeyBlob> {
    #[cfg(windows)]
    {
        return windows_protect(plaintext);
    }
    #[cfg(not(windows))]
    {
        // Portable software wrap for non-Windows CI/dev until Keychain/KeyStore FFI lands.
        software_protect(plaintext)
    }
}

/// Unprotect a previously wrapped blob.
pub fn unprotect_key(blob: &WrappedKeyBlob) -> VaultResult<Vec<u8>> {
    #[cfg(windows)]
    {
        if blob.platform == "dpapi" {
            return windows_unprotect(&blob.ciphertext);
        }
    }
    if blob.platform == "software-dev" {
        return software_unprotect(&blob.ciphertext);
    }
    Err(VaultError::SecureStore(format!(
        "unsupported platform blob: {}",
        blob.platform
    )))
}

/// Convenience: protect an [`AccountKey`].
pub fn protect_account_key(key: &AccountKey) -> VaultResult<WrappedKeyBlob> {
    protect_key(key.as_bytes())
}

pub fn unprotect_account_key(blob: &WrappedKeyBlob) -> VaultResult<AccountKey> {
    let raw = unprotect_key(blob)?;
    if raw.len() != MASTER_KEY_LEN {
        return Err(VaultError::SecureStore(
            "unprotected key has invalid length".into(),
        ));
    }
    let mut bytes = [0u8; MASTER_KEY_LEN];
    bytes.copy_from_slice(&raw);
    Ok(AccountKey::from_bytes(bytes))
}

// ─── Windows DPAPI ───────────────────────────────────────────────────────────

#[cfg(windows)]
fn windows_protect(plaintext: &[u8]) -> VaultResult<WrappedKeyBlob> {
    use windows_sys::Win32::Foundation::{LocalFree, BOOL};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: CryptProtectData with CRYPTPROTECT_UI_FORBIDDEN; in_blob points
    // at valid plaintext for the duration of the call.
    let ok: BOOL = unsafe {
        CryptProtectData(
            &mut in_blob,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(VaultError::SecureStore(
            "CryptProtectData failed".into(),
        ));
    }

    // SAFETY: out_blob was populated by CryptProtectData on success.
    let slice =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let ciphertext = slice.to_vec();
    unsafe {
        LocalFree(out_blob.pbData as _);
    }

    Ok(WrappedKeyBlob {
        platform: "dpapi".into(),
        ciphertext,
    })
}

#[cfg(windows)]
fn windows_unprotect(ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
    use windows_sys::Win32::Foundation::{LocalFree, BOOL};
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok: BOOL = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(VaultError::SecureStore(
            "CryptUnprotectData failed".into(),
        ));
    }

    let slice =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let mut plaintext = slice.to_vec();
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    // Note: caller owns zeroization of returned buffer when done.
    let _ = &mut plaintext;
    Ok(plaintext)
}

// ─── Portable software wrap (dev / non-Windows CI) ───────────────────────────

/// Dev-only software wrap using a machine-local key derived from a fixed
/// application salt. Production non-Windows builds must use Keychain/KeyStore.
/// On Windows the primary path is DPAPI; this remains available for cross-platform
/// blob compatibility and non-Windows targets.
#[cfg_attr(windows, allow(dead_code))]
fn software_protect(plaintext: &[u8]) -> VaultResult<WrappedKeyBlob> {
    use crate::vault_crypto::{encrypt, CipherAlgorithm};

    let key = software_dev_key()?;
    let ct = encrypt(
        &key,
        plaintext,
        b"secure-store-dev",
        CipherAlgorithm::Aes256Gcm,
    )?;
    Ok(WrappedKeyBlob {
        platform: "software-dev".into(),
        ciphertext: ct,
    })
}

fn software_unprotect(ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
    use crate::vault_crypto::decrypt;
    let key = software_dev_key()?;
    decrypt(&key, ciphertext, b"secure-store-dev")
}

fn software_dev_key() -> VaultResult<crate::kdf::MasterKey> {
    use sha2::{Digest, Sha256};
    // Not a secret for multi-user security — only isolates casual disk scrapes
    // in CI. Real deployments use OS enclaves.
    let mut hasher = Sha256::new();
    hasher.update(b"keyvault-software-dev-v1");
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        hasher.update(home.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; MASTER_KEY_LEN];
    bytes.copy_from_slice(&digest);
    Ok(crate::kdf::MasterKey::from_bytes(bytes))
}

/// Trait for future biometric unlock bridges (Phase 2).
pub trait BiometricUnlock {
    /// Prompt the user (biometrics / PIN ≥ 8 digits) and return the released AK.
    fn unlock(&self) -> VaultResult<AccountKey>;
    /// Store AK protected by the OS enclave.
    fn enroll(&self, key: &AccountKey) -> VaultResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_unprotect_roundtrip() {
        let data = b"super-secret-key-material-32b!!";
        let blob = protect_key(data).unwrap();
        let out = unprotect_key(&blob).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn account_key_roundtrip() {
        let ak = AccountKey::generate();
        let blob = protect_account_key(&ak).unwrap();
        let restored = unprotect_account_key(&blob).unwrap();
        assert_eq!(ak.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn debug_redacts_account_key() {
        let ak = AccountKey::from_bytes([0xAA; 32]);
        assert!(format!("{:?}", ak).contains("REDACTED"));
    }

    #[test]
    fn blob_debug_hides_ciphertext() {
        let blob = protect_key(&[1, 2, 3, 4]).unwrap();
        let s = format!("{:?}", blob);
        assert!(s.contains("ciphertext_len"));
        // Should not dump full hex of ciphertext in Debug.
        assert!(!s.contains("ciphertext: ["));
    }
}
