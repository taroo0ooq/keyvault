//! QR-code device pairing tokens and handshake material.
//!
//! Pairing establishes a short-lived pre-shared token that remote clients
//! (mobile / extension over a tunnel) must present. Tokens are HMAC-bound so
//! they cannot be forged without the daemon's pairing secret.
//!
//! QR payload is JSON (UTF-8) suitable for encoding as a QR code by the UI.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};

type HmacSha256 = Hmac<Sha256>;

/// Default pairing token lifetime (10 minutes).
pub const DEFAULT_PAIRING_TTL_SECS: u64 = 600;

/// Long-lived pairing secret held by the daemon (zeroized on drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret {
    bytes: [u8; 32],
}

impl PairingSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret([REDACTED])")
    }
}

/// Issued pairing challenge shown as QR / deep link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingOffer {
    pub pairing_id: String,
    /// Absolute expiry as Unix seconds.
    pub expires_at: u64,
    /// Opaque token for the remote client (includes HMAC).
    pub token: String,
    /// Local loopback base the tunnel should forward to (never non-loopback).
    pub local_base: String,
    /// Public/tunnel base URL if known (empty until tunnel starts).
    pub public_base: String,
    /// Protocol version for clients.
    pub version: u8,
}

/// Compact QR / deep-link payload (encode as JSON string in QR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingQrPayload {
    pub v: u8,
    pub id: String,
    pub token: String,
    pub exp: u64,
    /// Preferred base URL for the client (public tunnel or local).
    pub base: String,
}

impl PairingOffer {
    /// Build a QR-ready payload preferring public_base when set.
    pub fn qr_payload(&self) -> PairingQrPayload {
        let base = if self.public_base.is_empty() {
            self.local_base.clone()
        } else {
            self.public_base.clone()
        };
        PairingQrPayload {
            v: self.version,
            id: self.pairing_id.clone(),
            token: self.token.clone(),
            exp: self.expires_at,
            base,
        }
    }

    pub fn qr_json(&self) -> VaultResult<String> {
        Ok(serde_json::to_string(&self.qr_payload())?)
    }
}

/// Create a new pairing offer signed by `secret`.
pub fn create_pairing_offer(
    secret: &PairingSecret,
    local_base: &str,
    public_base: &str,
    ttl_secs: u64,
) -> VaultResult<PairingOffer> {
    if !local_base.contains("127.0.0.1") && !local_base.contains("localhost") {
        return Err(VaultError::Pairing(
            "local_base must be loopback (127.0.0.1 or localhost)".into(),
        ));
    }
    let pairing_id = Uuid::new_v4().to_string();
    let now = now_unix();
    let expires_at = now.saturating_add(ttl_secs.max(60));
    let token = mint_token(secret, &pairing_id, expires_at)?;
    Ok(PairingOffer {
        pairing_id,
        expires_at,
        token,
        local_base: local_base.to_string(),
        public_base: public_base.to_string(),
        version: 1,
    })
}

/// Verify a client-presented token for `pairing_id`.
pub fn verify_pairing_token(
    secret: &PairingSecret,
    pairing_id: &str,
    token: &str,
) -> VaultResult<()> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| VaultError::Pairing(format!("invalid token encoding: {e}")))?;
    let text = String::from_utf8(raw)
        .map_err(|e| VaultError::Pairing(format!("invalid token utf8: {e}")))?;
    // format: pairing_id|expires_at|hex_mac
    let parts: Vec<&str> = text.splitn(3, '|').collect();
    if parts.len() != 3 {
        return Err(VaultError::Pairing("malformed token".into()));
    }
    if parts[0] != pairing_id {
        return Err(VaultError::Pairing("pairing id mismatch".into()));
    }
    let exp: u64 = parts[1]
        .parse()
        .map_err(|_| VaultError::Pairing("bad expiry".into()))?;
    if now_unix() > exp {
        return Err(VaultError::Pairing("token expired".into()));
    }
    let expected = mint_token(secret, pairing_id, exp)?;
    if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        return Err(VaultError::Pairing("invalid token signature".into()));
    }
    Ok(())
}

fn mint_token(secret: &PairingSecret, pairing_id: &str, expires_at: u64) -> VaultResult<String> {
    let msg = format!("{pairing_id}|{expires_at}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| VaultError::Pairing(e.to_string()))?;
    mac.update(msg.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_hex = hex_encode(&sig);
    let packed = format!("{msg}|{sig_hex}");
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(packed.as_bytes()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Session record after a remote successfully claims a pairing offer.
///
/// Only the **hash** of the API token is retained server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    pub device_id: String,
    pub pairing_id: String,
    pub label: String,
    pub paired_at: u64,
    /// SHA-256 hex of the device API token (never store plaintext).
    pub api_token_hash: String,
}

/// Issue a long-lived API token for a paired device (plaintext returned once).
pub fn issue_device_api_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash an API token for storage / comparison (SHA-256 hex).
pub fn hash_api_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

/// Constant-time check that `token` matches a stored hash.
pub fn api_token_matches(token: &str, stored_hash: &str) -> bool {
    let h = hash_api_token(token);
    constant_time_eq(h.as_bytes(), stored_hash.as_bytes())
}

/// Find a paired device by presenting a bearer API token.
pub fn find_device_by_token<'a>(
    devices: &'a [PairedDevice],
    token: &str,
) -> Option<&'a PairedDevice> {
    devices
        .iter()
        .find(|d| api_token_matches(token, &d.api_token_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_roundtrip_verify() {
        let secret = PairingSecret::generate();
        let offer = create_pairing_offer(
            &secret,
            "http://127.0.0.1:8080",
            "https://tunnel.example",
            300,
        )
        .unwrap();
        verify_pairing_token(&secret, &offer.pairing_id, &offer.token).unwrap();
        let qr = offer.qr_json().unwrap();
        assert!(qr.contains(&offer.pairing_id));
        assert!(qr.contains("tunnel.example"));
    }

    #[test]
    fn rejects_non_loopback_local_base() {
        let secret = PairingSecret::generate();
        let err = create_pairing_offer(&secret, "http://0.0.0.0:8080", "", 300).unwrap_err();
        assert!(matches!(err, VaultError::Pairing(_)));
    }

    #[test]
    fn rejects_tampered_token() {
        let secret = PairingSecret::generate();
        let offer =
            create_pairing_offer(&secret, "http://127.0.0.1:8080", "", 300).unwrap();
        let mut bad = offer.token.clone();
        // flip last char
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(verify_pairing_token(&secret, &offer.pairing_id, &bad).is_err());
    }

    #[test]
    fn secret_debug_redacts() {
        let s = PairingSecret::generate();
        assert!(format!("{:?}", s).contains("REDACTED"));
    }

    #[test]
    fn api_token_hash_roundtrip() {
        let t = issue_device_api_token();
        let h = hash_api_token(&t);
        assert!(api_token_matches(&t, &h));
        assert!(!api_token_matches("wrong", &h));
        let dev = PairedDevice {
            device_id: "d1".into(),
            pairing_id: "p1".into(),
            label: "phone".into(),
            paired_at: 1,
            api_token_hash: h,
        };
        assert!(find_device_by_token(&[dev], &t).is_some());
    }
}
