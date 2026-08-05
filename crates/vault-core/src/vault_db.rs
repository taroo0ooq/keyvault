//! Encrypted vault storage (SQLCipher-compatible schema + AEAD field encryption).
//!
//! Schema is designed for SQLCipher. This build uses `rusqlite` bundled SQLite
//! with AES-256-GCM encryption of sensitive columns and a master-key verifier
//! so the vault remains zero-knowledge even without a linked SQLCipher binary.
//! Swap `rusqlite` features to `bundled-sqlcipher*` when native SQLCipher is
//! available — table layout stays identical.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{VaultError, VaultResult};
use crate::kdf::{derive_master_key, derive_master_key_with_fresh_params, KdfParams, MasterKey};
use crate::secure_key::{protect_key, unprotect_key, WrappedKeyBlob};
use crate::vault_crypto::{
    create_key_verifier, decrypt, encrypt, verify_master_key, CipherAlgorithm, DEFAULT_CIPHER,
};

/// Schema version embedded in vault metadata.
pub const SCHEMA_VERSION: i32 = 3;

/// Storage backend label written to vault_meta.
/// - `sqlite-aead`: plain SQLite + field-level AEAD (default / CI)
/// - `sqlcipher-aead`: SQLCipher full-file key + field-level AEAD (feature `sqlcipher`)
pub fn storage_backend_label() -> &'static str {
    if cfg!(feature = "sqlcipher") {
        "sqlcipher-aead"
    } else {
        "sqlite-aead"
    }
}

/// SQL DDL matching the SQLCipher-oriented product schema.
pub const SCHEMA_SQL: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_items (
    id              TEXT PRIMARY KEY NOT NULL,
    title_enc       BLOB NOT NULL,
    username_enc    BLOB,
    password_enc    BLOB NOT NULL,
    url_enc         BLOB,
    notes_enc       BLOB,
    tags_enc        BLOB,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT,
    totp_enc        BLOB,
    deleted_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_items_updated ON vault_items(updated_at);
CREATE INDEX IF NOT EXISTS idx_vault_items_deleted ON vault_items(deleted_at);
"#;

/// Plaintext view of a vault item (zeroize password/notes/totp after use in UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Base32 TOTP secret (Authenticator-compatible). None if 2FA not set.
    #[serde(default)]
    pub totp: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Soft-delete timestamp (None = active in vault).
    #[serde(default)]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl VaultItem {
    pub fn new(
        title: impl Into<String>,
        username: Option<String>,
        password: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            title: title.into(),
            username,
            password: password.into(),
            url: None,
            notes: None,
            totp: None,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            last_used_at: None,
            deleted_at: None,
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }
}

/// In-memory unlocked vault session. Dropping clears the master key.
pub struct Vault {
    path: PathBuf,
    conn: Connection,
    master_key: Option<MasterKey>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("unlocked", &self.master_key.is_some())
            .finish()
    }
}

impl Vault {
    /// Create a new vault file with KDF params + key verifier; leaves vault unlocked.
    pub fn create(path: impl AsRef<Path>, master_password: &str) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(VaultError::VaultAlreadyExists);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = open_connection(&path, master_password, true)?;
        migrate_schema(&conn)?;

        let (master_key, kdf_params) = derive_master_key_with_fresh_params(master_password)?;
        let verifier = create_key_verifier(&master_key)?;

        set_meta(
            &conn,
            "schema_version",
            &SCHEMA_VERSION.to_string(),
        )?;
        set_meta(
            &conn,
            "kdf_params",
            &serde_json::to_string(&kdf_params)?,
        )?;
        set_meta(
            &conn,
            "key_verifier",
            &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &verifier),
        )?;
        set_meta(&conn, "cipher", "aes-256-gcm")?;
        set_meta(&conn, "storage_backend", storage_backend_label())?;
        set_meta(&conn, "created_at", &Utc::now().to_rfc3339())?;

        Ok(Self {
            path,
            conn,
            master_key: Some(master_key),
        })
    }

    /// Open an existing vault file (locked until [`Vault::unlock`]).
    ///
    /// When the `sqlcipher` feature is enabled, the master password is also used
    /// as the SQLCipher database key (PRAGMA key) before reading schema.
    pub fn open(path: impl AsRef<Path>) -> VaultResult<Self> {
        // Without password we can only open non-SQLCipher files.
        // Callers that use SQLCipher must use [`Vault::open_with_password`] first
        // or unlock path that re-opens — for default builds this is fine.
        Self::open_with_password(path, "")
    }

    /// Open vault file applying SQLCipher key when the feature is enabled.
    ///
    /// Empty password is allowed only for non-SQLCipher builds (default).
    pub fn open_with_password(path: impl AsRef<Path>, master_password: &str) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(VaultError::VaultNotFound);
        }
        let conn = open_connection(&path, master_password, false)?;
        // Ensure schema exists / migrate older vaults (e.g. add totp_enc).
        migrate_schema(&conn)?;
        Ok(Self {
            path,
            conn,
            master_key: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    /// Unlock with master password; verifies against stored key verifier.
    ///
    /// With `sqlcipher`, re-opens the connection under PRAGMA key when needed
    /// so wrong-password SQLCipher files fail closed.
    pub fn unlock(&mut self, master_password: &str) -> VaultResult<()> {
        if self.master_key.is_some() {
            return Err(VaultError::VaultAlreadyUnlocked);
        }

        #[cfg(feature = "sqlcipher")]
        {
            // Re-open with key so page-level decryption matches the password.
            let conn = open_connection(&self.path, master_password, false)?;
            migrate_schema(&conn)?;
            self.conn = conn;
        }

        let kdf_json = get_meta(&self.conn, "kdf_params")?
            .ok_or_else(|| VaultError::Database("missing kdf_params".into()))?;
        let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
        let verifier_b64 = get_meta(&self.conn, "key_verifier")?
            .ok_or_else(|| VaultError::Database("missing key_verifier".into()))?;
        let verifier = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            verifier_b64,
        )
        .map_err(|e| VaultError::Database(e.to_string()))?;

        let key = derive_master_key(master_password, &kdf)?;
        verify_master_key(&key, &verifier)?;
        self.master_key = Some(key);
        Ok(())
    }

    /// Lock the vault: zeroize master key from memory.
    pub fn lock(&mut self) {
        self.master_key = None;
    }

    /// Wrap the in-memory master key with the OS secure store (DPAPI / software-dev).
    ///
    /// Used for biometric / OS-login quick unlock without re-entering the master
    /// password. The returned blob must be stored outside the vault DB (sidecar).
    pub fn wrap_master_key_for_enclave(&self) -> VaultResult<WrappedKeyBlob> {
        let key = self.key()?;
        protect_key(key.as_bytes())
    }

    /// Unlock using a previously enclave-wrapped master key blob.
    ///
    /// Still verifies the key against the vault verifier so a corrupted or
    /// swapped blob cannot silently open the wrong vault.
    pub fn unlock_with_enclave_blob(&mut self, blob: &WrappedKeyBlob) -> VaultResult<()> {
        if self.master_key.is_some() {
            return Err(VaultError::VaultAlreadyUnlocked);
        }
        let raw = unprotect_key(blob)?;
        if raw.len() != crate::kdf::MASTER_KEY_LEN {
            return Err(VaultError::SecureStore(
                "enclave blob has invalid key length".into(),
            ));
        }
        let mut bytes = [0u8; crate::kdf::MASTER_KEY_LEN];
        bytes.copy_from_slice(&raw);
        let key = MasterKey::from_bytes(bytes);

        let verifier_b64 = get_meta(&self.conn, "key_verifier")?
            .ok_or_else(|| VaultError::Database("missing key_verifier".into()))?;
        let verifier = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            verifier_b64,
        )
        .map_err(|e| VaultError::Database(e.to_string()))?;
        verify_master_key(&key, &verifier)?;
        self.master_key = Some(key);
        Ok(())
    }

    /// Sidecar path for enclave-wrapped MK: `{vault_path}.enclave.json`.
    pub fn enclave_sidecar_path(vault_path: impl AsRef<Path>) -> PathBuf {
        let p = vault_path.as_ref();
        let mut s = p.as_os_str().to_os_string();
        s.push(".enclave.json");
        PathBuf::from(s)
    }

    /// Persist wrapped MK next to the vault file.
    pub fn save_enclave_blob(vault_path: impl AsRef<Path>, blob: &WrappedKeyBlob) -> VaultResult<()> {
        let path = Self::enclave_sidecar_path(vault_path);
        let json = serde_json::to_vec_pretty(blob)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load enclave sidecar if present.
    /// Remove OS enclave quick-unlock sidecar (e.g. after master password change).
    pub fn clear_enclave_sidecar(vault_path: impl AsRef<Path>) -> VaultResult<bool> {
        let p = Self::enclave_sidecar_path(vault_path);
        if p.exists() {
            std::fs::remove_file(&p)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn load_enclave_blob(vault_path: impl AsRef<Path>) -> VaultResult<Option<WrappedKeyBlob>> {
        let path = Self::enclave_sidecar_path(vault_path);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(path)?;
        let blob: WrappedKeyBlob = serde_json::from_slice(&raw)?;
        Ok(Some(blob))
    }

    fn key(&self) -> VaultResult<&MasterKey> {
        self.master_key
            .as_ref()
            .ok_or(VaultError::VaultLocked)
    }

    /// Insert a new item (fields encrypted under MK).
    pub fn add_item(&self, item: &VaultItem) -> VaultResult<()> {
        let key = self.key()?;
        let id = &item.id;
        let aad = id.as_bytes();

        let title_enc = encrypt(key, item.title.as_bytes(), aad, DEFAULT_CIPHER)?;
        let username_enc = match &item.username {
            Some(u) => Some(encrypt(key, u.as_bytes(), aad, DEFAULT_CIPHER)?),
            None => None,
        };
        let password_enc = encrypt(key, item.password.as_bytes(), aad, DEFAULT_CIPHER)?;
        let url_enc = match &item.url {
            Some(u) => Some(encrypt(key, u.as_bytes(), aad, DEFAULT_CIPHER)?),
            None => None,
        };
        let notes_enc = match &item.notes {
            Some(n) => Some(encrypt(key, n.as_bytes(), aad, DEFAULT_CIPHER)?),
            None => None,
        };
        let totp_enc = match &item.totp {
            Some(t) if !t.is_empty() => {
                let norm = crate::totp::normalize_totp_secret(t);
                Some(encrypt(key, norm.as_bytes(), aad, DEFAULT_CIPHER)?)
            }
            _ => None,
        };
        let tags_json = serde_json::to_string(&item.tags)?;
        let tags_enc = encrypt(key, tags_json.as_bytes(), aad, DEFAULT_CIPHER)?;

        self.conn.execute(
            r#"INSERT INTO vault_items
               (id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                created_at, updated_at, last_used_at, totp_enc, deleted_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            params![
                item.id,
                title_enc,
                username_enc,
                password_enc,
                url_enc,
                notes_enc,
                tags_enc,
                item.created_at.to_rfc3339(),
                item.updated_at.to_rfc3339(),
                item.last_used_at.map(|t| t.to_rfc3339()),
                totp_enc,
                item.deleted_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Fetch and decrypt a single item by id (includes trash).
    pub fn get_item(&self, id: &str) -> VaultResult<VaultItem> {
        let key = self.key()?;
        let mut stmt = self.conn.prepare(
            r#"SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                      created_at, updated_at, last_used_at, totp_enc, deleted_at
               FROM vault_items WHERE id = ?1"#,
        )?;
        let row = stmt
            .query_row(params![id], map_item_row)
            .optional()?
            .ok_or_else(|| VaultError::ItemNotFound(id.into()))?;

        decrypt_row(key, row)
    }

    /// List active (non-deleted) items.
    pub fn list_items(&self) -> VaultResult<Vec<VaultItem>> {
        self.list_items_inner(ListFilter::Active)
    }

    /// List soft-deleted items (trash).
    pub fn list_trash(&self) -> VaultResult<Vec<VaultItem>> {
        self.list_items_inner(ListFilter::Trash)
    }

    /// All items including trash (for re-encrypt / full backup).
    pub fn list_all_items(&self) -> VaultResult<Vec<VaultItem>> {
        self.list_items_inner(ListFilter::All)
    }

    fn list_items_inner(&self, filter: ListFilter) -> VaultResult<Vec<VaultItem>> {
        let key = self.key()?;
        let sql = match filter {
            ListFilter::Active => {
                r#"SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                          created_at, updated_at, last_used_at, totp_enc, deleted_at
                   FROM vault_items WHERE deleted_at IS NULL ORDER BY updated_at DESC"#
            }
            ListFilter::Trash => {
                r#"SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                          created_at, updated_at, last_used_at, totp_enc, deleted_at
                   FROM vault_items WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC"#
            }
            ListFilter::All => {
                r#"SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                          created_at, updated_at, last_used_at, totp_enc, deleted_at
                   FROM vault_items ORDER BY updated_at DESC"#
            }
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], map_item_row)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(decrypt_row(key, r?)?);
        }
        Ok(items)
    }

    /// Current TOTP code for an item (does not return the secret).
    pub fn totp_code_for_item(&self, id: &str) -> VaultResult<crate::totp::TotpCode> {
        let item = self.get_item(id)?;
        let secret = item
            .totp
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| VaultError::InvalidInput("item has no TOTP secret".into()))?;
        crate::totp::generate_totp(secret, None)
    }

    /// Case-insensitive substring search over decrypted title/username/url.
    pub fn search(&self, query: &str) -> VaultResult<Vec<VaultItem>> {
        let q = query.to_lowercase();
        let items = self.list_items()?;
        Ok(items
            .into_iter()
            .filter(|i| {
                i.title.to_lowercase().contains(&q)
                    || i.username
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&q))
                        .unwrap_or(false)
                    || i.url
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&q))
                        .unwrap_or(false)
                    || i.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect())
    }

    /// Update an existing item (re-encrypts all fields).
    pub fn update_item(&self, item: &VaultItem) -> VaultResult<()> {
        // Hard-delete + insert keeps encryption path consistent.
        self.hard_delete_item(&item.id)?;
        let mut updated = item.clone();
        updated.updated_at = Utc::now();
        self.add_item(&updated)
    }

    /// Soft-delete: move item to trash (recoverable until purged).
    pub fn delete_item(&self, id: &str) -> VaultResult<()> {
        let _ = self.key()?;
        let n = self.conn.execute(
            "UPDATE vault_items SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            params![Utc::now().to_rfc3339(), id],
        )?;
        if n == 0 {
            return Err(VaultError::ItemNotFound(id.into()));
        }
        Ok(())
    }

    /// Restore a soft-deleted item from trash.
    pub fn restore_item(&self, id: &str) -> VaultResult<()> {
        let _ = self.key()?;
        let n = self.conn.execute(
            "UPDATE vault_items SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND deleted_at IS NOT NULL",
            params![Utc::now().to_rfc3339(), id],
        )?;
        if n == 0 {
            return Err(VaultError::ItemNotFound(id.into()));
        }
        Ok(())
    }

    /// Permanently remove an item (from active vault or trash).
    pub fn purge_item(&self, id: &str) -> VaultResult<()> {
        self.hard_delete_item(id)
    }

    /// Empty trash: permanently delete all soft-deleted items. Returns count purged.
    pub fn empty_trash(&self) -> VaultResult<usize> {
        let _ = self.key()?;
        let n = self
            .conn
            .execute("DELETE FROM vault_items WHERE deleted_at IS NOT NULL", [])?;
        Ok(n)
    }

    fn hard_delete_item(&self, id: &str) -> VaultResult<()> {
        let _ = self.key()?;
        let n = self
            .conn
            .execute("DELETE FROM vault_items WHERE id = ?1", params![id])?;
        if n == 0 {
            return Err(VaultError::ItemNotFound(id.into()));
        }
        Ok(())
    }

    /// Export all items as an encrypted portable backup (JSON + AEAD).
    ///
    /// The backup is sealed under a **separate** passphrase-derived key (Argon2id),
    /// so it can be restored without the original vault master password.
    /// Returns a single base64-encoded envelope string (safe for file/clipboard).
    pub fn export_encrypted_backup(&self, export_passphrase: &str) -> VaultResult<String> {
        if export_passphrase.len() < 12 {
            return Err(VaultError::InvalidInput(
                "export passphrase must be at least 12 characters".into(),
            ));
        }
        // Include trash so soft-deleted credentials are not lost on backup restore.
        let items = self.list_all_items()?;
        let payload = serde_json::to_vec(&BackupPayload {
            format: BACKUP_FORMAT.to_string(),
            exported_at: Utc::now().to_rfc3339(),
            item_count: items.len(),
            items,
        })?;
        let (key, kdf) = derive_master_key_with_fresh_params(export_passphrase)?;
        let ciphertext = encrypt(&key, &payload, BACKUP_AAD, DEFAULT_CIPHER)?;
        let envelope = BackupEnvelope {
            version: BACKUP_VERSION,
            format: BACKUP_FORMAT.to_string(),
            kdf,
            ciphertext,
        };
        let json = serde_json::to_vec(&envelope)?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            json,
        ))
    }

    /// Import items from an encrypted backup produced by [`export_encrypted_backup`].
    ///
    /// When `merge` is true, items whose IDs already exist are skipped; new IDs are
    /// always inserted. When `merge` is false, existing IDs are overwritten.
    /// Returns the number of items written.
    pub fn import_encrypted_backup(
        &self,
        backup_b64: &str,
        export_passphrase: &str,
        merge: bool,
    ) -> VaultResult<usize> {
        let _ = self.key()?;
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            backup_b64.trim(),
        )
        .map_err(|e| VaultError::InvalidInput(format!("invalid backup base64: {e}")))?;
        let envelope: BackupEnvelope = serde_json::from_slice(&raw)
            .map_err(|e| VaultError::InvalidInput(format!("invalid backup envelope: {e}")))?;
        if envelope.version != BACKUP_VERSION {
            return Err(VaultError::InvalidInput(format!(
                "unsupported backup version {}",
                envelope.version
            )));
        }
        let key = derive_master_key(export_passphrase, &envelope.kdf)?;
        let plain = decrypt(&key, &envelope.ciphertext, BACKUP_AAD)?;
        let payload: BackupPayload = serde_json::from_slice(&plain)
            .map_err(|_| VaultError::AuthenticationFailed)?;

        let mut written = 0usize;
        for item in payload.items {
            let exists = self.get_item(&item.id).is_ok();
            if exists {
                if merge {
                    continue;
                }
                self.hard_delete_item(&item.id)?;
            }
            self.add_item(&item)?;
            written += 1;
        }
        Ok(written)
    }

    /// Change the master password: re-encrypts all items under a new MK.
    ///
    /// Vault must be unlocked. `current_password` is verified before any rewrite.
    /// After success the session remains unlocked under the new key. Any OS
    /// enclave sidecar for the old key becomes invalid and should be re-enrolled.
    pub fn change_master_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> VaultResult<()> {
        if new_password.len() < 12 {
            return Err(VaultError::InvalidInput(
                "new master password must be at least 12 characters".into(),
            ));
        }
        if current_password == new_password {
            return Err(VaultError::InvalidInput(
                "new password must differ from current".into(),
            ));
        }

        let kdf_json = get_meta(&self.conn, "kdf_params")?
            .ok_or_else(|| VaultError::Database("missing kdf_params".into()))?;
        let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
        let verifier_b64 = get_meta(&self.conn, "key_verifier")?
            .ok_or_else(|| VaultError::Database("missing key_verifier".into()))?;
        let verifier = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            verifier_b64,
        )
        .map_err(|e| VaultError::Database(e.to_string()))?;
        let current_key = derive_master_key(current_password, &kdf)?;
        verify_master_key(&current_key, &verifier)?;

        let session_key = self.key()?;
        if !session_key.ct_eq(&current_key) {
            return Err(VaultError::AuthenticationFailed);
        }

        // Re-encrypt active + trash so soft-deleted secrets stay recoverable under new MK.
        let items = self.list_all_items()?;
        let (new_key, new_kdf) = derive_master_key_with_fresh_params(new_password)?;
        let new_verifier = create_key_verifier(&new_key)?;
        let verifier_b64_new = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &new_verifier,
        );

        // Pre-encrypt all rows under the new key so the DB rewrite is one transaction.
        let mut prepared: Vec<PreparedItemRow> = Vec::with_capacity(items.len());
        for item in &items {
            prepared.push(prepare_item_row(&new_key, item)?);
        }

        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM vault_items", [])?;
        for row in &prepared {
            tx.execute(
                r#"INSERT INTO vault_items
                   (id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                    created_at, updated_at, last_used_at, totp_enc, deleted_at)
                   VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
                params![
                    row.id,
                    row.title_enc,
                    row.username_enc,
                    row.password_enc,
                    row.url_enc,
                    row.notes_enc,
                    row.tags_enc,
                    row.created_at,
                    row.updated_at,
                    row.last_used_at,
                    row.totp_enc,
                    row.deleted_at,
                ],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params!["kdf_params", serde_json::to_string(&new_kdf)?],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params!["key_verifier", verifier_b64_new],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params!["password_changed_at", Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;

        // SQLCipher outer file key must track the master password.
        #[cfg(feature = "sqlcipher")]
        {
            let escaped = new_password.replace('\'', "''");
            self.conn
                .pragma_update(None, "rekey", &escaped)
                .map_err(|e| {
                    VaultError::Database(format!("SQLCipher PRAGMA rekey failed: {e}"))
                })?;
        }

        self.master_key = Some(new_key);
        // Old enclave blob is bound to previous MK — remove if present.
        let _ = Self::clear_enclave_sidecar(&self.path);
        Ok(())
    }

    /// Export all items as Chrome-compatible CSV (name,url,username,password,notes,totp).
    ///
    /// Values are escaped per RFC 4180 (quotes doubled). Contains secrets — treat as sensitive.
    pub fn export_csv(&self) -> VaultResult<String> {
        let items = self.list_items()?;
        let mut out = String::from("name,url,username,password,notes,totp\n");
        for item in items {
            out.push_str(&csv_escape(&item.title));
            out.push(',');
            out.push_str(&csv_escape(item.url.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_escape(item.username.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_escape(&item.password));
            out.push(',');
            out.push_str(&csv_escape(item.notes.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_escape(item.totp.as_deref().unwrap_or("")));
            out.push('\n');
        }
        Ok(out)
    }

    /// Local password health report: weak scores and exact duplicate passwords.
    ///
    /// Offline only — does not contact Have I Been Pwned or any network.
    pub fn password_health(&self) -> VaultResult<PasswordHealthReport> {
        use crate::password::score_password;
        use std::collections::HashMap;

        let items = self.list_items()?;
        let mut by_password: HashMap<String, Vec<String>> = HashMap::new();
        let mut weak = Vec::new();

        for item in &items {
            let score = score_password(&item.password);
            if score.score < 3 || item.password.len() < 12 {
                weak.push(HealthFinding {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    kind: "weak".into(),
                    detail: format!(
                        "score={} length={} label={}",
                        score.score,
                        item.password.len(),
                        score.label
                    ),
                });
            }
            by_password
                .entry(item.password.clone())
                .or_default()
                .push(item.id.clone());
        }

        let mut reused = Vec::new();
        for (pw, ids) in by_password {
            if ids.len() < 2 || pw.is_empty() {
                continue;
            }
            for id in &ids {
                let title = items
                    .iter()
                    .find(|i| i.id == *id)
                    .map(|i| i.title.clone())
                    .unwrap_or_default();
                reused.push(HealthFinding {
                    id: id.clone(),
                    title,
                    kind: "reused".into(),
                    detail: format!("password shared by {} items", ids.len()),
                });
            }
        }

        Ok(PasswordHealthReport {
            total_items: items.len(),
            weak_count: weak.len(),
            reused_count: reused.len(),
            weak,
            reused,
        })
    }

    /// Import items from a CSV export (Chrome, Bitwarden-style, or generic headers).
    ///
    /// Recognized columns (case-insensitive): `name`/`title`, `url`/`login_uri`,
    /// `username`/`login_username`, `password`/`login_password`, `notes`.
    /// Rows without a password are skipped. Returns count of imported items.
    pub fn import_csv(&self, csv_text: &str) -> VaultResult<usize> {
        let _ = self.key()?;
        let rows = parse_csv(csv_text)?;
        if rows.is_empty() {
            return Ok(0);
        }
        let header = rows[0]
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        let col = |names: &[&str]| -> Option<usize> {
            header.iter().position(|h| names.iter().any(|n| h == n))
        };
        let i_title = col(&["name", "title", "login_name"]);
        let i_url = col(&["url", "login_uri", "uri", "hostname"]);
        let i_user = col(&["username", "login_username", "user", "login"]);
        let i_pass = col(&["password", "login_password", "pass"]);
        let i_notes = col(&["notes", "note", "comments"]);
        let i_totp = col(&["totp", "login_totp", "otpauth", "twofactor_secret"]);
        let Some(i_pass) = i_pass else {
            return Err(VaultError::InvalidInput(
                "CSV missing password column".into(),
            ));
        };

        let mut written = 0usize;
        for row in rows.iter().skip(1) {
            let get = |idx: Option<usize>| -> Option<String> {
                idx.and_then(|i| row.get(i))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            };
            let password = match get(Some(i_pass)) {
                Some(p) => p,
                None => continue,
            };
            let title = get(i_title)
                .or_else(|| get(i_url))
                .unwrap_or_else(|| "Imported".into());
            let mut item = VaultItem::new(title, get(i_user), password);
            item.url = get(i_url);
            item.notes = get(i_notes);
            if let Some(t) = get(i_totp) {
                item.totp = Some(crate::totp::normalize_totp_secret(&t));
            }
            item.tags = vec!["imported".into()];
            self.add_item(&item)?;
            written += 1;
        }
        Ok(written)
    }

    /// Active cipher used for new records.
    pub fn default_cipher(&self) -> CipherAlgorithm {
        DEFAULT_CIPHER
    }
}

enum ListFilter {
    Active,
    Trash,
    All,
}

struct PreparedItemRow {
    id: String,
    title_enc: Vec<u8>,
    username_enc: Option<Vec<u8>>,
    password_enc: Vec<u8>,
    url_enc: Option<Vec<u8>>,
    notes_enc: Option<Vec<u8>>,
    tags_enc: Vec<u8>,
    created_at: String,
    updated_at: String,
    last_used_at: Option<String>,
    totp_enc: Option<Vec<u8>>,
    deleted_at: Option<String>,
}

fn prepare_item_row(key: &MasterKey, item: &VaultItem) -> VaultResult<PreparedItemRow> {
    let id = item.id.clone();
    let aad = id.as_bytes();
    let title_enc = encrypt(key, item.title.as_bytes(), aad, DEFAULT_CIPHER)?;
    let username_enc = match &item.username {
        Some(u) => Some(encrypt(key, u.as_bytes(), aad, DEFAULT_CIPHER)?),
        None => None,
    };
    let password_enc = encrypt(key, item.password.as_bytes(), aad, DEFAULT_CIPHER)?;
    let url_enc = match &item.url {
        Some(u) => Some(encrypt(key, u.as_bytes(), aad, DEFAULT_CIPHER)?),
        None => None,
    };
    let notes_enc = match &item.notes {
        Some(n) => Some(encrypt(key, n.as_bytes(), aad, DEFAULT_CIPHER)?),
        None => None,
    };
    let totp_enc = match &item.totp {
        Some(t) if !t.is_empty() => {
            let norm = crate::totp::normalize_totp_secret(t);
            Some(encrypt(key, norm.as_bytes(), aad, DEFAULT_CIPHER)?)
        }
        _ => None,
    };
    let tags_json = serde_json::to_string(&item.tags)?;
    let tags_enc = encrypt(key, tags_json.as_bytes(), aad, DEFAULT_CIPHER)?;
    Ok(PreparedItemRow {
        id,
        title_enc,
        username_enc,
        password_enc,
        url_enc,
        notes_enc,
        tags_enc,
        created_at: item.created_at.to_rfc3339(),
        updated_at: item.updated_at.to_rfc3339(),
        last_used_at: item.last_used_at.map(|t| t.to_rfc3339()),
        totp_enc,
        deleted_at: item.deleted_at.map(|t| t.to_rfc3339()),
    })
}

/// Local vault password hygiene summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHealthReport {
    pub total_items: usize,
    pub weak_count: usize,
    pub reused_count: usize,
    pub weak: Vec<HealthFinding>,
    pub reused: Vec<HealthFinding>,
}

/// One weak or reused password finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthFinding {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub detail: String,
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Minimal RFC4180-ish CSV parser (handles quotes and commas).
fn parse_csv(text: &str) -> VaultResult<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut field = String::new();
    let mut row = Vec::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                row.push(std::mem::take(&mut field));
            }
            '\n' if !in_quotes => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|f| !f.is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            '\r' if !in_quotes => { /* skip CR */ }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        if row.iter().any(|f| !f.is_empty()) {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Portable backup envelope version.
pub const BACKUP_VERSION: u8 = 1;
/// Format identifier embedded in backup payloads.
pub const BACKUP_FORMAT: &str = "keyvault-backup-v1";
const BACKUP_AAD: &[u8] = b"keyvault-backup-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEnvelope {
    version: u8,
    format: String,
    kdf: KdfParams,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupPayload {
    format: String,
    exported_at: String,
    item_count: usize,
    items: Vec<VaultItem>,
}

type RawRow = (
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    String,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
);

fn map_item_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((
        row.get::<_, String>(0)?,
        row.get::<_, Vec<u8>>(1)?,
        row.get::<_, Option<Vec<u8>>>(2)?,
        row.get::<_, Vec<u8>>(3)?,
        row.get::<_, Option<Vec<u8>>>(4)?,
        row.get::<_, Option<Vec<u8>>>(5)?,
        row.get::<_, Vec<u8>>(6)?,
        row.get::<_, String>(7)?,
        row.get::<_, String>(8)?,
        row.get::<_, Option<String>>(9)?,
        row.get::<_, Option<Vec<u8>>>(10)?,
        row.get::<_, Option<String>>(11)?,
    ))
}

fn decrypt_row(key: &MasterKey, row: RawRow) -> VaultResult<VaultItem> {
    let (
        id,
        title_enc,
        username_enc,
        password_enc,
        url_enc,
        notes_enc,
        tags_enc,
        created,
        updated,
        last_used,
        totp_enc,
        deleted_at,
    ) = row;
    let aad = id.as_bytes();

    let title = String::from_utf8(decrypt(key, &title_enc, aad)?)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let username = match username_enc {
        Some(b) => Some(
            String::from_utf8(decrypt(key, &b, aad)?)
                .map_err(|e| VaultError::Crypto(e.to_string()))?,
        ),
        None => None,
    };
    let mut password_bytes = decrypt(key, &password_enc, aad)?;
    let password = String::from_utf8(password_bytes.clone())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    password_bytes.zeroize();

    let url = match url_enc {
        Some(b) => Some(
            String::from_utf8(decrypt(key, &b, aad)?)
                .map_err(|e| VaultError::Crypto(e.to_string()))?,
        ),
        None => None,
    };
    let notes = match notes_enc {
        Some(b) => Some(
            String::from_utf8(decrypt(key, &b, aad)?)
                .map_err(|e| VaultError::Crypto(e.to_string()))?,
        ),
        None => None,
    };
    let totp = match totp_enc {
        Some(b) => Some(
            String::from_utf8(decrypt(key, &b, aad)?)
                .map_err(|e| VaultError::Crypto(e.to_string()))?,
        ),
        None => None,
    };
    let tags_json = String::from_utf8(decrypt(key, &tags_enc, aad)?)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let tags: Vec<String> = serde_json::from_str(&tags_json)?;

    Ok(VaultItem {
        id,
        title,
        username,
        password,
        url,
        notes,
        totp,
        tags,
        created_at: DateTime::parse_from_rfc3339(&created)
            .map_err(|e| VaultError::Database(e.to_string()))?
            .with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&updated)
            .map_err(|e| VaultError::Database(e.to_string()))?
            .with_timezone(&Utc),
        last_used_at: match last_used {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| VaultError::Database(e.to_string()))?
                    .with_timezone(&Utc),
            ),
            None => None,
        },
        deleted_at: match deleted_at {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| VaultError::Database(e.to_string()))?
                    .with_timezone(&Utc),
            ),
            None => None,
        },
    })
}

fn migrate_schema(conn: &Connection) -> VaultResult<()> {
    conn.execute_batch(SCHEMA_SQL)?;
    let mut stmt = conn.prepare("PRAGMA table_info(vault_items)")?;
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|c| c.ok())
        .collect();
    if !cols.iter().any(|c| c == "totp_enc") {
        conn.execute("ALTER TABLE vault_items ADD COLUMN totp_enc BLOB", [])?;
    }
    if !cols.iter().any(|c| c == "deleted_at") {
        conn.execute("ALTER TABLE vault_items ADD COLUMN deleted_at TEXT", [])?;
    }
    set_meta(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    // Best-effort backend label (may already exist on create).
    if get_meta(conn, "storage_backend")?.is_none() {
        let _ = set_meta(conn, "storage_backend", storage_backend_label());
    }
    Ok(())
}

/// Open a SQLite/SQLCipher connection.
///
/// `for_create`: when SQLCipher is enabled, set PRAGMA key before any writes.
fn open_connection(
    path: &Path,
    master_password: &str,
    for_create: bool,
) -> VaultResult<Connection> {
    let conn = Connection::open(path)?;
    apply_sqlcipher_key(&conn, master_password, for_create)?;
    Ok(conn)
}

#[cfg(feature = "sqlcipher")]
fn apply_sqlcipher_key(
    conn: &Connection,
    master_password: &str,
    for_create: bool,
) -> VaultResult<()> {
    if master_password.is_empty() && !for_create {
        return Err(VaultError::InvalidInput(
            "SQLCipher vaults require a password to open".into(),
        ));
    }
    // Escape single quotes for PRAGMA key = '...'
    let escaped = master_password.replace('\'', "''");
    conn.pragma_update(None, "key", &escaped)
        .map_err(|e| VaultError::Database(format!("SQLCipher PRAGMA key failed: {e}")))?;
    // Force a read so wrong keys fail early on existing files.
    if !for_create {
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|_| VaultError::AuthenticationFailed)?;
    }
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
fn apply_sqlcipher_key(
    _conn: &Connection,
    _master_password: &str,
    _for_create: bool,
) -> VaultResult<()> {
    Ok(())
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> VaultResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn get_meta(conn: &Connection, key: &str) -> VaultResult<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = ?1")?;
    let v = stmt
        .query_row(params![key], |row| row.get(0))
        .optional()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.vault");
        // Use product KDF in create — tests accept the cost for correctness.
        // For faster local loops, integration tests may mock; unit path uses real KDF.
        let vault = Vault::create(&path, "test-master-password-32chars!!").unwrap();
        (dir, vault)
    }

    #[test]
    fn create_unlock_lock_cycle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cycle.vault");
        {
            let v = Vault::create(&path, "master-pass-one").unwrap();
            assert!(v.is_unlocked());
        }
        // SQLCipher builds require the password at open (PRAGMA key).
        let mut v = Vault::open_with_password(&path, "master-pass-one").unwrap();
        assert!(!v.is_unlocked());
        v.unlock("master-pass-one").unwrap();
        assert!(v.is_unlocked());
        v.lock();
        assert!(!v.is_unlocked());
        assert!(matches!(v.list_items(), Err(VaultError::VaultLocked)));
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wrong.vault");
        Vault::create(&path, "correct-password").unwrap();
        // Open with correct SQLCipher key (or plain SQLite), then wrong MK fails.
        let mut v = Vault::open_with_password(&path, "correct-password").unwrap();
        assert!(matches!(
            v.unlock("incorrect-password"),
            Err(VaultError::AuthenticationFailed)
        ));
        // With SQLCipher, a wrong open key must also fail closed.
        #[cfg(feature = "sqlcipher")]
        {
            assert!(matches!(
                Vault::open_with_password(&path, "incorrect-password"),
                Err(VaultError::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn crud_and_search() {
        let (_dir, vault) = test_vault();
        let mut item = VaultItem::new("GitHub", Some("alice".into()), "s3cret!");
        item.url = Some("https://github.com".into());
        item.tags = vec!["dev".into(), "work".into()];
        vault.add_item(&item).unwrap();

        let got = vault.get_item(&item.id).unwrap();
        assert_eq!(got.title, "GitHub");
        assert_eq!(got.username.as_deref(), Some("alice"));
        assert_eq!(got.password, "s3cret!");
        assert_eq!(got.url.as_deref(), Some("https://github.com"));
        assert_eq!(got.tags, vec!["dev", "work"]);

        let found = vault.search("git").unwrap();
        assert_eq!(found.len(), 1);

        let mut updated = got;
        updated.password = "new-pass".into();
        vault.update_item(&updated).unwrap();
        assert_eq!(vault.get_item(&item.id).unwrap().password, "new-pass");

        vault.delete_item(&item.id).unwrap();
        // Soft-delete: item remains gettable, gone from active list.
        assert!(vault.get_item(&item.id).unwrap().is_deleted());
        assert!(vault.list_items().unwrap().is_empty());
        vault.purge_item(&item.id).unwrap();
        assert!(matches!(
            vault.get_item(&item.id),
            Err(VaultError::ItemNotFound(_))
        ));
    }

    #[test]
    fn totp_secret_roundtrip_and_code() {
        let (_dir, vault) = test_vault();
        let mut item = VaultItem::new("2FA", Some("u".into()), "pw");
        item.totp = Some("JBSWY3DPEHPK3PXP".into());
        vault.add_item(&item).unwrap();
        let got = vault.get_item(&item.id).unwrap();
        assert_eq!(got.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let code = vault.totp_code_for_item(&item.id).unwrap();
        assert_eq!(code.code.len(), 6);
    }

    #[test]
    fn change_master_password_reencrypts() {
        let (dir, mut vault) = test_vault();
        let item = VaultItem::new("Site", Some("u".into()), "secret-pw");
        let id = item.id.clone();
        vault.add_item(&item).unwrap();

        vault
            .change_master_password("test-master-password-32chars!!", "new-master-password-ok")
            .unwrap();
        assert_eq!(vault.get_item(&id).unwrap().password, "secret-pw");

        // Old password no longer unlocks (SQLCipher rekey + new MK verifier).
        vault.lock();
        #[cfg(feature = "sqlcipher")]
        {
            assert!(
                Vault::open_with_password(vault.path(), "test-master-password-32chars!!").is_err(),
                "old SQLCipher key must fail after rekey"
            );
        }
        let mut v2 = Vault::open_with_password(vault.path(), "new-master-password-ok").unwrap();
        assert!(v2.unlock("test-master-password-32chars!!").is_err());
        v2.unlock("new-master-password-ok").unwrap();
        assert_eq!(v2.get_item(&id).unwrap().password, "secret-pw");
        let _ = dir;
    }

    #[test]
    fn import_csv_chrome_style() {
        let (_dir, vault) = test_vault();
        let csv = "name,url,username,password\n\
GitHub,https://github.com,alice,gh-secret\n\
Empty,,user,\n\
\"Quoted, Inc\",https://q.example,bob,\"p,ass\"\n";
        let n = vault.import_csv(csv).unwrap();
        assert_eq!(n, 2);
        let items = vault.list_items().unwrap();
        assert!(items.iter().any(|i| i.title == "GitHub" && i.password == "gh-secret"));
        assert!(items.iter().any(|i| i.title == "Quoted, Inc" && i.password == "p,ass"));
    }

    #[test]
    fn export_csv_roundtrip() {
        let (_dir, vault) = test_vault();
        let mut a = VaultItem::new("A", Some("u".into()), "pw-a");
        a.url = Some("https://a.example".into());
        a.totp = Some("JBSWY3DPEHPK3PXP".into());
        vault.add_item(&a).unwrap();
        vault
            .add_item(&VaultItem::new("Comma, Site", None, "p,ass"))
            .unwrap();

        let csv = vault.export_csv().unwrap();
        assert!(csv.starts_with("name,url,username,password,notes,totp\n"));
        assert!(csv.contains("JBSWY3DPEHPK3PXP"));
        assert!(csv.contains("\"Comma, Site\"") || csv.contains("Comma, Site"));

        let dest = Vault::create(
            _dir.path().join("from-csv.vault"),
            "other-master-password",
        )
        .unwrap();
        let n = dest.import_csv(&csv).unwrap();
        assert_eq!(n, 2);
        assert_eq!(dest.list_items().unwrap().len(), 2);
    }

    #[test]
    fn storage_backend_meta_on_create() {
        let (_dir, vault) = test_vault();
        let backend = get_meta(&vault.conn, "storage_backend").unwrap();
        assert_eq!(backend.as_deref(), Some(storage_backend_label()));
        assert!(
            backend.as_deref() == Some("sqlite-aead")
                || backend.as_deref() == Some("sqlcipher-aead")
        );
    }

    #[test]
    fn soft_delete_restore_and_purge() {
        let (_dir, vault) = test_vault();
        let item = VaultItem::new("TrashMe", None, "pw-trash");
        let id = item.id.clone();
        vault.add_item(&item).unwrap();
        vault.delete_item(&id).unwrap();
        assert_eq!(vault.list_items().unwrap().len(), 0);
        assert_eq!(vault.list_trash().unwrap().len(), 1);
        assert!(vault.get_item(&id).unwrap().is_deleted());

        vault.restore_item(&id).unwrap();
        assert_eq!(vault.list_items().unwrap().len(), 1);
        assert_eq!(vault.list_trash().unwrap().len(), 0);

        vault.delete_item(&id).unwrap();
        vault.purge_item(&id).unwrap();
        assert!(matches!(
            vault.get_item(&id),
            Err(VaultError::ItemNotFound(_))
        ));
        assert_eq!(vault.empty_trash().unwrap(), 0);
    }

    #[test]
    fn password_health_finds_reused_and_weak() {
        let (_dir, vault) = test_vault();
        vault
            .add_item(&VaultItem::new("W1", None, "short"))
            .unwrap();
        vault
            .add_item(&VaultItem::new("R1", None, "same-password-everywhere"))
            .unwrap();
        vault
            .add_item(&VaultItem::new("R2", None, "same-password-everywhere"))
            .unwrap();
        let rep = vault.password_health().unwrap();
        assert_eq!(rep.total_items, 3);
        assert!(rep.weak_count >= 1);
        assert!(rep.reused_count >= 2);
    }

    #[test]
    fn encrypted_backup_roundtrip() {
        let (dir, vault) = test_vault();
        let mut a = VaultItem::new("A", Some("u".into()), "pw-a");
        a.url = Some("https://a.example".into());
        vault.add_item(&a).unwrap();
        vault
            .add_item(&VaultItem::new("B", None, "pw-b"))
            .unwrap();

        let blob = vault
            .export_encrypted_backup("export-passphrase-ok")
            .unwrap();
        assert!(!blob.is_empty());

        // Wrong passphrase fails
        let dest_path = dir.path().join("restore.vault");
        let dest = Vault::create(&dest_path, "other-master-password").unwrap();
        assert!(dest
            .import_encrypted_backup(&blob, "wrong-passphrase!", false)
            .is_err());

        let n = dest
            .import_encrypted_backup(&blob, "export-passphrase-ok", false)
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(dest.list_items().unwrap().len(), 2);
        assert_eq!(dest.get_item(&a.id).unwrap().password, "pw-a");

        // Merge skip existing
        let n2 = dest
            .import_encrypted_backup(&blob, "export-passphrase-ok", true)
            .unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn cannot_create_over_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("exists.vault");
        Vault::create(&path, "pw1").unwrap();
        assert!(matches!(
            Vault::create(&path, "pw2"),
            Err(VaultError::VaultAlreadyExists)
        ));
    }

    #[test]
    fn disk_bytes_do_not_contain_plaintext_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.vault");
        let vault = Vault::create(&path, "master-xyz").unwrap();
        let item = VaultItem::new("Bank", None, "PLAINTEXT_PASSWORD_SHOULD_NOT_LEAK");
        vault.add_item(&item).unwrap();
        drop(vault);

        let raw = std::fs::read(&path).unwrap();
        let as_str = String::from_utf8_lossy(&raw);
        assert!(
            !as_str.contains("PLAINTEXT_PASSWORD_SHOULD_NOT_LEAK"),
            "password must not appear in cleartext on disk"
        );
    }

    #[test]
    fn enclave_wrap_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("enclave.vault");
        {
            let v = Vault::create(&path, "master-enclave-pass").unwrap();
            let blob = v.wrap_master_key_for_enclave().unwrap();
            Vault::save_enclave_blob(&path, &blob).unwrap();
            let item = VaultItem::new("Site", None, "secret");
            v.add_item(&item).unwrap();
        }
        let mut v = Vault::open_with_password(&path, "master-enclave-pass").unwrap();
        assert!(!v.is_unlocked());
        let blob = Vault::load_enclave_blob(&path).unwrap().expect("sidecar");
        v.unlock_with_enclave_blob(&blob).unwrap();
        assert!(v.is_unlocked());
        assert_eq!(v.list_items().unwrap().len(), 1);
    }
}
