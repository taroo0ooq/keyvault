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
use crate::vault_crypto::{
    create_key_verifier, decrypt, encrypt, verify_master_key, CipherAlgorithm, DEFAULT_CIPHER,
};

/// Schema version embedded in vault metadata.
pub const SCHEMA_VERSION: i32 = 1;

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
    last_used_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_items_updated ON vault_items(updated_at);
"#;

/// Plaintext view of a vault item (zeroize password/notes after use in UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
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
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            last_used_at: None,
        }
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

        let conn = Connection::open(&path)?;
        conn.execute_batch(SCHEMA_SQL)?;

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
        set_meta(&conn, "created_at", &Utc::now().to_rfc3339())?;

        Ok(Self {
            path,
            conn,
            master_key: Some(master_key),
        })
    }

    /// Open an existing vault file (locked until [`Vault::unlock`]).
    pub fn open(path: impl AsRef<Path>) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(VaultError::VaultNotFound);
        }
        let conn = Connection::open(&path)?;
        // Ensure schema exists for older empty files.
        conn.execute_batch(SCHEMA_SQL)?;
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
    pub fn unlock(&mut self, master_password: &str) -> VaultResult<()> {
        if self.master_key.is_some() {
            return Err(VaultError::VaultAlreadyUnlocked);
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
        let tags_json = serde_json::to_string(&item.tags)?;
        let tags_enc = encrypt(key, tags_json.as_bytes(), aad, DEFAULT_CIPHER)?;

        self.conn.execute(
            r#"INSERT INTO vault_items
               (id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                created_at, updated_at, last_used_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
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
            ],
        )?;
        Ok(())
    }

    /// Fetch and decrypt a single item by id.
    pub fn get_item(&self, id: &str) -> VaultResult<VaultItem> {
        let key = self.key()?;
        let mut stmt = self.conn.prepare(
            r#"SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                      created_at, updated_at, last_used_at
               FROM vault_items WHERE id = ?1"#,
        )?;
        let row = stmt
            .query_row(params![id], |row| {
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
                ))
            })
            .optional()?
            .ok_or_else(|| VaultError::ItemNotFound(id.into()))?;

        decrypt_row(key, row)
    }

    /// List all items (decrypted). Prefer search for large vaults (Phase 2).
    pub fn list_items(&self) -> VaultResult<Vec<VaultItem>> {
        let key = self.key()?;
        let mut stmt = self.conn.prepare(
            r#"SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc,
                      created_at, updated_at, last_used_at
               FROM vault_items ORDER BY updated_at DESC"#,
        )?;
        let rows = stmt.query_map([], |row| {
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
            ))
        })?;

        let mut items = Vec::new();
        for r in rows {
            items.push(decrypt_row(key, r?)?);
        }
        Ok(items)
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
        // Delete + insert keeps encryption path consistent; could be single UPDATE.
        self.delete_item(&item.id)?;
        let mut updated = item.clone();
        updated.updated_at = Utc::now();
        self.add_item(&updated)
    }

    pub fn delete_item(&self, id: &str) -> VaultResult<()> {
        let _ = self.key()?;
        let n = self
            .conn
            .execute("DELETE FROM vault_items WHERE id = ?1", params![id])?;
        if n == 0 {
            return Err(VaultError::ItemNotFound(id.into()));
        }
        Ok(())
    }

    /// Active cipher used for new records.
    pub fn default_cipher(&self) -> CipherAlgorithm {
        DEFAULT_CIPHER
    }
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
);

fn decrypt_row(key: &MasterKey, row: RawRow) -> VaultResult<VaultItem> {
    let (id, title_enc, username_enc, password_enc, url_enc, notes_enc, tags_enc, created, updated, last_used) =
        row;
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
    })
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
        let mut v = Vault::open(&path).unwrap();
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
        let mut v = Vault::open(&path).unwrap();
        assert!(matches!(
            v.unlock("incorrect-password"),
            Err(VaultError::AuthenticationFailed)
        ));
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
        assert!(matches!(
            vault.get_item(&item.id),
            Err(VaultError::ItemNotFound(_))
        ));
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
}
