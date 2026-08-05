//! KeyVault desktop shell — Tauri commands over `vault-core`.
//!
//! All cryptography stays in Rust. The webview only receives decrypted
//! item views while the vault session is unlocked, and never implements crypto.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use vault_core::{
    generate_password, score_password, EntropyScore, PasswordPolicy, Vault, VaultItem,
};

/// Default idle lock timeout (seconds). Product default: 5 minutes.
const DEFAULT_AUTO_LOCK_SECS: u64 = 300;
/// Clear clipboard this many seconds after copying a password.
const CLIPBOARD_CLEAR_SECS: u64 = 30;
/// Minimum master password length for create.
const MIN_MASTER_LEN: usize = 12;
/// Minimum unlock PIN length when PIN mode is used (product: ≥8).
const MIN_PIN_LEN: usize = 8;

/// Process-local unlocked vault session (never shared outside the app).
struct VaultSession {
    path: PathBuf,
    vault: Vault,
    last_activity: Instant,
    auto_lock_secs: u64,
}

struct AppState {
    session: Mutex<Option<VaultSession>>,
    /// Monotonic counter used to cancel stale clipboard-clear tasks.
    clipboard_epoch: AtomicU64,
}

fn map_err(e: impl ToString) -> String {
    e.to_string()
}

fn default_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("KeyVault")
        .join("vault.db")
}

fn touch(session: &mut VaultSession) {
    session.last_activity = Instant::now();
}

fn maybe_auto_lock(session: &mut Option<VaultSession>) -> bool {
    let Some(s) = session.as_ref() else {
        return false;
    };
    if s.last_activity.elapsed() >= Duration::from_secs(s.auto_lock_secs) {
        if let Some(mut s) = session.take() {
            s.vault.lock();
        }
        return true;
    }
    false
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionStatus {
    unlocked: bool,
    path: Option<String>,
    auto_lock_secs: u64,
    idle_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemInput {
    id: Option<String>,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    /// Base32 TOTP secret or otpauth:// URI (optional).
    totp: Option<String>,
    tags: Option<Vec<String>>,
}

#[tauri::command]
fn default_vault_path() -> String {
    default_path().to_string_lossy().into_owned()
}

#[tauri::command]
fn session_status(state: State<'_, AppState>) -> SessionStatus {
    let mut guard = state.session.lock().expect("session lock");
    if maybe_auto_lock(&mut guard) {
        return SessionStatus {
            unlocked: false,
            path: None,
            auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
            idle_secs: 0,
        };
    }
    match guard.as_ref() {
        Some(s) => SessionStatus {
            unlocked: s.vault.is_unlocked(),
            path: Some(s.path.to_string_lossy().into_owned()),
            auto_lock_secs: s.auto_lock_secs,
            idle_secs: s.last_activity.elapsed().as_secs(),
        },
        None => SessionStatus {
            unlocked: false,
            path: None,
            auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
            idle_secs: 0,
        },
    }
}

#[tauri::command]
fn touch_activity(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().expect("session lock");
    if maybe_auto_lock(&mut guard) {
        return Err("vault auto-locked due to inactivity".into());
    }
    if let Some(s) = guard.as_mut() {
        touch(s);
    }
    Ok(())
}

#[tauri::command]
fn set_auto_lock_secs(state: State<'_, AppState>, secs: u64) -> Result<(), String> {
    let secs = secs.clamp(30, 86_400);
    let mut guard = state.session.lock().expect("session lock");
    if let Some(s) = guard.as_mut() {
        s.auto_lock_secs = secs;
        touch(s);
    }
    Ok(())
}

fn pin_to_secret(pin: &str) -> Result<String, String> {
    if pin.len() < MIN_PIN_LEN || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("PIN must be at least {MIN_PIN_LEN} digits"));
    }
    // Domain-separated secret so PIN vaults never collide with password vaults.
    Ok(format!("kv-pin-v1:{pin}"))
}

fn enroll_enclave(path: &Path, vault: &Vault) {
    if let Ok(blob) = vault.wrap_master_key_for_enclave() {
        let _ = Vault::save_enclave_blob(path, &blob);
    }
}

fn open_session(
    state: &AppState,
    path: PathBuf,
    master_password: &str,
    create: bool,
) -> Result<(), String> {
    if create {
        if master_password.len() < MIN_MASTER_LEN && !master_password.starts_with("kv-pin-v1:") {
            return Err(format!(
                "master password must be at least {MIN_MASTER_LEN} characters"
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(map_err)?;
        }
        let vault = Vault::create(&path, master_password).map_err(map_err)?;
        enroll_enclave(&path, &vault);
        let mut guard = state.session.lock().expect("session lock");
        *guard = Some(VaultSession {
            path,
            vault,
            last_activity: Instant::now(),
            auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
        });
    } else {
        if !path.exists() {
            return Err(format!("vault not found: {}", path.display()));
        }
        let mut vault = Vault::open_with_password(&path, master_password).map_err(map_err)?;
        vault.unlock(master_password).map_err(map_err)?;
        enroll_enclave(&path, &vault);
        let mut guard = state.session.lock().expect("session lock");
        *guard = Some(VaultSession {
            path,
            vault,
            last_activity: Instant::now(),
            auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
        });
    }
    Ok(())
}

#[tauri::command]
fn create_vault(
    state: State<'_, AppState>,
    path: String,
    master_password: String,
) -> Result<(), String> {
    open_session(
        &state,
        PathBuf::from(path.trim()),
        &master_password,
        true,
    )
}

#[tauri::command]
fn unlock_vault(
    state: State<'_, AppState>,
    path: String,
    master_password: String,
) -> Result<(), String> {
    open_session(
        &state,
        PathBuf::from(path.trim()),
        &master_password,
        false,
    )
}

/// Unlock using a numeric PIN (product minimum 8 digits).
/// Same KDF path as master password — PIN never leaves the device.
#[tauri::command]
fn unlock_with_pin(state: State<'_, AppState>, path: String, pin: String) -> Result<(), String> {
    let secret = pin_to_secret(&pin)?;
    open_session(&state, PathBuf::from(path.trim()), &secret, false)
}

#[tauri::command]
fn create_with_pin(state: State<'_, AppState>, path: String, pin: String) -> Result<(), String> {
    let secret = pin_to_secret(&pin)?;
    open_session(&state, PathBuf::from(path.trim()), &secret, true)
}

/// Whether an OS-enclave quick-unlock sidecar exists for this vault path.
#[tauri::command]
fn enclave_available(path: String) -> bool {
    let path = PathBuf::from(path.trim());
    Vault::enclave_sidecar_path(path).exists()
}

/// Unlock using OS-protected master key wrap (DPAPI / software-dev).
/// Host apps should gate this behind biometrics / Windows Hello when available.
#[tauri::command]
fn unlock_with_enclave(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let path = PathBuf::from(path.trim());
    if !path.exists() {
        return Err(format!("vault not found: {}", path.display()));
    }
    let blob = Vault::load_enclave_blob(&path)
        .map_err(map_err)?
        .ok_or_else(|| "no enclave sidecar; unlock with password once to enroll".to_string())?;
    let mut vault = Vault::open(&path).map_err(map_err)?;
    vault.unlock_with_enclave_blob(&blob).map_err(map_err)?;
    let mut guard = state.session.lock().expect("session lock");
    *guard = Some(VaultSession {
        path,
        vault,
        last_activity: Instant::now(),
        auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
    });
    Ok(())
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().expect("session lock");
    if let Some(session) = guard.as_mut() {
        session.vault.lock();
    }
    *guard = None;
    // Invalidate any pending clipboard clears.
    state.clipboard_epoch.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn with_vault<F, T>(state: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce(&Vault) -> Result<T, String>,
{
    let mut guard = state.session.lock().expect("session lock");
    if maybe_auto_lock(&mut guard) {
        return Err("vault auto-locked due to inactivity".into());
    }
    let session = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;
    if !session.vault.is_unlocked() {
        return Err("vault is locked".into());
    }
    touch(session);
    f(&session.vault)
}

#[tauri::command]
fn list_items(state: State<'_, AppState>) -> Result<Vec<VaultItem>, String> {
    with_vault(&state, |v| v.list_items().map_err(map_err))
}

#[tauri::command]
fn search_items(state: State<'_, AppState>, query: String) -> Result<Vec<VaultItem>, String> {
    with_vault(&state, |v| v.search(&query).map_err(map_err))
}

#[tauri::command]
fn get_item(state: State<'_, AppState>, id: String) -> Result<VaultItem, String> {
    with_vault(&state, |v| v.get_item(&id).map_err(map_err))
}

#[tauri::command]
fn save_item(state: State<'_, AppState>, item: ItemInput) -> Result<VaultItem, String> {
    if item.title.trim().is_empty() {
        return Err("title is required".into());
    }
    if item.password.is_empty() {
        return Err("password is required".into());
    }

    let mut guard = state.session.lock().expect("session lock");
    if maybe_auto_lock(&mut guard) {
        return Err("vault auto-locked due to inactivity".into());
    }
    let session = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;
    if !session.vault.is_unlocked() {
        return Err("vault is locked".into());
    }
    touch(session);

    let mut vault_item = if let Some(id) = item.id.filter(|s| !s.is_empty()) {
        let mut existing = session.vault.get_item(&id).map_err(map_err)?;
        existing.title = item.title;
        existing.username = item.username.filter(|s| !s.is_empty());
        existing.password = item.password;
        existing.url = item.url.filter(|s| !s.is_empty());
        existing.notes = item.notes.filter(|s| !s.is_empty());
        existing.totp = item
            .totp
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vault_core::normalize_totp_secret(&s));
        existing.tags = item.tags.unwrap_or_default();
        existing.updated_at = chrono::Utc::now();
        existing
    } else {
        let mut created = VaultItem::new(
            item.title,
            item.username.filter(|s| !s.is_empty()),
            item.password,
        );
        created.url = item.url.filter(|s| !s.is_empty());
        created.notes = item.notes.filter(|s| !s.is_empty());
        created.totp = item
            .totp
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vault_core::normalize_totp_secret(&s));
        created.tags = item.tags.unwrap_or_default();
        created
    };

    if session.vault.get_item(&vault_item.id).is_ok() {
        session.vault.update_item(&vault_item).map_err(map_err)?;
    } else {
        session.vault.add_item(&vault_item).map_err(map_err)?;
    }

    vault_item = session.vault.get_item(&vault_item.id).map_err(map_err)?;
    Ok(vault_item)
}

#[tauri::command]
fn delete_item(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_vault(&state, |v| v.delete_item(&id).map_err(map_err))
}

#[tauri::command]
fn list_trash(state: State<'_, AppState>) -> Result<Vec<VaultItem>, String> {
    with_vault(&state, |v| v.list_trash().map_err(map_err))
}

#[tauri::command]
fn restore_item(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_vault(&state, |v| v.restore_item(&id).map_err(map_err))
}

#[tauri::command]
fn purge_item(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_vault(&state, |v| v.purge_item(&id).map_err(map_err))
}

#[tauri::command]
fn empty_trash(state: State<'_, AppState>) -> Result<usize, String> {
    with_vault(&state, |v| v.empty_trash().map_err(map_err))
}

/// Export portable encrypted backup (separate passphrase, min 12 chars).
#[tauri::command]
fn export_backup(state: State<'_, AppState>, passphrase: String) -> Result<String, String> {
    with_vault(&state, |v| {
        v.export_encrypted_backup(&passphrase).map_err(map_err)
    })
}

/// Import portable encrypted backup. `merge=true` skips existing IDs.
#[tauri::command]
fn import_backup(
    state: State<'_, AppState>,
    passphrase: String,
    backup: String,
    merge: bool,
) -> Result<usize, String> {
    with_vault(&state, |v| {
        v.import_encrypted_backup(&backup, &passphrase, merge)
            .map_err(map_err)
    })
}

/// Change master password (re-encrypts vault). Invalidates OS enclave quick-unlock.
#[tauri::command]
fn change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(|e| e.to_string())?;
    let session = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;
    touch(session);
    let path = session.path.clone();
    session
        .vault
        .change_master_password(&current_password, &new_password)
        .map_err(map_err)?;
    // Defense in depth: core also clears sidecar; ensure gone on desktop.
    let _ = Vault::clear_enclave_sidecar(&path);
    Ok(())
}

/// Current TOTP code for an item id (secret not returned).
#[tauri::command]
fn item_totp_code(
    state: State<'_, AppState>,
    id: String,
) -> Result<vault_core::TotpCode, String> {
    with_vault(&state, |v| v.totp_code_for_item(&id).map_err(map_err))
}

/// Import Chrome/Bitwarden-style CSV into the unlocked vault.
#[tauri::command]
fn import_csv(state: State<'_, AppState>, csv: String) -> Result<usize, String> {
    with_vault(&state, |v| v.import_csv(&csv).map_err(map_err))
}

/// Export vault items as Chrome-compatible CSV (contains secrets).
#[tauri::command]
fn export_csv(state: State<'_, AppState>) -> Result<String, String> {
    with_vault(&state, |v| v.export_csv().map_err(map_err))
}

/// Offline password health report (weak + reused).
#[tauri::command]
fn password_health(state: State<'_, AppState>) -> Result<vault_core::PasswordHealthReport, String> {
    with_vault(&state, |v| v.password_health().map_err(map_err))
}

/// Optional HIBP k-anonymity check via local vault_daemon (requires network + daemon).
#[tauri::command]
fn check_pwned_via_daemon(id: String) -> Result<serde_json::Value, String> {
    daemon_post(
        "/v1/health/pwned",
        serde_json::json!({ "id": id }),
    )
}

#[tauri::command(rename = "generate_password")]
fn generate_password_cmd(policy: PasswordPolicy) -> Result<String, String> {
    generate_password(&policy).map_err(map_err)
}

#[tauri::command(rename = "score_password")]
fn score_password_cmd(password: String) -> Result<EntropyScore, String> {
    Ok(score_password(&password))
}

#[tauri::command]
fn ensure_parent_dir(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(map_err)?;
    }
    Ok(())
}

const DEFAULT_DAEMON: &str = "http://127.0.0.1:8080";

fn daemon_get(path: &str) -> Result<serde_json::Value, String> {
    let url = format!("{DEFAULT_DAEMON}{path}");
    ureq::get(&url)
        .timeout(Duration::from_secs(5))
        .call()
        .map_err(map_err)?
        .into_json()
        .map_err(map_err)
}

fn daemon_post(path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
    let url = format!("{DEFAULT_DAEMON}{path}");
    ureq::post(&url)
        .timeout(Duration::from_secs(15))
        .send_json(body)
        .map_err(map_err)?
        .into_json()
        .map_err(map_err)
}

/// Phase 4: tunnel status from local vault_daemon (must be running).
#[tauri::command]
fn daemon_tunnel_status() -> Result<serde_json::Value, String> {
    daemon_get("/v1/tunnel/status")
}

#[tauri::command]
fn daemon_tunnel_start(provider: String, public_url: Option<String>) -> Result<serde_json::Value, String> {
    let mut body = serde_json::json!({ "provider": provider });
    if let Some(u) = public_url.filter(|s| !s.is_empty()) {
        body["public_url"] = serde_json::json!(u);
    }
    daemon_post("/v1/tunnel/start", body)
}

#[tauri::command]
fn daemon_tunnel_stop() -> Result<serde_json::Value, String> {
    daemon_post("/v1/tunnel/stop", serde_json::json!({}))
}

#[tauri::command]
fn daemon_pairing_create() -> Result<serde_json::Value, String> {
    daemon_post("/v1/pairing/create", serde_json::json!({}))
}

#[tauri::command]
fn daemon_pairing_devices() -> Result<serde_json::Value, String> {
    daemon_get("/v1/pairing/devices")
}

#[tauri::command]
fn daemon_auth_mode() -> Result<serde_json::Value, String> {
    daemon_get("/v1/auth/mode")
}

/// Copy secret to clipboard and schedule clear after [`CLIPBOARD_CLEAR_SECS`].
#[tauri::command]
fn copy_secret(app: AppHandle, state: State<'_, AppState>, secret: String) -> Result<u64, String> {
    {
        let mut guard = state.session.lock().expect("session lock");
        if maybe_auto_lock(&mut guard) {
            return Err("vault auto-locked due to inactivity".into());
        }
        if let Some(s) = guard.as_mut() {
            touch(s);
        }
    }

    let mut clipboard = arboard::Clipboard::new().map_err(map_err)?;
    clipboard.set_text(&secret).map_err(map_err)?;

    let epoch = state.clipboard_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    let clear_after = CLIPBOARD_CLEAR_SECS;
    let app_handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(clear_after));
        let state = app_handle.state::<AppState>();
        if state.clipboard_epoch.load(Ordering::SeqCst) != epoch {
            return; // superseded by a later copy or lock
        }
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text("");
        }
        let _ = app_handle.emit("clipboard-cleared", clear_after);
    });

    Ok(clear_after)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            session: Mutex::new(None),
            clipboard_epoch: AtomicU64::new(0),
        })
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            // Idle auto-lock poller (every 15s).
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(15));
                let state = handle.state::<AppState>();
                let mut guard = state.session.lock().expect("session lock");
                if maybe_auto_lock(&mut guard) {
                    let _ = handle.emit("vault-auto-locked", ());
                    state.clipboard_epoch.fetch_add(1, Ordering::SeqCst);
                    if let Ok(mut cb) = arboard::Clipboard::new() {
                        let _ = cb.set_text("");
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            default_vault_path,
            session_status,
            touch_activity,
            set_auto_lock_secs,
            create_vault,
            unlock_vault,
            create_with_pin,
            unlock_with_pin,
            enclave_available,
            unlock_with_enclave,
            lock_vault,
            list_items,
            search_items,
            get_item,
            save_item,
            export_backup,
            import_backup,
            change_master_password,
            import_csv,
            export_csv,
            password_health,
            check_pwned_via_daemon,
            item_totp_code,
            delete_item,
            list_trash,
            restore_item,
            purge_item,
            empty_trash,
            generate_password_cmd,
            score_password_cmd,
            ensure_parent_dir,
            copy_secret,
            daemon_tunnel_status,
            daemon_tunnel_start,
            daemon_tunnel_stop,
            daemon_pairing_create,
            daemon_pairing_devices,
            daemon_auth_mode,
        ])
        .run(tauri::generate_context!())
        .expect("error while running KeyVault");
}
