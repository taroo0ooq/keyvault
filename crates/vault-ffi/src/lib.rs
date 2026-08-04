//! C-compatible FFI surface for `vault-core`.
//!
//! Intended for Flutter (`dart:ffi`) and other non-Rust clients.
//! All crypto stays in Rust; callers only exchange UTF-8 strings / JSON.
//!
//! # Ownership
//!
//! Functions that return `*mut c_char` allocate with the system allocator.
//! Callers **must** free them with [`kv_string_free`].

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use vault_core::{
    generate_password, health_check, score_password, PasswordPolicy, Vault, VaultItem,
};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static SESSIONS: Lazy<Mutex<HashMap<u64, Vault>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn cstr_to_str<'a>(p: *const c_char) -> Result<&'a str, String> {
    if p.is_null() {
        return Err("null pointer".into());
    }
    // SAFETY: caller guarantees null-terminated C string or null (checked).
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().map_err(|e| e.to_string())
}

fn ok_string(s: impl Into<String>) -> *mut c_char {
    match CString::new(s.into()) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn err_string(e: impl ToString) -> *mut c_char {
    ok_string(format!("ERR:{}", e.to_string()))
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must be null or a pointer previously returned by vault-ffi.
#[no_mangle]
pub unsafe extern "C" fn kv_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: paired with CString::into_raw from this crate.
    let _ = unsafe { CString::from_raw(s) };
}

/// Library version string (free with [`kv_string_free`]).
#[no_mangle]
pub extern "C" fn kv_version() -> *mut c_char {
    ok_string(vault_core::VERSION)
}

/// Health JSON (free with [`kv_string_free`]).
#[no_mangle]
pub extern "C" fn kv_health_json() -> *mut c_char {
    match serde_json::to_string(&health_check()) {
        Ok(j) => ok_string(j),
        Err(e) => err_string(e),
    }
}

/// Create vault at path; returns session handle as decimal string, or `ERR:…`.
#[no_mangle]
pub extern "C" fn kv_vault_create(path: *const c_char, master_password: *const c_char) -> *mut c_char {
    let path = match cstr_to_str(path) {
        Ok(s) => PathBuf::from(s),
        Err(e) => return err_string(e),
    };
    let pw = match cstr_to_str(master_password) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    match Vault::create(&path, pw) {
        Ok(v) => {
            if let Ok(blob) = v.wrap_master_key_for_enclave() {
                let _ = Vault::save_enclave_blob(&path, &blob);
            }
            let h = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
            SESSIONS.lock().insert(h, v);
            ok_string(h.to_string())
        }
        Err(e) => err_string(e),
    }
}

/// Open + unlock vault; returns session handle or `ERR:…`.
#[no_mangle]
pub extern "C" fn kv_vault_unlock(path: *const c_char, master_password: *const c_char) -> *mut c_char {
    let path = match cstr_to_str(path) {
        Ok(s) => PathBuf::from(s),
        Err(e) => return err_string(e),
    };
    let pw = match cstr_to_str(master_password) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    let mut v = match Vault::open(&path) {
        Ok(v) => v,
        Err(e) => return err_string(e),
    };
    if let Err(e) = v.unlock(pw) {
        return err_string(e);
    }
    if let Ok(blob) = v.wrap_master_key_for_enclave() {
        let _ = Vault::save_enclave_blob(&path, &blob);
    }
    let h = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    SESSIONS.lock().insert(h, v);
    ok_string(h.to_string())
}

/// Lock and drop session. `handle` is decimal string from create/unlock.
#[no_mangle]
pub extern "C" fn kv_vault_lock(handle: *const c_char) -> *mut c_char {
    let h = match parse_handle(handle) {
        Ok(h) => h,
        Err(e) => return err_string(e),
    };
    if let Some(mut v) = SESSIONS.lock().remove(&h) {
        v.lock();
    }
    ok_string("ok")
}

fn parse_handle(handle: *const c_char) -> Result<u64, String> {
    let s = cstr_to_str(handle)?;
    s.parse::<u64>().map_err(|e| e.to_string())
}

/// List items as JSON array (free with [`kv_string_free`]).
#[no_mangle]
pub extern "C" fn kv_vault_list_json(handle: *const c_char) -> *mut c_char {
    let h = match parse_handle(handle) {
        Ok(h) => h,
        Err(e) => return err_string(e),
    };
    let sessions = SESSIONS.lock();
    let Some(v) = sessions.get(&h) else {
        return err_string("invalid handle");
    };
    match v.list_items() {
        Ok(items) => match serde_json::to_string(&items) {
            Ok(j) => ok_string(j),
            Err(e) => err_string(e),
        },
        Err(e) => err_string(e),
    }
}

/// Search items as JSON array.
#[no_mangle]
pub extern "C" fn kv_vault_search_json(handle: *const c_char, query: *const c_char) -> *mut c_char {
    let h = match parse_handle(handle) {
        Ok(h) => h,
        Err(e) => return err_string(e),
    };
    let q = match cstr_to_str(query) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    let sessions = SESSIONS.lock();
    let Some(v) = sessions.get(&h) else {
        return err_string("invalid handle");
    };
    match v.search(q) {
        Ok(items) => match serde_json::to_string(&items) {
            Ok(j) => ok_string(j),
            Err(e) => err_string(e),
        },
        Err(e) => err_string(e),
    }
}

#[derive(serde::Deserialize)]
struct ItemIn {
    #[serde(default)]
    id: String,
    title: String,
    #[serde(default)]
    username: Option<String>,
    password: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// Save item from JSON body; returns saved item JSON.
///
/// Accepts either a full `VaultItem` or a slim object with
/// `{id?, title, username?, password, url?, notes?, tags?}`.
#[no_mangle]
pub extern "C" fn kv_vault_save_json(handle: *const c_char, item_json: *const c_char) -> *mut c_char {
    let h = match parse_handle(handle) {
        Ok(h) => h,
        Err(e) => return err_string(e),
    };
    let raw = match cstr_to_str(item_json) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    let input: ItemIn = match serde_json::from_str(raw) {
        Ok(i) => i,
        Err(e) => return err_string(e),
    };
    let sessions = SESSIONS.lock();
    let Some(v) = sessions.get(&h) else {
        return err_string("invalid handle");
    };

    let item_id = if !input.id.is_empty() && v.get_item(&input.id).is_ok() {
        let mut existing = match v.get_item(&input.id) {
            Ok(i) => i,
            Err(e) => return err_string(e),
        };
        existing.title = input.title;
        existing.username = input.username.filter(|s| !s.is_empty());
        existing.password = input.password;
        existing.url = input.url.filter(|s| !s.is_empty());
        existing.notes = input.notes.filter(|s| !s.is_empty());
        existing.totp = input
            .totp
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vault_core::normalize_totp_secret(&s));
        existing.tags = input.tags;
        if let Err(e) = v.update_item(&existing) {
            return err_string(e);
        }
        existing.id
    } else {
        let mut created = VaultItem::new(
            input.title,
            input.username.filter(|s| !s.is_empty()),
            input.password,
        );
        created.url = input.url.filter(|s| !s.is_empty());
        created.notes = input.notes.filter(|s| !s.is_empty());
        created.totp = input
            .totp
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vault_core::normalize_totp_secret(&s));
        created.tags = input.tags;
        if let Err(e) = v.add_item(&created) {
            return err_string(e);
        }
        created.id
    };

    match v.get_item(&item_id) {
        Ok(saved) => match serde_json::to_string(&saved) {
            Ok(j) => ok_string(j),
            Err(e) => err_string(e),
        },
        Err(e) => err_string(e),
    }
}

/// Current TOTP code JSON for item id: `{code, period_secs, remaining_secs, digits}`.
#[no_mangle]
pub extern "C" fn kv_vault_totp_json(handle: *const c_char, id: *const c_char) -> *mut c_char {
    let h = match parse_handle(handle) {
        Ok(h) => h,
        Err(e) => return err_string(e),
    };
    let id = match cstr_to_str(id) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    let sessions = SESSIONS.lock();
    let Some(v) = sessions.get(&h) else {
        return err_string("invalid handle");
    };
    match v.totp_code_for_item(id) {
        Ok(code) => match serde_json::to_string(&code) {
            Ok(j) => ok_string(j),
            Err(e) => err_string(e),
        },
        Err(e) => err_string(e),
    }
}

/// Delete item by id.
#[no_mangle]
pub extern "C" fn kv_vault_delete(handle: *const c_char, id: *const c_char) -> *mut c_char {
    let h = match parse_handle(handle) {
        Ok(h) => h,
        Err(e) => return err_string(e),
    };
    let id = match cstr_to_str(id) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    let sessions = SESSIONS.lock();
    let Some(v) = sessions.get(&h) else {
        return err_string("invalid handle");
    };
    match v.delete_item(id) {
        Ok(()) => ok_string("ok"),
        Err(e) => err_string(e),
    }
}

/// Generate password from policy JSON `{"length":20,"lowercase":true,...}`.
#[no_mangle]
pub extern "C" fn kv_generate_password_json(policy_json: *const c_char) -> *mut c_char {
    let raw = match cstr_to_str(policy_json) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    let policy: PasswordPolicy = if raw.trim().is_empty() || raw.trim() == "{}" {
        PasswordPolicy::default()
    } else {
        match serde_json::from_str(raw) {
            Ok(p) => p,
            Err(_) => {
                // Merge with defaults so partial JSON works from mobile.
                let mut base = serde_json::to_value(PasswordPolicy::default()).unwrap_or_default();
                if let Ok(serde_json::Value::Object(patch)) = serde_json::from_str::<serde_json::Value>(raw)
                {
                    if let serde_json::Value::Object(ref mut map) = base {
                        for (k, v) in patch {
                            map.insert(k, v);
                        }
                    }
                    match serde_json::from_value(base) {
                        Ok(p) => p,
                        Err(e) => return err_string(e),
                    }
                } else {
                    return err_string("invalid policy json");
                }
            }
        }
    };
    match generate_password(&policy) {
        Ok(p) => ok_string(p),
        Err(e) => err_string(e),
    }
}

/// Unlock via OS-enclave sidecar (`{path}.enclave.json`). Returns handle or ERR.
#[no_mangle]
pub extern "C" fn kv_vault_unlock_enclave(path: *const c_char) -> *mut c_char {
    let path = match cstr_to_str(path) {
        Ok(s) => PathBuf::from(s),
        Err(e) => return err_string(e),
    };
    let blob = match Vault::load_enclave_blob(&path) {
        Ok(Some(b)) => b,
        Ok(None) => return err_string("no enclave sidecar"),
        Err(e) => return err_string(e),
    };
    let mut v = match Vault::open(&path) {
        Ok(v) => v,
        Err(e) => return err_string(e),
    };
    if let Err(e) = v.unlock_with_enclave_blob(&blob) {
        return err_string(e);
    }
    let h = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    SESSIONS.lock().insert(h, v);
    ok_string(h.to_string())
}

/// 1 if enclave sidecar exists, else 0 (returned as string).
#[no_mangle]
pub extern "C" fn kv_vault_enclave_available(path: *const c_char) -> *mut c_char {
    let path = match cstr_to_str(path) {
        Ok(s) => PathBuf::from(s),
        Err(e) => return err_string(e),
    };
    let exists = Vault::enclave_sidecar_path(path).exists();
    ok_string(if exists { "1" } else { "0" })
}

/// Score password; returns entropy JSON.
#[no_mangle]
pub extern "C" fn kv_score_password_json(password: *const c_char) -> *mut c_char {
    let pw = match cstr_to_str(password) {
        Ok(s) => s,
        Err(e) => return err_string(e),
    };
    match serde_json::to_string(&score_password(pw)) {
        Ok(j) => ok_string(j),
        Err(e) => err_string(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use tempfile::tempdir;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        // SAFETY: pointer returned by vault-ffi; free via kv_string_free.
        let s = unsafe { CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned();
        unsafe { kv_string_free(p) };
        s
    }

    #[test]
    fn create_list_lock_cycle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ffi.vault");
        let path_c = c(path.to_str().unwrap());
        let pw = c("test-master-password-32chars!!");

        let handle = unsafe { take(kv_vault_create(path_c.as_ptr(), pw.as_ptr())) };
        assert!(!handle.starts_with("ERR:"), "{handle}");

        let handle_c = c(&handle);
        let list = unsafe { take(kv_vault_list_json(handle_c.as_ptr())) };
        assert_eq!(list, "[]");

        let item = c(
            r#"{"title":"Test","username":"u","password":"p","totp":"JBSWY3DPEHPK3PXP"}"#,
        );
        let saved = unsafe { take(kv_vault_save_json(handle_c.as_ptr(), item.as_ptr())) };
        assert!(!saved.starts_with("ERR:"), "{saved}");
        assert!(saved.contains("Test"));
        assert!(saved.contains("JBSWY3DPEHPK3PXP"));

        let id: String = serde_json::from_str::<serde_json::Value>(&saved)
            .ok()
            .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()))
            .expect("id");
        let id_c = c(&id);
        let totp = unsafe { take(kv_vault_totp_json(handle_c.as_ptr(), id_c.as_ptr())) };
        assert!(!totp.starts_with("ERR:"), "{totp}");
        assert!(totp.contains("\"code\""), "{totp}");

        let lock = unsafe { take(kv_vault_lock(handle_c.as_ptr())) };
        assert_eq!(lock, "ok");
    }

    #[test]
    fn generate_and_score() {
        let policy = c("{}");
        let pw = unsafe { take(kv_generate_password_json(policy.as_ptr())) };
        assert!(!pw.starts_with("ERR:"), "{pw}");
        assert!(pw.len() >= 8);
        let pwc = c(&pw);
        let score = unsafe { take(kv_score_password_json(pwc.as_ptr())) };
        assert!(score.contains("bits"), "{score}");
    }
}
