//! Local loopback vault daemon.
//!
//! Binds **only** to `127.0.0.1` (never 0.0.0.0). Used by browser extensions,
//! mobile tunnel clients, and the DAST baseline scan against `/health`.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use vault_core::{
    create_pairing_offer, find_device_by_token, generate_password, hash_api_token, health_check,
    issue_device_api_token, score_password, verify_pairing_token, PairedDevice, PairingOffer,
    PairingSecret, PasswordPolicy, TunnelAgent, TunnelConfig, TunnelProvider, Vault, VaultItem,
    DEFAULT_PAIRING_TTL_SECS,
};

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_AUTO_LOCK_SECS: u64 = 300;
/// One-shot reveal: max secrets returned per rolling window.
const REVEAL_MAX_PER_WINDOW: usize = 20;
const REVEAL_WINDOW: Duration = Duration::from_secs(60);
/// Client-facing advisory TTL for how long the secret should be retained in memory.
const REVEAL_TTL_MS: u64 = 15_000;

struct VaultSession {
    path: PathBuf,
    vault: Vault,
    last_activity: Instant,
    auto_lock_secs: u64,
}

struct AppState {
    session: Mutex<Option<VaultSession>>,
    req_count: AtomicU64,
    /// Timestamps of recent secret reveals (rate limit).
    reveal_log: Mutex<Vec<Instant>>,
    reveal_seq: AtomicU64,
    tunnel: TunnelAgent,
    pairing_secret: PairingSecret,
    active_offer: Mutex<Option<PairingOffer>>,
    paired_devices: Mutex<Vec<PairedDevice>>,
    /// SHA-256 of operator token (printed once at startup for local use when tunnel is on).
    operator_token_hash: String,
    /// Force Bearer auth even without tunnel (tests / hardening).
    require_auth: bool,
}

/// Paths that never require Bearer (health / pairing claim / public status).
fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/health"
            | "/health/"
            | "/v1/status"
            | "/v1/tunnel/status"
            | "/v1/pairing/claim"
            | "/v1/pairing/create"
            | "/v1/pairing/devices"
            | "/v1/tunnel/start"
            | "/v1/tunnel/stop"
            | "/v1/auth/mode"
    )
}

/// Vault data paths that must use Bearer when auth is required.
fn is_protected_vault_path(path: &str) -> bool {
    path == "/v1/unlock"
        || path == "/v1/lock"
        || path == "/v1/items"
        || path == "/v1/items/update"
        || path == "/v1/items/delete"
        || path == "/v1/reveal"
        || path == "/v1/generate"
        || path == "/v1/score"
        || path == "/v1/export"
        || path == "/v1/import"
        || path == "/v1/change-password"
        || path == "/v1/import/csv"
        || path == "/v1/export/csv"
        || path == "/v1/health/passwords"
        || path == "/v1/health/pwned"
        || path == "/v1/trash"
        || path == "/v1/items/restore"
        || path == "/v1/items/purge"
        || path == "/v1/trash/empty"
        || path == "/v1/totp"
        || path.starts_with("/v1/search")
}

fn auth_required(state: &AppState) -> bool {
    state.require_auth || state.tunnel.status().running
}

fn extract_bearer(request: &Request) -> Option<String> {
    for h in request.headers() {
        let name = h.field.as_str().to_string();
        if name.eq_ignore_ascii_case("Authorization") {
            let v = h.value.as_str().trim();
            let prefix = "Bearer ";
            if v.len() > prefix.len() && v[..prefix.len()].eq_ignore_ascii_case(prefix) {
                return Some(v[prefix.len()..].trim().to_string());
            }
        }
    }
    None
}

/// Returns Ok(identity) or Err(response).
fn check_bearer(state: &AppState, request: &Request) -> Result<String, Response<std::io::Cursor<Vec<u8>>>> {
    let Some(token) = extract_bearer(request) else {
        return Err(json_response(
            StatusCode(401),
            serde_json::json!({
                "error": "authorization required",
                "hint": "Authorization: Bearer <token> when tunnel is running (or VAULT_DAEMON_REQUIRE_AUTH=1)",
            })
            .to_string(),
        ));
    };
    // hash_api_token + constant-time compare lives in vault_core (api_token_matches).
    if vault_core::api_token_matches(&token, &state.operator_token_hash) {
        return Ok("operator".into());
    }
    let devices = state.paired_devices.lock().expect("devices");
    if let Some(d) = find_device_by_token(&devices, &token) {
        return Ok(d.device_id.clone());
    }
    Err(json_response(
        StatusCode(401),
        serde_json::json!({"error": "invalid bearer token"}).to_string(),
    ))
}

fn main() {
    let bind = env::var("VAULT_DAEMON_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .unwrap_or_else(|_| panic!("invalid VAULT_DAEMON_BIND: {bind}"));

    if !addr.ip().is_loopback() {
        eprintln!("refusing to bind non-loopback address: {addr}");
        std::process::exit(2);
    }

    let server = Server::http(addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        std::process::exit(1);
    });

    let operator_token = issue_device_api_token();
    let operator_token_hash = hash_api_token(&operator_token);
    let require_auth = env::var("VAULT_DAEMON_REQUIRE_AUTH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let state = Arc::new(AppState {
        session: Mutex::new(None),
        req_count: AtomicU64::new(0),
        reveal_log: Mutex::new(Vec::new()),
        reveal_seq: AtomicU64::new(0),
        tunnel: TunnelAgent::new(TunnelConfig {
            provider: TunnelProvider::Cloudflared,
            local_port: addr.port(),
            binary_path: None,
        }),
        pairing_secret: PairingSecret::generate(),
        active_offer: Mutex::new(None),
        paired_devices: Mutex::new(Vec::new()),
        operator_token_hash,
        require_auth,
    });

    println!("vault_daemon listening on http://{addr}");
    println!(
        "endpoints: /health /v1/* vault + /v1/tunnel/* + /v1/pairing/*"
    );
    println!(
        "operator bearer token (save now; required when tunnel is running):\n  {operator_token}"
    );
    if require_auth {
        println!("VAULT_DAEMON_REQUIRE_AUTH=1 — Bearer required for vault routes always");
    }

    for mut request in server.incoming_requests() {
        let n = state.req_count.fetch_add(1, Ordering::Relaxed) + 1;
        let method = request.method().clone();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or(&url).to_string();

        // CORS preflight (loopback only — origin still restricted by bind address).
        if method == Method::Options {
            let _ = request.respond(cors_preflight());
            continue;
        }

        // Auth gate for vault data when tunnel is active (or forced).
        if is_protected_vault_path(&path) && auth_required(&state) {
            if let Err(resp) = check_bearer(&state, &request) {
                let _ = request.respond(resp);
                continue;
            }
        }

        let response = match (method, path.as_str()) {
            (Method::Get, "/health") | (Method::Get, "/health/") => {
                let status = health_check();
                let body = serde_json::to_string_pretty(&status)
                    .unwrap_or_else(|_| r#"{"ok":false}"#.into());
                json_response(StatusCode(200), body)
            }
            (Method::Get, "/") => {
                let body = serde_json::json!({
                    "service": "vault_daemon",
                    "version": vault_core::VERSION,
                    "requests": n,
                    "auth_required": auth_required(&state),
                    "endpoints": [
                        "/health",
                        "/v1/status",
                        "/v1/auth/mode",
                        "/v1/unlock",
                        "/v1/lock",
                        "/v1/items",
                        "/v1/items/update",
                        "/v1/items/delete",
                        "/v1/search",
                        "/v1/reveal",
                        "/v1/generate",
                        "/v1/score",
                        "/v1/export",
                        "/v1/import",
                        "/v1/import/csv",
                        "/v1/export/csv",
                        "/v1/health/passwords",
                        "/v1/health/pwned",
                        "/v1/trash",
                        "/v1/items/restore",
                        "/v1/items/purge",
                        "/v1/trash/empty",
                        "/v1/change-password",
                        "/v1/totp",
                        "/v1/tunnel/status",
                        "/v1/tunnel/start",
                        "/v1/tunnel/stop",
                        "/v1/pairing/create",
                        "/v1/pairing/claim",
                        "/v1/pairing/devices"
                    ],
                    "notes": "loopback only; Bearer required for vault routes when tunnel running",
                })
                .to_string();
                json_response(StatusCode(200), body)
            }
            (Method::Get, "/v1/auth/mode") => json_response(
                StatusCode(200),
                serde_json::json!({
                    "auth_required": auth_required(&state),
                    "tunnel_running": state.tunnel.status().running,
                    "require_auth_env": state.require_auth,
                    "paired_devices": state.paired_devices.lock().expect("d").len(),
                })
                .to_string(),
            ),
            (Method::Get, "/v1/status") => handle_status(&state),
            (Method::Post, "/v1/unlock") => handle_unlock(&state, &mut request),
            (Method::Post, "/v1/lock") => handle_lock(&state),
            (Method::Get, "/v1/items") => handle_list(&state, None),
            (Method::Get, p) if p.starts_with("/v1/search") => {
                let q = url
                    .split('?')
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .find_map(|pair| {
                        let mut it = pair.splitn(2, '=');
                        match (it.next(), it.next()) {
                            (Some("q"), Some(v)) => Some(urlencoding_decode(v)),
                            _ => None,
                        }
                    })
                    .unwrap_or_default();
                handle_list(&state, Some(q))
            }
            (Method::Post, "/v1/reveal") => handle_reveal(&state, &mut request),
            (Method::Post, "/v1/items") => handle_add_item(&state, &mut request),
            (Method::Post, "/v1/items/update") => handle_update_item(&state, &mut request),
            (Method::Post, "/v1/items/delete") => handle_delete_item(&state, &mut request),
            (Method::Post, "/v1/items/restore") => handle_restore_item(&state, &mut request),
            (Method::Post, "/v1/items/purge") => handle_purge_item(&state, &mut request),
            (Method::Get, "/v1/trash") => handle_list_trash(&state),
            (Method::Post, "/v1/trash/empty") => handle_empty_trash(&state),
            (Method::Post, "/v1/export") => handle_export(&state, &mut request),
            (Method::Post, "/v1/import") => handle_import(&state, &mut request),
            (Method::Post, "/v1/import/csv") => handle_import_csv(&state, &mut request),
            (Method::Get, "/v1/export/csv") => handle_export_csv(&state),
            (Method::Get, "/v1/health/passwords") => handle_password_health(&state),
            (Method::Post, "/v1/health/pwned") => handle_pwned_check(&state, &mut request),
            (Method::Post, "/v1/change-password") => handle_change_password(&state, &mut request),
            (Method::Post, "/v1/totp") => handle_totp(&state, &mut request),
            (Method::Post, "/v1/generate") => handle_generate(&mut request),
            (Method::Post, "/v1/score") => handle_score(&mut request),
            (Method::Get, "/v1/tunnel/status") => handle_tunnel_status(&state),
            (Method::Post, "/v1/tunnel/start") => handle_tunnel_start(&state, &mut request, addr.port()),
            (Method::Post, "/v1/tunnel/stop") => handle_tunnel_stop(&state),
            (Method::Post, "/v1/pairing/create") => handle_pairing_create(&state, addr.port()),
            (Method::Post, "/v1/pairing/claim") => handle_pairing_claim(&state, &mut request),
            (Method::Get, "/v1/pairing/devices") => handle_pairing_devices(&state),
            _ => {
                let _ = is_public_path(&path);
                json_response(StatusCode(404), r#"{"error":"not_found"}"#.into())
            }
        };

        if let Err(e) = request.respond(response) {
            eprintln!("respond error: {e}");
        }
    }
}

fn urlencoding_decode(s: &str) -> String {
    // Minimal decode for space and common chars; full crate not required.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
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

fn handle_status(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    let locked_out = maybe_auto_lock(&mut guard);
    let body = if locked_out {
        serde_json::json!({
            "ok": true,
            "unlocked": false,
            "path": null,
            "auto_locked": true,
            "daemon_version": vault_core::VERSION,
        })
    } else if let Some(s) = guard.as_ref() {
        serde_json::json!({
            "ok": true,
            "unlocked": s.vault.is_unlocked(),
            "path": s.path.to_string_lossy(),
            "auto_locked": false,
            "idle_secs": s.last_activity.elapsed().as_secs(),
            "auto_lock_secs": s.auto_lock_secs,
            "daemon_version": vault_core::VERSION,
        })
    } else {
        serde_json::json!({
            "ok": true,
            "unlocked": false,
            "path": null,
            "auto_locked": false,
            "daemon_version": vault_core::VERSION,
        })
    };
    json_response(StatusCode(200), body.to_string())
}

fn handle_unlock(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let path = parsed
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let password = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if path.is_empty() || password.is_empty() {
        return json_response(
            StatusCode(400),
            r#"{"error":"path and password required"}"#.into(),
        );
    }
    let path_buf = PathBuf::from(path);
    let create = parsed
        .get("create")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let result = if create {
        Vault::create(&path_buf, password)
    } else {
        Vault::open(&path_buf).and_then(|mut v| {
            v.unlock(password)?;
            Ok(v)
        })
    };

    match result {
        Ok(vault) => {
            if let Ok(blob) = vault.wrap_master_key_for_enclave() {
                let _ = Vault::save_enclave_blob(&path_buf, &blob);
            }
            let mut guard = state.session.lock().expect("session");
            *guard = Some(VaultSession {
                path: path_buf,
                vault,
                last_activity: Instant::now(),
                auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
            });
            json_response(
                StatusCode(200),
                serde_json::json!({"ok": true, "unlocked": true}).to_string(),
            )
        }
        Err(e) => json_response(
            StatusCode(401),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_lock(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    if let Some(mut s) = guard.take() {
        s.vault.lock();
    }
    json_response(StatusCode(200), r#"{"ok":true,"unlocked":false}"#.into())
}

fn handle_list(
    state: &AppState,
    query: Option<String>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();
    let items: Result<Vec<VaultItem>, _> = match &query {
        Some(q) if !q.is_empty() => session.vault.search(q),
        _ => session.vault.list_items(),
    };
    // Redact passwords in list view for extension sidebar safety.
    match items {
        Ok(list) => {
            let safe: Vec<_> = list
                .into_iter()
                .map(|mut i| {
                    i.password = "••••••••".into();
                    // Redact TOTP secret; clients use POST /v1/totp for codes.
                    if i.totp.is_some() {
                        i.totp = Some("••••••••".into());
                    }
                    i
                })
                .collect();
            json_response(
                StatusCode(200),
                serde_json::to_string(&safe).unwrap_or_else(|_| "[]".into()),
            )
        }
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_add_item(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let title = parsed
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let password = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if title.is_empty() || password.is_empty() {
        return json_response(
            StatusCode(400),
            r#"{"error":"title and password required"}"#.into(),
        );
    }
    let username = parsed
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let url = parsed
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    let mut item = VaultItem::new(title, username, password);
    item.url = url;
    if let Some(n) = parsed.get("notes").and_then(|v| v.as_str()) {
        if !n.is_empty() {
            item.notes = Some(n.to_string());
        }
    }
    if let Some(tags) = parsed.get("tags").and_then(|v| v.as_array()) {
        item.tags = tags
            .iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect();
    }
    if let Some(t) = parsed.get("totp").and_then(|v| v.as_str()) {
        if !t.is_empty() && t != "••••••••" {
            item.totp = Some(vault_core::normalize_totp_secret(t));
        }
    }
    match session.vault.add_item(&item) {
        Ok(()) => json_response(
            StatusCode(200),
            serde_json::json!({
                "ok": true,
                "id": item.id,
                "title": item.title,
            })
            .to_string(),
        ),
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// Update an existing item. Body requires `id`.
/// Omit `password` or pass redacted `••••••••` to keep the current secret.
fn handle_update_item(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return json_response(StatusCode(400), r#"{"error":"id required"}"#.into());
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    let mut item = match session.vault.get_item(id) {
        Ok(i) => i,
        Err(e) => {
            return json_response(
                StatusCode(404),
                serde_json::json!({"error": e.to_string()}).to_string(),
            );
        }
    };

    if let Some(t) = parsed.get("title").and_then(|v| v.as_str()) {
        let t = t.trim();
        if !t.is_empty() {
            item.title = t.to_string();
        }
    }
    if parsed.get("username").is_some() {
        item.username = parsed
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
    }
    if let Some(pw) = parsed.get("password").and_then(|v| v.as_str()) {
        if !pw.is_empty() && pw != "••••••••" && pw != "********" {
            item.password = pw.to_string();
        }
    }
    if parsed.get("url").is_some() {
        item.url = parsed
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
    }
    if parsed.get("notes").is_some() {
        item.notes = parsed
            .get("notes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
    }
    if let Some(tags) = parsed.get("tags").and_then(|v| v.as_array()) {
        item.tags = tags
            .iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect();
    }
    if parsed.get("totp").is_some() {
        let t = parsed
            .get("totp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if t.is_empty() {
            item.totp = None;
        } else if t != "••••••••" && t != "********" {
            item.totp = Some(vault_core::normalize_totp_secret(t));
        }
        // else keep existing secret when redacted placeholder is sent
    }

    match session.vault.update_item(&item) {
        Ok(()) => json_response(
            StatusCode(200),
            serde_json::json!({ "ok": true, "id": item.id, "title": item.title }).to_string(),
        ),
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// Soft-delete item to trash. Body: `{ "id": "..." }`.
fn handle_delete_item(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    item_id_action(state, request, |vault, id| {
        vault.delete_item(id)?;
        Ok(serde_json::json!({ "ok": true, "trashed": true }))
    })
}

/// Restore from trash. Body: `{ "id": "..." }`.
fn handle_restore_item(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    item_id_action(state, request, |vault, id| {
        vault.restore_item(id)?;
        Ok(serde_json::json!({ "ok": true, "restored": true }))
    })
}

/// Permanently purge. Body: `{ "id": "..." }`.
fn handle_purge_item(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    item_id_action(state, request, |vault, id| {
        vault.purge_item(id)?;
        Ok(serde_json::json!({ "ok": true, "purged": true }))
    })
}

fn handle_list_trash(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();
    match session.vault.list_trash() {
        Ok(list) => {
            let safe: Vec<_> = list
                .into_iter()
                .map(|mut i| {
                    i.password = "••••••••".into();
                    if i.totp.is_some() {
                        i.totp = Some("••••••••".into());
                    }
                    i
                })
                .collect();
            json_response(
                StatusCode(200),
                serde_json::to_string(&safe).unwrap_or_else(|_| "[]".into()),
            )
        }
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_empty_trash(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();
    match session.vault.empty_trash() {
        Ok(n) => json_response(
            StatusCode(200),
            serde_json::json!({ "ok": true, "purged": n }).to_string(),
        ),
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn item_id_action<F>(
    state: &AppState,
    request: &mut Request,
    f: F,
) -> Response<std::io::Cursor<Vec<u8>>>
where
    F: FnOnce(&vault_core::Vault, &str) -> Result<serde_json::Value, vault_core::VaultError>,
{
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return json_response(StatusCode(400), r#"{"error":"id required"}"#.into());
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match f(&session.vault, id) {
        Ok(v) => json_response(StatusCode(200), v.to_string()),
        Err(e) => {
            let code = if e.to_string().contains("not found") || e.to_string().contains("NotFound")
            {
                StatusCode(404)
            } else {
                StatusCode(500)
            };
            json_response(
                code,
                serde_json::json!({"error": e.to_string()}).to_string(),
            )
        }
    }
}

/// Export encrypted portable backup.
/// Body: `{ "passphrase": "..." }`
fn handle_export(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let passphrase = parsed
        .get("passphrase")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if passphrase.len() < 12 {
        return json_response(
            StatusCode(400),
            r#"{"error":"passphrase must be at least 12 characters"}"#.into(),
        );
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match session.vault.export_encrypted_backup(passphrase) {
        Ok(backup) => json_response(
            StatusCode(200),
            serde_json::json!({
                "ok": true,
                "format": vault_core::BACKUP_FORMAT,
                "version": vault_core::BACKUP_VERSION,
                "backup": backup,
            })
            .to_string(),
        ),
        Err(e) => json_response(
            StatusCode(400),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// Import encrypted portable backup.
/// Body: `{ "passphrase": "...", "backup": "<base64>", "merge": true }`
fn handle_import(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let passphrase = parsed
        .get("passphrase")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let backup = parsed
        .get("backup")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let merge = parsed
        .get("merge")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if passphrase.is_empty() || backup.is_empty() {
        return json_response(
            StatusCode(400),
            r#"{"error":"passphrase and backup required"}"#.into(),
        );
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match session
        .vault
        .import_encrypted_backup(backup, passphrase, merge)
    {
        Ok(written) => json_response(
            StatusCode(200),
            serde_json::json!({ "ok": true, "written": written, "merge": merge }).to_string(),
        ),
        Err(e) => json_response(
            StatusCode(400),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// Change master password. Body: `{ "current_password": "...", "new_password": "..." }`
fn handle_change_password(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let current = parsed
        .get("current_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_pw = parsed
        .get("new_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if current.is_empty() || new_pw.is_empty() {
        return json_response(
            StatusCode(400),
            r#"{"error":"current_password and new_password required"}"#.into(),
        );
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match session
        .vault
        .change_master_password(current, new_pw)
    {
        Ok(()) => json_response(
            StatusCode(200),
            r#"{"ok":true,"note":"re-enroll OS enclave quick-unlock if used"}"#.into(),
        ),
        Err(e) => {
            let code = if e.to_string().contains("authentication")
                || e.to_string().contains("Authentication")
            {
                StatusCode(401)
            } else {
                StatusCode(400)
            };
            json_response(
                code,
                serde_json::json!({"error": e.to_string()}).to_string(),
            )
        }
    }
}

/// Export vault as CSV (contains secrets — Bearer protected).
fn handle_export_csv(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();
    match session.vault.export_csv() {
        Ok(csv) => json_response(
            StatusCode(200),
            serde_json::json!({ "ok": true, "csv": csv }).to_string(),
        ),
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// HIBP k-anonymity check for one item's password (opt-in; requires network).
/// Body: `{ "id": "..." }` — never sends full password, only SHA-1 prefix.
fn handle_pwned_check(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return json_response(StatusCode(400), r#"{"error":"id required"}"#.into());
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();
    let item = match session.vault.get_item(id) {
        Ok(i) => i,
        Err(e) => {
            return json_response(
                StatusCode(404),
                serde_json::json!({"error": e.to_string()}).to_string(),
            );
        }
    };
    match hibp_pwned_count(&item.password) {
        Ok(count) => json_response(
            StatusCode(200),
            serde_json::json!({
                "ok": true,
                "id": id,
                "title": item.title,
                "pwned": count > 0,
                "count": count,
                "method": "hibp-k-anonymity",
            })
            .to_string(),
        ),
        Err(e) => json_response(
            StatusCode(502),
            serde_json::json!({"error": e}).to_string(),
        ),
    }
}

/// Have I Been Pwned range API (k-anonymity). Returns breach count or 0.
fn hibp_pwned_count(password: &str) -> Result<u64, String> {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(password.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
    let (prefix, suffix) = hex.split_at(5);
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let body = ureq::get(&url)
        .set("Add-Padding", "true")
        .set("User-Agent", "KeyVault-local-daemon")
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| format!("HIBP request failed: {e}"))?
        .into_string()
        .map_err(|e| format!("HIBP body: {e}"))?;
    for line in body.lines() {
        let mut parts = line.split(':');
        if let (Some(hash_suffix), Some(count_s)) = (parts.next(), parts.next()) {
            if hash_suffix.eq_ignore_ascii_case(suffix) {
                return count_s
                    .trim()
                    .parse()
                    .map_err(|e| format!("bad HIBP count: {e}"));
            }
        }
    }
    Ok(0)
}

/// Offline password health (weak + reused). No network calls.
fn handle_password_health(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();
    match session.vault.password_health() {
        Ok(rep) => json_response(
            StatusCode(200),
            serde_json::to_string(&rep).unwrap_or_else(|_| "{}".into()),
        ),
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// Generate current TOTP code for an item (secret never returned).
/// Body: `{ "id": "..." }`
fn handle_totp(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return json_response(StatusCode(400), r#"{"error":"id required"}"#.into());
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match session.vault.totp_code_for_item(id) {
        Ok(code) => json_response(
            StatusCode(200),
            serde_json::to_string(&code).unwrap_or_else(|_| "{}".into()),
        ),
        Err(e) => json_response(
            StatusCode(400),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// Import CSV. Body: `{ "csv": "name,url,..." }`
fn handle_import_csv(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let csv = parsed
        .get("csv")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if csv.trim().is_empty() {
        return json_response(StatusCode(400), r#"{"error":"csv required"}"#.into());
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match session.vault.import_csv(csv) {
        Ok(written) => json_response(
            StatusCode(200),
            serde_json::json!({ "ok": true, "written": written }).to_string(),
        ),
        Err(e) => json_response(
            StatusCode(400),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

/// One-shot secret reveal for autofill.
///
/// Body: `{ "id": "<item-id>", "purpose": "autofill", "origin": "https://…" }`
/// Returns plaintext username/password once; rate-limited; `ttl_ms` advises client
/// to drop the secret from memory after fill.
fn handle_reveal(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return json_response(StatusCode(400), r#"{"error":"id required"}"#.into());
    }
    let purpose = parsed
        .get("purpose")
        .and_then(|v| v.as_str())
        .unwrap_or("autofill");
    let origin = parsed
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Rate limit
    {
        let mut log = state.reveal_log.lock().expect("reveal_log");
        let cutoff = Instant::now() - REVEAL_WINDOW;
        log.retain(|t| *t > cutoff);
        if log.len() >= REVEAL_MAX_PER_WINDOW {
            return json_response(
                StatusCode(429),
                serde_json::json!({
                    "error": "reveal rate limit exceeded",
                    "max_per_window": REVEAL_MAX_PER_WINDOW,
                    "window_secs": REVEAL_WINDOW.as_secs(),
                })
                .to_string(),
            );
        }
        log.push(Instant::now());
    }

    let mut guard = state.session.lock().expect("session");
    if maybe_auto_lock(&mut guard) {
        return json_response(
            StatusCode(401),
            r#"{"error":"vault auto-locked"}"#.into(),
        );
    }
    let Some(session) = guard.as_mut() else {
        return json_response(StatusCode(401), r#"{"error":"vault locked"}"#.into());
    };
    session.last_activity = Instant::now();

    match session.vault.get_item(id) {
        Ok(item) => {
            let seq = state.reveal_seq.fetch_add(1, Ordering::SeqCst) + 1;
            // Audit line (no password) for local diagnostics.
            eprintln!(
                "reveal ok id={} purpose={} origin={} seq={}",
                item.id, purpose, origin, seq
            );
            json_response(
                StatusCode(200),
                serde_json::json!({
                    "ok": true,
                    "reveal_id": format!("r{seq}"),
                    "id": item.id,
                    "title": item.title,
                    "username": item.username,
                    "password": item.password,
                    "url": item.url,
                    "ttl_ms": REVEAL_TTL_MS,
                    "purpose": purpose,
                })
                .to_string(),
            )
        }
        Err(e) => json_response(
            StatusCode(404),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_generate(request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let policy: PasswordPolicy = if body.trim().is_empty() {
        PasswordPolicy::default()
    } else {
        match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                return json_response(
                    StatusCode(400),
                    serde_json::json!({"error": e.to_string()}).to_string(),
                );
            }
        }
    };
    match generate_password(&policy) {
        Ok(p) => json_response(
            StatusCode(200),
            serde_json::json!({"password": p}).to_string(),
        ),
        Err(e) => json_response(
            StatusCode(400),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_score(request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": e.to_string()}).to_string(),
            );
        }
    };
    let password = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let score = score_password(password);
    json_response(
        StatusCode(200),
        serde_json::to_string(&score).unwrap_or_else(|_| "{}".into()),
    )
}

fn handle_tunnel_status(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let status = state.tunnel.status();
    json_response(
        StatusCode(200),
        serde_json::to_string(&status).unwrap_or_else(|_| "{}".into()),
    )
}

fn handle_tunnel_start(
    state: &AppState,
    request: &mut Request,
    default_port: u16,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = if body.trim().is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                return json_response(
                    StatusCode(400),
                    serde_json::json!({"error": e.to_string()}).to_string(),
                );
            }
        }
    };
    let provider_s = parsed
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("cloudflared");
    let provider = match TunnelProvider::from_str_loose(provider_s) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": e.to_string()}).to_string(),
            );
        }
    };
    let port = parsed
        .get("local_port")
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or(default_port);
    let public_url = parsed
        .get("public_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let cfg = TunnelConfig {
        provider,
        local_port: port,
        binary_path: None,
    };
    match state.tunnel.start(cfg) {
        Ok(mut status) => {
            if let Some(url) = public_url {
                state.tunnel.set_public_url(Some(url.clone()));
                status.public_url = Some(url);
            }
            json_response(
                StatusCode(200),
                serde_json::to_string(&status).unwrap_or_else(|_| "{}".into()),
            )
        }
        Err(e) => json_response(
            StatusCode(503),
            serde_json::json!({
                "error": e.to_string(),
                "hint": "Install cloudflared or ngrok on PATH, or run without tunnel (loopback only)",
                "status": state.tunnel.status(),
            })
            .to_string(),
        ),
    }
}

fn handle_tunnel_stop(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    match state.tunnel.stop() {
        Ok(status) => json_response(
            StatusCode(200),
            serde_json::to_string(&status).unwrap_or_else(|_| "{}".into()),
        ),
        Err(e) => json_response(
            StatusCode(500),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_pairing_create(state: &AppState, port: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let local_base = format!("http://127.0.0.1:{port}");
    // Prefer scraped/override public URL from tunnel agent (KI-040).
    let public_base = state
        .tunnel
        .status()
        .public_url
        .unwrap_or_default();
    match create_pairing_offer(
        &state.pairing_secret,
        &local_base,
        &public_base,
        DEFAULT_PAIRING_TTL_SECS,
    ) {
        Ok(offer) => {
            let qr = offer.qr_json().unwrap_or_default();
            *state.active_offer.lock().expect("offer") = Some(offer.clone());
            json_response(
                StatusCode(200),
                serde_json::json!({
                    "ok": true,
                    "offer": offer,
                    "qr_json": qr,
                    "instructions": "Encode qr_json as a QR code; remote app claims via POST /v1/pairing/claim",
                })
                .to_string(),
            )
        }
        Err(e) => json_response(
            StatusCode(400),
            serde_json::json!({"error": e.to_string()}).to_string(),
        ),
    }
}

fn handle_pairing_claim(
    state: &AppState,
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = read_body(request);
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode(400),
                serde_json::json!({"error": e.to_string()}).to_string(),
            );
        }
    };
    let pairing_id = parsed
        .get("pairing_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let token = parsed
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let label = parsed
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("device")
        .to_string();

    let offer = state.active_offer.lock().expect("offer").clone();
    let Some(offer) = offer else {
        return json_response(
            StatusCode(404),
            r#"{"error":"no active pairing offer"}"#.into(),
        );
    };
    if offer.pairing_id != pairing_id {
        return json_response(
            StatusCode(400),
            r#"{"error":"pairing_id mismatch"}"#.into(),
        );
    }
    if let Err(e) = verify_pairing_token(&state.pairing_secret, pairing_id, token) {
        return json_response(
            StatusCode(401),
            serde_json::json!({"error": e.to_string()}).to_string(),
        );
    }

    let api_token = issue_device_api_token();
    let device = PairedDevice {
        device_id: uuid::Uuid::new_v4().to_string(),
        pairing_id: pairing_id.to_string(),
        label,
        paired_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        api_token_hash: hash_api_token(&api_token),
    };
    let device_id = device.device_id.clone();
    let device_label = device.label.clone();
    state
        .paired_devices
        .lock()
        .expect("devices")
        .push(device);
    // Single-use offer
    *state.active_offer.lock().expect("offer") = None;

    json_response(
        StatusCode(200),
        serde_json::json!({
            "ok": true,
            "device_id": device_id,
            "api_token": api_token,
            "label": device_label,
            "note": "Store api_token securely; use Authorization: Bearer when tunnel is running. Server stores only hash.",
        })
        .to_string(),
    )
}

fn handle_pairing_devices(state: &AppState) -> Response<std::io::Cursor<Vec<u8>>> {
    let devices = state.paired_devices.lock().expect("devices");
    // Never return raw api_tokens in list — only metadata.
    let safe: Vec<_> = devices
        .iter()
        .map(|d| {
            serde_json::json!({
                "device_id": d.device_id,
                "pairing_id": d.pairing_id,
                "label": d.label,
                "paired_at": d.paired_at,
            })
        })
        .collect();
    json_response(
        StatusCode(200),
        serde_json::json!({ "devices": safe }).to_string(),
    )
}

fn read_body(request: &mut Request) -> String {
    let mut buf = Vec::new();
    let _ = std::io::copy(request.as_reader(), &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn cors_preflight() -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_string("").with_status_code(StatusCode(204));
    add_security_headers(&mut response);
    add_cors(&mut response);
    response
}

fn json_response(status: StatusCode, body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_string(body).with_status_code(status);
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        response.add_header(h);
    }
    add_security_headers(&mut response);
    add_cors(&mut response);
    response
}

fn add_security_headers(response: &mut Response<std::io::Cursor<Vec<u8>>>) {
    // Sensitive vault API — never cache; reduce MIME sniffing / framing risk.
    if let Ok(h) =
        Header::from_bytes(&b"Cache-Control"[..], &b"no-store, no-cache, must-revalidate"[..])
    {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Pragma"[..], &b"no-cache"[..]) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(
        &b"Content-Security-Policy"[..],
        &b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"[..],
    ) {
        response.add_header(h);
    }
}

fn add_cors(response: &mut Response<std::io::Cursor<Vec<u8>>>) {
    // Daemon is loopback-only. ACAO * enables MV3 extension + local tools without
    // credentials; bind address is the trust boundary (see COMPLIANCE C-05).
    if let Ok(h) = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(
        &b"Access-Control-Allow-Methods"[..],
        &b"GET, POST, OPTIONS"[..],
    ) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(
        &b"Access-Control-Allow-Headers"[..],
        &b"Content-Type, Authorization"[..],
    ) {
        response.add_header(h);
    }
}
