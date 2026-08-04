//! Chrome/Firefox native messaging host for KeyVault.
//!
//! Speaks length-prefixed (u32 LE) JSON on stdin/stdout and proxies vault
//! operations to the loopback `vault_daemon` HTTP API. Use when extension
//! → loopback `fetch` is blocked by browser policy.
//!
//! Protocol (request JSON):
//! ```json
//! { "cmd": "ping" }
//! { "cmd": "health" }
//! { "cmd": "status" }
//! { "cmd": "auth_mode" }
//! { "cmd": "items" }
//! { "cmd": "search", "q": "query" }
//! { "cmd": "reveal", "id": "...", "purpose": "autofill", "origin": "..." }
//! { "cmd": "unlock", "path": "...", "password": "...", "create": false }
//! { "cmd": "lock" }
//! { "cmd": "update", "id": "...", "title": "...", ... }
//! { "cmd": "delete", "id": "..." }
//! { "cmd": "totp", "id": "..." }
//! { "cmd": "export", "passphrase": "..." }
//! { "cmd": "import", "passphrase": "...", "backup": "...", "merge": true }
//! { "cmd": "proxy", "method": "GET|POST", "path": "/v1/...", "body": {} }
//! ```
//!
//! Env: `VAULT_DAEMON_URL` (default `http://127.0.0.1:8080`),
//!      `VAULT_DAEMON_TOKEN` optional Bearer.

use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::io::{self, Read, Write};

const DEFAULT_DAEMON: &str = "http://127.0.0.1:8080";
const MAX_MSG: usize = 1024 * 1024; // 1 MiB

fn daemon_base() -> String {
    env::var("VAULT_DAEMON_URL").unwrap_or_else(|_| DEFAULT_DAEMON.to_string())
}

fn auth_token() -> Option<String> {
    env::var("VAULT_DAEMON_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_message(stdin: &mut impl Read) -> io::Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match stdin.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(None);
    }
    if len > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len}"),
        ));
    }
    let mut body = vec![0u8; len];
    stdin.read_exact(&mut body)?;
    let v: Value = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(v))
}

fn write_message(stdout: &mut impl Write, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    let len = (bytes.len() as u32).to_le_bytes();
    stdout.write_all(&len)?;
    stdout.write_all(&bytes)?;
    stdout.flush()?;
    Ok(())
}

fn http_json(method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let base = daemon_base().trim_end_matches('/').to_string();
    let url = format!("{base}{path}");
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();

    let mut req = match method.to_uppercase().as_str() {
        "GET" => agent.get(&url),
        "POST" => agent.post(&url),
        "PUT" => agent.put(&url),
        "DELETE" => agent.delete(&url),
        other => return Err(format!("unsupported method {other}")),
    };

    if let Some(tok) = auth_token() {
        req = req.set("Authorization", &format!("Bearer {tok}"));
    }

    let resp = if let Some(b) = body {
        req.set("Content-Type", "application/json")
            .send_json(b.clone())
    } else {
        req.call()
    };

    match resp {
        Ok(r) => {
            let status = r.status();
            let text = r.into_string().unwrap_or_default();
            if text.is_empty() {
                return Ok(json!({ "ok": status < 400, "status": status }));
            }
            match serde_json::from_str::<Value>(&text) {
                Ok(v) => Ok(v),
                Err(_) => Ok(json!({ "ok": status < 400, "status": status, "body": text })),
            }
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                // Pass through daemon JSON errors with HTTP status hint.
                let mut obj = v;
                if let Some(map) = obj.as_object_mut() {
                    map.entry("http_status".to_string())
                        .or_insert(json!(code));
                    map.entry("ok".to_string()).or_insert(json!(false));
                }
                Ok(obj)
            } else {
                Err(format!("HTTP {code}: {text}"))
            }
        }
        Err(e) => Err(format!("daemon unreachable: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct HostRequest {
    cmd: String,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    create: Option<bool>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    backup: Option<String>,
    #[serde(default)]
    merge: Option<bool>,
}

fn handle(req: HostRequest) -> Value {
    match req.cmd.as_str() {
        "ping" => json!({
            "ok": true,
            "via": "native",
            "host": "vault_native_host",
            "version": env!("CARGO_PKG_VERSION"),
        }),
        "health" => match http_json("GET", "/health", None) {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "status" => match http_json("GET", "/v1/status", None) {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "auth_mode" => match http_json("GET", "/v1/auth/mode", None) {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "items" => match http_json("GET", "/v1/items", None) {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "search" => {
            let q = req.q.unwrap_or_default();
            let path = format!("/v1/search?q={}", urlencoding_minimal(&q));
            match http_json("GET", &path, None) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "reveal" => {
            let id = match req.id {
                Some(i) if !i.is_empty() => i,
                _ => return json!({ "ok": false, "error": "id required" }),
            };
            let body = json!({
                "id": id,
                "purpose": req.purpose.unwrap_or_else(|| "autofill".into()),
                "origin": req.origin.unwrap_or_default(),
            });
            match http_json("POST", "/v1/reveal", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "unlock" => {
            let path = match req.path {
                Some(p) if !p.is_empty() => p,
                _ => return json!({ "ok": false, "error": "path required" }),
            };
            let password = req.password.unwrap_or_default();
            let body = json!({
                "path": path,
                "password": password,
                "create": req.create.unwrap_or(false),
            });
            match http_json("POST", "/v1/unlock", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "lock" => match http_json("POST", "/v1/lock", None) {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "update" => {
            let id = match req.id {
                Some(i) if !i.is_empty() => i,
                _ => return json!({ "ok": false, "error": "id required" }),
            };
            let mut body = json!({ "id": id });
            if let Some(t) = req.title {
                body["title"] = json!(t);
            }
            if let Some(u) = req.username {
                body["username"] = json!(u);
            }
            if let Some(p) = req.password {
                body["password"] = json!(p);
            }
            if let Some(u) = req.url {
                body["url"] = json!(u);
            }
            if let Some(n) = req.notes {
                body["notes"] = json!(n);
            }
            match http_json("POST", "/v1/items/update", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "delete" => {
            let id = match req.id {
                Some(i) if !i.is_empty() => i,
                _ => return json!({ "ok": false, "error": "id required" }),
            };
            let body = json!({ "id": id });
            match http_json("POST", "/v1/items/delete", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "totp" => {
            let id = match req.id {
                Some(i) if !i.is_empty() => i,
                _ => return json!({ "ok": false, "error": "id required" }),
            };
            let body = json!({ "id": id });
            match http_json("POST", "/v1/totp", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "export" => {
            let passphrase = match req.passphrase {
                Some(p) if p.len() >= 12 => p,
                _ => {
                    return json!({
                        "ok": false,
                        "error": "passphrase must be at least 12 characters"
                    })
                }
            };
            let body = json!({ "passphrase": passphrase });
            match http_json("POST", "/v1/export", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "import" => {
            let passphrase = match req.passphrase {
                Some(p) if !p.is_empty() => p,
                _ => return json!({ "ok": false, "error": "passphrase required" }),
            };
            let backup = match req.backup {
                Some(b) if !b.is_empty() => b,
                _ => return json!({ "ok": false, "error": "backup required" }),
            };
            let body = json!({
                "passphrase": passphrase,
                "backup": backup,
                "merge": req.merge.unwrap_or(true),
            });
            match http_json("POST", "/v1/import", Some(&body)) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        "proxy" => {
            let method = req.method.unwrap_or_else(|| "GET".into());
            let path = match req.path {
                Some(p) if p.starts_with('/') => p,
                _ => return json!({ "ok": false, "error": "path must start with /" }),
            };
            match http_json(&method, &path, req.body.as_ref()) {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }
        other => json!({ "ok": false, "error": format!("unknown cmd: {other}") }),
    }
}

/// Minimal query encoding (enough for search q).
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn main() {
    // Native hosts must not write to stdout except framed messages.
    // Log only to stderr if needed.
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    loop {
        match read_message(&mut stdin) {
            Ok(None) => break,
            Ok(Some(v)) => {
                let req: HostRequest = match serde_json::from_value(v) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = write_message(
                            &mut stdout,
                            &json!({ "ok": false, "error": format!("bad request: {e}") }),
                        );
                        continue;
                    }
                };
                let resp = handle(req);
                if write_message(&mut stdout, &resp).is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = write_message(
                    &mut stdout,
                    &json!({ "ok": false, "error": format!("read error: {e}") }),
                );
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_framing() {
        let msg = json!({ "cmd": "ping" });
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(got["cmd"], "ping");
    }

    fn empty_req(cmd: &str) -> HostRequest {
        HostRequest {
            cmd: cmd.into(),
            q: None,
            id: None,
            purpose: None,
            origin: None,
            path: None,
            password: None,
            create: None,
            method: None,
            body: None,
            title: None,
            username: None,
            url: None,
            notes: None,
            passphrase: None,
            backup: None,
            merge: None,
        }
    }

    #[test]
    fn handle_ping() {
        let v = handle(empty_req("ping"));
        assert_eq!(v["ok"], true);
        assert_eq!(v["via"], "native");
    }

    #[test]
    fn reveal_requires_id() {
        let v = handle(empty_req("reveal"));
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn urlencoding_spaces() {
        assert_eq!(urlencoding_minimal("a b"), "a+b");
        assert_eq!(urlencoding_minimal("a&b"), "a%26b");
    }
}
