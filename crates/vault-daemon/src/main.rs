//! Local loopback vault daemon.
//!
//! Binds **only** to `127.0.0.1` (never 0.0.0.0). Used by browser extensions,
//! mobile tunnel clients, and the DAST baseline scan against `/health`.

use std::env;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tiny_http::{Header, Method, Response, Server, StatusCode};
use vault_core::health_check;

const DEFAULT_BIND: &str = "127.0.0.1:8080";

fn main() {
    let bind = env::var("VAULT_DAEMON_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .unwrap_or_else(|_| panic!("invalid VAULT_DAEMON_BIND: {bind}"));

    // Hard safety: refuse non-loopback binds.
    if !addr.ip().is_loopback() {
        eprintln!("refusing to bind non-loopback address: {addr}");
        std::process::exit(2);
    }

    let server = Server::http(addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        std::process::exit(1);
    });

    let req_count = Arc::new(AtomicU64::new(0));
    println!("vault_daemon listening on http://{addr}");
    println!("health: GET /health");

    for request in server.incoming_requests() {
        let n = req_count.fetch_add(1, Ordering::Relaxed) + 1;
        let method = request.method().clone();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or(&url);

        let response = match (method, path) {
            (Method::Get, "/health") | (Method::Get, "/health/") => {
                let status = health_check();
                let body = serde_json::to_string_pretty(&status).unwrap_or_else(|_| {
                    r#"{"ok":false,"error":"serialize"}"#.into()
                });
                json_response(StatusCode(200), body)
            }
            (Method::Get, "/") => {
                let body = serde_json::json!({
                    "service": "vault_daemon",
                    "version": vault_core::VERSION,
                    "requests": n,
                    "endpoints": ["/health"],
                })
                .to_string();
                json_response(StatusCode(200), body)
            }
            _ => {
                let body = r#"{"error":"not_found"}"#.to_string();
                json_response(StatusCode(404), body)
            }
        };

        if let Err(e) = request.respond(response) {
            eprintln!("respond error: {e}");
        }
    }
}

fn json_response(status: StatusCode, body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_string(body).with_status_code(status);
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        response.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]) {
        response.add_header(h);
    }
    // Defense in depth even on loopback.
    if let Ok(h) = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]) {
        response.add_header(h);
    }
    response
}
