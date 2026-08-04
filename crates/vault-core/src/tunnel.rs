//! Secure tunnel gateway agent (cloudflared / ngrok wrappers).
//!
//! The vault API **always** binds loopback only. Tunnel providers are external
//! processes that forward a public hostname to `127.0.0.1:<port>`. This module
//! does not open non-loopback sockets itself.
//!
//! Process control is optional: when `cloudflared` / `ngrok` are not installed,
//! APIs return a clear error so UIs can guide the user.
//!
//! **Public URL discovery (KI-040):** stdout/stderr are scraped for
//! `https://*.trycloudflare.com` / `https://*.ngrok*` URLs.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};

use crate::error::{VaultError, VaultResult};

/// Supported tunnel backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProvider {
    Cloudflared,
    Ngrok,
}

impl TunnelProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelProvider::Cloudflared => "cloudflared",
            TunnelProvider::Ngrok => "ngrok",
        }
    }

    pub fn from_str_loose(s: &str) -> VaultResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cloudflared" | "cloudflare" | "cf" => Ok(TunnelProvider::Cloudflared),
            "ngrok" => Ok(TunnelProvider::Ngrok),
            other => Err(VaultError::Tunnel(format!("unknown provider: {other}"))),
        }
    }
}

/// Desired tunnel configuration (always targets loopback).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub provider: TunnelProvider,
    /// Local port of vault_daemon (must be served on 127.0.0.1).
    pub local_port: u16,
    /// Optional path to binary override.
    pub binary_path: Option<PathBuf>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            provider: TunnelProvider::Cloudflared,
            local_port: 8080,
            binary_path: None,
        }
    }
}

/// Runtime status snapshot for APIs / UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub running: bool,
    pub provider: Option<TunnelProvider>,
    pub local_port: u16,
    pub public_url: Option<String>,
    pub pid: Option<u32>,
    pub binary_found: bool,
    pub last_error: Option<String>,
    /// Hard safety note for operators.
    pub bind_policy: &'static str,
}

impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            running: false,
            provider: None,
            local_port: 8080,
            public_url: None,
            pid: None,
            binary_found: false,
            last_error: None,
            bind_policy: "vault API remains on 127.0.0.1 only; tunnel is external process",
        }
    }
}

/// Resolve path to tunnel CLI on PATH or override.
pub fn resolve_binary(provider: TunnelProvider, override_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    which(provider.as_str())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
            let cmd = dir.join(format!("{name}.cmd"));
            if cmd.is_file() {
                return Some(cmd);
            }
        }
    }
    None
}

/// Build argv for starting a tunnel to loopback.
pub fn tunnel_command_line(cfg: &TunnelConfig, binary: &Path) -> VaultResult<(PathBuf, Vec<String>)> {
    let local = format!("http://127.0.0.1:{}", cfg.local_port);
    let args = match cfg.provider {
        TunnelProvider::Cloudflared => vec![
            "tunnel".into(),
            "--url".into(),
            local,
            "--no-autoupdate".into(),
        ],
        TunnelProvider::Ngrok => vec!["http".into(), format!("127.0.0.1:{}", cfg.local_port)],
    };
    Ok((binary.to_path_buf(), args))
}

/// Extract a public tunnel URL from a provider log line (if present).
///
/// Matches common cloudflared trycloud and ngrok HTTPS hostnames.
pub fn parse_public_url_from_line(line: &str) -> Option<String> {
    // Prefer scanning tokens; also handle "url=https://..."
    for raw in line.split(|c: char| c.is_whitespace() || c == '|' || c == ',' || c == '"') {
        let t = raw.trim().trim_end_matches(['.', ')', ']', ';']);
        if !t.starts_with("https://") {
            continue;
        }
        let host = t.trim_start_matches("https://");
        let host = host.split('/').next().unwrap_or(host);
        let looks_public = host.ends_with(".trycloudflare.com")
            || host.ends_with(".cfargotunnel.com")
            || host.contains("ngrok")
            || host.ends_with(".loca.lt");
        if looks_public && !host.contains("127.0.0.1") && !host.contains("localhost") {
            return Some(format!("https://{host}"));
        }
    }
    None
}

fn spawn_log_scraper<R: std::io::Read + Send + 'static>(
    reader: R,
    public_url: Arc<Mutex<Option<String>>>,
) {
    thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines().map_while(Result::ok) {
            if let Some(url) = parse_public_url_from_line(&line) {
                let mut slot = public_url.lock().expect("url lock");
                if slot.is_none() {
                    *slot = Some(url);
                }
            }
        }
    });
}

/// Managed tunnel child process.
pub struct TunnelAgent {
    inner: Mutex<TunnelAgentInner>,
}

struct TunnelAgentInner {
    child: Option<Child>,
    config: TunnelConfig,
    /// Shared with scraper threads; first discovered public URL wins.
    public_url: Arc<Mutex<Option<String>>>,
    /// Manual override (takes precedence over scraped URL when set).
    public_url_override: Option<String>,
    last_error: Option<String>,
}

impl Default for TunnelAgent {
    fn default() -> Self {
        Self::new(TunnelConfig::default())
    }
}

impl TunnelAgent {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            inner: Mutex::new(TunnelAgentInner {
                child: None,
                config,
                public_url: Arc::new(Mutex::new(None)),
                public_url_override: None,
                last_error: None,
            }),
        }
    }

    fn resolved_public_url(g: &TunnelAgentInner) -> Option<String> {
        g.public_url_override
            .clone()
            .or_else(|| g.public_url.lock().expect("url").clone())
    }

    pub fn status(&self) -> TunnelStatus {
        let mut g = self.inner.lock().expect("tunnel lock");
        // Reap exited children
        if let Some(child) = g.child.as_mut() {
            if let Ok(Some(_status)) = child.try_wait() {
                g.child = None;
                *g.public_url.lock().expect("url") = None;
                g.public_url_override = None;
            }
        }
        let binary = resolve_binary(g.config.provider, g.config.binary_path.as_deref());
        let running = g.child.is_some();
        let pid = g.child.as_ref().map(|c| c.id());
        TunnelStatus {
            running,
            provider: Some(g.config.provider),
            local_port: g.config.local_port,
            public_url: Self::resolved_public_url(&g),
            pid,
            binary_found: binary.is_some(),
            last_error: g.last_error.clone(),
            bind_policy: "vault API remains on 127.0.0.1 only; tunnel is external process",
        }
    }

    /// Start tunnel process. Fails if binary missing or already running.
    ///
    /// stdout/stderr are scraped for a public HTTPS URL (cloudflared/ngrok).
    pub fn start(&self, config: TunnelConfig) -> VaultResult<TunnelStatus> {
        let mut g = self.inner.lock().expect("tunnel lock");
        if g.child.is_some() {
            return Err(VaultError::Tunnel("tunnel already running".into()));
        }
        let binary = resolve_binary(config.provider, config.binary_path.as_deref()).ok_or_else(
            || {
                VaultError::Tunnel(format!(
                    "{} binary not found on PATH; install it or set binary_path",
                    config.provider.as_str()
                ))
            },
        )?;
        let (bin, args) = tunnel_command_line(&config, &binary)?;
        let mut cmd = Command::new(&bin);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match cmd.spawn() {
            Ok(mut child) => {
                let url_slot = Arc::new(Mutex::new(None));
                if let Some(out) = child.stdout.take() {
                    spawn_log_scraper(out, Arc::clone(&url_slot));
                }
                if let Some(err) = child.stderr.take() {
                    spawn_log_scraper(err, Arc::clone(&url_slot));
                }
                g.child = Some(child);
                g.config = config;
                g.public_url = url_slot;
                g.public_url_override = None;
                g.last_error = None;
            }
            Err(e) => {
                g.last_error = Some(e.to_string());
                return Err(VaultError::Tunnel(format!("failed to spawn tunnel: {e}")));
            }
        }
        drop(g);
        Ok(self.status())
    }

    /// Record public URL (manual override; preferred over scraped value).
    pub fn set_public_url(&self, url: Option<String>) {
        let mut g = self.inner.lock().expect("tunnel lock");
        g.public_url_override = url;
    }

    pub fn stop(&self) -> VaultResult<TunnelStatus> {
        let mut g = self.inner.lock().expect("tunnel lock");
        if let Some(mut child) = g.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        *g.public_url.lock().expect("url") = None;
        g.public_url_override = None;
        g.last_error = None;
        drop(g);
        Ok(self.status())
    }
}

impl Drop for TunnelAgent {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parse() {
        assert_eq!(
            TunnelProvider::from_str_loose("cloudflared").unwrap(),
            TunnelProvider::Cloudflared
        );
        assert_eq!(
            TunnelProvider::from_str_loose("ngrok").unwrap(),
            TunnelProvider::Ngrok
        );
        assert!(TunnelProvider::from_str_loose("foo").is_err());
    }

    #[test]
    fn command_line_targets_loopback() {
        let cfg = TunnelConfig {
            provider: TunnelProvider::Cloudflared,
            local_port: 8080,
            binary_path: None,
        };
        let bin = PathBuf::from("cloudflared");
        let (_, args) = tunnel_command_line(&cfg, &bin).unwrap();
        assert!(args.iter().any(|a| a.contains("127.0.0.1:8080")));
    }

    #[test]
    fn status_default_not_running() {
        let agent = TunnelAgent::default();
        let s = agent.status();
        assert!(!s.running);
        assert!(s.bind_policy.contains("127.0.0.1"));
    }

    #[test]
    fn start_missing_binary_errors() {
        let agent = TunnelAgent::default();
        let cfg = TunnelConfig {
            provider: TunnelProvider::Cloudflared,
            local_port: 8080,
            binary_path: Some(PathBuf::from(
                "/nonexistent/path/to/cloudflared-keyvault-test",
            )),
        };
        let err = agent.start(cfg).unwrap_err();
        assert!(matches!(err, VaultError::Tunnel(_)));
    }

    #[test]
    fn parse_cloudflared_trycloud_line() {
        let line = "2024-01-01 INF |  https://random-words-1234.trycloudflare.com";
        assert_eq!(
            parse_public_url_from_line(line).as_deref(),
            Some("https://random-words-1234.trycloudflare.com")
        );
    }

    #[test]
    fn parse_ngrok_line() {
        let line = "Forwarding  https://abc123.ngrok-free.app -> http://127.0.0.1:8080";
        assert_eq!(
            parse_public_url_from_line(line).as_deref(),
            Some("https://abc123.ngrok-free.app")
        );
    }

    #[test]
    fn parse_ignores_loopback() {
        assert!(parse_public_url_from_line("listening on https://127.0.0.1:8080").is_none());
        assert!(parse_public_url_from_line("no url here").is_none());
    }
}
