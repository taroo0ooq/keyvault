/** Loopback vault_daemon client (127.0.0.1 only), with optional native host fallback. */

import { nativeApiAvailable, sendNative } from "./native.js";

export const DEFAULT_DAEMON = "http://127.0.0.1:8080";

/** Prefer native messaging when set (after successful ping) or when loopback fails. */
let preferNative = false;

export function setPreferNative(v: boolean): void {
  preferNative = v;
}

export function getPreferNative(): boolean {
  return preferNative;
}

/** Optional Bearer for when vault_daemon has tunnel auth enabled. */
let authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token && token.trim() ? token.trim() : null;
}

export function getAuthToken(): string | null {
  return authToken;
}

function authHeaders(json = false): HeadersInit {
  const h: Record<string, string> = {};
  if (json) h["Content-Type"] = "application/json";
  if (authToken) h["Authorization"] = `Bearer ${authToken}`;
  return h;
}

export type DaemonStatus = {
  ok: boolean;
  unlocked: boolean;
  path: string | null;
  auto_locked?: boolean;
  idle_secs?: number;
  auto_lock_secs?: number;
  daemon_version?: string;
};

export type VaultListItem = {
  id: string;
  title: string;
  username?: string | null;
  password: string;
  /** Present (possibly redacted) when item has a TOTP secret. */
  totp?: string | null;
  url?: string | null;
  tags?: string[];
};

async function fetchJson(
  path: string,
  init?: RequestInit,
  base = DEFAULT_DAEMON,
): Promise<Response> {
  return fetch(`${base}${path}`, init);
}

async function withNativeFallback<T>(
  loopback: () => Promise<T>,
  native: () => Promise<T>,
): Promise<T> {
  if (preferNative && nativeApiAvailable()) {
    try {
      return await native();
    } catch {
      /* fall through to loopback */
    }
  }
  try {
    return await loopback();
  } catch (loopErr) {
    if (!nativeApiAvailable()) throw loopErr;
    try {
      const v = await native();
      preferNative = true;
      return v;
    } catch {
      throw loopErr;
    }
  }
}

export async function getHealth(
  base = DEFAULT_DAEMON,
): Promise<{ ok: boolean; version?: string }> {
  return withNativeFallback(
    async () => {
      const res = await fetchJson("/health", { method: "GET" }, base);
      if (!res.ok) throw new Error(`health ${res.status}`);
      return res.json();
    },
    async () => {
      const r = await sendNative<{ ok?: boolean; version?: string; error?: string }>({
        cmd: "health",
      });
      if (r.error) throw new Error(r.error);
      return r as { ok: boolean; version?: string };
    },
  );
}

export async function getStatus(base = DEFAULT_DAEMON): Promise<DaemonStatus> {
  return withNativeFallback(
    async () => {
      const res = await fetchJson("/v1/status", { method: "GET" }, base);
      if (!res.ok) throw new Error(`status ${res.status}`);
      return res.json();
    },
    async () => {
      const r = await sendNative<DaemonStatus & { error?: string }>({
        cmd: "status",
      });
      if (r.error && r.ok === false) throw new Error(r.error);
      return r;
    },
  );
}

export async function getAuthMode(
  base = DEFAULT_DAEMON,
): Promise<{ auth_required: boolean; tunnel_running: boolean }> {
  return withNativeFallback(
    async () => {
      const res = await fetchJson("/v1/auth/mode", { method: "GET" }, base);
      if (!res.ok) throw new Error(`auth/mode ${res.status}`);
      return res.json();
    },
    async () => {
      const r = await sendNative<{
        auth_required: boolean;
        tunnel_running: boolean;
        error?: string;
      }>({ cmd: "auth_mode" });
      if (r.error) throw new Error(r.error);
      return r;
    },
  );
}

export async function unlockVault(
  path: string,
  password: string,
  opts?: { create?: boolean; base?: string },
): Promise<void> {
  const base = opts?.base ?? DEFAULT_DAEMON;
  await withNativeFallback(
    async () => {
      const res = await fetch(`${base}/v1/unlock`, {
        method: "POST",
        headers: authHeaders(true),
        body: JSON.stringify({ path, password, create: opts?.create ?? false }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `unlock ${res.status}`);
    },
    async () => {
      const r = await sendNative<{ ok?: boolean; error?: string }>({
        cmd: "unlock",
        path,
        password,
        create: opts?.create ?? false,
      });
      if (r.error || r.ok === false) throw new Error(r.error || "unlock failed");
    },
  );
}

export async function lockVault(base = DEFAULT_DAEMON): Promise<void> {
  await withNativeFallback(
    async () => {
      const res = await fetch(`${base}/v1/lock`, {
        method: "POST",
        headers: authHeaders(false),
      });
      if (!res.ok) throw new Error(`lock ${res.status}`);
    },
    async () => {
      const r = await sendNative<{ ok?: boolean; error?: string }>({ cmd: "lock" });
      if (r.error) throw new Error(r.error);
    },
  );
}

export async function listItems(
  query = "",
  base = DEFAULT_DAEMON,
): Promise<VaultListItem[]> {
  return withNativeFallback(
    async () => {
      const url = query
        ? `${base}/v1/search?q=${encodeURIComponent(query)}`
        : `${base}/v1/items`;
      const res = await fetch(url, { method: "GET", headers: authHeaders(false) });
      if (res.status === 401) return [];
      if (!res.ok) throw new Error(`items ${res.status}`);
      return res.json();
    },
    async () => {
      const r = query
        ? await sendNative<VaultListItem[] | { ok?: boolean; error?: string }>({
            cmd: "search",
            q: query,
          })
        : await sendNative<VaultListItem[] | { ok?: boolean; error?: string }>({
            cmd: "items",
          });
      if (Array.isArray(r)) return r;
      if (r && typeof r === "object" && "error" in r && r.error) {
        throw new Error(String(r.error));
      }
      return [];
    },
  );
}

export type RevealResult = {
  ok: boolean;
  reveal_id: string;
  id: string;
  title: string;
  username?: string | null;
  password: string;
  url?: string | null;
  ttl_ms: number;
  purpose?: string;
};

/**
 * One-shot secret reveal for autofill. Caller must drop password after `ttl_ms`.
 * List endpoints never return real passwords.
 */
export async function revealItem(
  id: string,
  opts?: { purpose?: string; origin?: string; base?: string },
): Promise<RevealResult> {
  const base = opts?.base ?? DEFAULT_DAEMON;
  return withNativeFallback(
    async () => {
      const res = await fetch(`${base}/v1/reveal`, {
        method: "POST",
        headers: authHeaders(true),
        body: JSON.stringify({
          id,
          purpose: opts?.purpose ?? "autofill",
          origin: opts?.origin ?? "",
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `reveal ${res.status}`);
      return body as RevealResult;
    },
    async () => {
      const body = await sendNative<RevealResult & { error?: string }>({
        cmd: "reveal",
        id,
        purpose: opts?.purpose ?? "autofill",
        origin: opts?.origin ?? "",
      });
      if (body.error && !body.password) {
        throw new Error(body.error);
      }
      return body as RevealResult;
    },
  );
}

export type TotpResult = {
  code: string;
  period_secs: number;
  remaining_secs: number;
  digits: number;
};

/** Current TOTP code for an item (daemon never returns the secret). */
export async function totpCode(
  id: string,
  base = DEFAULT_DAEMON,
): Promise<TotpResult> {
  return withNativeFallback(
    async () => {
      const res = await fetch(`${base}/v1/totp`, {
        method: "POST",
        headers: authHeaders(true),
        body: JSON.stringify({ id }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `totp ${res.status}`);
      return body as TotpResult;
    },
    async () => {
      const body = await sendNative<TotpResult & { error?: string }>({
        cmd: "totp",
        id,
      });
      if (body.error && !body.code) throw new Error(body.error);
      return body as TotpResult;
    },
  );
}

export async function generatePassword(
  length = 20,
  base = DEFAULT_DAEMON,
): Promise<string> {
  const res = await fetch(`${base}/v1/generate`, {
    method: "POST",
    headers: authHeaders(true),
    body: JSON.stringify({
      length,
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
      exclude_ambiguous: false,
    }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error || `generate ${res.status}`);
  return body.password as string;
}

/** Match credentials by page hostname against item url/title. */
export function matchItemsForHost(
  items: VaultListItem[],
  hostname: string,
): VaultListItem[] {
  const host = hostname.toLowerCase().replace(/^www\./, "");
  return items.filter((item) => {
    const url = (item.url || "").toLowerCase();
    const title = (item.title || "").toLowerCase();
    try {
      if (url) {
        const u = new URL(url.startsWith("http") ? url : `https://${url}`);
        const h = u.hostname.toLowerCase().replace(/^www\./, "");
        if (h === host || host.endsWith(`.${h}`) || h.endsWith(`.${host}`)) {
          return true;
        }
      }
    } catch {
      /* ignore bad urls */
    }
    return title.includes(host) || host.includes(title.replace(/\s+/g, ""));
  });
}
