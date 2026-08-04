import { test, expect } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(process.cwd(), "..", "..");
const DAEMON_WIN = join(ROOT, "target", "release", "vault_daemon.exe");
const DAEMON_UNIX = join(ROOT, "target", "release", "vault_daemon");
const BASE = "http://127.0.0.1:18080";

function daemonPath(): string {
  if (existsSync(DAEMON_WIN)) return DAEMON_WIN;
  if (existsSync(DAEMON_UNIX)) return DAEMON_UNIX;
  throw new Error("vault_daemon release binary not found; run cargo build -p vault-daemon --release");
}

test.describe("reveal API", () => {
  let child: ChildProcess | null = null;
  let vaultDir: string;

  test.beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "kv-ext-"));
    child = spawn(daemonPath(), [], {
      env: { ...process.env, VAULT_DAEMON_BIND: "127.0.0.1:18080" },
      stdio: "ignore",
    });
    for (let i = 0; i < 50; i++) {
      try {
        const r = await fetch(`${BASE}/health`);
        if (r.ok) return;
      } catch {
        /* retry */
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("daemon did not start");
  });

  test.afterAll(() => {
    child?.kill();
    try {
      rmSync(vaultDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  test("list redacts; reveal returns password", async () => {
    const path = join(vaultDir, "t.vault");
    const unlock = await fetch(`${BASE}/v1/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path,
        password: "test-master-password-32chars!!",
        create: true,
      }),
    });
    expect(unlock.ok).toBeTruthy();

    const add = await fetch(`${BASE}/v1/items`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "GitHub",
        username: "alice",
        password: "s3cret-value-not-in-list",
        url: "https://github.com/login",
      }),
    });
    expect(add.ok).toBeTruthy();
    const added = await add.json();
    expect(added.id).toBeTruthy();

    const itemsRes = await fetch(`${BASE}/v1/items`);
    expect(itemsRes.ok).toBeTruthy();
    const items = await itemsRes.json();
    expect(items.length).toBe(1);
    expect(items[0].password).not.toBe("s3cret-value-not-in-list");
    expect(String(items[0].password)).toMatch(/•/);

    const rev = await fetch(`${BASE}/v1/reveal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: added.id,
        purpose: "autofill",
        origin: "https://github.com",
      }),
    });
    expect(rev.ok).toBeTruthy();
    const body = await rev.json();
    expect(body.password).toBe("s3cret-value-not-in-list");
    expect(body.username).toBe("alice");
    expect(body.ttl_ms).toBe(15000);
    expect(body.reveal_id).toBeTruthy();
  });
});
