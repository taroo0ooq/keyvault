import {
  DEFAULT_DAEMON,
  generatePassword,
  getAuthMode,
  getStatus,
  listItems,
  lockVault,
  revealItem,
  setAuthToken,
  totpCode,
  unlockVault,
  type DaemonStatus,
  type VaultListItem,
} from "./daemon.js";

const $ = (id: string) => document.getElementById(id)!;

function show(id: string, on: boolean): void {
  $(id).classList.toggle("hidden", !on);
}

function setBadge(text: string, cls: string): void {
  const b = $("badge");
  b.textContent = text;
  b.className = `badge ${cls}`;
}

async function refresh(): Promise<void> {
  $("status-line").textContent = "Checking local daemon…";
  const bearer = ($("bearer") as HTMLInputElement).value;
  setAuthToken(bearer || null);
  try {
    const mode = await getAuthMode(DEFAULT_DAEMON);
    $("auth-line").textContent = mode.auth_required
      ? `Auth required (tunnel=${mode.tunnel_running}) — set Bearer above`
      : "Auth open (local loopback, no tunnel)";
  } catch {
    $("auth-line").textContent = "";
  }
  try {
    const status: DaemonStatus = await getStatus(DEFAULT_DAEMON);
    if (status.unlocked) {
      setBadge("Unlocked", "ok");
      $("status-line").textContent = `Daemon OK · ${status.path || "vault"}`;
      show("unlock-block", false);
      show("vault-block", true);
      await renderItems();
    } else {
      setBadge("Locked", "warn");
      $("status-line").textContent = status.auto_locked
        ? "Vault auto-locked — unlock again"
        : "Daemon online · vault locked";
      show("unlock-block", true);
      show("vault-block", false);
    }
  } catch {
    setBadge("Offline", "err");
    $("status-line").textContent =
      "Cannot reach vault_daemon on 127.0.0.1:8080. Start the desktop app or daemon.";
    show("unlock-block", false);
    show("vault-block", false);
  }
}

async function renderItems(query = ""): Promise<void> {
  const ul = $("items");
  ul.innerHTML = "";
  let items: VaultListItem[] = [];
  try {
    items = await listItems(query, DEFAULT_DAEMON);
  } catch (e) {
    ul.innerHTML = `<li class="muted">${String(e)}</li>`;
    return;
  }
  if (!items.length) {
    ul.innerHTML = `<li class="muted">No items</li>`;
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    const hasTotp = !!(item.totp && item.totp.length > 0);
    li.innerHTML = `<div><strong></strong>${hasTotp ? ' <span class="badge ok">2FA</span>' : ""}</div><div class="muted"></div><div class="row"></div>`;
    li.querySelector("strong")!.textContent = item.title;
    (li.querySelector(".muted") as HTMLElement).textContent =
      item.username || item.url || item.id;
    const row = li.querySelector(".row") as HTMLElement;
    const btnPw = document.createElement("button");
    btnPw.type = "button";
    btnPw.className = "copy-pw";
    btnPw.textContent = "Copy password";
    btnPw.addEventListener("click", async () => {
      try {
        const r = await revealItem(item.id, { purpose: "clipboard" });
        await navigator.clipboard.writeText(r.password);
        btnPw.textContent = `Copied (${Math.round(r.ttl_ms / 1000)}s)`;
      } catch (e) {
        btnPw.textContent = String(e);
      }
    });
    row.appendChild(btnPw);
    if (hasTotp) {
      const btnTotp = document.createElement("button");
      btnTotp.type = "button";
      btnTotp.className = "copy-totp";
      btnTotp.textContent = "Copy TOTP";
      btnTotp.addEventListener("click", async () => {
        try {
          const t = await totpCode(item.id);
          await navigator.clipboard.writeText(t.code);
          btnTotp.textContent = `${t.code} (${t.remaining_secs}s)`;
        } catch (e) {
          btnTotp.textContent = String(e);
        }
      });
      row.appendChild(btnTotp);
    }
    ul.appendChild(li);
  }
}

function wire(): void {
  $("bearer").addEventListener("change", () => {
    setAuthToken(($("bearer") as HTMLInputElement).value || null);
    void refresh();
  });
  $("btn-unlock").addEventListener("click", async () => {
    $("unlock-error").textContent = "";
    try {
      await unlockVault(
        ($("path") as HTMLInputElement).value.trim(),
        ($("password") as HTMLInputElement).value,
      );
      ($("password") as HTMLInputElement).value = "";
      await refresh();
      chrome.runtime.sendMessage({ type: "REFRESH" });
    } catch (e) {
      $("unlock-error").textContent = String(e);
    }
  });

  $("btn-create").addEventListener("click", async () => {
    $("unlock-error").textContent = "";
    try {
      await unlockVault(
        ($("path") as HTMLInputElement).value.trim(),
        ($("password") as HTMLInputElement).value,
        { create: true },
      );
      ($("password") as HTMLInputElement).value = "";
      await refresh();
      chrome.runtime.sendMessage({ type: "REFRESH" });
    } catch (e) {
      $("unlock-error").textContent = String(e);
    }
  });

  $("btn-lock").addEventListener("click", async () => {
    await lockVault();
    await refresh();
    chrome.runtime.sendMessage({ type: "REFRESH" });
  });

  $("search").addEventListener("input", (e) => {
    const q = (e.target as HTMLInputElement).value.trim();
    void renderItems(q);
  });

  $("btn-gen").addEventListener("click", async () => {
    try {
      const pw = await generatePassword(20);
      $("gen-out").textContent = pw;
      await navigator.clipboard.writeText(pw);
    } catch (e) {
      $("gen-out").textContent = String(e);
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  // Sensible default vault path hint (user edits for their machine).
  ($("path") as HTMLInputElement).value = "keyvault.vault";
  wire();
  void refresh();
});
