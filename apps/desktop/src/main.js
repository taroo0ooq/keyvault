import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const state = {
  items: [],
  selectedId: null,
  vaultPath: null,
  autoLockSecs: 300,
  totpTimer: null,
  lastTotpCode: "",
};

function showAuthError(msg) {
  $("#auth-error").textContent = msg || "";
}

function showVaultError(msg) {
  const el = $("#vault-error");
  el.textContent = msg || "";
  el.classList.toggle("hidden", !msg);
  if (msg) {
    setTimeout(() => {
      if (el.textContent === msg) {
        el.textContent = "";
        el.classList.add("hidden");
      }
    }, 4000);
  }
}

function showView(name) {
  $("#view-auth").classList.toggle("hidden", name !== "auth");
  $("#view-vault").classList.toggle("hidden", name !== "vault");
}

async function defaultVaultPath() {
  try {
    return await invoke("default_vault_path");
  } catch {
    return "";
  }
}

function isPinMode(formRoot) {
  const mode = formRoot.querySelector('input[name="auth-mode"]:checked');
  return mode?.value === "pin";
}

async function refreshEnclaveUi() {
  const path = $("#unlock-path")?.value?.trim();
  const btn = $("#btn-enclave-unlock");
  const hint = $("#enclave-hint");
  if (!path || !btn) return;
  try {
    const ok = await invoke("enclave_available", { path });
    btn.classList.toggle("hidden", !ok);
    hint?.classList.toggle("hidden", !ok);
  } catch {
    btn.classList.add("hidden");
    hint?.classList.add("hidden");
  }
}

async function initAuth() {
  const path = await defaultVaultPath();
  $("#unlock-path").value = path;
  $("#create-path").value = path;
  await refreshEnclaveUi();
  $("#unlock-path").addEventListener("change", refreshEnclaveUi);
  $("#unlock-path").addEventListener("input", () => {
    clearTimeout(refreshEnclaveUi._t);
    refreshEnclaveUi._t = setTimeout(refreshEnclaveUi, 300);
  });

  $("#btn-enclave-unlock")?.addEventListener("click", async () => {
    showAuthError("");
    try {
      const p = $("#unlock-path").value.trim();
      await invoke("unlock_with_enclave", { path: p });
      await enterVault(p);
    } catch (err) {
      showAuthError(String(err));
    }
  });

  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const which = tab.dataset.tab;
      $("#form-unlock").classList.toggle("hidden", which !== "unlock");
      $("#form-create").classList.toggle("hidden", which !== "create");
      showAuthError("");
    });
  });

  const wireMode = (formId, secretId, secret2Id, labelId) => {
    const form = $(formId);
    form.querySelectorAll('input[name="auth-mode"]').forEach((radio) => {
      radio.addEventListener("change", () => {
        const pin = isPinMode(form);
        const secret = $(secretId);
        const secret2 = secret2Id ? $(secret2Id) : null;
        const label = $(labelId);
        if (pin) {
          secret.type = "password";
          secret.inputMode = "numeric";
          secret.autocomplete = "one-time-code";
          secret.placeholder = "8+ digits";
          if (label) label.textContent = "PIN (≥8 digits)";
          if (secret2) {
            secret2.inputMode = "numeric";
            secret2.placeholder = "Confirm PIN";
          }
        } else {
          secret.inputMode = "text";
          secret.autocomplete =
            formId === "#form-create" ? "new-password" : "current-password";
          secret.placeholder = "";
          if (label) label.textContent = "Master password";
          if (secret2) {
            secret2.inputMode = "text";
            secret2.placeholder = "";
          }
        }
        showAuthError("");
      });
    });
  };
  wireMode("#form-unlock", "#unlock-password", null, "#unlock-secret-label");
  wireMode(
    "#form-create",
    "#create-password",
    "#create-password2",
    "#create-secret-label",
  );

  $("#form-unlock").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAuthError("");
    const path = $("#unlock-path").value.trim();
    const secret = $("#unlock-password").value;
    try {
      if (isPinMode($("#form-unlock"))) {
        await invoke("unlock_with_pin", { path, pin: secret });
      } else {
        await invoke("unlock_vault", { path, masterPassword: secret });
      }
      $("#unlock-password").value = "";
      await enterVault(path);
    } catch (err) {
      showAuthError(String(err));
    }
  });

  $("#create-password").addEventListener("input", async () => {
    if (isPinMode($("#form-create"))) {
      const pin = $("#create-password").value;
      $("#create-entropy").textContent =
        pin.length >= 8 && /^\d+$/.test(pin)
          ? "PIN length OK"
          : "PIN must be at least 8 digits";
      return;
    }
    const pw = $("#create-password").value;
    if (!pw) {
      $("#create-entropy").textContent = "";
      return;
    }
    try {
      const score = await invoke("score_password", { password: pw });
      $("#create-entropy").textContent = `Strength: ${score.label} (${score.score}/4, ~${score.bits.toFixed(0)} bits)`;
    } catch {
      $("#create-entropy").textContent = "";
    }
  });

  $("#form-create").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAuthError("");
    const path = $("#create-path").value.trim();
    const pw = $("#create-password").value;
    const pw2 = $("#create-password2").value;
    if (pw !== pw2) {
      showAuthError("Secrets do not match");
      return;
    }
    try {
      if (isPinMode($("#form-create"))) {
        if (pw.length < 8 || !/^\d+$/.test(pw)) {
          showAuthError("PIN must be at least 8 digits");
          return;
        }
        await invoke("create_with_pin", { path, pin: pw });
      } else {
        if (pw.length < 12) {
          showAuthError("Use at least 12 characters for the master password");
          return;
        }
        await invoke("create_vault", { path, masterPassword: pw });
      }
      $("#create-password").value = "";
      $("#create-password2").value = "";
      await enterVault(path);
    } catch (err) {
      showAuthError(String(err));
    }
  });
}

async function enterVault(path) {
  state.vaultPath = path;
  state.selectedId = null;
  $("#vault-path-label").textContent = path;
  showView("vault");
  try {
    const status = await invoke("session_status");
    state.autoLockSecs = status.autoLockSecs || 300;
    $("#auto-lock-secs").value = String(state.autoLockSecs);
  } catch {
    /* ignore */
  }
  await refreshList();
}

async function onAutoLocked() {
  state.items = [];
  state.selectedId = null;
  showView("auth");
  showAuthError("Vault locked after idle timeout");
}

async function refreshList(query = "") {
  showVaultError("");
  try {
    await invoke("touch_activity");
    state.items = query
      ? await invoke("search_items", { query })
      : await invoke("list_items");
    renderList();
    if (state.selectedId) {
      const still = state.items.find((i) => i.id === state.selectedId);
      if (still) selectItem(still.id);
      else {
        state.selectedId = null;
        showEmptyDetail();
      }
    }
  } catch (err) {
    const msg = String(err);
    if (msg.includes("auto-locked") || msg.includes("locked")) {
      await onAutoLocked();
    } else {
      showVaultError(msg);
    }
  }
}

function renderList() {
  const ul = $("#item-list");
  ul.innerHTML = "";
  $("#empty-list").classList.toggle("hidden", state.items.length > 0);
  for (const item of state.items) {
    const li = document.createElement("li");
    li.dataset.id = item.id;
    if (item.id === state.selectedId) li.classList.add("active");
    li.innerHTML = `<div class="title"></div><div class="sub"></div>`;
    li.querySelector(".title").textContent = item.title;
    li.querySelector(".sub").textContent = item.username || item.url || "—";
    li.addEventListener("click", () => selectItem(item.id));
    ul.appendChild(li);
  }
}

function showEmptyDetail() {
  $("#detail-empty").classList.remove("hidden");
  $("#form-item").classList.add("hidden");
  stopTotpLive();
}

function stopTotpLive() {
  if (state.totpTimer) {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
  }
  $("#totp-live")?.classList.add("hidden");
  state.lastTotpCode = "";
}

async function refreshTotpLive(id) {
  if (!id || !$("#item-totp")?.value) {
    stopTotpLive();
    return;
  }
  try {
    const code = await invoke("item_totp_code", { id });
    state.lastTotpCode = code.code || "";
    $("#totp-code").textContent = code.code;
    $("#totp-remain").textContent = `(${code.remaining_secs}s)`;
    $("#totp-live").classList.remove("hidden");
  } catch {
    // Invalid secret while editing — hide live code
    $("#totp-live")?.classList.add("hidden");
  }
}

function startTotpLive(id) {
  stopTotpLive();
  if (!id) return;
  void refreshTotpLive(id);
  state.totpTimer = setInterval(() => void refreshTotpLive(id), 1000);
}

function fillForm(item) {
  $("#detail-empty").classList.add("hidden");
  $("#form-item").classList.remove("hidden");
  $("#item-id").value = item?.id || "";
  $("#item-title").value = item?.title || "";
  $("#item-username").value = item?.username || "";
  $("#item-password").value = item?.password || "";
  $("#item-password").type = "password";
  $("#btn-toggle-pw").textContent = "Show";
  $("#item-url").value = item?.url || "";
  $("#item-notes").value = item?.notes || "";
  $("#item-totp").value = item?.totp || "";
  $("#item-totp").type = "password";
  $("#item-tags").value = (item?.tags || []).join(", ");
  if (item?.id && item?.totp) {
    startTotpLive(item.id);
  } else {
    stopTotpLive();
  }
}

async function selectItem(id) {
  state.selectedId = id;
  renderList();
  try {
    await invoke("touch_activity");
    const item = await invoke("get_item", { id });
    fillForm(item);
  } catch (err) {
    const msg = String(err);
    if (msg.includes("auto-locked") || msg.includes("locked")) {
      await onAutoLocked();
    } else {
      showVaultError(msg);
    }
  }
}

function initVaultUi() {
  const bump = () => {
    invoke("touch_activity").catch(() => {});
  };
  ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach((ev) => {
    window.addEventListener(ev, bump, { passive: true });
  });

  $("#search").addEventListener("input", (e) => {
    refreshList(e.target.value.trim());
  });

  $("#auto-lock-secs")?.addEventListener("change", async (e) => {
    const secs = Number(e.target.value) || 300;
    try {
      await invoke("set_auto_lock_secs", { secs });
      state.autoLockSecs = secs;
      showVaultError(`Auto-lock set to ${secs}s`);
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#btn-lock").addEventListener("click", async () => {
    try {
      await invoke("lock_vault");
      state.items = [];
      state.selectedId = null;
      showView("auth");
      $("#unlock-password").value = "";
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#btn-add").addEventListener("click", () => {
    state.selectedId = null;
    renderList();
    fillForm({
      id: "",
      title: "",
      username: "",
      password: "",
      url: "",
      notes: "",
      totp: "",
      tags: [],
    });
    $("#item-title").focus();
  });

  $("#btn-toggle-pw").addEventListener("click", () => {
    const input = $("#item-password");
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    $("#btn-toggle-pw").textContent = show ? "Hide" : "Show";
  });

  $("#btn-copy-pw").addEventListener("click", async () => {
    const pw = $("#item-password").value;
    if (!pw) return;
    try {
      const secs = await invoke("copy_secret", { secret: pw });
      showVaultError(`Password copied — clipboard clears in ${secs}s`);
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#btn-copy-totp")?.addEventListener("click", async () => {
    const code = state.lastTotpCode || $("#totp-code")?.textContent;
    if (!code || code === "————") return;
    try {
      const secs = await invoke("copy_secret", { secret: code });
      showVaultError(`TOTP copied — clipboard clears in ${secs}s`);
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#form-item").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      id: $("#item-id").value || null,
      title: $("#item-title").value.trim(),
      username: $("#item-username").value.trim() || null,
      password: $("#item-password").value,
      url: $("#item-url").value.trim() || null,
      notes: $("#item-notes").value.trim() || null,
      totp: $("#item-totp").value.trim() || null,
      tags: $("#item-tags").value
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    };
    try {
      const saved = await invoke("save_item", { item: payload });
      state.selectedId = saved.id;
      await refreshList($("#search").value.trim());
      fillForm(saved);
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#btn-hibp")?.addEventListener("click", async () => {
    const id = $("#item-id").value;
    if (!id) {
      showVaultError("Select a saved item first");
      return;
    }
    if (
      !confirm(
        "Check this password against Have I Been Pwned via vault_daemon?\n" +
          "Only a SHA-1 prefix is sent (k-anonymity). Requires daemon + network.",
      )
    ) {
      return;
    }
    showVaultError("Checking HIBP…");
    try {
      const r = await invoke("check_pwned_via_daemon", { id });
      if (r.pwned) {
        showVaultError(
          `⚠ Found in breaches: count≈${r.count} (“${r.title || id}”)`,
        );
      } else {
        showVaultError(`✓ Not found in HIBP range for “${r.title || id}”`);
      }
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#btn-delete").addEventListener("click", async () => {
    const id = $("#item-id").value;
    if (!id) {
      showEmptyDetail();
      return;
    }
    if (!confirm("Move this item to trash? (recoverable)")) return;
    try {
      await invoke("delete_item", { id });
      state.selectedId = null;
      showEmptyDetail();
      await refreshList($("#search").value.trim());
      showVaultError("Moved to trash");
    } catch (err) {
      showVaultError(String(err));
    }
  });

  $("#btn-generate").addEventListener("click", () => {
    $("#dlg-generate").showModal();
  });

  async function refreshTrash() {
    const ul = $("#trash-list");
    ul.innerHTML = "";
    try {
      const items = await invoke("list_trash");
      if (!items.length) {
        ul.innerHTML = "<li class='muted'>Trash is empty</li>";
        return;
      }
      for (const item of items) {
        const li = document.createElement("li");
        li.className = "row";
        li.innerHTML = `<span></span><button type="button" class="btn restore">Restore</button><button type="button" class="btn danger purge">Purge</button>`;
        li.querySelector("span").textContent = item.title;
        li.querySelector(".restore").addEventListener("click", async () => {
          await invoke("restore_item", { id: item.id });
          await refreshTrash();
          await refreshList($("#search").value.trim());
          $("#trash-msg").textContent = `Restored ${item.title}`;
        });
        li.querySelector(".purge").addEventListener("click", async () => {
          if (!confirm(`Permanently delete "${item.title}"?`)) return;
          await invoke("purge_item", { id: item.id });
          await refreshTrash();
          $("#trash-msg").textContent = `Purged ${item.title}`;
        });
        ul.appendChild(li);
      }
    } catch (err) {
      $("#trash-msg").textContent = String(err);
    }
  }

  $("#btn-trash")?.addEventListener("click", () => {
    $("#trash-msg").textContent = "";
    $("#dlg-trash").showModal();
    void refreshTrash();
  });
  $("#btn-trash-refresh")?.addEventListener("click", () => void refreshTrash());
  $("#btn-empty-trash")?.addEventListener("click", async () => {
    if (!confirm("Permanently delete ALL trash items?")) return;
    try {
      const n = await invoke("empty_trash");
      $("#trash-msg").textContent = `Emptied trash (${n} item(s))`;
      await refreshTrash();
    } catch (err) {
      $("#trash-msg").textContent = String(err);
    }
  });

  $("#btn-security")?.addEventListener("click", () => {
    $("#security-msg").textContent = "";
    $("#chg-current").value = "";
    $("#chg-new").value = "";
    $("#chg-confirm").value = "";
    $("#dlg-security").showModal();
  });
  $("#btn-change-pw")?.addEventListener("click", async () => {
    const currentPassword = $("#chg-current").value;
    const newPassword = $("#chg-new").value;
    const confirm = $("#chg-confirm").value;
    if (newPassword !== confirm) {
      $("#security-msg").textContent = "New passwords do not match.";
      return;
    }
    $("#security-msg").textContent = "Changing…";
    try {
      await invoke("change_master_password", { currentPassword, newPassword });
      $("#security-msg").textContent =
        "Password changed. Re-enroll quick unlock if you use it.";
      $("#chg-current").value = "";
      $("#chg-new").value = "";
      $("#chg-confirm").value = "";
    } catch (err) {
      $("#security-msg").textContent = String(err);
    }
  });
  $("#btn-import-csv")?.addEventListener("click", async () => {
    const csv = $("#csv-blob").value;
    if (!csv.trim()) {
      $("#security-msg").textContent = "Paste CSV first.";
      return;
    }
    $("#security-msg").textContent = "Importing…";
    try {
      const written = await invoke("import_csv", { csv });
      $("#security-msg").textContent = `Imported ${written} item(s).`;
      await refreshList($("#search").value.trim());
    } catch (err) {
      $("#security-msg").textContent = String(err);
    }
  });
  $("#btn-export-csv")?.addEventListener("click", async () => {
    $("#security-msg").textContent = "Exporting CSV…";
    try {
      const csv = await invoke("export_csv");
      $("#csv-blob").value = csv;
      $("#security-msg").textContent =
        "CSV exported into the box (contains secrets — copy carefully).";
    } catch (err) {
      $("#security-msg").textContent = String(err);
    }
  });
  $("#btn-password-health")?.addEventListener("click", async () => {
    $("#security-msg").textContent = "Scanning…";
    $("#health-out").textContent = "";
    try {
      const rep = await invoke("password_health");
      $("#health-out").textContent = JSON.stringify(rep, null, 2);
      $("#security-msg").textContent = `Health: weak=${rep.weak_count} reused=${rep.reused_count} of ${rep.total_items}`;
    } catch (err) {
      $("#security-msg").textContent = String(err);
    }
  });

  $("#btn-backup")?.addEventListener("click", () => {
    $("#backup-msg").textContent = "";
    $("#dlg-backup").showModal();
  });
  $("#btn-backup-export")?.addEventListener("click", async () => {
    const passphrase = $("#backup-pass").value;
    $("#backup-msg").textContent = "Exporting…";
    try {
      const backup = await invoke("export_backup", { passphrase });
      $("#backup-blob").value = backup;
      $("#backup-msg").textContent = `Exported ${backup.length} chars (base64). Copy or save securely.`;
    } catch (err) {
      $("#backup-msg").textContent = String(err);
    }
  });
  $("#btn-backup-import")?.addEventListener("click", async () => {
    const passphrase = $("#backup-pass").value;
    const backup = $("#backup-blob").value.trim();
    const merge = $("#backup-merge").checked;
    if (!backup) {
      $("#backup-msg").textContent = "Paste backup data first.";
      return;
    }
    $("#backup-msg").textContent = "Importing…";
    try {
      const written = await invoke("import_backup", { passphrase, backup, merge });
      $("#backup-msg").textContent = `Imported ${written} item(s).`;
      await refreshList($("#search").value.trim());
    } catch (err) {
      $("#backup-msg").textContent = String(err);
    }
  });
  $("#btn-backup-copy")?.addEventListener("click", async () => {
    const blob = $("#backup-blob").value;
    if (!blob) return;
    try {
      await navigator.clipboard.writeText(blob);
      $("#backup-msg").textContent = "Copied to clipboard.";
    } catch {
      $("#backup-msg").textContent = "Copy failed — select and copy manually.";
    }
  });

  const remoteOut = (obj) => {
    $("#remote-out").textContent =
      typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  };

  async function refreshRemote() {
    try {
      const [tunnel, auth] = await Promise.all([
        invoke("daemon_tunnel_status"),
        invoke("daemon_auth_mode"),
      ]);
      $("#remote-status").textContent = `tunnel.running=${tunnel.running} public=${tunnel.public_url || "—"} auth_required=${auth.auth_required}`;
      remoteOut({ tunnel, auth });
    } catch (err) {
      $("#remote-status").textContent = "Daemon offline — start vault_daemon on :8080";
      remoteOut(String(err));
    }
  }

  $("#btn-remote")?.addEventListener("click", () => {
    $("#dlg-remote").showModal();
    void refreshRemote();
  });
  $("#btn-tunnel-refresh")?.addEventListener("click", () => void refreshRemote());
  $("#btn-tunnel-cf")?.addEventListener("click", async () => {
    try {
      const publicUrl = $("#tunnel-public-url").value.trim() || null;
      remoteOut(
        await invoke("daemon_tunnel_start", {
          provider: "cloudflared",
          publicUrl,
        }),
      );
      await refreshRemote();
    } catch (err) {
      remoteOut(String(err));
    }
  });
  $("#btn-tunnel-ngrok")?.addEventListener("click", async () => {
    try {
      const publicUrl = $("#tunnel-public-url").value.trim() || null;
      remoteOut(
        await invoke("daemon_tunnel_start", {
          provider: "ngrok",
          publicUrl,
        }),
      );
      await refreshRemote();
    } catch (err) {
      remoteOut(String(err));
    }
  });
  $("#btn-tunnel-stop")?.addEventListener("click", async () => {
    try {
      remoteOut(await invoke("daemon_tunnel_stop"));
      await refreshRemote();
    } catch (err) {
      remoteOut(String(err));
    }
  });
  $("#btn-pairing-create")?.addEventListener("click", async () => {
    try {
      remoteOut(await invoke("daemon_pairing_create"));
    } catch (err) {
      remoteOut(String(err));
    }
  });
  $("#btn-pairing-devices")?.addEventListener("click", async () => {
    try {
      remoteOut(await invoke("daemon_pairing_devices"));
    } catch (err) {
      remoteOut(String(err));
    }
  });

  $("#btn-gen-run").addEventListener("click", async () => {
    try {
      const password = await invoke("generate_password", {
        policy: {
          length: Number($("#gen-length").value) || 20,
          lowercase: $("#gen-lower").checked,
          uppercase: $("#gen-upper").checked,
          digits: $("#gen-digits").checked,
          symbols: $("#gen-symbols").checked,
          exclude_ambiguous: $("#gen-ambiguous").checked,
        },
      });
      $("#gen-result").textContent = password;
      const score = await invoke("score_password", { password });
      $("#gen-score").textContent = `Strength: ${score.label} (${score.score}/4)`;
    } catch (err) {
      $("#gen-result").textContent = String(err);
    }
  });

  $("#btn-gen-use").addEventListener("click", () => {
    const pw = $("#gen-result").textContent;
    if (!pw || pw.startsWith("Error") || pw.includes("error")) return;
    if ($("#form-item").classList.contains("hidden")) {
      $("#btn-add").click();
    }
    $("#item-password").value = pw;
    $("#dlg-generate").close();
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  showVaultError("");
  $("#vault-error").classList.add("hidden");
  await initAuth();
  initVaultUi();

  try {
    await listen("vault-auto-locked", () => {
      onAutoLocked();
    });
    await listen("clipboard-cleared", () => {
      showVaultError("Clipboard cleared");
    });
  } catch {
    /* browser-only preview without tauri */
  }

  try {
    const status = await invoke("session_status");
    if (status.unlocked) {
      await enterVault(status.path || (await defaultVaultPath()));
    } else {
      showView("auth");
    }
  } catch {
    showView("auth");
  }
});
