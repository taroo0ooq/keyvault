/**
 * KeyVault MV3 service worker.
 * Polls vault_daemon health and answers content-script credential requests.
 * Secrets from /v1/reveal are never cached in the service worker.
 */

import {
  DEFAULT_DAEMON,
  getStatus,
  listItems,
  matchItemsForHost,
  revealItem,
  type DaemonStatus,
  type VaultListItem,
} from "./daemon.js";

const POLL_ALARM = "kv-daemon-poll";

let lastStatus: DaemonStatus | null = null;
let cacheItems: VaultListItem[] = [];
let cacheAt = 0;

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(POLL_ALARM, { periodInMinutes: 0.5 });
  void refreshStatus();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === POLL_ALARM) void refreshStatus();
});

async function refreshStatus(): Promise<void> {
  try {
    lastStatus = await getStatus(DEFAULT_DAEMON);
    if (lastStatus.unlocked) {
      cacheItems = await listItems("", DEFAULT_DAEMON);
      cacheAt = Date.now();
    } else {
      cacheItems = [];
    }
    await chrome.action.setBadgeText({
      text: lastStatus.unlocked ? "ON" : "",
    });
    await chrome.action.setBadgeBackgroundColor({
      color: lastStatus.unlocked ? "#22c55e" : "#64748b",
    });
  } catch {
    lastStatus = null;
    cacheItems = [];
    await chrome.action.setBadgeText({ text: "!" });
    await chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void (async () => {
    try {
      if (message?.type === "GET_STATUS") {
        if (!lastStatus) await refreshStatus();
        sendResponse({ ok: true, status: lastStatus });
        return;
      }
      if (message?.type === "REFRESH") {
        await refreshStatus();
        sendResponse({ ok: true, status: lastStatus });
        return;
      }
      if (message?.type === "MATCH_FOR_HOST") {
        const host = String(message.hostname || "");
        if (!lastStatus?.unlocked || Date.now() - cacheAt > 30_000) {
          await refreshStatus();
        }
        const matches = matchItemsForHost(cacheItems, host);
        // Matches use redacted passwords from list API.
        sendResponse({
          ok: true,
          unlocked: !!lastStatus?.unlocked,
          matches,
        });
        return;
      }
      if (message?.type === "REVEAL_ITEM") {
        const id = String(message.id || "");
        if (!id) {
          sendResponse({ ok: false, error: "id required" });
          return;
        }
        if (!lastStatus?.unlocked) {
          await refreshStatus();
        }
        if (!lastStatus?.unlocked) {
          sendResponse({ ok: false, error: "vault locked" });
          return;
        }
        // Prefer tab URL origin when available (content script autofill).
        let origin = String(message.origin || "");
        if (!origin && sender.tab?.url) {
          try {
            origin = new URL(sender.tab.url).origin;
          } catch {
            origin = "";
          }
        }
        const revealed = await revealItem(id, {
          purpose: message.purpose || "autofill",
          origin,
        });
        // Pass through once; do not store in SW memory beyond this response.
        sendResponse({
          ok: true,
          reveal: {
            id: revealed.id,
            title: revealed.title,
            username: revealed.username,
            password: revealed.password,
            ttl_ms: revealed.ttl_ms,
            reveal_id: revealed.reveal_id,
          },
        });
        return;
      }
      sendResponse({ ok: false, error: "unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true; // async sendResponse
});

void refreshStatus();
