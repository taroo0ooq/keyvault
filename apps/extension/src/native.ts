/**
 * Optional Chrome native messaging bridge to vault_native_host.
 * Used when loopback fetch is blocked; host proxies to vault_daemon.
 */

export const NATIVE_HOST = "app.keyvault.native";

export type NativeCmd =
  | { cmd: "ping" }
  | { cmd: "health" }
  | { cmd: "status" }
  | { cmd: "auth_mode" }
  | { cmd: "items" }
  | { cmd: "search"; q: string }
  | { cmd: "reveal"; id: string; purpose?: string; origin?: string }
  | { cmd: "totp"; id: string }
  | { cmd: "unlock"; path: string; password: string; create?: boolean }
  | { cmd: "lock" }
  | { cmd: "proxy"; method: string; path: string; body?: unknown };

/** True if chrome.runtime.sendNativeMessage is available (extension context). */
export function nativeApiAvailable(): boolean {
  return (
    typeof chrome !== "undefined" &&
    !!chrome.runtime &&
    typeof chrome.runtime.sendNativeMessage === "function"
  );
}

/**
 * One-shot native message. Resolves host JSON or rejects on chrome.runtime.lastError.
 */
export function sendNative<T = unknown>(message: NativeCmd): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!nativeApiAvailable()) {
      reject(new Error("native messaging API unavailable"));
      return;
    }
    chrome.runtime.sendNativeMessage(
      NATIVE_HOST,
      message as unknown as object,
      (response) => {
        const err = chrome.runtime.lastError;
        if (err) {
          reject(new Error(err.message || "native host error"));
          return;
        }
        if (response == null) {
          reject(new Error("empty native response"));
          return;
        }
        resolve(response as T);
      },
    );
  });
}

/** Probe host without requiring daemon (host still needs daemon for other cmds). */
export async function nativePing(): Promise<boolean> {
  try {
    const r = await sendNative<{ ok?: boolean; via?: string }>({ cmd: "ping" });
    return r?.ok === true && r?.via === "native";
  } catch {
    return false;
  }
}
