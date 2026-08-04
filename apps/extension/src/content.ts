/**
 * Content script: detect login forms and show KeyVault autofill overlay.
 * List matches are redacted; passwords arrive only via one-shot REVEAL_ITEM
 * and are written into the form then cleared from JS after ttl_ms.
 */

type Match = {
  id: string;
  title: string;
  username?: string | null;
  password: string;
  url?: string | null;
};

const OVERLAY_ID = "keyvault-autofill-overlay";

function isPasswordField(el: Element): el is HTMLInputElement {
  return (
    el instanceof HTMLInputElement &&
    (el.type === "password" || el.autocomplete === "current-password")
  );
}

function findLoginContext(anchor: HTMLElement): {
  form: HTMLFormElement | null;
  user: HTMLInputElement | null;
  pass: HTMLInputElement | null;
} {
  const pass =
    anchor instanceof HTMLInputElement && isPasswordField(anchor)
      ? anchor
      : null;
  const form = pass?.form ?? (anchor.closest("form") as HTMLFormElement | null);
  let user: HTMLInputElement | null = null;
  const scope: ParentNode = form ?? document;
  user =
    scope.querySelector<HTMLInputElement>(
      'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[autocomplete="username"]',
    ) || null;
  const passField =
    pass ||
    scope.querySelector<HTMLInputElement>(
      'input[type="password"], input[autocomplete="current-password"]',
    );
  return { form, user, pass: passField };
}

function setNativeValue(input: HTMLInputElement, value: string): void {
  const proto = Object.getPrototypeOf(input) as HTMLInputElement;
  const desc = Object.getOwnPropertyDescriptor(proto, "value") ||
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  desc?.set?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function removeOverlay(): void {
  document.getElementById(OVERLAY_ID)?.remove();
}

function showOverlay(
  anchor: HTMLElement,
  matches: Match[],
  unlocked: boolean,
): void {
  removeOverlay();
  const rect = anchor.getBoundingClientRect();
  const root = document.createElement("div");
  root.id = OVERLAY_ID;
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-label", "KeyVault autofill");
  root.style.top = `${window.scrollY + rect.bottom + 4}px`;
  root.style.left = `${window.scrollX + rect.left}px`;

  const title = document.createElement("div");
  title.className = "kv-title";
  title.textContent = unlocked
    ? matches.length
      ? "KeyVault matches"
      : "KeyVault — no matches"
    : "KeyVault — vault locked";
  root.appendChild(title);

  if (!unlocked) {
    const p = document.createElement("p");
    p.className = "kv-hint";
    p.textContent = "Unlock via the KeyVault popup (local daemon).";
    root.appendChild(p);
  } else {
    for (const m of matches.slice(0, 5)) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "kv-item";
      btn.textContent = `${m.title}${m.username ? ` — ${m.username}` : ""}`;
      btn.addEventListener("click", () => {
        void fillFromReveal(m.id, anchor, btn);
      });
      root.appendChild(btn);
    }
  }

  const close = document.createElement("button");
  close.type = "button";
  close.className = "kv-close";
  close.textContent = "Close";
  close.addEventListener("click", removeOverlay);
  root.appendChild(close);

  document.documentElement.appendChild(root);
}

async function fillFromReveal(
  id: string,
  anchor: HTMLElement,
  btn: HTMLButtonElement,
): Promise<void> {
  btn.disabled = true;
  btn.textContent = "Revealing…";
  try {
    const res = await chrome.runtime.sendMessage({
      type: "REVEAL_ITEM",
      id,
      purpose: "autofill",
      origin: location.origin,
    });
    if (!res?.ok || !res.reveal) {
      btn.textContent = res?.error || "Reveal failed";
      btn.disabled = false;
      return;
    }

    const { user, pass } = findLoginContext(anchor);
    let username = res.reveal.username as string | null | undefined;
    let password = res.reveal.password as string;
    const ttl = Number(res.reveal.ttl_ms) || 15_000;

    if (user && username) {
      setNativeValue(user, username);
    }
    if (pass && password) {
      setNativeValue(pass, password);
    }

    btn.textContent = "Filled";
    removeOverlay();

    // Drop local copies after advisory TTL (defense in depth).
    window.setTimeout(() => {
      username = null;
      password = "";
    }, ttl);
  } catch (e) {
    btn.textContent = String(e);
    btn.disabled = false;
  }
}

async function onFocusPassword(pass: HTMLInputElement): Promise<void> {
  const hostname = location.hostname;
  const res = await chrome.runtime.sendMessage({
    type: "MATCH_FOR_HOST",
    hostname,
  });
  if (!res?.ok) return;
  showOverlay(pass, res.matches || [], !!res.unlocked);
}

function attach(): void {
  document.addEventListener(
    "focusin",
    (ev) => {
      const t = ev.target;
      if (t instanceof HTMLInputElement && isPasswordField(t)) {
        void onFocusPassword(t);
      }
    },
    true,
  );

  const mo = new MutationObserver(() => {
    /* focus handler covers new fields */
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", attach);
} else {
  attach();
}
