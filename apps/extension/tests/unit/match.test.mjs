import test from "node:test";
import assert from "node:assert/strict";

// Inline match logic mirror of daemon.ts for pure unit test without bundler.
function matchItemsForHost(items, hostname) {
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
      /* ignore */
    }
    return title.includes(host);
  });
}

test("matches by hostname", () => {
  const items = [
    { id: "1", title: "GitHub", url: "https://github.com/login", password: "x" },
    { id: "2", title: "Bank", url: "https://bank.example", password: "y" },
  ];
  const m = matchItemsForHost(items, "www.github.com");
  assert.equal(m.length, 1);
  assert.equal(m[0].id, "1");
});

test("no false match", () => {
  const items = [{ id: "1", title: "Other", url: "https://example.com", password: "x" }];
  assert.equal(matchItemsForHost(items, "github.com").length, 0);
});
