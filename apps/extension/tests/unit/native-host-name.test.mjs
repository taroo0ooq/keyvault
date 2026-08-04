import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");

test("manifest includes nativeMessaging permission", () => {
  const m = JSON.parse(readFileSync(join(root, "src/manifest.json"), "utf8"));
  assert.ok(m.permissions.includes("nativeMessaging"));
});

test("host manifest name is app.keyvault.native", () => {
  const m = JSON.parse(
    readFileSync(join(root, "native-messaging/host-manifest.chrome.json"), "utf8"),
  );
  assert.equal(m.name, "app.keyvault.native");
  assert.equal(m.type, "stdio");
});
