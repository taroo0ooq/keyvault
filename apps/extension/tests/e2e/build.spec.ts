import { test, expect } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dist = join(process.cwd(), "dist");

test("extension dist is built with MV3 manifest", () => {
  expect(existsSync(join(dist, "manifest.json"))).toBeTruthy();
  expect(existsSync(join(dist, "background.js"))).toBeTruthy();
  expect(existsSync(join(dist, "content.js"))).toBeTruthy();
  expect(existsSync(join(dist, "popup.js"))).toBeTruthy();
  expect(existsSync(join(dist, "popup.html"))).toBeTruthy();

  const manifest = JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8"));
  expect(manifest.manifest_version).toBe(3);
  expect(manifest.background.service_worker).toBe("background.js");
  expect(manifest.host_permissions).toContain("http://127.0.0.1:8080/*");
});

test("content script has no eval (CSP-friendly)", () => {
  const js = readFileSync(join(dist, "content.js"), "utf8");
  expect(js.includes("eval(")).toBeFalsy();
});
