import * as esbuild from "esbuild";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outdir = join(root, "dist");

mkdirSync(outdir, { recursive: true });

await esbuild.build({
  entryPoints: {
    background: join(root, "src/background.ts"),
    content: join(root, "src/content.ts"),
    popup: join(root, "src/popup.ts"),
  },
  bundle: true,
  outdir,
  format: "esm",
  target: ["chrome120", "firefox120"],
  sourcemap: true,
  logLevel: "info",
});

// Static assets
for (const file of ["popup.html", "popup.css", "content.css", "manifest.json"]) {
  cpSync(join(root, "src", file), join(outdir, file));
}

// Icons (simple SVG placeholders as data — copy if present)
try {
  cpSync(join(root, "icons"), join(outdir, "icons"), { recursive: true });
} catch {
  mkdirSync(join(outdir, "icons"), { recursive: true });
}

// Rewrite manifest to point at built JS (already correct names)
const manifest = JSON.parse(readFileSync(join(outdir, "manifest.json"), "utf8"));
writeFileSync(join(outdir, "manifest.json"), JSON.stringify(manifest, null, 2));

console.log("Built extension →", outdir);
