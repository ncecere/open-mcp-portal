#!/usr/bin/env node
/*
 * Bundle size report for the Open MCP Portal web app. Reads the last `npm run build`
 * (dist/) and prints raw and gzip sizes for the chunks worth tracking, then the same
 * numbers as one line of JSON (for diffing between commits).
 *
 *   - critical path: what dist/index.html loads before anything renders: the entry
 *     script, its <link rel="modulepreload"> chunks and the entry stylesheet;
 *   - tracked chunks: the vendor groups (vite.config.ts) and the heaviest lazy chunks;
 *   - totals: all JS and all CSS under dist/assets.
 *
 * Gzip is zlib's default level 6, the same as `gzip -c file | wc -c`. Hashes are
 * stripped from the names.
 *
 * Usage: npm run build && npm run report:bundle [-- --json] [-- --root <dir>]
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const args = process.argv.slice(2);
const argRoot = args.indexOf("--root");
const root = argRoot !== -1 && args[argRoot + 1] ? path.resolve(args[argRoot + 1]) : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const assets = path.join(dist, "assets");
const jsonOnly = args.includes("--json");

/** Chunks reported by name besides the critical path (matched as "<name>-<hash>.js"). */
const TRACKED = ["session", "server-record", "gateway-record"];

if (!fs.existsSync(path.join(dist, "index.html")) || !fs.existsSync(assets)) {
  console.error("No build found (dist/index.html, dist/assets). Run `npm run build` first.");
  process.exit(1);
}

const size = (file) => {
  const buf = fs.readFileSync(file);
  return { raw: buf.length, gzip: zlib.gzipSync(buf).length };
};
/** "index-B3xY_z1a.js" → "index.js": the hash is the last "-" segment before the extension. */
const stable = (name) => name.replace(/-[A-Za-z0-9_-]{8}(\.[a-z]+)$/, "$1");
const add = (a, b) => ({ raw: a.raw + b.raw, gzip: a.gzip + b.gzip });
const zero = { raw: 0, gzip: 0 };

const files = fs.readdirSync(assets).map((name) => ({ name, stable: stable(name), ...size(path.join(assets, name)) }));
const byName = new Map(files.map((f) => [f.name, f]));

const html = fs.readFileSync(path.join(dist, "index.html"), "utf8");
const tags = (name) => html.match(new RegExp(`<${name}\\b[^>]*>`, "g")) ?? [];
const attr = (tag, name) => tag.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1];
const fromTags = (list) => list.map((src) => byName.get(path.basename(src ?? ""))).filter(Boolean);

const entry = fromTags(
  tags("script")
    .filter((t) => attr(t, "type") === "module")
    .map((t) => attr(t, "src")),
);
const preloads = fromTags(
  tags("link")
    .filter((t) => attr(t, "rel") === "modulepreload")
    .map((t) => attr(t, "href")),
);
const styles = fromTags(
  tags("link")
    .filter((t) => attr(t, "rel") === "stylesheet")
    .map((t) => attr(t, "href")),
);

const row = (role, f) => ({ role, file: f.stable, raw: f.raw, gzip: f.gzip });
const rows = [
  ...entry.map((f) => row("entry", f)),
  ...preloads.map((f) => row("preload", f)),
  ...styles.map((f) => row("entry css", f)),
];
// A tracked chunk the page already preloads is listed once, under its critical-path role.
for (const name of TRACKED) {
  for (const f of files) if (f.stable === `${name}.js` && !rows.some((r) => r.file === f.stable)) rows.push(row("lazy", f));
}

const critical = [...entry, ...preloads];
const js = files.filter((f) => f.name.endsWith(".js"));
const css = files.filter((f) => f.name.endsWith(".css"));
const sum = (list) => list.reduce(add, zero);
const totals = {
  criticalJs: sum(critical),
  criticalCss: sum(styles),
  critical: sum([...critical, ...styles]),
  allJs: { ...sum(js), files: js.length },
  allCss: { ...sum(css), files: css.length },
};
const largest = [...js]
  .sort((a, b) => b.raw - a.raw)
  .slice(0, 12)
  .map((f) => row("js", f));

const report = { chunks: rows, totals, largest };

if (!jsonOnly) {
  const kb = (n) => (n / 1000).toFixed(2).padStart(9);
  const line = (role, file, s) => console.log(`${role.padEnd(10)} ${file.padEnd(34)} ${kb(s.raw)} ${kb(s.gzip)}`);
  const head = (title) => {
    console.log(`\n${title}`);
    console.log(`${"".padEnd(10)} ${"file".padEnd(34)} ${"raw kB".padStart(9)} ${"gzip kB".padStart(9)}`);
  };
  head("Critical path and tracked chunks");
  for (const r of rows) line(r.role, r.file, r);
  head("Totals");
  line("critical", "entry + preloads (JS)", totals.criticalJs);
  line("critical", "entry CSS", totals.criticalCss);
  line("critical", "JS + CSS", totals.critical);
  line("all", `JS (${totals.allJs.files} files)`, totals.allJs);
  line("all", `CSS (${totals.allCss.files} files)`, totals.allCss);
  head("Largest JS chunks");
  for (const r of largest) line("js", r.file, r);
  console.log("");
}
console.log(JSON.stringify(report));
