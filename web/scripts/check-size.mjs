#!/usr/bin/env node
/*
 * File size guard for the Open MCP Portal web app ("no hell files"). Fails (exit 1),
 * one line per finding, when a source file under src/ is longer than:
 *
 *   - 400 lines for source files (.ts, .tsx, .css), and
 *   - 700 lines for tests (src/test/**, *.test.ts[x]),
 *
 * or when one of its lines is longer than 230 characters, so that the line cap
 * isn't met by width. A long line is allowed when it can't sensibly be broken:
 *
 *   - an import or re-export (`import { … } from "…";`), or
 *   - one string or template literal on its own: optionally after a name
 *     (`key: "…"`, `attr="…"`, `return "…"`, `? "…"`, `: "…"`) and followed only
 *     by closing punctuation. Prose stays readable as one line; code does not.
 *
 * The target is 160 characters. The check starts at 230 because about 1,100 existing
 * lines are still over 160 (145 were over 230 and were reformatted when the rule was
 * added). Lower MAX_LINE as they are reformatted, and don't add new lines over 160.
 *
 * Skipped: the bitop-ui components (src/components/ui/**, managed by the
 * shadcn CLI) and the generated API types (src/api/schema.gen.ts).
 * Aim lower when you write code: about 350 lines per file and 120 per
 * component; split by feature (see README.md).
 *
 * Usage: node scripts/check-size.mjs [--root <dir>] [--max-line <n>]
 *        (--max-line only reports at another width, e.g. to count what's over 160)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const argRoot = process.argv.indexOf("--root");
const root =
  argRoot !== -1 && process.argv[argRoot + 1]
    ? path.resolve(process.argv[argRoot + 1])
    : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(root, "src");

const MAX_SOURCE = 400;
const MAX_TEST = 700;
const argLine = process.argv.indexOf("--max-line");
const MAX_LINE = argLine !== -1 && Number(process.argv[argLine + 1]) > 0 ? Number(process.argv[argLine + 1]) : 230;
const SKIP = [/^components\/ui\//, /^api\/schema\.gen\.ts$/];
const isTest = (rel) => rel.startsWith("test/") || /\.test\.tsx?$/.test(rel);

// One string or template literal: "…", '…' or `…` with no unescaped closing quote inside.
const LITERAL = String.raw`(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`(?:[^`\\\\]|\\\\.)*`)";
const LONE_LITERAL = new RegExp(`^(?:[\\w$.-]+\\s*[:=]\\s*\\{?|return |[?:] |\\{)?${LITERAL}[\\]}),;]*$`);
const IMPORT = /^(?:import|export) .* from "[^"]+";$/;
/** Whether a line may be longer than MAX_LINE (see the header). */
const mayBeLong = (line) => {
  const t = line.trim();
  return IMPORT.test(t) || LONE_LITERAL.test(t);
};

function walk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (/\.(tsx?|css)$/.test(e.name)) acc.push(p);
  }
  return acc;
}

const errors = [];
const wide = [];
let checked = 0;
for (const file of walk(src)) {
  const rel = path.relative(src, file).split(path.sep).join("/");
  if (SKIP.some((re) => re.test(rel))) continue;
  checked++;
  const text = fs.readFileSync(file, "utf8");
  const all = text.split("\n");
  const lines = text.endsWith("\n") ? all.length - 1 : all.length;
  all.forEach((line, i) => {
    if (line.length > MAX_LINE && !mayBeLong(line)) wide.push(`src/${rel}:${i + 1}: ${line.length} characters (limit ${MAX_LINE}). Break the line.`);
  });
  const max = isTest(rel) ? MAX_TEST : MAX_SOURCE;
  if (lines > max) {
    errors.push(`src/${rel}: ${lines} lines (limit ${max}${isTest(rel) ? " for tests" : ""}). Split it by feature: components, hooks and helpers in their own files.`);
  }
}

if (errors.length || wide.length) {
  for (const e of [...errors, ...wide]) console.error(e);
  console.error(`\nFile size check failed: ${errors.length} file(s) too long, ${wide.length} line(s) too wide.`);
  process.exit(1);
}
console.log(`File size OK: ${checked} files (source ≤ ${MAX_SOURCE} lines, tests ≤ ${MAX_TEST}, lines ≤ ${MAX_LINE} characters).`);
