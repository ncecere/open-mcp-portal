// Temporary compatibility for the generator's pinned Redocly v1 dependency.
// minimatch 11 fixes GHSA-g3hv-75wg-m249, but exposes a named CJS function;
// Redocly 1.34.22 expects the old callable default. Never patch arbitrary versions.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const legacyImport = 'const minimatch = require("minimatch");';
const compatibleImport = 'const { minimatch } = require("minimatch");';

export function compatibleSource(source, version) {
  assert.equal(version, "1.34.22", "Review the Redocly compatibility patch for this version");
  const oldCount = source.split(legacyImport).length - 1;
  const newCount = source.split(compatibleImport).length - 1;
  if (oldCount === 0 && newCount === 1) return source;
  assert.equal(oldCount, 1, "Expected exactly one legacy minimatch import");
  assert.equal(newCount, 0, "Unexpected mixed minimatch imports");
  return source.replace(legacyImport, compatibleImport);
}

export async function prepare() {
  const require = createRequire(import.meta.url);
  // Resolve through the generator, not an unrelated package hoisted nearby.
  const generator = require.resolve("openapi-typescript/package.json");
  const generatorRequire = createRequire(generator);
  const corePackage = generatorRequire.resolve("@redocly/openapi-core/package.json");
  const core = JSON.parse(await readFile(corePackage, "utf8"));
  const coreRequire = createRequire(corePackage);
  const matcherPackage = JSON.parse(await readFile(coreRequire.resolve("minimatch/package.json"), "utf8"));
  assert.equal(matcherPackage.version, "11.0.1", "Use the reviewed patched minimatch version");
  const utils = resolve(dirname(corePackage), "lib/utils.js");
  const original = await readFile(utils, "utf8");
  const patched = compatibleSource(original, core.version);
  const { minimatch } = coreRequire("minimatch");
  assert.equal(typeof minimatch, "function");
  assert.equal(minimatch("schemas/tool.json", "schemas/**/*.json"), true);
  assert.equal(minimatch("schemas/tool.yaml", "schemas/**/*.json"), false);
  assert.equal(minimatch("schemas/.private.json", "schemas/**/*.json"), false);
  if (patched !== original) await writeFile(utils, patched);
  // Exercise the actual legacy utility's URL/header matching with no network.
  // A matcher upgrade must not forward configured headers to a sibling origin.
  const { readFileFromUrl } = coreRequire(utils);
  for (const [url, expected] of [
    ["https://schema.example.com/schemas/tool.json", true],
    ["https://schema.example.com.evil.invalid/schemas/tool.json", false],
    ["https://other.example.com/schemas/tool.json", false],
  ]) {
    let sent;
    await readFileFromUrl(url, {
      headers: [{ name: "X-Codegen-Test", matches: "schema.example.com/schemas/**", value: "synthetic-test-value" }],
      customFetch: async (_url, options) => {
        sent = options.headers;
        return { ok: true, text: async () => "{}", headers: { get: () => "application/json" } };
      },
    });
    assert.equal(Object.hasOwn(sent, "X-Codegen-Test"), expected);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await prepare();
}
