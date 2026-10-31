import assert from "node:assert/strict";
import test from "node:test";
import { compatibleSource } from "./prepare-openapi.mjs";

const oldImport = 'const minimatch = require("minimatch");';
const newImport = 'const { minimatch } = require("minimatch");';

test("changes only the reviewed import and is idempotent", () => {
  const source = `"use strict";\n${oldImport}\nfunction match(url, pattern) { return minimatch(url, pattern); }\n`;
  const expected = source.replace(oldImport, newImport);
  assert.equal(compatibleSource(source, "1.34.22"), expected);
  assert.equal(compatibleSource(expected, "1.34.22"), expected);
});

test("refuses an unreviewed dependency version", () => {
  for (const version of ["1.34.19", "1.34.20", "1.34.21", "2.72.1", undefined]) {
    assert.throws(() => compatibleSource(oldImport, version));
  }
});

test("refuses missing, duplicate, altered or mixed imports", () => {
  for (const source of ["", `${oldImport}\n${oldImport}`, `${newImport}\n${newImport}`,
    `${oldImport}\n${newImport}`, 'const minimatch = require("other");']) {
    assert.throws(() => compatibleSource(source, "1.34.22"));
  }
});
