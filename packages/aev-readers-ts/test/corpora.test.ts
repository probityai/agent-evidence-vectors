import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { loadManifest, readRecord } from "../src/common.js";
import { SUITES, verdictLines } from "../src/verdicts.js";

const CORPORA = [
  "vectors-attenuated-delegation",
  "vectors-grant-use",
  "vectors-revocation-epoch",
  "vectors-durable-history",
  "vectors-approval-binding-v2",
  "vectors-decision-client-failure-modes",
];

// dist/test/corpora.test.js -> the repository root is four levels up.
const corpus = (name: string): string =>
  fileURLToPath(new URL(`../../../../corpora/${name}`, import.meta.url));
const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));

test("every record of every corpus parses and is listed in manifest order", () => {
  for (const name of CORPORA) {
    const dir = corpus(name);
    const manifest = loadManifest(dir);
    assert.ok(SUITES.has(manifest.suite), `${name}: ${manifest.suite}`);
    assert.ok(manifest.vectors.length > 0, name);
    for (const vector of manifest.vectors) readRecord(join(dir, vector.path));
    const lines = verdictLines(dir);
    assert.equal(lines.length, manifest.vectors.length, name);
    lines.forEach((line, index) => {
      const fields = line.split("\t");
      assert.equal(fields.length, 3, line);
      assert.equal(fields[0], manifest.vectors[index]?.id);
    });
  }
});

test("the suite names are exactly the six corpus suites", () => {
  const declared = CORPORA.map((name) => loadManifest(corpus(name)).suite).sort();
  assert.deepEqual([...SUITES.keys()].sort(), declared);
});

test("an unreadable corpus and an unknown suite are refused", () => {
  assert.throws(() => verdictLines("/nonexistent-corpus-dir"));
  const dir = mkdtempSync(join(tmpdir(), "aev-readers-ts-"));
  try {
    writeFileSync(join(dir, "MANIFEST.json"), '{"suite":"nope/v1","vectors":[]}');
    assert.throws(() => verdictLines(dir), /unknown suite/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("the CLI prints one line per vector and exits 2 when it cannot read", () => {
  const dir = corpus(CORPORA[1] as string);
  const ok = spawnSync(process.execPath, [cli, dir], { encoding: "utf8" });
  assert.equal(ok.status, 0);
  assert.equal(ok.stdout.split("\n").filter(Boolean).length, loadManifest(dir).vectors.length);
  const bad = spawnSync(process.execPath, [cli, "/nonexistent-corpus-dir"], { encoding: "utf8" });
  assert.equal(bad.status, 2);
  assert.equal(bad.stdout, "");
  assert.equal(spawnSync(process.execPath, [cli], { encoding: "utf8" }).status, 2);
});
