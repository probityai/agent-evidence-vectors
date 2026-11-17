// The cross-language check: the Go module and this package must agree on every
// case: its kind, identifier, input and canonical digests, features and codes.
// Usage: node test/cross.mjs <summary.json written by the Go TestWriteSummary>
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

import { summary } from "./summary.mjs";

const path = process.argv[2];
if (!path) {
  console.error("usage: node test/cross.mjs <go-summary.json>");
  process.exit(2);
}
const go = JSON.parse(readFileSync(path, "utf8"));
const js = summary();
const byKey = (rows) => new Map(rows.map((r) => [`${r.kind} ${r.corpus}/${r.id}`, r]));
const [g, j] = [byKey(go), byKey(js)];
let differences = 0;
for (const key of new Set([...g.keys(), ...j.keys()])) {
  if (!isDeepStrictEqual(g.get(key), j.get(key))) {
    differences++;
    console.error(`DIFFER ${key}\n  go: ${JSON.stringify(g.get(key))}\n  js: ${JSON.stringify(j.get(key))}`);
  }
}
if (go.length !== g.size || js.length !== j.size) {
  console.error(`duplicate keys: go ${go.length} rows/${g.size} keys, js ${js.length} rows/${j.size} keys`);
  differences++;
}
console.log(`cross-language: ${go.length} Go rows, ${js.length} npm rows, ${differences} differences`);
process.exit(differences === 0 && go.length > 0 ? 0 : 1);
