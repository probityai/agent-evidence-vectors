// Builds extra-cases.json from extra-inputs.json. Canonical bytes come from the
// same ECMAScript oracle as corpora/jcs-byte-vectors/check.mjs, and every case is
// cross-checked against the jcs-admit probe given as argv[2]: both must produce
// identical bytes, or jcs-admit must refuse (which marks the case a reject).
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const probe = process.argv[2];
const inputs = JSON.parse(readFileSync(new URL("./extra-inputs.json", import.meta.url)));
for (const c of inputs) if (c.depth) c.input = "[".repeat(c.depth) + "]".repeat(c.depth);
const run = spawnSync(probe, [], { input: inputs.map(c => c.input).join("\n") + "\n" });
if (run.status !== 0) throw new Error(`probe failed: ${run.stderr}`);
const lines = run.stdout.toString().trimEnd().split("\n");
const out = { format: "mcp-sdks-jcs-extra/v1", canonicalCases: [], rejectCases: [] };
inputs.forEach((c, i) => {
  const [rfc] = lines[i].split("\t");
  if (rfc.startsWith("ERR ")) {
    out.rejectCases.push({ id: c.id, input: c.input, jcsError: rfc.slice(4) });
    return;
  }
  const admitted = Buffer.from(rfc.slice(3), "base64");
  const oracle = Buffer.from(canonical(JSON.parse(c.input)), "utf8");
  if (!admitted.equals(oracle)) throw new Error(`${c.id}: jcs-admit and the ECMAScript oracle disagree`);
  out.canonicalCases.push({
    id: c.id,
    input: c.input,
    canonicalHex: oracle.toString("hex"),
    sha256: createHash("sha256").update(oracle).digest("hex"),
  });
});
writeFileSync(new URL("./extra-cases.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
console.log(`${out.canonicalCases.length} canonical, ${out.rejectCases.length} reject`);
