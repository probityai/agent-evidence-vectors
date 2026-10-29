import { readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../../", import.meta.url));
const utf8 = (text) => [...new TextEncoder().encode(text)];

export async function loadCases() {
  const cases = [];
  const sourceFiles = {};
  async function bytes(relative) {
    const body = await readFile(path.join(root, relative));
    sourceFiles[relative] = createHash("sha256").update(body).digest("hex");
    return [...body];
  }
  const referenceNames = (await readdir(path.join(root, "tests/vectors/rfc8785/input"))).sort();
  if (referenceNames.length !== 6) throw new Error("Retained reference input corpus changed size");
  for (const name of referenceNames) {
    cases.push({ id: `rfc8785/${name}`, bytes: await bytes(`tests/vectors/rfc8785/input/${name}`), expected: await bytes(`tests/vectors/rfc8785/output/${name}`), expectedProfiles: ["admit"] });
  }
  const canonicalNames = new Set(await readdir(path.join(root, "tests/vectors/cross-rail/canonical")));
  const crossRailNames = (await readdir(path.join(root, "tests/vectors/cross-rail/input"))).sort();
  if (crossRailNames.length !== 39) throw new Error("Retained cross-rail input corpus changed size");
  for (const name of crossRailNames) {
    const item = { id: `cross-rail/${name}`, bytes: await bytes(`tests/vectors/cross-rail/input/${name}`) };
    if (canonicalNames.has(name)) {
      item.expected = await bytes(`tests/vectors/cross-rail/canonical/${name}`);
      item.expectedProfiles = ["admit", "admit_ijson"];
    }
    cases.push(item);
  }
  const attack = new TextDecoder().decode(new Uint8Array(await bytes("tests/vectors/attack/strings-keys-members.tsv")));
  let attackRows = 0;
  for (const line of attack.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const [name, hex, expected] = line.split("\t");
    if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error(`Invalid retained input hex: ${name}`);
    const item = { id: `attack/${name}`, bytes: [...Buffer.from(hex, "hex")] };
    if (expected.startsWith("ACCEPT ")) {
      item.expected = [...Buffer.from(expected.slice(7).trimEnd(), "hex")];
      item.expectedProfiles = ["admit", "admit_ijson"];
    }
    cases.push(item);
    attackRows += 1;
  }
  if (attackRows !== 317) throw new Error("Retained 317-case input corpus changed size");
  const ties = new TextDecoder().decode(new Uint8Array(await bytes("tests/vectors/es-number-ties.tsv")));
  let tieRows = 0;
  for (const line of ties.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const [input, expected] = line.split("\t");
    cases.push({ id: `number-tie/${tieRows}`, bytes: utf8(input), expected: utf8(expected), expectedProfiles: ["admit"] });
    tieRows += 1;
  }
  if (tieRows !== 850) throw new Error("Retained 850-case number corpus changed size");
  const own = [
    ["unsafe-integer", "9007199254740993"], ["noncharacter", '"\\ufdd0"'],
    ["lone-surrogate", '"\\ud800"'], ["trailing", "{} {}"],
    ["syntax", '{"a":}'], ["nonfinite", "1e400"],
    ["deep", "[".repeat(129) + "0" + "]".repeat(129)],
    ["unicode-offset", '{"é":0,"é":1}'],
    ...["name", "message", "variant", "fields", "__proto__", "constructor"].map((name) => [`duplicate-${name}`, `{${JSON.stringify(name)}:1,${JSON.stringify(name)}:2}`]),
  ];
  for (const [id, text] of own) cases.push({ id: `binding/${id}`, bytes: utf8(text), origin: "Binding control; not an independent corpus addition" });
  cases.push({ id: "binding/invalid-utf8", bytes: [0x22, 0xc0, 0xaf, 0x22] });
  cases.push({ id: "binding/size-cap", repeat: { byte: 0x20, len: (20 << 20) + 1 } });
  return { cases, sourceFiles, retainedCounts: { reference: referenceNames.length, crossRail: crossRailNames.length, attack: attackRows, numberTies: tieRows }, scope: "Native/WASM parity under admit and admit_ijson. Independent canonical byte expectations apply where the retained source supplies a compatible accepted form. The Go rail's additional integers-only policy is not a new JS default." };
}
