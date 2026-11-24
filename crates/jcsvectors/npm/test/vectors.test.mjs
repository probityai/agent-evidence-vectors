import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { test } from "node:test";

import {
  A2A_CORPUS,
  BYTE_CORPUS,
  DEPTH_CAP,
  FEATURES,
  PROFILES,
  admits,
  canonical,
  depthAdmitted,
  drifts,
  features,
  files,
  filter,
  includes,
  parserDifferential,
  reject,
  tooDeep,
} from "../index.mjs";
import { fileDigests } from "../digests.mjs";
import { readers } from "../lib.mjs";

const enc = new TextEncoder();
const dataDir = new URL("../data/", import.meta.url);
const readData = (name) => new Uint8Array(readFileSync(new URL(name, dataDir)));

function walk(dir, prefix = "") {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const url = new URL(entry, dir);
    if (statSync(url).isDirectory()) out.push(...walk(new URL(`${entry}/`, dir), `${prefix}${entry}/`));
    else out.push(`${prefix}${entry}`);
  }
  return out;
}

test("every file under data/ has its digest and hashes to it", () => {
  const onDisk = walk(dataDir).sort();
  assert.deepEqual(onDisk, fileDigests.map(([name]) => name).sort());
  assert.equal(files().length, fileDigests.length);
});

test("a file edited by one byte is refused by every reader", () => {
  for (const name of [`${BYTE_CORPUS}/cases.json`, `${A2A_CORPUS}/MANIFEST.json`, `${A2A_CORPUS}/a3-object-key-ordering/A3-001.json`]) {
    const edited = readers((path) => {
      const bytes = readData(path);
      if (path !== name) return bytes;
      const copy = bytes.slice();
      copy[copy.length >> 1] ^= 0x01;
      return copy;
    });
    assert.throws(() => edited.canonical(), /sha256/, name);
    if (name.startsWith(BYTE_CORPUS)) assert.throws(() => edited.parserDifferential(), /sha256/, name);
  }
});

test("accept cases are JSON and carry canonical bytes", () => {
  const vectors = canonical();
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    assert.ok(v.canonical instanceof Uint8Array && v.canonical.length > 0, v.id);
    JSON.parse(new TextDecoder().decode(v.canonical));
  }
});

test("reject cases carry no canonical bytes, and every refusal case is one", () => {
  const vectors = reject();
  assert.ok(vectors.length > 0);
  for (const v of vectors) assert.equal(v.canonical, null, v.id);
  const ids = new Set(vectors.filter((v) => v.corpus === BYTE_CORPUS).map((v) => v.id));
  const cases = JSON.parse(new TextDecoder().decode(readData(`${BYTE_CORPUS}/cases.json`)));
  for (const r of [...cases.refusalCases, ...cases.invalidInputCases]) assert.ok(ids.has(r.id), r.id);
});

test("identifiers are unique and only RFC 8785 clauses come from the a2a corpus", () => {
  const all = [...canonical(), ...reject()];
  const keys = all.map((v) => `${v.corpus}/${v.id}`);
  assert.equal(new Set(keys).size, keys.length);
  for (const v of all) if (v.corpus === A2A_CORPUS) assert.match(v.clause, /^RFC8785-/);
});

test("JSON.stringify of a parsed input does not reproduce every canonical vector", () => {
  let misses = 0;
  for (const v of canonical()) {
    const printed = enc.encode(JSON.stringify(JSON.parse(new TextDecoder().decode(v.input))));
    if (Buffer.compare(Buffer.from(printed), Buffer.from(v.canonical)) !== 0) misses++;
  }
  assert.ok(misses > 0);
});

test("number and string features", () => {
  const cases = [
    ['{"n":1}', ["integer"]],
    ['{"n":9007199254740991}', ["integer"]],
    ['{"n":-9007199254740991}', ["integer"]],
    ['{"n":9007199254740992}', ["unsafe-integer"]],
    ['{"n":-9007199254740993}', ["unsafe-integer"]],
    ['{"n":1000.0}', ["fraction"]],
    ['{"n":1e3}', ["exponent"]],
    ['{"n":1E3}', ["exponent"]],
    ['{"n":-1.5e-7}', ["exponent", "fraction"]],
    ['{"n":00000000000000000000001}', ["integer"]],
    ['{"n":-00000000000000009007199254740992}', ["unsafe-integer"]],
    ['{"n":1-2}', []],
    ['{"n":-0}', ["integer", "negative-zero"]],
    ['{"n":-0.0}', ["fraction", "negative-zero"]],
    ['{"n":-Infinity}', []],
    ['{"s":"1.5e3"}', []],
    ['{"s":"a\\"1.5"}', ["escape"]],
    ['{"s":"caf\\u00e9"}', ["escape"]],
  ];
  for (const [input, want] of cases) assert.deepEqual(features(enc.encode(input)), want, input);
  assert.deepEqual(features(enc.encode('{"s":"caf\u00e9"}')), ["non-ascii"]);
  assert.deepEqual(features(Uint8Array.from([0x5b, 0x22, 0xff, 0x22, 0x5d])), ["non-ascii", "not-utf8"]);
  assert.ok(features(enc.encode('["\\u00e9"]'), enc.encode('["\u00e9"]')).includes(FEATURES.nonAscii));
  // A token far longer than a call's argument limit is read, not a RangeError.
  const long = new Uint8Array(1 << 20).fill(0x31);
  long[0] = 0x5b;
  long[long.length - 1] = 0x5d;
  assert.deepEqual(features(long), ["unsafe-integer"]);
});

test("every case's features are read from its bytes, sorted and unique", () => {
  for (const v of [...canonical(), ...reject(), ...tooDeep()]) {
    assert.deepEqual(v.features, features(v.input, v.canonical), v.id);
    assert.deepEqual(v.features, [...new Set(v.features)].sort(), v.id);
  }
});

test("the integer-only profile excludes exactly the accept cases with a fraction, exponent or unsafe integer", () => {
  const all = [...canonical(), ...reject()];
  const { inProfile, outOfProfile } = filter("integer-only", all);
  assert.equal(inProfile.length + outOfProfile.length, all.length);
  const nonInteger = (v) => v.features.some((f) => ["fraction", "exponent", "unsafe-integer"].includes(f));
  for (const v of inProfile) assert.ok(v.canonical === null || !nonInteger(v), v.id);
  for (const v of outOfProfile) assert.ok(nonInteger(v) && v.canonical !== null, v.id);
  // "[1e999]" is refused by every profile: an integer-only canonicalizer that
  // prints it has failed, not left its profile.
  const refusals = reject({ profile: "integer-only" });
  assert.equal(refusals.length, reject().length);
  assert.equal(refusals.filter((v) => v.id.startsWith("refuse-non-finite-overflow") && nonInteger(v)).length, 3);
  assert.ok(refusals.every((v) => includes("integer-only", v)));
  assert.throws(() => includes("integer", { features: [], canonical: null }), /unknown profile/);
  assert.throws(() => reject({ profile: "integer" }), /unknown profile/);
  assert.equal(outOfProfile.filter((v) => v.corpus === A2A_CORPUS).length, 11);
  assert.equal(canonical({ profile: "integer-only" }).length, inProfile.filter((v) => v.canonical !== null).length);
  assert.equal(canonical({ profile: "rfc8785" }).length, canonical().length);
  assert.throws(() => canonical({ profile: "integer" }), /unknown profile/);
  assert.throws(() => admits("", []), /unknown profile/);
  assert.throws(() => admits("toString", []), /unknown profile/);
  assert.deepEqual([...PROFILES], ["rfc8785", "integer-only"]);
});

test("parser differentials", () => {
  const all = [...parserDifferential()];
  assert.ok(all.length > 0);
  const ids = new Set();
  const families = new Map();
  for (const d of all) {
    assert.ok(!ids.has(d.id), d.id);
    ids.add(d.id);
    families.set(d.family, (families.get(d.family) ?? 0) + 1);
    assert.notEqual(d.boundedError, "", d.id);
    assert.equal(d.accepted, d.error === "", d.id);
    if (!d.accepted) assert.equal(d.canonical, null, d.id);
    assert.ok(!d.id.startsWith("noncharacter-neighbour"), d.id);
  }
  for (const family of ["duplicate-member", "invalid-unicode", "non-finite", "trailing-content", "syntax", "noncharacter", "unsafe-integer", "non-integer"]) {
    assert.ok(families.get(family) > 0, family);
  }
  for (const v of reject()) if (v.corpus === BYTE_CORPUS) assert.ok(ids.has(v.id), v.id);
  let lenient = 0;
  for (const d of all) {
    try {
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(d.input));
      lenient++;
    } catch {
      // refused
    }
  }
  assert.ok(lenient > 0 && lenient < all.length, `JSON.parse accepted ${lenient} of ${all.length}`);
  // A reader that edits its input in place cannot change the next call.
  for (const d of parserDifferential()) {
    d.input.fill(0);
    d.canonical?.fill(0);
    d.features.length = 0;
  }
  assert.deepEqual([...parserDifferential()], all);
  const iterator = parserDifferential();
  assert.equal(iterator.next().done, false);
  assert.equal(typeof iterator.return, "function");
});

test("drift and depth cases", () => {
  const d = drifts();
  assert.ok(d.length > 0);
  for (const c of d) assert.notDeepEqual(c.presented, c.canonical, c.id);
  const deep = tooDeep();
  const admitted = depthAdmitted();
  assert.equal(deep.length, 8);
  assert.equal(admitted.length, 2);
  const nesting = (bytes) => {
    let depth = 0;
    let deepest = 0;
    for (const b of bytes) {
      if (b === 0x5b || b === 0x7b) deepest = Math.max(deepest, ++depth);
      else if (b === 0x5d || b === 0x7d) depth--;
    }
    return deepest;
  };
  for (const v of deep) assert.ok(nesting(v.input) > DEPTH_CAP, v.id);
  for (const v of admitted) {
    assert.equal(nesting(v.input), DEPTH_CAP, v.id);
    assert.deepEqual(v.input, v.canonical, v.id);
  }
});

test("provenance is asked for only by the release workflow", () => {
  // The first version goes up by token from a checkout, where npm cannot
  // generate provenance and refuses a publish that asks for it.
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.publishConfig?.provenance, undefined);
  const release = readFileSync(new URL("../../../../.github/workflows/release.yml", import.meta.url), "utf8");
  const job = release.slice(release.indexOf("publish-jcsvectors-npm:"));
  assert.match(job.slice(0, job.indexOf("\n  qualify-")), /npm publish "\$TARBALL" --access public --provenance/);
});
