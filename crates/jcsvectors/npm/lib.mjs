// The readers behind index.mjs, over any function that reads an embedded file
// by its path under data/. index.mjs binds them to the package's own files; the
// tests bind them to an edited copy to prove that a changed byte is refused.

import { createHash } from "node:crypto";

import { fileDigests } from "./digests.mjs";

export const A2A_CORPUS = "vectors-a2a-jcs-v01";
export const BYTE_CORPUS = "jcs-byte-vectors";
/** The nesting depth the corpus admits. Input nested one level deeper must be refused. */
export const DEPTH_CAP = 128;
/** The `source` of a drift case whose presented bytes are what Go's encoding/json prints. */
export const SOURCE_GO = "go-encoding-json";
const RFC8785_CLAUSE = "RFC8785-";

/** Every feature a case can carry, read from its bytes. */
export const FEATURES = Object.freeze({
  integer: "integer",
  unsafeInteger: "unsafe-integer",
  fraction: "fraction",
  exponent: "exponent",
  negativeZero: "negative-zero",
  escape: "escape",
  nonAscii: "non-ascii",
  notUtf8: "not-utf8",
});

/** The features that put a case outside each profile. */
const EXCLUDED = Object.freeze({
  rfc8785: Object.freeze([]),
  "integer-only": Object.freeze([FEATURES.fraction, FEATURES.exponent, FEATURES.unsafeInteger]),
});

/** Every profile this package knows. */
export const PROFILES = Object.freeze(Object.keys(EXCLUDED));

const MAX_SAFE_INTEGER = 2n ** 53n - 1n;
const utf8 = new TextEncoder();

/** True when a case with these features is inside the profile; throws on an unknown profile. */
export function admits(profile, features) {
  const out = Object.hasOwn(EXCLUDED, profile) ? EXCLUDED[profile] : undefined;
  if (out === undefined) throw new Error(`jcsvectors: unknown profile ${JSON.stringify(profile)}`);
  return !features.some((f) => out.includes(f));
}

/** Split cases into those inside the profile and those outside it, keeping their order. */
export function filter(profile, cases) {
  const inProfile = [];
  const outOfProfile = [];
  for (const c of cases) (admits(profile, c.features) ? inProfile : outOfProfile).push(c);
  return { inProfile, outOfProfile };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function checkDigest(name, bytes, want) {
  const got = sha256(bytes);
  if (got !== want) throw new Error(`${name}: sha256 ${got}, the corpus records ${want}`);
}

function hexBytes(text, what) {
  if (typeof text !== "string" || !/^(?:[0-9a-f]{2})*$/i.test(text)) throw new Error(`${what}: not hex`);
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function isValidUtf8(bytes) {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

const isDigit = (b) => b >= 0x30 && b <= 0x39;
const isNumberByte = (b) => isDigit(b) || b === 0x2d || b === 0x2b || b === 0x2e || b === 0x65 || b === 0x45;

/** Classify one number token as written. A token with no digit is not a number. */
function numberFeatures(token) {
  const lower = token.toLowerCase();
  const e = lower.indexOf("e");
  const exponent = e >= 0;
  const significand = exponent ? lower.slice(0, e) : lower;
  const fraction = significand.includes(".");
  if (!/[0-9]/.test(significand)) return [];
  const out = [];
  if (exponent) out.push(FEATURES.exponent);
  if (fraction) out.push(FEATURES.fraction);
  if (token[0] === "-" && !/[1-9]/.test(significand)) out.push(FEATURES.negativeZero);
  if (exponent || fraction) return out;
  let value;
  try {
    value = BigInt(token);
  } catch {
    // Digits with a stray sign: malformed, refused before any number is read.
    return out;
  }
  if ((value < 0n ? -value : value) > MAX_SAFE_INTEGER) out.push(FEATURES.unsafeInteger);
  else out.push(FEATURES.integer);
  return out;
}

/**
 * What a case exercises, read lexically from its input and canonical bytes, so
 * malformed input never fails the scan. The same rules as the Go module.
 */
export function features(input, canonical = null) {
  const set = new Set();
  if (!isValidUtf8(input)) set.add(FEATURES.notUtf8);
  if (input.some((b) => b > 0x7f) || (canonical !== null && canonical.some((b) => b > 0x7f))) set.add(FEATURES.nonAscii);
  let inString = false;
  for (let i = 0; i < input.length; i++) {
    const b = input[i];
    if (inString && b === 0x5c) {
      set.add(FEATURES.escape);
      i++;
    } else if (b === 0x22) {
      inString = !inString;
    } else if (!inString && (b === 0x2d || isDigit(b))) {
      const start = i;
      while (i + 1 < input.length && isNumberByte(input[i + 1])) i++;
      const token = String.fromCharCode(...input.subarray(start, i + 1));
      for (const f of numberFeatures(token)) set.add(f);
    }
  }
  return [...set].sort();
}

const WHITESPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);

/** The end offset of the JSON value starting at `i` in `bytes`, scanned lexically. */
function valueEnd(bytes, i) {
  let depth = 0;
  for (; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x22) {
      for (i++; i < bytes.length && bytes[i] !== 0x22; i++) if (bytes[i] === 0x5c) i++;
      if (depth === 0) return i + 1;
    } else if (b === 0x5b || b === 0x7b) {
      depth++;
    } else if (b === 0x5d || b === 0x7d) {
      if (depth === 0) return i;
      depth--;
      if (depth === 0) return i + 1;
    } else if (depth === 0 && (b === 0x2c || WHITESPACE.has(b))) {
      return i;
    }
  }
  return i;
}

/**
 * The raw bytes of one member of a JSON object, as written: what Go's
 * json.RawMessage keeps. JSON.parse would print the value again and lose them.
 */
function rawMember(bytes, member) {
  let i = 0;
  const skip = () => {
    while (i < bytes.length && WHITESPACE.has(bytes[i])) i++;
  };
  skip();
  if (bytes[i] !== 0x7b) throw new Error("not a JSON object");
  i++;
  for (;;) {
    skip();
    if (bytes[i] === 0x7d) return null;
    const keyEnd = valueEnd(bytes, i);
    const key = JSON.parse(new TextDecoder().decode(bytes.subarray(i, keyEnd)));
    i = keyEnd;
    skip();
    if (bytes[i] !== 0x3a) throw new Error("malformed object");
    i++;
    skip();
    const end = valueEnd(bytes, i);
    if (key === member) return bytes.slice(i, end);
    i = end;
    skip();
    if (bytes[i] === 0x2c) i++;
  }
}

/** Every reader, over `read(path)`, which returns the bytes of a file under data/. */
export function readers(read) {
  const digests = new Map(fileDigests);

  function readFile(name) {
    const want = digests.get(name);
    if (want === undefined) throw new Error(`${name}: no recorded digest`);
    const bytes = read(name);
    checkDigest(name, bytes, want);
    return bytes;
  }

  const readJSON = (name) => JSON.parse(new TextDecoder().decode(readFile(name)));

  function withFeatures(c) {
    return { ...c, features: features(c.input, c.canonical ?? null) };
  }

  function acceptCanonical(c) {
    const canonical = hexBytes(c.canonicalHex, `${BYTE_CORPUS} case ${c.id}`);
    if (canonical.length === 0) throw new Error(`${BYTE_CORPUS} case ${c.id}: no canonical bytes`);
    checkDigest(`${BYTE_CORPUS} case ${c.id}`, canonical, c.sha256);
    return canonical;
  }

  function refusalInput(c) {
    const hasText = typeof c.input === "string";
    const hasHex = typeof c.inputHex === "string";
    if (hasText === hasHex) throw new Error(`${BYTE_CORPUS} case ${c.id}: needs exactly one of input and inputHex`);
    return hasText ? utf8.encode(c.input) : hexBytes(c.inputHex, `${BYTE_CORPUS} case ${c.id}`);
  }

  function byteCases() {
    const cases = readJSON(`${BYTE_CORPUS}/cases.json`);
    if (cases.format !== "jcs-byte-vectors/v1") throw new Error(`${BYTE_CORPUS}: unknown format ${cases.format}`);
    return cases;
  }

  function loadA2A() {
    const manifest = readJSON(`${A2A_CORPUS}/MANIFEST.json`);
    const accept = [];
    const reject = [];
    for (const entry of manifest.vectors) {
      const name = `${A2A_CORPUS}/${entry.path}`;
      const raw = readFile(name);
      checkDigest(name, raw, entry.sha256);
      const vector = JSON.parse(new TextDecoder().decode(raw));
      if (!String(vector.clause ?? "").startsWith(RFC8785_CLAUSE)) continue;
      const base = { id: vector.id, corpus: A2A_CORPUS, clause: vector.clause };
      if (vector.disposition === "MUST-ACCEPT") {
        const canonical = hexBytes(vector.expected?.canonical_utf8_hex, `vector ${vector.id}`);
        if (canonical.length === 0) throw new Error(`vector ${vector.id}: no canonical bytes`);
        accept.push({ ...base, input: rawMember(raw, "input"), canonical });
      } else if (vector.disposition === "MUST-REJECT") {
        if (typeof vector.input_raw !== "string") throw new Error(`vector ${vector.id}: no input_raw`);
        reject.push({ ...base, input: utf8.encode(vector.input_raw), canonical: null });
      } else {
        throw new Error(`vector ${vector.id}: unknown disposition ${vector.disposition}`);
      }
    }
    const want = manifest.targets.rfc8785.vectors;
    if (accept.length + reject.length !== want) {
      throw new Error(`${A2A_CORPUS}: read ${accept.length + reject.length} RFC 8785 vectors, the manifest declares ${want}`);
    }
    return { accept, reject };
  }

  function loadBytes() {
    const cases = byteCases();
    const accept = [...cases.canonicalCases, ...(cases.noncharacterCases ?? [])].map((c) => ({
      id: c.id,
      corpus: BYTE_CORPUS,
      clause: "",
      input: utf8.encode(c.input),
      canonical: acceptCanonical(c),
    }));
    const reject = cases.rejectCases
      .filter((c) => c.jcsError)
      .map((c) => ({ id: c.id, corpus: BYTE_CORPUS, clause: "", input: utf8.encode(c.input), canonical: null }));
    for (const c of cases.refusalCases ?? []) {
      if (c.expect !== "reject") throw new Error(`${BYTE_CORPUS} case ${c.id}: a refusal case expects ${c.expect}, not reject`);
      reject.push({ id: c.id, corpus: BYTE_CORPUS, clause: "", input: refusalInput(c), canonical: null });
    }
    return { accept, reject };
  }

  function load() {
    const a2a = loadA2A();
    const bytes = loadBytes();
    return {
      accept: [...a2a.accept, ...bytes.accept].map(withFeatures),
      reject: [...a2a.reject, ...bytes.reject].map(withFeatures),
    };
  }

  const inProfile = (cases, options) =>
    options?.profile === undefined ? cases : filter(options.profile, cases).inProfile;

  function depthCases() {
    const reject = [];
    const accept = [];
    for (const c of byteCases().depthCases) {
      const v = { id: c.id, corpus: BYTE_CORPUS, clause: "", input: utf8.encode(c.input), canonical: null };
      if (c.expect === "reject") reject.push(withFeatures(v));
      else if (c.expect === "accept") accept.push(withFeatures({ ...v, canonical: acceptCanonical(c) }));
      else throw new Error(`${BYTE_CORPUS} case ${c.id}: unknown expect ${c.expect}`);
    }
    return { reject, accept };
  }

  function differentials() {
    const cases = byteCases();
    const out = [];
    const add = (d) => out.push({ ...d, features: features(d.input, d.canonical) });
    for (const c of [...cases.canonicalCases, ...(cases.noncharacterCases ?? [])]) {
      if (!c.boundedError) {
        if (c.bounded === "reject") throw new Error(`${BYTE_CORPUS} case ${c.id}: the bounded profile refuses it with no code`);
        continue;
      }
      add({
        id: c.id,
        family: c.family || c.boundedError,
        input: utf8.encode(c.input),
        error: "",
        canonical: acceptCanonical(c),
        boundedError: c.boundedError,
      });
    }
    for (const c of cases.rejectCases) {
      const bounded = c.boundedError || c.jcsError || "";
      if (!bounded) throw new Error(`${BYTE_CORPUS} case ${c.id}: a reject case with no code`);
      add({
        id: c.id,
        family: c.jcsError || bounded,
        input: utf8.encode(c.input),
        error: c.jcsError ?? "",
        canonical: null,
        boundedError: bounded,
      });
    }
    for (const c of cases.refusalCases ?? []) {
      if (!c.error || !c.family) throw new Error(`${BYTE_CORPUS} case ${c.id}: a refusal case needs a family and an error`);
      add({ id: c.id, family: c.family, input: refusalInput(c), error: c.error, canonical: null, boundedError: c.error });
    }
    return out.map((d) => ({ ...d, accepted: d.error === "" }));
  }

  return {
    canonical: (options) => inProfile(load().accept, options),
    reject: (options) => inProfile(load().reject, options),
    drifts: () =>
      byteCases().driftCases.map((c) => {
        const canonical = acceptCanonical(c);
        return {
          id: c.id,
          family: c.family,
          source: c.source,
          input: utf8.encode(c.input),
          presented: utf8.encode(c.presented),
          canonical,
        };
      }),
    tooDeep: () => depthCases().reject,
    depthAdmitted: () => depthCases().accept,
    parserDifferential: () => {
      const cases = differentials();
      return (function* yieldEach() {
        yield* cases;
      })();
    },
    files: () => fileDigests.map(([name]) => [name, readFile(name)]),
  };
}
