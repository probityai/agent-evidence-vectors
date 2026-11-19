import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const cases = JSON.parse(readFileSync(new URL("./cases.json", import.meta.url)));
const args = process.argv.slice(2);
let profile = "jcs";
let command = null;
if (args[0] === "--profile") {
  profile = args[1];
  args.splice(0, 2);
}
if (!new Set(["jcs", "bounded"]).has(profile)) {
  throw new Error(`unknown profile: ${profile}`);
}
if (args.length) {
  if (args.shift() !== "--verifier" || !args.length) {
    throw new Error("usage: node check.mjs [--profile jcs|bounded] [--verifier command [args...]]");
  }
  command = args;
}

function assertScalars(value) {
  if (Array.isArray(value)) {
    value.forEach(assertScalars);
  } else if (value !== null && typeof value === "object") {
    for (const [key, member] of Object.entries(value)) {
      assertScalars(key);
      assertScalars(member);
    }
  } else if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) {
      const unit = value.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new Error("lone high surrogate");
        }
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw new Error("lone low surrogate");
      }
    }
  }
}

// ECMAScript strings use UTF-16 code units. Number and string rendering come
// from JSON.stringify; assembling objects here avoids its numeric-key reorder.
function canonical(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      key => `${JSON.stringify(key)}:${canonical(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function runVerifier(entry, expected) {
  if (!command) return;
  const result = spawnSync(command[0], command.slice(1), {
    input: entry.inputHex !== undefined ? Buffer.from(entry.inputHex, "hex") : Buffer.from(entry.input, "utf8"),
    maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (expected === null) {
    if (result.status === 0) throw new Error(`${entry.id}: verifier accepted a reject`);
  } else {
    if (result.status !== 0 || !result.stdout.equals(expected)) {
      throw new Error(
        `${entry.id}: verifier returned status ${result.status}, bytes ` +
        `${result.stdout.toString("hex")}; expected ${expected.toString("hex")}`
      );
    }
  }
}

for (const entry of cases.canonicalCases) {
  const value = JSON.parse(entry.input);
  assertScalars(value);
  const actual = Buffer.from(canonical(value), "utf8");
  const pinned = Buffer.from(entry.canonicalHex, "hex");
  if (
    pinned.toString("hex") !== entry.canonicalHex ||
    !actual.equals(pinned) ||
    createHash("sha256").update(pinned).digest("hex") !== entry.sha256
  ) {
    throw new Error(`${entry.id}: pinned bytes or digest disagree with the ECMAScript oracle`);
  }
  runVerifier(entry, profile === "bounded" && entry.bounded === "reject" ? null : pinned);
}
for (const entry of cases.rejectCases) {
  if (profile === "bounded" || entry.jcsError) runVerifier(entry, null);
}

// Drift cases: bytes presented as canonical that RFC 8785 does not print. The
// ECMAScript oracle must give the pinned canonical bytes for the value, and the
// presented bytes must differ from them. A verifier given the presented text as
// input must return the pinned bytes, never echo what it was given.
for (const entry of cases.driftCases) {
  const value = JSON.parse(entry.input);
  assertScalars(value);
  const pinned = Buffer.from(entry.canonicalHex, "hex");
  const presented = Buffer.from(entry.presented, "utf8");
  if (
    !Buffer.from(canonical(value), "utf8").equals(pinned) ||
    !Buffer.from(canonical(JSON.parse(entry.presented)), "utf8").equals(pinned) ||
    createHash("sha256").update(pinned).digest("hex") !== entry.sha256 ||
    presented.equals(pinned)
  ) {
    throw new Error(`${entry.id}: drift case disagrees with the ECMAScript oracle`);
  }
  runVerifier({ id: entry.id, input: entry.presented }, pinned);
}

// Refusal cases: not one valid JCS input at all. No profile excuses a verifier
// that prints bytes for them.
for (const entry of cases.refusalCases) {
  if ((entry.input === undefined) === (entry.inputHex === undefined)) {
    throw new Error(`${entry.id}: needs exactly one of input and inputHex`);
  }
  if (entry.expect !== "reject") throw new Error(`${entry.id}: a refusal case must expect reject`);
  runVerifier(entry, null);
}

// Depth cases: the cap of 128 nested containers is this corpus's admission
// profile, not RFC 8785, so a verifier is held to it under --profile bounded.
for (const entry of cases.depthCases) {
  JSON.parse(entry.input);
  if (entry.expect === "accept") {
    const pinned = Buffer.from(entry.canonicalHex, "hex");
    if (createHash("sha256").update(pinned).digest("hex") !== entry.sha256) {
      throw new Error(`${entry.id}: pinned digest disagrees with the pinned bytes`);
    }
    if (profile === "bounded") runVerifier(entry, pinned);
  } else if (profile === "bounded") {
    runVerifier(entry, null);
  }
}

console.log(`${cases.canonicalCases.length} JCS byte vectors, ${cases.driftCases.length} drift vectors, ${cases.refusalCases.length} refusal vectors and ${cases.depthCases.length} depth vectors checked${command ? ` against ${command[0]} (${profile})` : ""}`);
