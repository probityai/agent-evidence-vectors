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
    input: Buffer.from(entry.input, "utf8"),
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

console.log(`${cases.canonicalCases.length} JCS byte vectors checked${command ? ` against ${command[0]} (${profile})` : ""}`);
