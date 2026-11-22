// A second generator for the computed families of cases.json, sharing no code
// with scripts/gen-jcs-drift-vectors.py: it re-mints depthCases,
// noncharacterCases and preimageCases from their definitions alone and compares
// every member, key order included, with the file. A difference means one of the
// two generators is wrong, and neither is trusted until they agree.
//
//   node corpora/jcs-byte-vectors/remint.mjs      exit 0 when both agree, 1 otherwise
//
// check.mjs runs it first, so every run of the byte oracle also proves the
// computed families can be produced independently.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const utf8 = (text) => Buffer.from(text, "utf8");
const hex4 = (n) => n.toString(16).padStart(4, "0");

function depthCases() {
  const cap = 128;
  const out = [];
  for (const shape of ["array", "object"]) {
    for (const depth of [cap, 129, 256, 512, 1024]) {
      const text = shape === "array"
        ? "[".repeat(depth) + "]".repeat(depth)
        : '{"a":'.repeat(depth) + "1" + "}".repeat(depth);
      const member = { id: `depth-${shape}-${depth}`, shape, depth, limit: cap, input: text };
      if (depth > cap) {
        member.expect = "reject";
        member.error = "too-deep";
      } else {
        member.expect = "accept";
        member.canonicalHex = utf8(text).toString("hex");
        member.sha256 = sha256(utf8(text));
      }
      out.push(member);
    }
  }
  return out;
}

function noncharacterCases() {
  const out = [];
  const members = [
    ...[0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x10ffff].map((cp) => ["noncharacter", cp]),
    ...[0xfdcf, 0xfdf0, 0xfffd, 0x1fffd, 0x10fffd].map((cp) => ["noncharacter-neighbour", cp]),
  ];
  for (const [family, cp] of members) {
    const raw = String.fromCodePoint(cp);
    const escaped = cp < 0x10000
      ? `\\u${hex4(cp)}`
      : `\\u${hex4(0xd800 + ((cp - 0x10000) >> 10))}\\u${hex4(0xdc00 + ((cp - 0x10000) & 0x3ff))}`;
    for (const position of ["value", "member-name"]) {
      for (const spelling of ["raw", "escaped"]) {
        const written = spelling === "raw" ? raw : escaped;
        const text = position === "value" ? `["${written}"]` : `{"${written}":1}`;
        const canonical = position === "value" ? `["${raw}"]` : `{"${raw}":1}`;
        const member = {
          id: `${family}-u${hex4(cp)}-${position}-${spelling}`,
          family,
          codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
          position,
          spelling,
          input: text,
          canonicalHex: utf8(canonical).toString("hex"),
          sha256: sha256(utf8(canonical)),
        };
        if (family === "noncharacter") member.boundedError = "invalid-unicode";
        out.push(member);
      }
    }
  }
  return out;
}

function preimageCases() {
  // [id, profile, value text or null, right preimage, wrong preimage, mistake]
  const table = [
    ["scalar-ascii", "scalar-text", '"approve"', "approve", '"approve"', "json-form"],
    ["scalar-non-ascii", "scalar-text", '"caf\\u00e9"', "café", '"café"', "json-form"],
    ["scalar-newline", "scalar-text", '"a\\nb"', "a\nb", '"a\\nb"', "json-form"],
    ["scalar-empty", "scalar-text", '""', "", '""', "json-form"],
    ["structured-reordered", "structured-json", '{"b":2,"a":1}', '{"a":1,"b":2}', '{"b":2,"a":1}', "as-written"],
    ["structured-escaped", "structured-json", '["caf\\u00e9"]', '["café"]', '["caf\\u00e9"]', "as-written"],
    ["structured-null", "structured-json", "null", "null", "", "null-as-absent"],
    ["absent", "absent", null, "", "null", "json-null"],
  ];
  const empty = sha256(Buffer.alloc(0));
  return table.map(([id, profile, value, right, wrong, mistake]) => {
    const member = { id: `preimage-${id}`, profile };
    if (value !== null) member.value = value;
    member.preimageHex = utf8(right).toString("hex");
    member.sha256 = sha256(utf8(right));
    member.statedWrongPreimageHex = utf8(wrong).toString("hex");
    member.statedWrongSha256 = sha256(utf8(wrong));
    member.statedWrongReading = mistake;
    if (member.sha256 === empty && profile !== "absent") member.collidesWith = "preimage-absent";
    return member;
  });
}

export function remint(cases) {
  const problems = [];
  const families = { depthCases, noncharacterCases, preimageCases };
  for (const [key, make] of Object.entries(families)) {
    const ours = make();
    const theirs = cases[key] ?? [];
    if (ours.length !== theirs.length) {
      problems.push(`${key}: re-minted ${ours.length} members, the file holds ${theirs.length}`);
    }
    ours.forEach((member, i) => {
      if (JSON.stringify(member) !== JSON.stringify(theirs[i])) {
        problems.push(`${key}[${i}] ${member.id}: the second generator writes different bytes`);
      }
    });
  }
  return problems;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cases = JSON.parse(readFileSync(new URL("./cases.json", import.meta.url)));
  const problems = remint(cases);
  for (const p of problems) console.error(p);
  console.log(problems.length ? `remint: ${problems.length} difference(s)` : "remint: the second generator agrees on every computed member");
  process.exit(problems.length ? 1 : 0);
}
