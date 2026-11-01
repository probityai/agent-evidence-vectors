import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { assert } from "./check.mjs";

const root = new URL("../../", import.meta.url);
const bytes = (value) => [...new TextEncoder().encode(value)];
const decoded = (value) => [...Buffer.from(value, "base64")];
const encoded = (value) => bytes(JSON.stringify(value));
const copy = (value) => structuredClone(value);

export async function loadCases() {
  const sourceFiles = {};
  async function source(name) {
    const raw = await readFile(new URL(name, root));
    sourceFiles[name] = createHash("sha256").update(raw).digest("hex");
    return raw.toString("utf8");
  }
  const fixture = JSON.parse(await source("vectors/cross_lang_signing.json"));
  const threshold = JSON.parse(await source("interop/sigstore-js-threshold-2026-10-04/cases.json"));
  const spec = await source("tests/spec_vector.rs");
  await source("tests/envelope_refusals.rs");
  assert(fixture.fixtures.length === 11, "Pinned Go reference fixture population differs");
  assert(threshold.cases.length === 17, "Retained threshold control population differs");
  const der = Buffer.from(fixture.public_key_pem.split("\n").filter((line) => !line.startsWith("-----")).join(""), "base64");
  assert(der.length === 44 && der.subarray(0, 12).toString("hex") === "302a300506032b6570032100", "Reference key is not the pinned Ed25519 SPKI shape");
  const key = { public_key: [...der.subarray(12)], key_id: fixture.key_id };
  const cases = [];
  const retainedCounts = { referenceVerify: 0, referencePae: 0, threshold: 0, specification: 0, binding: 0 };
  function add(group, value) {
    cases.push(value);
    retainedCounts[group] += 1;
  }
  for (const item of fixture.fixtures) {
    add("referenceVerify", { id: `reference/verify/${item.name}`, operation: "verify", envelope: encoded(item.envelope), trusted_keys: [key], threshold: 1,
      retainedVerified: { payload_type: item.payload_type, payload: decoded(item.canonical_b64), accepted_keys: [fixture.key_id] } });
    add("referencePae", { id: `reference/pae/${item.name}`, operation: "pae", payload_type: item.payload_type, payload: decoded(item.canonical_b64), retainedOutput: decoded(item.pae_b64) });
  }
  for (const item of threshold.cases) {
    const trusted_keys = item.trusted_keys.map((entry) => ({ public_key: [...Buffer.from(entry.public_hex, "hex")], key_id: entry.id }));
    add("threshold", { id: `threshold/${item.id}`, operation: "verify", envelope: encoded(item.envelope), trusted_keys, threshold: item.threshold,
      retainedDecision: item.expected.decision, retainedMessage: item.expected.rust_message, retainedAcceptedKeys: item.expected.accepted_keys });
  }
  const pae = spec.match(/let got = pae\("([^"]+)", b"([^"]+)"\);/);
  const want = spec.match(/b"(DSSEv1[^"]+)"\.to_vec\(\)/);
  const envelope = spec.match(/let json = br#"([\s\S]*?)"#;/);
  assert(pae && want && envelope, "Pinned specification literals could not be read");
  add("specification", { id: "specification/pae", operation: "pae", payload_type: pae[1], payload: bytes(pae[2]), retainedOutput: bytes(want[1]) });
  // The specification's envelope carries ECDSA. This Ed25519 API only checks
  // its container/refusal behavior; it does not claim that signature verifies.
  add("specification", { id: "specification/ecdsa-container", operation: "verify", envelope: bytes(envelope[1]), trusted_keys: [key], threshold: 1, retainedDecision: "refused" });

  const binary = fixture.fixtures.find((item) => item.name === "binary_batch_root");
  assert(binary, "Binary reference fixture is missing");
  const base = binary.envelope;
  function verify(id, changes = {}, trusted_keys = [key], count = 1) {
    add("binding", { id: `binding/${id}`, operation: "verify", envelope: encoded({ ...copy(base), ...changes }), trusted_keys, threshold: count });
  }
  verify("anonymous-key", {}, [{ public_key: key.public_key }]);
  verify("no-trusted-keys", {}, []);
  verify("maximum-u32-threshold", {}, [key], 0xffffffff);
  verify("duplicate-signature-at-threshold-one", { signatures: [base.signatures[0], base.signatures[0]] });
  verify("extra-envelope-members", { future: { value: [1, null, true] } });
  verify("signature-hint-absent", { signatures: [{ sig: base.signatures[0].sig }] });
  verify("signature-cap-boundary", { signatures: Array.from({ length: 1024 }, () => base.signatures[0]) });
  verify("signature-cap-overflow", { signatures: Array.from({ length: 1025 }, () => base.signatures[0]) });
  for (const length of [0, 31, 33]) verify(`invalid-key-length-${length}`, {}, [{ public_key: Array(length).fill(0), key_id: "bad" }]);
  for (const [name, payload] of [["nonzero-trailing-bits", "eB=="], ["missing-padding", "eA"], ["mixed-alphabets", "a-b+cd=="]]) verify(name, { payload });
  for (const [name, raw] of [["invalid-utf8", [0xff]], ["overlong-utf8", [0xc0, 0xaf]], ["empty-envelope", []]]) {
    add("binding", { id: `binding/${name}`, operation: "verify", envelope: raw, trusted_keys: [key], threshold: 1 });
  }
  const rawDuplicate = JSON.stringify(base).replace('"payload":', `"payload":"${base.payload}","payload":`);
  add("binding", { id: "binding/duplicate-payload-member", operation: "verify", envelope: bytes(rawDuplicate), trusted_keys: [key], threshold: 1 });
  for (const payload_type of ["", "t\u0000x", "caf\u00e9", "cafe\u0301", "\ud83d\ude00"]) {
    add("binding", { id: `binding/pae-scalar-${retainedCounts.binding}`, operation: "pae", payload_type, payload: [0, 255, 128, 65] });
  }
  assert(new Set(cases.map((item) => item.id)).size === cases.length, "Consumer case IDs collide");
  assert(Object.values(retainedCounts).reduce((sum, count) => sum + count, 0) === cases.length, "Case group count differs");
  return { cases, retainedCounts, sourceFiles,
    scope: "Unchanged eleven Go reference envelopes/PAE values, the existing seventeen authored threshold controls, specification literals, and finite raw binding controls. Native/WASM Ed25519 verification and PAE parity only; no independent operator, signing-service or universal verifier claim." };
}
