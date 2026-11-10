import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ReaderError,
  b64DecodeStrict,
  canonicalJson,
  digest,
  ed25519Verify,
  parseInstantZ,
  parseRecord,
  parseRfc3339Micros,
  sha256Hex,
} from "../src/common.js";

test("sha256 known answers", () => {
  assert.equal(sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("canonicalJson matches RFC 8785 section 3.2.4", () => {
  const sample =
    '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
    '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"/","literals":[null,true,false]}';
  const expected =
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
    '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
  assert.equal(canonicalJson(parseRecord(sample)), expected);
});

test("canonicalJson sorts member names by UTF-16 code units (RFC 8785 section 3.2.3)", () => {
  const sample =
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh",' +
    '"1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",' +
    '"\\u00f6":"Latin Small Letter O With Diaeresis"}';
  const names = canonicalJson(parseRecord(sample))
    .match(/"(?:[^"\\]|\\.)*":/g)
    ?.map((member) => JSON.parse(member.slice(0, -1)) as string);
  assert.deepEqual(names, ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\u{1F600}", "\ufb33"]);
});

test("canonicalJson number forms from RFC 8785 appendix B", () => {
  const cases: Array<[string, string]> = [
    ["9007199254740994.0", "9007199254740994"],
    ["5e-324", "5e-324"],
    ["1.7976931348623157e308", "1.7976931348623157e+308"],
    ["1e21", "1e+21"],
    ["1e20", "100000000000000000000"],
    ["333333333.3333332", "333333333.3333332"],
    ["0.000001", "0.000001"],
    ["1e-7", "1e-7"],
    ["-0.0", "0"],
  ];
  for (const [input, expected] of cases) {
    assert.equal(canonicalJson(parseRecord(input)), expected, input);
  }
});

test("digest prefixes the hash of the canonical bytes", () => {
  const value = parseRecord('{"b":1,"a":[true,"x"]}');
  assert.equal(canonicalJson(value), '{"a":[true,"x"],"b":1}');
  assert.equal(digest(value), `sha256:${sha256Hex('{"a":[true,"x"],"b":1}')}`);
});

test("parseRecord keeps Python's int and float split", () => {
  const value = parseRecord('{"i":1,"f":1.0,"e":1e2,"big":9007199254740993}') as Record<string, unknown>;
  assert.equal(value["i"], 1n);
  assert.equal(value["f"], 1);
  assert.equal(value["e"], 100);
  assert.equal(value["big"], 9007199254740993n);
});

test("parseRecord refuses what jcs-admit refuses", () => {
  for (const bad of [
    '{"a":1,"a":2}',
    '{"x":{"b":1,"b":1}}',
    "{",
    '{"a":1} x',
    '"\\ud800"',
    '"\\udc00"',
    "01",
    "1e999",
    '{"a":1,}',
    '"tab\there"',
    "'single'",
    "",
  ]) {
    assert.throws(() => parseRecord(bad), ReaderError, bad);
  }
  assert.throws(() => parseRecord(Uint8Array.from([0x22, 0xff, 0x22])), ReaderError);
  assert.throws(() => parseRecord("[".repeat(200) + "]".repeat(200)), ReaderError);
  assert.doesNotThrow(() => parseRecord("[".repeat(100) + "]".repeat(100)));
});

test("a member named __proto__ is an ordinary key", () => {
  const value = parseRecord('{"__proto__":{"x":1}}');
  assert.equal(canonicalJson(value), '{"__proto__":{"x":1}}');
});

test("instants parse to epoch seconds and strict spelling is exact", () => {
  assert.equal(parseInstantZ("1970-01-01T00:00:00Z"), 0);
  assert.equal(parseInstantZ("2000-03-01T00:00:00Z"), 951_868_800);
  assert.equal(parseInstantZ("2024-02-29T23:59:59Z"), 1_709_251_199);
  for (const text of [
    "2026-02-30T00:00:00Z", "2026-11-09T24:00:00Z", "2026-11-09T00:60:00Z",
    "2026-11-09T00:00:60Z", "2026-13-09T00:00:00Z", "2026-11-09T00:00:00",
    "2026-11-09T00:00:00.5Z", "2026-11-09T00:00:00+00:00", "2026-11-09 00:00:00Z",
    "2026-11-09t00:00:00z", "2023-02-29T00:00:00Z", "0000-01-01T00:00:00Z", "",
  ]) {
    assert.equal(parseInstantZ(text), null, text);
  }
});

test("rfc3339 handles fraction and offset", () => {
  assert.equal(parseRfc3339Micros("2000-03-01T01:00:00+01:00"), 951_868_800_000_000n);
  assert.equal(parseRfc3339Micros("2000-02-29T19:30:00-04:30"), 951_868_800_000_000n);
  assert.equal(parseRfc3339Micros("2000-03-01T00:00:00.25Z"), 951_868_800_250_000n);
  assert.equal(parseRfc3339Micros("2000-03-01T00:00:00.1234567Z"), null);
  assert.equal(parseRfc3339Micros("2000-03-01T00:00:00+0100"), null);
  assert.equal(parseRfc3339Micros("2000-03-01T00:00:00."), null);
});

test("base64 follows Python validate=True", () => {
  assert.equal(b64DecodeStrict("aGVsbG8=")?.toString(), "hello");
  assert.equal(b64DecodeStrict("aGVsbG9=")?.toString(), "hello");
  assert.equal(b64DecodeStrict("aGVsbG8"), null);
  assert.equal(b64DecodeStrict("aGVs bG8="), null);
  assert.equal(b64DecodeStrict("aGVsbG8=\n"), null);
  assert.equal(b64DecodeStrict("====") , null);
  assert.equal(b64DecodeStrict("")?.length, 0);
});

test("ed25519 RFC 8032 test vector 1", () => {
  const publicKey = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
  const signature = Buffer.from(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "hex",
  );
  assert.equal(ed25519Verify(publicKey, Buffer.alloc(0), signature), true);
  assert.equal(ed25519Verify(publicKey, Buffer.from("x"), signature), false);
  assert.equal(ed25519Verify(publicKey.subarray(0, 31), Buffer.alloc(0), signature), false);
});
