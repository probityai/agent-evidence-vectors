// Helpers every family reader shares.
//
// - Verdict, allow, deny, unimplemented: the (decision, reason) a reader derives.
// - loadManifest, readRecord: read a corpus directory.
// - parseRecord: strict JSON parse that refuses duplicate members; integers
//   come back as bigint and every other number as number, which is Python's
//   int/float split, so a reader can tell 1 from 1.0 as the Python readers do.
// - canonicalJson, canonicalBytes, digest, sha256Hex: RFC 8785 and the
//   `sha256:`-prefixed digests the records carry.
// - ed25519Verify, b64DecodeStrict: signatures and base64 as Python and the
//   Rust crate take them.
// - parseInstantZ, parseRfc3339Micros: timestamps as the Python readers accept
//   them.

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** The decision and reason a reader derives from one record. */
export interface Verdict {
  /** `allow`, `deny`, or `unimplemented` for a family not ported yet. */
  readonly decision: string;
  /** The reason code the corpus names, for example `authorized_use`. */
  readonly reason: string;
}

/** An `allow` verdict with the given reason. */
export function allow(reason: string): Verdict {
  return { decision: "allow", reason };
}

/** A `deny` verdict with the given reason. */
export function deny(reason: string): Verdict {
  return { decision: "deny", reason };
}

/**
 * The verdict of a family whose reader is not written yet. It never equals a
 * manifest's expected answer, so an agreement check fails on it.
 */
export function unimplemented(): Verdict {
  return { decision: "unimplemented", reason: "reader_not_ported" };
}

/** A corpus, manifest or record that could not be read. */
export class ReaderError extends Error {
  override readonly name = "ReaderError";
}

/** A parsed JSON value. Integers are bigint; numbers written with a fraction or exponent are number. */
export type Json = null | boolean | number | bigint | string | Json[] | JsonObject;

/** A parsed JSON object. It has no prototype, so a member named `__proto__` is an ordinary key. */
export interface JsonObject {
  [member: string]: Json;
}

/** One manifest row: the case identifier and its directory under the corpus. */
export interface VectorEntry {
  readonly id: string;
  readonly path: string;
}

/** The parts of MANIFEST.json a reader needs; `expected` answers are never loaded. */
export interface Manifest {
  readonly suite: string;
  readonly vectors: readonly VectorEntry[];
}

function readFile(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch (error) {
    throw new ReaderError(`cannot read ${path}: ${String(error)}`);
  }
}

/** Read `MANIFEST.json` from a corpus directory. */
export function loadManifest(dir: string): Manifest {
  const path = join(dir, "MANIFEST.json");
  let value: unknown;
  try {
    value = JSON.parse(readFile(path).toString("utf8"));
  } catch (error) {
    if (error instanceof ReaderError) throw error;
    throw new ReaderError(`${path} does not parse: ${String(error)}`);
  }
  if (typeof value !== "object" || value === null) {
    throw new ReaderError(`${path} is not an object`);
  }
  const { suite, vectors } = value as { suite?: unknown; vectors?: unknown };
  if (typeof suite !== "string") throw new ReaderError(`${path} has no string suite`);
  if (!Array.isArray(vectors)) throw new ReaderError(`${path} has no vectors list`);
  const entries = vectors.map((row: unknown): VectorEntry => {
    const { id, path: casePath } = (row ?? {}) as { id?: unknown; path?: unknown };
    if (typeof id !== "string" || typeof casePath !== "string") {
      throw new ReaderError("a manifest vector lacks a string id or path");
    }
    return { id, path: casePath };
  });
  return { suite, vectors: entries };
}

const MAX_DEPTH = 128;
const NUMBER = /^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

/** A recursive-descent JSON parser: RFC 8259 grammar, duplicate members refused. */
class Parser {
  private at = 0;

  constructor(private readonly text: string) {}

  document(): Json {
    this.space();
    const value = this.value(0);
    this.space();
    if (this.at !== this.text.length) this.fail("data after the document");
    return value;
  }

  private fail(message: string): never {
    throw new ReaderError(`record.json does not parse: ${message} at offset ${this.at}`);
  }

  private space(): void {
    while (" \t\n\r".includes(this.text.charAt(this.at)) && this.at < this.text.length) this.at += 1;
  }

  private value(depth: number): Json {
    if (depth > MAX_DEPTH) this.fail("nesting too deep");
    const char = this.text.charAt(this.at);
    if (char === "{") return this.object(depth);
    if (char === "[") return this.array(depth);
    if (char === '"') return this.string();
    for (const [word, value] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.text.startsWith(word, this.at)) {
        this.at += word.length;
        return value;
      }
    }
    return this.number();
  }

  private object(depth: number): Json {
    const result: JsonObject = Object.create(null) as JsonObject;
    this.at += 1;
    this.space();
    if (this.text.charAt(this.at) === "}") {
      this.at += 1;
      return result;
    }
    for (;;) {
      this.space();
      if (this.text.charAt(this.at) !== '"') this.fail("expected a member name");
      const name = this.string();
      if (Object.hasOwn(result, name)) this.fail(`duplicate member ${JSON.stringify(name)}`);
      this.space();
      if (this.text.charAt(this.at) !== ":") this.fail("expected ':'");
      this.at += 1;
      this.space();
      result[name] = this.value(depth + 1);
      this.space();
      const next = this.text.charAt(this.at);
      this.at += 1;
      if (next === "}") return result;
      if (next !== ",") this.fail("expected ',' or '}'");
    }
  }

  private array(depth: number): Json {
    const result: Json[] = [];
    this.at += 1;
    this.space();
    if (this.text.charAt(this.at) === "]") {
      this.at += 1;
      return result;
    }
    for (;;) {
      this.space();
      result.push(this.value(depth + 1));
      this.space();
      const next = this.text.charAt(this.at);
      this.at += 1;
      if (next === "]") return result;
      if (next !== ",") this.fail("expected ',' or ']'");
    }
  }

  private string(): string {
    this.at += 1;
    let out = "";
    for (;;) {
      if (this.at >= this.text.length) this.fail("unterminated string");
      const char = this.text.charAt(this.at);
      this.at += 1;
      if (char === '"') return out;
      if (char < " ") this.fail("control character in string");
      if (char !== "\\") {
        out += char;
        continue;
      }
      const escape = this.text.charAt(this.at);
      this.at += 1;
      const simple: Record<string, string> = {
        '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
      };
      const mapped = simple[escape];
      if (mapped !== undefined) {
        out += mapped;
      } else if (escape === "u") {
        out += this.unicode();
      } else {
        this.fail("bad escape");
      }
    }
  }

  private hex4(): number {
    const digits = this.text.slice(this.at, this.at + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(digits)) this.fail("bad \\u escape");
    this.at += 4;
    return Number.parseInt(digits, 16);
  }

  private unicode(): string {
    const unit = this.hex4();
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (!this.text.startsWith("\\u", this.at)) this.fail("lone surrogate");
      this.at += 2;
      const low = this.hex4();
      if (low < 0xdc00 || low > 0xdfff) this.fail("lone surrogate");
      return String.fromCharCode(unit, low);
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) this.fail("lone surrogate");
    return String.fromCharCode(unit);
  }

  private number(): Json {
    const start = this.at;
    while (this.at < this.text.length && "+-.0123456789eE".includes(this.text.charAt(this.at))) {
      this.at += 1;
    }
    const lexeme = this.text.slice(start, this.at);
    const match = NUMBER.exec(lexeme);
    if (match === null) this.fail("bad value");
    if (match[1] === undefined && match[2] === undefined) return BigInt(lexeme);
    const value = Number(lexeme);
    if (!Number.isFinite(value)) this.fail("number out of range");
    return value;
  }
}

/**
 * Parse record.json bytes into a value, refusing what the Rust reader's
 * `jcs-admit` gate refuses: a repeated object member, a lone surrogate, bytes
 * that are not UTF-8, nesting past 128 and a number with no finite double.
 * Integers (no fraction, no exponent) come back as bigint, other numbers as
 * number.
 */
export function parseRecord(bytes: Uint8Array | string): Json {
  let text: string;
  if (typeof bytes === "string") {
    text = bytes;
  } else {
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      throw new ReaderError("record.json is not UTF-8");
    }
  }
  return new Parser(text).document();
}

/** Read and parse `record.json` in a case directory; returns the value and the exact bytes. */
export function readRecord(caseDir: string): { record: Json; bytes: Buffer } {
  const path = join(caseDir, "record.json");
  const bytes = readFile(path);
  try {
    return { record: parseRecord(bytes), bytes };
  } catch (error) {
    throw new ReaderError(`${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Lowercase hex SHA-256 of `data`. */
export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function canonicalNumber(value: number): string {
  if (!Number.isFinite(value)) throw new ReaderError("cannot canonicalize a non-finite number");
  return JSON.stringify(value);
}

/**
 * RFC 8785 (JCS) text of a value: members sorted by UTF-16 code units, strings
 * escaped as JSON.stringify does, numbers in the ECMAScript form. A bigint is
 * written as the double it converts to, which is its decimal form for every
 * safe integer.
 */
export function canonicalJson(value: Json): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      return canonicalNumber(value);
    case "bigint":
      return canonicalNumber(Number(value));
    default:
      break;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const members = Object.keys(value)
    .sort()
    .map((name) => `${JSON.stringify(name)}:${canonicalJson(value[name] as Json)}`);
  return `{${members.join(",")}}`;
}

/** UTF-8 bytes of {@link canonicalJson}. */
export function canonicalBytes(value: Json): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

/** `sha256:` plus the hex SHA-256 of the value's canonical bytes; the Python readers' `digest(value)`. */
export function digest(value: Json): string {
  return `sha256:${sha256Hex(canonicalBytes(value))}`;
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Whether `signature` is a valid Ed25519 signature of `message` under the
 * 32-byte `publicKey`. A malformed key or signature is false. node:crypto
 * verifies with OpenSSL, which refuses a non-canonical signature scalar but
 * does not refuse a small-order public key as the Rust crate's verify_strict does.
 */
export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Decode standard-alphabet base64 as Python's `base64.b64decode(s,
 * validate=True)` does: characters outside the alphabet are refused, padding
 * must be exactly right, and non-zero trailing bits are accepted. Returns null
 * where Python would raise.
 */
export function b64DecodeStrict(text: string): Buffer | null {
  return BASE64.test(text) ? Buffer.from(text, "base64") : null;
}

const MICROS = 1_000_000n;

function daysInMonth(year: number, month: number): number {
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  if (month === 2) return leap ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/** Days from 1970-01-01 to a civil date in the proleptic Gregorian calendar. */
function daysFromCivil(year: number, month: number, day: number): number {
  const shifted = month <= 2 ? year - 1 : year;
  const era = Math.floor(shifted / 400);
  const yearOfEra = shifted - era * 400;
  const dayOfYear = Math.floor((153 * ((month + 9) % 12) + 2) / 5) + day - 1;
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:(Z)|([+-])(\d{2}):(\d{2}))$/;

/**
 * Parse an RFC 3339 timestamp, `YYYY-MM-DDTHH:MM:SS[.f{1,6}](Z|+HH:MM|-HH:MM)`,
 * into microseconds since the Unix epoch (UTC), or null. The subset of Python's
 * `datetime.fromisoformat` that appears in the v2 corpora; a family whose
 * Python reader accepts a wider spelling extends this against the cases that
 * need it.
 */
export function parseRfc3339Micros(text: string): bigint | null {
  const match = RFC3339.exec(text);
  if (match === null) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [
    number, number, number, number, number, number,
  ];
  if (
    year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59
  ) {
    return null;
  }
  const fraction = BigInt((match[7] ?? "").padEnd(6, "0") || "0");
  let offsetSeconds = 0;
  if (match[8] === undefined) {
    const offsetHour = Number(match[10]);
    const offsetMinute = Number(match[11]);
    if (offsetHour > 23 || offsetMinute > 59) return null;
    offsetSeconds = (offsetHour * 3600 + offsetMinute * 60) * (match[9] === "-" ? -1 : 1);
  }
  const local = daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
  return BigInt(local - offsetSeconds) * MICROS + fraction;
}

/**
 * Parse the one spelling the strict contracts take, `YYYY-MM-DDTHH:MM:SSZ`
 * (attenuated-delegation, grant-use), into seconds since the Unix epoch, or null.
 */
export function parseInstantZ(text: string): number | null {
  if (text.length !== 20 || !text.endsWith("Z")) return null;
  const micros = parseRfc3339Micros(text);
  return micros === null ? null : Number(micros / MICROS);
}
