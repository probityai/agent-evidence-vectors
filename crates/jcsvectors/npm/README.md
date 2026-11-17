# jcsvectors

RFC 8785 (JSON Canonicalization Scheme) test vectors for JavaScript, shipped inside the package and checked against their SHA-256 digests before any case is returned.

It is for anyone who writes or depends on a JCS canonicalizer in JavaScript and wants a fixed, shared set of accept and refuse cases in `node --test`, with no download, no network and no dependencies.

```sh
npm install --save-dev --save-exact jcsvectors@0.2.0
```

## Example

```js
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonical, reject, filter } from "jcsvectors";
import { canonicalize } from "my-canonicalizer";

test("RFC 8785 vectors", () => {
  for (const v of canonical()) {
    assert.deepEqual(canonicalize(v.input), v.canonical, `${v.corpus}/${v.id}`);
  }
  for (const v of reject()) {
    assert.throws(() => canonicalize(v.input), `${v.corpus}/${v.id} was accepted`);
  }
});
```

`input` and `canonical` are `Uint8Array`: some refusal inputs are not UTF-8, so compare bytes.

## What is in it

| Function | Cases | A canonicalizer must |
|---|---|---|
| `canonical({ profile })` | every accept case, with the exact output bytes | print exactly `canonical` |
| `reject({ profile })` | duplicate members (also escaped or nested), lone surrogates, invalid UTF-8, non-finite numbers, trailing content, malformed JSON | refuse the input |
| `parserDifferential()` | a generator over the byte strings two JSON readers read apart, each with what RFC 8785 does (`error`, `canonical`) and what the bounded I-JSON profile does (`boundedError`) | match the profile it claims |
| `drifts()` | bytes a real printer presents as canonical that are not | not treat `presented` as canonical |
| `tooDeep()`, `depthAdmitted()` | nesting one level past, and exactly at, a cap of 128 | refuse, or accept and print, under that cap |
| `files()` | the raw embedded files at their corpus paths | (for your own reader) |

## Profiles

Every case carries `features` read from its bytes: `integer`, `unsafe-integer`, `fraction`, `exponent`, `negative-zero`, `escape`, `non-ascii`, `not-utf8`. A canonicalizer that supports only part of RFC 8785 declares a profile and scores the cases outside it apart:

```js
const { inProfile, outOfProfile } = filter("integer-only", canonical());
// a divergence on inProfile is a failure; report outOfProfile.length as out of profile
```

`integer-only` admits an accept case whose every number token is an integer inside +-(2^53 - 1) written with no fraction or exponent. A case that must be refused is inside every profile, because a subset of RFC 8785 accepts less input, never more: `reject({ profile: "integer-only" })` still returns `[1e999]`, and an integer-only canonicalizer that prints it has failed. `includes(profile, c)` is the rule `filter` and the `profile` option apply. `rfc8785` admits every case. An unknown profile throws.

## Same bytes in Go and Rust

The files are byte copies of `corpora/vectors-a2a-jcs-v01` and `corpora/jcs-byte-vectors` in [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors). The Go module `github.com/probityai/agent-evidence-vectors/jcsvectors` reads the same files by the same rules; CI compares the two packages case by case (identifier, clause, family, input and output digests, features, profile and codes), so implementations tested with either are held to the same bytes. The Rust crate `jcsvectors` 0.1 embeds the same files, without features, profiles or parser differentials.

## Pinning

Pin an exact version. A release that adds a case can turn a passing implementation red, so such a release is a minor version, never a patch, and its notes list the cases that changed. Add a Dependabot `npm` entry for the directory that holds your `package.json` so each release opens a pull request your tests run.

## Status

0.2.0. Node 22 or later. ESM only. Licensed MIT OR Apache-2.0.
