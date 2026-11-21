# Canonical JSON bytes at the audit transcript boundary

`cases.json` pins raw JSON, canonical UTF-8 hex, and SHA-256 for five small
inputs, then 18 drift and 10 depth cases, a noncharacter family and a preimage family (below). `check.mjs` checks those bytes with ECMAScript string and number
serialization and UTF-16 member sorting. The Go test checks the separate
safe-integer record profile, including three malformed inputs.

Run the byte oracle:

```sh
node corpora/jcs-byte-vectors/check.mjs
```

The wheel ships `cases.json` and this README, so an SDK's CI can pin the
package and read the cases offline instead of fetching them by tag:

```sh
pip install agent-evidence-vectors==VERSION
agent-evidence-vectors --jcs-byte-vectors
python -c "from agent_evidence_vectors.run_vectors import jcs_byte_vectors_path; print(jcs_byte_vectors_path())"
```

Both print the absolute path of the installed `cases.json`. Releases from 0.17.7 on carry it.

To run a candidate canonicalizer, pass a command that reads one JSON value
from stdin and writes canonical bytes to stdout, with no trailing newline.
It exits nonzero on rejected input:

```sh
node corpora/jcs-byte-vectors/check.mjs --verifier ./canonicalizer
node corpora/jcs-byte-vectors/check.mjs --profile bounded --verifier ./record-canonicalizer
```

| Input | Boundary |
| --- | --- |
| Escaped `caf\u00e9` | JCS emits the UTF-8 character. Python's default `json.dumps` escapes it. |
| `\ud83d\ude00` and `\ue000` as nested keys | UTF-16 puts the supplementary key first; Python's `sort_keys` puts it second. |
| `1e-7` and `1e-6` | JCS emits `1e-7` and `0.000001`. Both are rejected by the integer-only record profile. |
| 2^53 - 1 and 2^53 | JCS can serialize both exact values. The bounded profile admits only the first. |
| Duplicate key, lone surrogate, 2^53 + 1 | The first two are invalid JCS input. The last is rejected by the bounded profile before a parser can round it. |

The [`TRACEAuditSink`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/src/agentmesh/governance/trace_sink.py)
uses `json.dumps` with default ASCII escaping for its transcript hash.
[`trace_model`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/src/agentmesh/governance/trace_model.py)
sets `ensure_ascii=False`; both paths use Python key and number formatting.
The fixture is a byte contract for the entry array. A TRACE record's signature,
schema, and call count require their own checks.

Why parse, sort keys and `JSON.stringify` fails these cases, and the fix byte by byte:
[JSON.stringify used as JCS](../../docs/guides/json-stringify-as-jcs.md).

## A second generator

`remint.mjs` re-mints `depthCases`, `noncharacterCases` and `preimageCases` from
their definitions with no code shared with `scripts/gen-jcs-drift-vectors.py`,
and `check.mjs` refuses to run when any member differs from the file, key order
included. Two independent generators agreeing byte for byte is the evidence that
the computed members say what their definitions say.

## Worked examples

One member of each family, written from `cases.json` by the same generator that
writes the families, so the table cannot say something the corpus does not.
Recompute any of them with `node corpora/jcs-byte-vectors/check.mjs`.

<!-- examples: written by scripts/gen-jcs-drift-vectors.py from cases.json -->
| Member | Input | Expected answer |
| --- | --- | --- |
| `ordinary-unicode` | `[{"data":{"label":"caf\u00e9"}}]` | bytes 5b7b2264617461223a7b226c6162656c223a22636166c3a9227d7d5d |
| `drift-html-less-than` | `{"a":"\u003c"}` | not canonical; bytes 7b2261223a223c227d |
| `refuse-non-finite-overflow-positive` | `{"a":1e999}` | refuse (non-finite-number) |
| `noncharacter-ufdd0-value-escaped` | `["\ufdd0"]` | bytes 5b22efb790225d; bounded: refuse (invalid-unicode) |
| `preimage-scalar-ascii` | `"approve"` | sha256 74e21680eac7385ca408cb01878465fd693b37e58eb0c0c32663a2d8f15d8136, never 6ef4cbc4f3f0a1af3187e96c208a6b7737cfa1cdfe40d84822a94d8d5eea0ac3 |
<!-- examples: end -->

## Drift and depth families

`cases.json` also carries two generated families, written by
`scripts/gen-jcs-drift-vectors.py` (`--check` fails when the file differs).

`driftCases` (18 members) are bytes a producer printed and presented as the
canonical form of a value, which RFC 8785 does not print that way. Each pins
`input` (the value as JSON text), `presented` (the drifted bytes) and
`canonicalHex` (the correct bytes, with their SHA-256). The expected answer is
the same for every member: a check that `presented` is canonical says no, and
canonicalizing either `input` or `presented` gives `canonicalHex`.

| Family | Members | What drifts |
| --- | --- | --- |
| `html-escape` | 5 | `<`, `>` and `&` printed as `\u003c`, `\u003e` and `\u0026`, in values and in member names. This is Go `encoding/json`'s default. |
| `non-ascii-escape` | 5 | Non-ASCII text left as `\u` escapes (BMP, surrogate pairs, member names), and U+2028 and U+2029, which Go escapes and JCS prints as UTF-8. |
| `number-format` | 8 | `-0`, `1.0`, `1e-07`, `1E2`, `1e30`, `1000000000000000000000`, `0.0000001` and an integer past 2^53 printed verbatim. |

One member, `drift-number-integer-beyond-double`, also carries `reference:
"refuse"` and `referenceError: "inexact-number"`. An integer past 2^53 has no
exact double, so the Python reference (`a2ajcs`) refuses it (RFC 7493 section
2.2) instead of printing `canonicalHex`. `canonicalHex` stays what an
implementation that rounds to the nearest double prints, so the drift between
a refusing and a rounding reader is recorded, and a reader that refuses is
conformant for this member.

`source` names the printer. A `go-encoding-json` member is held to a real run of
`encoding/json` by the `jcsvectors` Go test: it must print exactly `presented`.

`depthCases` (10 members) nest arrays and objects 129, 256, 512 and 1024
levels deep, which a gate with the normative cap of 128 containers refuses
(`expect: "reject"`, `error: "too-deep"`), and the same two shapes at exactly 128
levels, which it admits (`expect: "accept"`, with `canonicalHex`). RFC 8785 has
no depth rule, so `check.mjs --profile bounded` holds a verifier to these, and
the default profile does not.

Run `check.mjs --verifier CMD` and the verifier receives each `presented` text
and must print `canonicalHex`; under `--profile bounded` it must also exit
nonzero on every too-deep input and accept the two 128-deep ones. A verifier
that passed before can fail now, so the families arrived in a minor release.

## Noncharacter family

`noncharacterCases`, also written by `scripts/gen-jcs-drift-vectors.py`, puts a
Unicode noncharacter in a string value and in a member name, spelled raw and as a
`\u` escape: U+FDD0 and U+FDEF (both ends of the contiguous run), U+FFFE and
U+FFFF, U+1FFFE and U+10FFFF (supplementary planes, escaped as surrogate pairs).
Its `noncharacter-neighbour` members put the scalar value just outside each edge
(U+FDCF, U+FDF0, U+FFFD, U+1FFFD, U+10FFFD) in the same four places with no
`boundedError`: every profile prints them, so a bounded verifier whose
noncharacter test is too wide (all of U+FDC0..U+FDFF, or every U+nFFFx) fails
them instead of passing the family. `check.mjs` classifies each member's code
point from the Unicode definition rather than from either generator's list.

| Profile | Expected answer | Why |
| --- | --- | --- |
| default (`jcs`) | the pinned `canonicalHex`, the noncharacter printed as UTF-8 | A noncharacter is a Unicode scalar value, and RFC 8785 section 3.2.2.2 prints it as itself. |
| `bounded` | refuse (`boundedError: invalid-unicode`) a `noncharacter` member; print the pinned bytes of a `noncharacter-neighbour` member | [RFC 7493 section 2.1](https://www.rfc-editor.org/rfc/rfc7493#section-2.1): member names and string values MUST NOT include code points that identify noncharacters, escaped or not. The neighbours are ordinary scalar values. |

The raw and escaped spellings of one value pin the same bytes, so a verifier that
refuses only one spelling fails the bounded run, and one that refuses either
fails the default run. `jcs_admit::admit` prints them; `jcs_admit::admit_ijson`
refuses them.

## Preimage family

`preimageCases` says which bytes a field digest covers, and pins the wrong
answer a reader usually gives, so agreeing with it fails the member:

| Profile | Correct preimage | Stated wrong answer (`statedWrongReading`) |
| --- | --- | --- |
| `scalar-text` | the string's raw UTF-8 bytes | its JSON form, quotes and escapes included (`json-form`) |
| `structured-json` | the value's RFC 8785 bytes | the value as written (`as-written`) |
| `structured-json`, value `null` | the four bytes `null` | the empty input, as if the field were absent (`null-as-absent`) |
| `absent` | the empty input, SHA-256 `e3b0c442...b855` | the text `null` (`json-null`) |

A present `null` is a value, not an absent field: `preimage-structured-null` and
`preimage-absent` pin each other's answers as their wrong ones, so a reader that
maps `null` to absent, or absent to `null`, fails one of the two.

`preimage-scalar-empty` carries `collidesWith: preimage-absent`: under this
profile an empty string and an absent field hash the same bytes, so a record that
must tell them apart needs a presence bit beside the digest. `check.mjs` recomputes
every pinned digest with the ECMAScript oracle, and
`scripts/jcs-drift-vectors-test.py` shows a reader that hashes the JSON form
failing every scalar and absent member.

RFC 8785 [sections 3.2.2 and 3.2.3](https://www.rfc-editor.org/rfc/rfc8785#section-3.2)
define the byte rules. The safe-integer rejection is an application profile,
not a blanket JCS rejection.
