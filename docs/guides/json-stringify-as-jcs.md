# JSON.stringify used as JCS

A common way to "canonicalize" JSON in JavaScript is to parse the input, sort the
object keys, and call `JSON.stringify`. The output often matches RFC 8785 (JCS)
for ordinary records, so the bug stays hidden until a signed record carries one
of the inputs below. Then two verifiers compute different bytes for the same
record, or one of them signs bytes that RFC 8785 says cannot be produced at all.

We measured three hand-rolled JavaScript canonicalizers built this way. Every
one of them accepted a lone surrogate, a duplicate member name and invalid UTF-8
instead of refusing them. The cause is the same in each: the
refusals RFC 8785 requires happen at the parse and decode layer, and
`JSON.parse` followed by `JSON.stringify` has no step where a refusal can occur.

## What the RFC requires and what the pattern does

| RFC 8785 clause | Requirement | Parse, sort keys, stringify | Vector ids that catch it |
| --- | --- | --- | --- |
| 3.1 (input is I-JSON, RFC 7493 2.3) | A repeated member name is an error | `JSON.parse` keeps the last value and drops the first, so the signed bytes hide a member a different parser reads | `duplicate-member`, `refuse-duplicate-member-escaped-spelling`, `refuse-duplicate-member-nested` |
| 3.1 (RFC 7493 2.1) | Strings are sequences of Unicode scalar values | A lone surrogate survives `JSON.parse`; `JSON.stringify` prints it as `\udc00` | `lone-surrogate`, `refuse-unicode-lone-low-surrogate`, `refuse-unicode-reversed-surrogate-pair`, `refuse-unicode-lone-surrogate-in-member-name` |
| 3.1 | The input is valid UTF-8 | `TextDecoder` without `fatal: true` replaces bad bytes with U+FFFD and continues | `refuse-unicode-invalid-utf8-byte`, `refuse-unicode-overlong-utf8`, `refuse-unicode-surrogate-encoded-in-utf8` |
| 3.2.2.3 | Numbers are IEEE 754 doubles; NaN and Infinity are errors | `1e999` parses to `Infinity`, which `JSON.stringify` prints as `null` | `refuse-non-finite-overflow-positive`, `refuse-non-finite-overflow-negative` |
| RFC 7493 2.2, in an exact-integer profile | RFC 8785 itself canonicalizes `9007199254740992`; a profile that admits only exact integers refuses any integer beyond 2^53 - 1 | `JSON.parse` rounds `9007199254740993` to `9007199254740992` silently, so the refusal has to read the token before parsing | `rounded-unsafe-integer`, `first-unsafe-integer` (refusals under `--profile bounded`; under the default profile `first-unsafe-integer` must print its pinned bytes) |
| 3.2.3 | Members are sorted by UTF-16 code units, at every depth | `Object.keys(x).sort()` sorts by UTF-16 too, but a sort applied only at the top level, or a replacer that skips arrays, leaves nested objects in insertion order | `utf16-nested-key-order` |
| 3.2.2.2 | Strings print with the minimal escapes | `JSON.stringify` matches here, so tests that cover only strings pass | `ordinary-unicode` |

All ids are in [`corpora/jcs-byte-vectors/cases.json`](../../corpora/jcs-byte-vectors/cases.json).
Run a candidate against them with `node corpora/jcs-byte-vectors/check.mjs --verifier <command>`
for RFC 8785, or `node corpora/jcs-byte-vectors/check.mjs --profile bounded --verifier <command>`
for the exact-integer profile (the profile comes first). The last two rows are canonical cases: a
correct canonicalizer prints their pinned bytes rather than refusing them.

## The fix, at the byte level

Refuse before you parse into a host object, because after `JSON.parse` the
evidence is gone:

1. Decode the bytes with a fatal UTF-8 decoder (`new TextDecoder("utf-8", { fatal: true })`).
2. Tokenize the text yourself, or use a parser that reports duplicate member
   names after escape processing (`"a"` and `"a"` are the same name) at every depth.
3. Refuse any string, member names included, that holds an unpaired surrogate.
   Checking only the final output string is not enough: a check on the
   stringified output misses duplicates and decode errors, which never reach it.
4. Refuse non-finite numbers, and in an integer-only profile refuse an integer
   token outside plus or minus 2^53 - 1 by its spelling, before it becomes a double.
5. Only then sort members by UTF-16 code units at every depth and print numbers
   with the ECMAScript algorithm.

## Pinned tools per language

In each package, `admit` refuses every reject input in the table under the default profile and
prints the pinned RFC 8785 bytes for the canonical ones. `admit_ijson` is the same call with the
RFC 7493 checks added, and is the one that refuses the two integer cases. The Action row scores
your own canonicalizer rather than replacing it. Pin the exact version, and let Dependabot or
Renovate open the bump.

| Language | Package | Pin |
| --- | --- | --- |
| Rust | `jcs-admit` on crates.io | `jcs-admit = "=0.1.3"` |
| Python | `jcs-admit` on PyPI | `jcs-admit==0.1.1` |
| JavaScript | `jcs-admit` on npm | `"jcs-admit": "0.1.0"` |
| Any language, in CI | the Action, scoring your canonicalizer as a bare RFC 8785 target | `uses: probityai/agent-evidence-vectors@v0.37.0` with `corpus: vectors-a2a-jcs-v01`, your command as `verifier` and `A2A_JCS_TARGET: rfc8785` in the step env |

Versions were read from crates.io, PyPI and npm on 17 Nov 2026. Read the
registries again before you copy a pin.
