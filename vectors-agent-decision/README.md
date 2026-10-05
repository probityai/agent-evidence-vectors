# Agent decision conformance vectors

Vectors for the `tool_calls[].args_hash` rule of the `agent-decision/v0.1`
predicate proposed in
[in-toto/attestation#554](https://github.com/in-toto/attestation/issues/554).
The RFC writes `args_hash` as `sha256:<hex>` and leaves open how the argument
object is turned into bytes, so two producers can hash one call to different
digests. The thread asked the rule to say two things, and these vectors pin both:

- `args_hash` is SHA-256 over the RFC 8785 (JCS) bytes of the argument object,
  the named projection the hash covers
  ([#554 comment](https://github.com/in-toto/attestation/issues/554#issuecomment-4962035548));
- each tool call carries `args_state`, one of `recorded`, `redacted`,
  `unavailable` or `not_recorded`, so a redacted call and an unrecorded one are
  different signed claims rather than two absent hashes (same comment).

The number cases follow the list in
[#554 comment 5874454918](https://github.com/in-toto/attestation/issues/554#issuecomment-5874454918):
integral doubles across the exponent range, the integer boundary at 2^53 - 1,
and the `args_state` distinctions reaching different verdicts.

## Running it

```sh
# Rebuild every member (byte-identical on every machine), then judge the
# committed bytes, recompute every canonical form a second way, and disable
# each rule in turn to show it is load-bearing.
uv run --extra generators python vectors-agent-decision/gen_vectors.py
uv run --extra generators python vectors-agent-decision/check_vectors.py

# The Go rail, from the repository root.
go run ./cmd/aee-verify vectors-agent-decision
```

Each member is a DSSE envelope over an in-toto Statement v1 whose predicate is an
agent-decision record with one tool call. A member whose call is `recorded` also
discloses its arguments, as the exact bytes the producer read, in the file its
manifest entry's `arguments` field names. To score a verifier, give it the
envelope, the disclosed arguments and `keys.producer.publicKey`, and compare its
verdict with `expected.verdict`. `expected.codes` name the reference reader's
first refusal so two implementations can compare where they stopped; the RFC
defines no codes.

### Scoring a canonicalizer on its own

Every member whose arguments are admissible carries `canonicalArguments`, the
RFC 8785 text of those arguments. A JCS implementation can be scored without any
DSSE code: canonicalize each `arguments` file and compare the bytes. A repository
with more than one canonicalization path should run each path separately and
report each result under its own name, since one figure leaves open which path
was measured. Report a run with the
[independent run form](https://github.com/probityai/agent-evidence-vectors/issues/new?template=independent-run.yml);
each path is its own report and becomes its own row in [`RUNS.md`](../RUNS.md).

## The rules

[`INDEX.md`](INDEX.md) lists every member with its rule and parent. In the
reader's order, which is also the order of first refusal:

| rule | refusal | verdict |
| --- | --- | --- |
| the one signature verifies under the producer key over PAE | `signature-invalid` | invalid |
| the payload is an in-toto Statement v1 naming the predicate type, with a subject | `statement-malformed` | malformed |
| every field the RFC marks required is present with its type, and `decision` is `allow` or `deny` | `predicate-malformed` | malformed |
| every tool call carries `args_state` from the closed set | `args-state-missing`, `args-state-unknown` | malformed |
| `recorded` and `redacted` carry `args_hash`; `unavailable` and `not_recorded` carry none | `args-hash-required`, `args-hash-forbidden` | malformed |
| `args_hash` is `sha256:` and 64 lowercase hex digits | `args-hash-format` | malformed |
| the disclosed arguments are one JSON object | `arguments-not-json` | malformed |
| no object in them repeats a member name | `arguments-duplicate-member` | malformed |
| an integer written without fraction or exponent lies within -(2^53 - 1) to 2^53 - 1 | `arguments-integer-unsafe` | malformed |
| any other number is a finite double | `arguments-number-overflow` | malformed |
| `args_hash` is SHA-256 over the RFC 8785 bytes of the disclosed arguments | `args-hash-mismatch` | invalid |

### What the four states mean

- `recorded`: the arguments were recorded and are disclosed with the record, and
  `args_hash` binds them, so a verifier recomputes it.
- `redacted`: the arguments were recorded and withheld; `args_hash` commits to
  them, so a later disclosure can be checked against it.
- `unavailable`: the producer could not read the arguments.
- `not_recorded`: the producer chose not to record them.

`redacted-without-hash` and `not-recorded` carry the same tool call except for the
state word, and one is refused while the other is accepted. `state-absent` is the
tool call exactly as the RFC's own example writes it, `args_hash` with no state,
and this rule refuses it.

### Numbers

An integer written without a fraction or exponent is held to the RFC 7493
section 2.2 range. That boundary is where libraries split between refusing a
value and rounding it to the nearest double, and a rounding library hashes
`9007199254740993` as `9007199254740992` without saying so. The vectors pin
refusal: `integer-2-53`, `integer-2-53-plus-1` and `integer-1e21-digits` are each
hashed over the text a rounding library writes, so a verifier that rounds accepts
them and fails. A number written with a fraction or an exponent is a double by
the writer's own spelling and canonicalizes per RFC 8785 section 3.2.2.3, which
is why `integer-past-boundary-as-double` (`9007199254740993.0`) is accepted with
the hash of `9007199254740992`.

Each `-drift` member is hashed over the spelling a known writer produces, named
in its row: plain digits at 1e21, Python's `repr` and `json.dumps`, a
printf-style exponent, a kept negative zero, and member names sorted by code
point where RFC 8785 sorts by UTF-16 code unit. Its `hashedOver` field carries
that text, and its `parent` is the member with the same arguments and the
correct hash.

## The reference rule sweep

`check_vectors.py` disables one rule at a time and requires each to admit at
least one reject member while refusing no accept member. A disabled admission
rule is replaced by what a common library does instead: the last repeated member
wins, an out-of-range integer becomes the nearest double, an overflowing number
becomes the `null` that `JSON.stringify` writes for Infinity, and a projection
that is not an object is hashed as it stands. Each admission reject is hashed
over exactly that library's output, so the sweep shows the vector catches that
library rather than only a reader that skips the rule.

## What the members are built from

The producer key is a published test key derived from a fixed seed in
[`gen_vectors.py`](gen_vectors.py) (`keyRecipe` in the manifest). All values are
synthetic. The subject names the tool and carries the SHA-256 of the canonical
`tool_calls` array; the vectors judge only that the subject is present and
well formed, since what the subject should name is still open on #554.
