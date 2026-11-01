# Design and evidence

Why `jcs-admit` exists, what it refuses and delegates, and how each claim is tested. The [README](../README.md) is the short version.

Admission control for JSON that is about to be signed or verified.

RFC 8785 says how to write a document's canonical bytes. It does not say which documents
are allowed to have them.

This crate decides that, on the raw bytes, before anything is decoded. Then it hands the
writing to a delegate,
[`serde_json_canonicalizer`](https://crates.io/crates/serde_json_canonicalizer), which
already does that part well.

## What a serializer cannot check

Seven RFC 8785 implementations on crates.io were read on 2026-09-19. Not one of them
accepts bytes: six canonicalize a value something else already parsed, and the seventh takes
`&str`. The entry points and download counts are in
[`docs/INCUMBENT-MEASUREMENT.md`](INCUMBENT-MEASUREMENT.md).

That shape is right for their job, and it fixes where they can stand. The faults that matter
to a verifier are the ones that vanished during the parse ahead of them.

A repeated object member is the clearest case. By the time a value exists it is gone:
the parsed map kept one of the two, and nothing downstream can tell it happened.

One of the seven does reject a duplicate member, by parsing a `&str` with a strict
deserializer. A `&str` cannot hold a surrogate encoded directly in UTF-8 or an overlong form,
so that route reaches the one byte-level fault that survives being spelled in UTF-8 and none
of the others.

To check every fault class you need to be below the parse, on the bytes. That is where this
crate sits.

## What the delegate does with a hostile document

Measured on 2026-09-19 against `serde_json_canonicalizer` 0.3.2, resolving `serde_json`
1.0.151 and `ryu-js` 1.0.3. Every row is a committed test in
[`tests/incumbent_differential.rs`](../tests/incumbent_differential.rs), so it goes red the day
any of it stops being true.

| input | `serde_json_canonicalizer` | this crate |
|---|---|---|
| `{"a":1,"a":2}` | `{"a":2}` through `pipe`; `{"a":1}` straight into its serializer | `Error::DuplicateMember` |
| 129 nested arrays | accepted by `to_vec`; 10,000 aborts the process | `Error::TooDeep` |
| `9007199254740993` | `9007199254740992`, a different integer, no error | `Error::UnsafeInteger` under `admit_ijson` only; `admit` returns the same rewritten integer the delegate does |
| 12 MB of array | accepted | `Error::TooLarge` |
| `ED A0 80` in the bytes | cannot be offered: `pipe` takes `&str` | `Error::StringNotScalar` |

Read the third row in both directions. Its right-hand cell says `admit_ijson`, and it means
it: the RFC 8785 default admits `9007199254740993` and canonicalizes it to
`9007199254740992`, exactly as the delegate does.

Section 3.2.2.3 of the RFC defers number formatting to ECMAScript, and ECMAScript has one
numeric type. So that row is a statement about a profile you opt into, not about the default.

The cell said only `Error::UnsafeInteger` until an adversarial pass ran `admit` on that
token. The default cannot change without failing the specification the crate implements,
because the RFC's own reference vectors carry `1e30`. What changed is that the claim now
names the function that makes it, and the test file pins both halves.

Read the first row twice as well. One document, one crate, **two canonical forms** depending
on which entry point you used, and a signature over either one verifies. That is a split
view without an attacker needing two implementations.

The second row is the one that takes a service down. The delegate's depth bound exists on
exactly one of its four public entry points, because that one borrows `serde_json`'s
deserializer.

`to_vec`, `to_string` and `to_writer` have no parser and no bound. A deep enough value ends
the process with `fatal runtime error: stack overflow`: an abort, not an `Err`, and it
happens before any signature is checked.

## What it refuses

- A repeated object member, compared on the *decoded* name, so `"a"` and `"a"` are one
  member.
- Nesting past a cap. The default is 128, the value the in-toto attestation specification
  carries as normative text. You can raise it to 512 and no further, because a cap above the
  stack is not a cap.
- A string whose bytes are not Unicode scalar values: an unpaired surrogate escape, a
  surrogate written directly in UTF-8, an overlong form, a raw control character. Checked
  before any decode, because a decoder that substitutes U+FFFD leaves `"\ud800"`, `"\udc00"`
  and a literal U+FFFD canonicalizing to identical bytes. To confirm that, delete the check
  and watch it happen.
- A number with no finite double, and under the opt-in RFC 7493 profile an integer at or
  above 2^53 or a Unicode noncharacter.
- An input past a size cap. A depth cap bounds the stack; a size cap bounds the heap.

Every refusal is a named variant carrying a byte offset, so a verifier can route on the
fault. The delegate reports what it does refuse as one untyped `serde_json::Error`, which
cannot tell a split-view document from a typo.

## What it delegates

Number output. Section 3.2.2.3 of the RFC defers to ECMAScript `Number::toString`.

`serde_json_canonicalizer` implements that over `ryu_js`, and it reads the RFC's own awkward
reference number `333333333.33333329` correctly.

A third implementation of that algorithm would add a way for two rails to disagree and
nothing else. This crate depends on that implementation being right rather than
reproducing it.

## Evidence

`cargo test` runs 67 tests over the 15 targets in `tests/`. The byte-identity suites load
pinned vectors produced by an independent Go implementation, never by this crate:

- 30 cross-rail canonical forms with 9 refusals
- 317 enumerated adversarial string, name and member cases
- 26 RFC 8785 Appendix B rows
- 850 ECMAScript round-to-even tie rows read off node v24.19.0
- the 6-document RFC reference suite

Provenance and commit hashes for all of it are in
[`tests/vectors/PROVENANCE.md`](../tests/vectors/PROVENANCE.md).

Every refusal is red-green-mutated: 17 mutations of the implementation, each caught. The
record, including the three test gaps the mutation sweep found and closed, is in
[`docs/MUTATION-SWEEP.md`](MUTATION-SWEEP.md).

The measurements behind every claim this file makes about the delegate are in
[`docs/INCUMBENT-MEASUREMENT.md`](INCUMBENT-MEASUREMENT.md).
