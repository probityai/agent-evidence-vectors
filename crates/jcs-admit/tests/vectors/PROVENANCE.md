# Where these vectors come from

Nothing in this directory was invented. Each set is copied from a pinned source, and the
source is named so a reader can re-derive it.

## `rfc8785/`

The RFC 8785 reference test suite: six input documents and their canonical forms.

Taken verbatim from `https://github.com/trailofbits/rfc8785.py` at commit
`f1a446e930dcd54228414bd2319b78ccc92be12a` (2026-06-09), files `test/assets/input/*.json` and
`test/assets/output/*.json`. That repository states in turn that they are taken verbatim from
the RFC's own reference implementation, `https://github.com/cyberphone/json-canonicalization`.

`rfc8785/appendix-b.tsv` is Appendix B of the RFC, 26 rows, copied from the RFC's own table:
the IEEE 754 bit pattern, the representation the specification requires, and the RFC's comment.
Two of the appendix's entries are NaN and Infinity, which no JSON number token denotes; the
test exercises those as literals instead of as rows.

License: rfc8785.py is Apache-2.0 (Trail of Bits), and the upstream reference
implementation is Apache-2.0 (Anders Rundgren).

## The cases in `tests/*.rs` that are not files

The nested duplicate-member cases in `tests/duplicate_members.rs`, the two depth-bound cases in
`tests/depth_cap.rs`, and the safe-integer profile cases in `tests/ijson_profile.rs` are copied
from the Go implementation this crate is a port of.

Each of those three files names the Go source it took its cases from, in its own module
comment: `aee/jcs_string_test.go`, `aee/jcs_dos_test.go`, and `TestSafeIntegerProfile` in
`aee/jcs_number_test.go`. All three are in `github.com/astrogilda/agent-evidence-vectors`, at
the `aee/jcs.go` revision `d7689f9445dcb966ac0e4ce6cbc21ae69efeafd1` (2026-08-10).

Where a test case is this crate's own rather than copied, the test says so.

## `cross-rail/`

The differential corpus. `input/` holds conformance vectors copied unmodified from
`vectors/statements/` in `github.com/astrogilda/agent-evidence-vectors`.

`canonical/` holds the canonical form each one takes under THAT repository's Go
implementation: `aee.Canonicalize` in `aee/jcs.go` at revision
`d7689f9445dcb966ac0e4ce6cbc21ae69efeafd1`, run under Go 1.25.5. Nothing in `canonical/` was
produced by this crate.

`refused.tsv` lists the vectors the Go rail refuses, with the error class this crate must
refuse them in and the reason the Go rail gave, verbatim.

What is committed is what a reader can check: 39 input documents, of which 30 carry a pinned
canonical form and 9 are listed in `refused.tsv`. Those counts are the file counts in this
directory, so `ls` settles them.

## `attack/`

`strings-keys-members.tsv` is 317 adversarial documents aimed at strings, member names and
members, enumerated rather than sampled.

The enumeration covers: every C0 control as an escape and again raw, in value and in
member-name position; DEL and the C1 range; each escape whose mandated output differs from the
escape written; surrogate halves alone, mispaired, and in either hex case; surrogates, overlong
forms and truncated sequences encoded directly in the bytes; the Unicode noncharacters in the
BMP and in a supplementary plane; member names differing only by escaping, only by Unicode
normalization form, or only by hex case; the empty name; a name carrying NUL; repeats at the
top level, nested, and inside an array element; and member ordering across the boundary where
UTF-16 code-unit order stops agreeing with UTF-8 byte order.

The inputs are this crate's own. The EXPECTED column is not: it is what `aee.Canonicalize` in
`aee/jcs.go` produced, at the revision named above, under Go 1.25.5. A mistake this crate and
its own test share therefore cannot pass by agreeing with itself.

That rail applies the I-JSON string profile and the integers-only tightening unconditionally,
which is why `tests/attack_strings_keys_members.rs` compares under
`Options::ijson().integers_only(true)`.

A third implementation arbitrated the same corpus independently: the RFC author's own
reference lineage, via `trailofbits/rfc8785.py` at the commit named above. It is a value-level
canonicalizer, so it cannot express the byte-level refusals; over the 178 cases it can express
it agreed byte for byte with both other rails.

License: `agent-evidence-vectors` is Apache-2.0, and the copyright holder is
the same person who holds this crate's.

## `es-number-ties.tsv`

850 rows, one per double whose exact decimal expansion terminates one digit past its shortest
round-tripping form in a 5, which is where step 5 of ECMA-262 7.1.12.1 has a choice to make.
The expected column was read off node v24.19.0.

## Scope

The 39 committed cross-rail vectors and the 317 enumerated attack cases are what this
directory stands behind, and every one of them is on disk beside this file. No larger
randomized or differential corpus is included, so no count from one is quoted here.
