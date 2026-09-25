# Conformance vectors (ai-agent-action v0.1)

Every member of this suite, accepted and rejected alike, in one table.
Ground truth: in-toto/attestation#588, `spec/predicates/ai-agent-action.md`
at `a5dd509`, type URI
`https://in-toto.io/attestation/ai-agent-action/v0.1`.

**What a row reading `invalid` rests on.** The `basis` column names it: the
lines of the vendored specification that make the member rejectable, whose
quotation `aee-verify` finds in those lines on every run. Every reject member
rests on #588's own text except the one whose basis reads `proposal`, the
member-name ordering member under `aia-c-15`. It rests on the BMP-only rule
this project offers into the pull request
(`../docs/ai-agent-action-canonicalization.md`), and #588 at lines 611-612 and
624-625 reads the other way: a well-formed supplementary-plane character is
admissible in member-name position, and a verifier that rejects one is
over-rejecting. A verifier conforming to #588 alone accepts that member.

The commit is fetchable today as the head of `refs/pull/588/head` in
`in-toto/attestation` and of `add-ai-agent-action-predicate` on the fork
`elang2/attestation`. That branch has been rewritten before, so the commit is
provenance and not the pin: `../spec-vendored/` carries the text itself,
`MANIFEST.json` pins its sha256 as `specDigest`, and `aee-verify` recomputes
that digest on every run and refuses a copy whose bytes moved.

That type URI does not resolve. The in-toto attestation catalog redirects
the URIs of vetted predicates whose specification is merged, and this
predicate is in review as the pull request named above, so a request for
the URI returns 404. The URI identifies the predicate type, and
dereferencing it is not part of verifying any vector here.

Every file is a complete in-toto Statement. A member whose claim is about
the hash chain carries a sidecar in `../records/<id>.jsonl`, the log lines
the chain hash is computed over, because that preimage is the underlying
gateway record rather than the Statement.

Regenerate byte-identically: `python3 ../gen_vectors.py`.
Self-check: `aee-verify vectors-ai-agent-action/` from the repository root.

## Chain breaks and profiles

`aia-c-17`, `aia-c-18` and `aia-c-19` hold the root rule of #588 lines 766-794
from each side: a segment rooted at a chain_break with `priorHead: null` is
identified by the break record's own chain hash, a break whose prior head is
known is not a root, and a deployment claiming resistance against a
compromised attestor forbids `priorHead: null` (lines 1271-1274). A row whose
`profile` column is not empty holds under that profile only; `MANIFEST.json`
defines both profiles under `profiles` and cites the lines each comes from.
The `aia-c-17` reject members carry `PARENT_HASH`, the genesis identifier the
`aia-c-1` accept member declares, standing for the chain an unrecoverable
crash abandoned; `aee-verify` checks that the identifier they claim is a
genesis identifier of a chain this corpus carries.

## What an accept member claims

These bytes are valid under #588 at `a5dd509`, and where the member declares
a `chainHash` that value recomputes from the last line of its sidecar. Where
it declares a `chainRoot`, that is the chain hash of its first sidecar record,
the record is a genesis record or a chain_break with `priorHead: null`, and
the member carries it as its subject digest.

Every reject condition has an accepting member carrying the same condition id
under the same profile. That pairing is enforced rather than
intended: `aee-verify` fails when a reject condition has no accepting
twin, because a corpus of rejections alone gives full marks to a verifier
that rejects everything, which is the one verifier that certifies nothing.

Three members exist only to hold a boundary from the admissible side:
the `aia-c-13` accept member carries a valid surrogate pair in a VALUE, which the string rule
permits and an over-eager verifier rejects alongside the unpaired half;
the `aia-c-14` accept member carries 2^53 - 1, the largest value the
safe-integer bound admits; and the `aia-c-15` accept member carries extension
member NAMES inside the BMP, where UTF-16 code-unit order and code-point order
agree.

The `aia-c-13` and `aia-c-15` accept members are the two halves of one
distinction under the proposed text. A supplementary-plane character is well
formed everywhere and is admissible in value position; the proposed BMP-only
rule makes it inadmissible in member-name position, because that is the only
position JCS sorts, and the `aia-c-15` reject member is the one this corpus
rests on the proposal rather than on #588.

The `appendix-b` family carries RFC 8785 Appendix B, Table 1: every row of it
that has a JSON representation, one vector each. They share `aia-c-16` and
they are the only members here whose claim is about how a number is written
rather than about a chain, a string or a bound.

They are shaped by the `aia-c-9` accept member. #588 draws the float boundary
by where the bytes live: a record or a Statement admits no non-integer
number, and a payload behind its content digest may carry one, so that is
where the number lives. Each statement therefore
carries the digest of the canonical payload and names its own bit pattern in
`toolName`, while `MANIFEST.json` carries the IEEE input as `ieee754` and the
text it must serialize to as `canonicalNumber`. Those two fields are where a
reader checks the row against the RFC.

Appendix B rows 1 and 2 are the two IEEE patterns that share one JSON
representation, and their payload digests are equal by construction. Minus
zero serializing to `0` is the lossy step, and it is the row real
implementations disagree on. `aee-verify` recomputes each row from the
declared text rather than from the generator's serializer, so a generator
that agreed only with itself would not pass.

## Vectors

Vectors are named after their own bytes and live together in
`statements/`, so neither the identifier nor the path says whether a
member is meant to be accepted. That is deliberate: an identifier
carrying the answer lets a rail score the suite without reading it. The
verdict is in `MANIFEST.json` and in the `kind` column below, which is
where a scoring harness is supposed to look for it.

| vector | kind | conditions | profile | expected | basis | exercises |
|---|---|---|---|---|---|---|
| `v0fbb0059f0813e81` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 20. The IEEE 754 double 41b3de4355555555 is the JSON number 333333333.3333333, and no other text. |
| `v19200ece1a40066b` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 8. The IEEE 754 double c340000000000000 is the JSON number -9007199254740992, and no other text. Max neg int. |
| `v1aa63bb62de9b357` | accept | aia-c-11 | - | valid | - | chain shape: previousHash is lowercase 64-hex or the literal genesis |
| `v27af706aa6237b7a` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 5. The IEEE 754 double 7fefffffffffffff is the JSON number 1.7976931348623157e+308, and no other text. Max pos number. |
| `v2d317372d8b62a5b` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 19. The IEEE 754 double 41b3de4355555554 is the JSON number 333333333.33333325, and no other text. |
| `v362600d69975d14c` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 9. The IEEE 754 double 4430000000000000 is the JSON number 295147905179352830000, and no other text. ~2**68. |
| `v3e30ec52a2e1f716` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 18. The IEEE 754 double 41b3de4355555553 is the JSON number 333333333.3333332, and no other text. |
| `v401b49d063fe0a5e` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 6. The IEEE 754 double ffefffffffffffff is the JSON number -1.7976931348623157e+308, and no other text. Max neg number. |
| `v43175cd2ad003639` | accept | aia-c-12 | - | valid | - | bounds: 128 is admissible; the counting rule is #570's |
| `v4c882a9f1bbeb7f0` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 3. The IEEE 754 double 0000000000000001 is the JSON number 5e-324, and no other text. Min pos number. |
| `v663dae0ae9cfda97` | accept | aia-c-5 | - | valid | - | canonicalization: I-JSON, no duplicate member at any depth |
| `v6d21ff18cfa69ef8` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 15. The IEEE 754 double 444b1ae4d6e2ef50 is the JSON number 1e+21, and no other text. |
| `v726e35aa6179f8d9` | accept | aia-c-6, aia-c-7 | - | valid | - | chain shape: exactly one record carries any given previousHash |
| `v7460b093ad19f68d` | accept | aia-c-14 | - | valid | - | bounds: 2^53 - 1 is admissible, so the boundary is exercised from both sides rather than assumed |
| `v791c2a09aa3a06bc` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 4. The IEEE 754 double 8000000000000001 is the JSON number -5e-324, and no other text. Min neg number. |
| `v7d0402b3c091526e` | accept | aia-c-9 | - | valid | - | canonicalization: the float boundary is where the bytes live. A payload behind its content digest may carry floats; a record or a Statement may not |
| `v7d78f7f696236714` | accept | aia-c-3 | - | valid | - | canonicalization: JCS emits the character, never a \u escape |
| `v7fe454a506f992b2` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 1. The IEEE 754 double 0000000000000000 is the JSON number 0, and no other text. Zero. |
| `v843566cf72cd33c3` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 10. The IEEE 754 double 44b52d02c7e14af5 is the JSON number 9.999999999999997e+22, and no other text. |
| `v886b10508ab8ba51` | accept | aia-c-13 | - | valid | - | strings: the rule excludes an unpaired half, never a valid supplementary-plane character, so a verifier that rejects both is over-rejecting |
| `v904d162069c03d18` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 7. The IEEE 754 double 4340000000000000 is the JSON number 9007199254740992, and no other text. Max pos int. |
| `v9a8b364b8bc121de` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 2. The IEEE 754 double 8000000000000000 is the JSON number 0, and no other text. Minus zero. |
| `v9b57de6db73c1f29` | accept | aia-c-17 | default | valid | - | chain breaks: a segment rooted at a chain_break with priorHead null is identified by the break record's own chain hash, and its successor carries that hash as its subject digest |
| `va1ecbadeabba7b77` | accept | aia-c-4 | - | valid | - | canonicalization: the log line IS the canonical bytes, so the two readings of the preimage coincide |
| `vaa33c34f7bd1058b` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 13. The IEEE 754 double 444b1ae4d6e2ef4e is the JSON number 999999999999999700000, and no other text. |
| `vad17f7bf034c8dde` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 11. The IEEE 754 double 44b52d02c7e14af6 is the JSON number 1e+23, and no other text. |
| `vaec7f1c565e1a91a` | accept | aia-c-19 | - | valid | - | chain breaks: a break with a known prior head does not root a chain, so the successor chains from the break and still carries the genesis record's chain hash as its subject digest |
| `vaf1b67f038ffff84` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 17. The IEEE 754 double 3eb0c6f7a0b5ed8d is the JSON number 0.000001, and no other text. |
| `vb177ef3b3a945a72` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 14. The IEEE 754 double 444b1ae4d6e2ef4f is the JSON number 999999999999999900000, and no other text. |
| `vb7dd5fb8dcb6e345` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 12. The IEEE 754 double 44b52d02c7e14af7 is the JSON number 1.0000000000000001e+23, and no other text. |
| `vbd5d1d64de299ed7` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 21. The IEEE 754 double 41b3de4355555556 is the JSON number 333333333.3333334, and no other text. |
| `vc79800639733ed68` | accept | aia-c-8 | - | valid | - | chain shape: every record type links through predicate.chain |
| `vced2927f55260ad1` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 24. The IEEE 754 double 43143ff3c1cb0959 is the JSON number 1424953923781206.2, and no other text. Round to even. |
| `vd2659c36ece7eb47` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 23. The IEEE 754 double becbf647612f3696 is the JSON number -0.0000033333333333333333, and no other text. |
| `vd473932a82fd8779` | accept | aia-c-15 | - | valid | - | strings: extension member names inside the BMP sort the same way under UTF-16 code units and under code points, so the record has one canonical form and one chain hash |
| `vdd8899ebf08f5040` | accept | aia-c-10 | - | valid | - | content digest: a failed call digests the error member, named explicitly rather than left to the reader |
| `ve49e9dafdd7f4df9` | accept | aia-c-17 | default | valid | - | chain breaks: the break record's own Statement is in the segment it roots, so it carries its own chain hash, and it carries no predicate.chain because the prior head is unrecoverable |
| `ve78d80f4d7221cd9` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 22. The IEEE 754 double 41b3de4355555557 is the JSON number 333333333.33333343, and no other text. |
| `ve8b9155afcbd8224` | accept | aia-c-1, aia-c-2 | - | valid | - | canonicalization: member ordering is JCS, never the host language's property order |
| `vf2f6991c55096b1a` | accept | aia-c-16 | - | valid | - | number serialization: RFC 8785 Appendix B row 16. The IEEE 754 double 3eb0c6f7a0b5ed8c is the JSON number 9.999999999999997e-7, and no other text. |
| `vf89ec86066d8cf9b` | accept | aia-c-18 | compromised-attestor-resistant | valid | - | planted break: the prohibition forbids an unrecoverable prior head, not a break. A break whose priorHead is the chain hash of the record before it, and whose predicate.chain carries the same value, is accepted under that profile |
| `v0805461f7a5c9a1f` | reject | aia-c-10 | - | invalid / content-digest-mismatch | #588 434-442 | A8: one of four readings a verifier could take of an absent result member, and the only one this suite forbids by naming the other |
| `v0f4f2093061d303f` | reject | aia-c-5 | - | invalid / duplicate-member | #588 604-609 | A4: a first-wins reader displays read_file while the hash commits to delete_repository |
| `v26230ff87959bda5` | reject | aia-c-1 | - | invalid / chain-hash-mismatch | #588 379-383, 387-391, 400-409 | A1: JSON.stringify orders 2 before 10 and leaves zz before aa; JCS orders 10, 2, aa, zz. Three languages, three chain hashes. |
| `v4d02dbb1731f4972` | reject | aia-c-11 | - | invalid / previoushash-not-canonical | #588 685-692 | A9b: 40 hex digits. Nothing in the current text excludes a digest from another algorithm |
| `v5e1aca8594076334` | reject | aia-c-17 | default | invalid / break-rooted-foreign-identifier | #588 784-790 | chain breaks: the successor claims the identifier of the chain the crash abandoned. The attestor holds no truthful value for it, and carrying it would let a break-rooted segment pass for the complete history of the session |
| `v679f56481420e45a` | reject | aia-c-14 | - | invalid / unsafe-integer | #588 1320-1323 | bounds: 2^53 + 1, the first value the I-JSON profile excludes |
| `v79fbd4b605a4d914` | reject | aia-c-4 | - | invalid / noncanonical-bytes | #588 387-391 | A3: the record parses identically and hashes differently; any log shipper that reserializes produces this |
| `v861f20f3fa63ce2b` | reject | aia-c-6 | - | invalid / chain-fork | #588 700-704 | A5: two records carry one previousHash. Every hash verifies, the genesis hash and therefore the subject digest are unchanged, and the presenter chooses which branch the auditor sees. |
| `v86bb8bc8908fea42` | reject | aia-c-13 | - | invalid / ill-formed-string | #588 611-615 | F2: already forbidden by #588's own text. The vector is what stops the rule from being advice |
| `v925e6daf8ac78ef3` | reject | aia-c-3 | - | invalid / chain-hash-mismatch | #588 411-415 | A2: a producer whose serializer defaults to ASCII escaping emits different bytes for the same string |
| `v95fcded705b036d0` | reject | aia-c-18 | compromised-attestor-resistant | invalid / null-priorhead-forbidden | #588 1271-1274 | planted break: under a profile claiming resistance against a compromised attestor, a chain_break with priorHead null is rejected however well formed it is, because every field on it is one the restarted attestor controls |
| `v97f5d8777e514257` | reject | aia-c-9 | - | invalid / non-integer-in-signed-field | #588 384-387, 461-466 | A7: a float inside the record itself. The record canonical form admits no non-integer number, whatever the content digests bind; the content-digest form is where a float belongs |
| `v9bcf0d6fd251418f` | reject | aia-c-11 | - | invalid / previoushash-not-canonical | #588 685-692 | A9: a case-normalizing verifier links it and a byte-comparing one does not, so the same logical link has two spellings |
| `v9cc43bcbf367a00e` | reject | aia-c-3 | - | invalid / chain-hash-mismatch | #588 411-415 | A2b: Go's encoding/json escapes <, > and & by default, so a Go gateway and a Node gateway disagree on identical input |
| `vb1262555f2fd8afe` | reject | aia-c-19 | - | invalid / subject-not-chain-root | #588 771-773 | chain breaks: the successor re-roots its identifier at a break whose prior head is known. Only a genesis record or a break with priorHead null roots a chain, so one session now carries two identifiers |
| `vb1f091f42efd0715` | reject | aia-c-15 | - | invalid / non-bmp-member-name | proposal | strings: U+1F680 is encoded UTF-16 as D83D DE80, so it sorts before U+FF3A by code unit and after it by code point. The record is well formed and every field is untouched; it has two canonical byte strings and therefore two chain hashes, so the successor's previousHash and the chain's subject digest both fork. |
| `vc4898200910d84a2` | reject | aia-c-7 | - | invalid / duplicate-genesis | #588 775-779, 796-797 | F3: the successor of a break restarts at genesis instead of chaining from the break, discarding the scar. Detection is a MUST, not a SHOULD |
| `vc6a1b1b8e0388411` | reject | aia-c-17 | default | invalid / break-rooted-foreign-identifier | #588 784-790 | chain breaks: the break record's own Statement claims the abandoned chain's identifier, which the rule forbids for every statement in the segment, the break's own included |
| `vd94ac70c9f0d84bf` | reject | aia-c-12 | - | invalid / depth-exceeded | #588 602, 627-629 | bounds: one level past the stated cap, so the counting rule is exercised rather than assumed |
| `ve763abe0a98c932f` | reject | aia-c-8 | - | invalid / checkpoint-not-linked | #588 719-722 | A6: the successor chains past the checkpoint to the record before it, so the checkpoint is deletable and the anti-truncation mechanism carries no weight |
