# SCITT/COSE carriage conformance suite

What this corpus tests is the CARRIAGE, not the predicate. `vectors/` already
tests what an adversarial-execution-evidence statement must say. These vectors
test whether the COSE_Sign1 around it, the CWT claims inside its protected
header, and the RFC 9942 Receipt in its unprotected header hold together well
enough that a party who trusts neither the agent nor its operator can check the
thing offline.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

`../profiles/scitt-cose.md` is the profile these vectors enforce. Read it first;
every requirement here resolves to a section of it, and every section of it
resolves to a section of a published document.

## The gap this fills

RFC 9943 Section 6 says of Signed Statements: "Profiles and
implementation-specific choices should be used to determine admissibility of
conforming messages. This specification is left intentionally open to allow
implementations to make Registration restrictions that make the most sense for
their operational use cases."

Two implementations can therefore both conform to RFC 9943 and disagree about
every question this corpus asks. The architecture fixes the mandatory labels and
hands admissibility to a profile, and for execution evidence no profile existed.

## Identifiers name the bytes, not the answer

Every member is named after a digest of its own bytes and lives flat in
`statements/`. There is no `accept/` directory, no `reject/` directory, and no
prefix that says which. What a verifier must reach lives in `MANIFEST.json`,
which is where a scoring harness reads it: `expected.verdict` for an accept or
reject member, and for an indeterminate member the `readings` it lists, any one of
which conforms, with no `expected.verdict` at all. The layout is inherited from
the sibling corpus for the reason recorded there: a directory or a prefix that
names the verdict lets a rail certify against the suite without opening a single
statement.

## What a vector file is

One JSON object carrying the inputs and no answer:

- `transparentStatement`, hex. The complete RFC 9943 Section 7 Transparent
  Statement, tagged COSE_Sign1, receipts in label 394 of its unprotected header.
- `detachedPayload`, hex or null. The statement payload where the wire form
  detaches it, which a verifier must reattach before checking the signature.
- `verificationTime`. Fixed, so `exp` and `nbf` members mean the same thing on
  every machine and in every year. A vector whose verdict depended on a wall
  clock would change answer without changing bytes.
- `trust`. The issuer identity bound to its verification key, and the
  transparency-service keys. RFC 9943 Section 7.1 requires a Relying Party to
  trust "the verification key or certificate and the associated identity of at
  least one Issuer of a Receipt", so a corpus that supplied keys and no
  identities could not express an issuer mismatch at all.

## Running it

```
uv run --extra generators python vectors-scitt-cose/gen_vectors.py
uv run --extra generators python vectors-scitt-cose/check_vectors.py
```

The generator rebuilds every member byte-identically and deletes any statement
file it did not write this run. The checker re-derives each claim from the bytes
rather than reading it back out of the manifest: it recomputes every Merkle root
from RFC 9162 Section 2.1.3.2 independently of the tree code that built it,
verifies every signature, and confirms that each reject member carries the
specific fault it names.

## Why Ed25519 and why the identifier is -19

`scripts/regenerability-gate.py` rebuilds this corpus into a scratch tree and
diffs it, so a member has to come out byte-identical on every machine. ECDSA
draws a fresh nonce per signature, so an ES256 corpus would differ on every run.
Ed25519 signatures are deterministic (RFC 8032) and the keys here come from
fixed seeds.

The identifier is -19, the fully-specified Ed25519 registration of RFC 9864
Section 4.2.1 ("Name: Ed25519, Value: -19, Recommended: Yes"). RFC 9864
Section 4.2.2 has IANA update both -8 (EdDSA) and -7 (ES256) to "Recommended:
Deprecated". Every worked example in RFC 9943 and RFC 9942 carries `1: -7`, so
the published examples of the architecture this profile targets are all on a
deprecated identifier. Two reject members carry the deprecated identifiers so
that refusing them is a testable property rather than an assertion.

pycose 1.1.0 ships no -19. Both scripts register it through the library's own
`@CoseAlgorithm.register_attribute()` extension point, reusing EdDSA's sign and
verify. The library still builds every Sig_structure and does all the CBOR.

Two members are assembled at the Sig_structure level instead, and that is the
point rather than a shortcut: a COSE library honours its own protected header,
so it cannot mint an object whose declared algorithm differs from the one that
signed it. That object is exactly what an algorithm-confusion vector needs, and
`sign1_declaring` and `receipt_declaring` build it from RFC 9052 Section 4.4
directly.

## The pin on cbor2, which is load-bearing

`cbor2` is pinned below 6. pycose 1.1.0 reads a decoded CBOR tag's value as a
list; cbor2 6.0.0 returns a tuple, and every well-formed vector then fails to
decode with "Bytes cannot be decoded as COSE message". That message reads like a
corrupt corpus and is a library incompatibility, which is why the pin carries
its reason in `pyproject.toml` rather than sitting there as a bare bound.

## Open work

- **No media type is registered.** The protected content type is
  `application/x.aee-scitt-cose-statement+cose`, in the unregistered tree RFC
  6838 Section 3.4 reserves with the `x.` prefix, because this profile has
  registered nothing. Until a registration exists, nothing makes two conforming
  producers choose the same value, and a transparency service that dispatches
  policy on content type will treat them as different formats. One indeterminate
  member records exactly that fork.
- **The observer position sits at a Private Use label.** COSE header parameters
  below -65536 are Private Use, so the field needs no IANA action and cannot
  collide with a future registration. A real allocation is a later step and it
  changes the bytes of every member.
- **Consistency proofs are carried and not required.** RFC 9942 registers proof
  type -2 and this profile requires only -1. What a relying party concludes from
  a Transparent Statement whose only receipt is a consistency receipt is one of
  the four questions the indeterminate members record rather than answer.
