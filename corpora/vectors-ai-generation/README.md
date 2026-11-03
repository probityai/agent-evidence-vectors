# AI generation predicate v0.1 conformance suite

Conformance vectors for the generation predicate
`https://open-fab.ai/attestation/generation/v0.1`, an in-toto predicate that
records how an artifact was produced by an AI pipeline: per-range AI-or-human
attribution, the model, a prompt fingerprint, the embedded acceptance contract
and human sign-offs. The predicate is under discussion for adoption at
`ossf/tac#628`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The suite tests a verifier in the predicate's default **attest-only** mode:
recompute the artifact digests, verify the ed25519 signatures over the
canonical statement, and read attribution from the predicate without executing
anything.

## What it certifies against

Specification revision 0.1.5, vendored unchanged from `Open-fab-ai/openfab` at
commit `13fd0a8b89399e02dbc9a0322b2c34d3466cbf15`, with the JSON Schema and the
licence from the same commit, under `spec-vendored/`. `MANIFEST.json` pins each
file by sha256 and `aee-verify` refuses a copy whose bytes moved.

Revision 0.1.4 adopted the six findings in
`../docs/proposals/ai-generation-v01-findings.md`: member names ordered by
UTF-16 code units, integers admitted inside the I-JSON safe range, duplicate
member names refused, and the bytes each signature covers once sign-offs exist,
with every sign-off record bound to the key that signed it. The members that
showed those gaps as `proposed` are now required accepts and rejects.

The golden member is the upstream repository's own golden conformance vector,
the statement its test `canonical_encoding_golden_vector` pins by length and
sha256. The generator transcribes it and refuses to write anything unless the
transcription reproduces the pinned hash. The base attestation is that golden
statement with real artifact digests, signed with a fixed test key; every member
the generator builds is one change to it, and a refused member names the member
it was changed from in its `parent` field.

Four accept members were built by someone else: the signed attestations the
upstream repository publishes under `docs/vectors/`, one from its Rust
implementation and one from its browser implementation, each with and without
two sign-offs. They are copied byte for byte into `upstream-vectors/13fd0a8b/`,
their manifest rows carry the upstream path and sha256 under `source`, and the
generator refuses a copy whose bytes moved. Their subject is the digest of the
four bytes `test` and their one generated range is the line `hello`, both under
`artifacts/`.

## Required outcomes

Accept and reject members are graded against revision 0.1.5. Overlapping ranges
for one path and disagreement with supplied Assisted-by trailers are required
rejects. No proposed members remain. The historical findings document preserves
the earlier proposals and records their adoption.

Counts are in `INDEX.md` and `MANIFEST.json`, both written by the generator.

## Readings this suite has to state

The revision leaves one thing open that a digest cannot be computed without,
and this suite states its reading rather than leaving it implicit:

- A generated range's `sha256` is the digest of exactly the lines the range
  names, each with its LF terminator. The subject's digest is over the whole
  artifact file. The artifacts are under `artifacts/`.

One case this suite does not build: a prompt fingerprint checked against the
recorded model, because the predicate deliberately omits the prompt text and no
rule relates `prompt_sha256` to the model, so no verifier can check it from the
attestation.

## Keys

Every signature the generator makes is by a published test key derived from a
fixed seed, listed in `MANIFEST.json` under `keys` with the derivation in
`keyNote`. The four upstream members are signed by the upstream repository's own
published test keys, listed in its `docs/vectors/TEST-KEYS.json`. None of these
keys signs anything that should be trusted.

## Regenerate and check

```bash
uv run --extra generators python vectors-ai-generation/gen_vectors.py
uv run --extra generators python vectors-ai-generation/gen_vectors.py --check
go run ./cmd/aee-verify vectors-ai-generation
```

The corpus digest routine is `digest.py`, which imports only the standard
library, so a reader who installed nothing can recompute it.

## Licence of the vendored text

The files under `spec-vendored/` and `upstream-vectors/` are the upstream
project's, under the Apache License 2.0 carried as
`spec-vendored/LICENSE-13fd0a8b`.
