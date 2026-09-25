# AI generation predicate v0.1 conformance suite

Conformance vectors for the generation predicate
`https://open-fab.ai/attestation/generation/v0.1`, an in-toto predicate that
records how an artifact was produced by an AI pipeline: per-range AI-or-human
attribution, the model, a prompt fingerprint, the embedded acceptance contract
and human sign-offs. The predicate is under discussion for adoption at
`ossf/tac#628`.

The suite tests a verifier in the predicate's default **attest-only** mode:
recompute the artifact digests, verify the ed25519 signatures over the
canonical statement, and read attribution from the predicate without executing
anything.

## What it certifies against

Specification revision 0.1.3, vendored unchanged from `Open-fab-ai/openfab` at
commit `f558da05aae82a7d98f18287f2bcc17e2f1d8aee`, with the JSON Schema and the
licence from the same commit, under `spec-vendored/`. `MANIFEST.json` pins each
file by sha256 and `aee-verify` refuses a copy whose bytes moved.

The golden member is the upstream repository's own golden conformance vector,
the statement its test `canonical_encoding_golden_vector` pins by length and
sha256. The generator transcribes it and refuses to write anything unless the
transcription reproduces the pinned hash. The base attestation is that golden
statement with real artifact digests, signed with a fixed test key; every other
member is one change to it, and a refused member names the member it was
changed from in its `parent` field.

## Three kinds of member

- **accept** and **reject** are required by revision 0.1.3 as written. A reject
  member cites the clause it breaks and names the code a verifier refuses it
  with. An accept member is valid under the revision and under the proposal
  below.
- **proposed** members depend on text the revision does not yet carry. Each
  declares two outcomes: what revision 0.1.3 as written says of it, and what
  the proposal in `../docs/proposals/ai-generation-v01-findings.md` says. A
  verifier is never failed on a proposed member; the pair of outcomes is what
  the member shows. They cover sign-off coverage, forged sign-off records,
  sign-offs by one key under two names, overlapping attribution ranges, the
  `Assisted-by:` trailer cross-check, member order outside the Basic
  Multilingual Plane, unsafe integers and duplicate member names.

Counts are in `INDEX.md` and `MANIFEST.json`, both written by the generator.

## Readings this suite has to state

The revision leaves two things open that a digest cannot be computed without,
and this suite states its reading of each rather than leaving it implicit:

- A generated range's `sha256` is the digest of exactly the lines the range
  names, each with its LF terminator. The subject's digest is over the whole
  artifact file. The artifacts are under `artifacts/`.
- A proposed member's sign-off signatures follow the proposal: the fab
  signature and `payload_sha256` cover the statement without `signoffs`, and
  the n-th sign-off covers the first n records, its own included.

One case this suite does not build: a prompt fingerprint checked against the
recorded model, because the predicate deliberately omits the prompt text and no
rule relates `prompt_sha256` to the model, so no verifier can check it from the
attestation.

## Keys

Every signature is by a published test key derived from a fixed seed, listed
in `MANIFEST.json` under `keys` with the derivation in `keyNote`. They sign
nothing outside this directory.

## Regenerate and check

```bash
uv run --extra generators python vectors-ai-generation/gen_vectors.py
uv run --extra generators python vectors-ai-generation/gen_vectors.py --check
go run ./cmd/aee-verify vectors-ai-generation
```

The corpus digest routine is `digest.py`, which imports only the standard
library, so a reader who installed nothing can recompute it.

## Licence of the vendored text

The files under `spec-vendored/` are the upstream project's, under the Apache
License 2.0 carried beside them as `spec-vendored/LICENSE-f558da05`.
