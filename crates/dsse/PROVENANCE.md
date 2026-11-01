# Provenance

What in this repository came from somewhere else, and at which commit.

## Specification text

The normative rules this crate implements are read from DSSE's own specification
text, not from a description of it. Each rule below names the file it is read from,
inside one pinned clone:

```text
github.com/secure-systems-lab/dsse
  commit    851704a287847d8dcaf7ae1ca76ce9169511ee88 (merge of PR #77, 2025-11-10)
  version   1.0.2, dated 2024-05-10
  clone     ~/Documents/git-clones/dsse

  protocol.md                     the PAE rule, the signature definition, the
                                  verification order, the multi-signature (t, n)
                                  rule, and the worked test vector
  envelope.md                     the JSON envelope shape and its parsing rules
  envelope.proto                  signatures is REQUIRED, with length at least 1
  implementation/signing_spec.py  the reference implementation, read for the base64
                                  fallback order and the doctest envelope.
                                  Apache-2.0, Google LLC

  quoted in                       src/pae.rs, tests/spec_vector.rs
```

Reading that reference implementation is also what backs the README's claim that it
allows four of the six things this crate refuses. Four readings, each in one function:

```text
PAE       takes len(payloadType) on a Python string, which counts characters
b64dec    accepts non-canonical trailing bits
Verify    appends one name per verifying entry, so a caller counting the result
          counts entries rather than keys
Verify    skips a verifier whose identifier does not match the envelope's
          unauthenticated hint
```

It does refuse an envelope whose signature list is empty, and it has no threshold
parameter to set to zero.

## Test vectors

```text
file         vectors/cross_lang_signing.json
bytes        19671
sha256       f5f6c8e991ecb452d73b6289eef8632666dbb50c7f1ef25827b28e869e16152c
written by   vectors/generate (go run . > ../cross_lang_signing.json)
using        github.com/secure-systems-lab/go-securesystemslib/dsse v0.11.1,
             the DSSE reference Go implementation, Apache-2.0
Go           go1.25.5, pinned in CI
```

Eleven fixtures across five payload types. Each carries the signed body, the PAE
pre-image the reference implementation built, an ed25519 signature over it, and
the whole envelope that implementation emitted. The key is a published test key:
its seed is SHA-256 of the label in the file's `key_label` member, and the file
records the seed so the suite can check that this crate's signer reproduces the
reference signatures. ed25519 is deterministic, so a rerun of the generator
writes the same bytes, and CI fails if it does not.

The payloads are neutral by construction: in-toto Statements naming `example.com`
subjects, flat event records using the RFC 5737 documentation address
`203.0.113.9`, a text body, an empty body, a body over 1000 bytes, a 40-byte binary
root that is not valid UTF-8, and a payload type whose UTF-8 encoding is longer
than its character count.

Version 0.1.1 replaces the fixture file that 0.1.0 shipped, and 0.1.0 is yanked.

## Ported logic

The PAE implementation follows an earlier Go implementation by the same author:
the same decimal length, the same injectivity argument, and the same
CVE-2022-35929 reasoning for putting the payload type inside the signed bytes. A
second implementation of the same rule was read as a cross-check:
`aee/pae.go` in github.com/probityai/agent-evidence-vectors.

Four test ideas are ported from that earlier suite: the specification vector, the
empty body, injectivity across the type and body boundary, and domain separation
between payload types. The multi-byte length-prefix cases, the base64 malleability
cases, the duplicate-signature threshold case and the key-hint denial cases are new
here.

## What the shipped files may not contain

`tests/no_private_names.rs` walks every file the crate ships, decodes every JSON
string, base64 run, hex run and percent-encoding in it, and compares each token by
SHA-256 against a refused list supplied as digests from outside the repository.
CI runs it over the source tree and again over the unpacked `.crate` that
`cargo package` builds. A control plants a canary through each encoding and fails
if the scanner misses one.

## Licences

secure-systems-lab/dsse is Apache-2.0, Google LLC and the DSSE maintainers, an
organisation rather than an individual. Contact is MAINTAINERS.md in that repository.
The ported PAE logic and the generator are ours; the pre-images and envelopes in the
vector file are the output of secure-systems-lab/go-securesystemslib, Apache-2.0,
which the generator uses and the published crate does not ship.

```text
base64, serde, serde_json, thiserror   MIT OR Apache-2.0
ed25519-dalek                          BSD-3-Clause, dalek-cryptography
sha2 (tests only)                      MIT OR Apache-2.0
```
