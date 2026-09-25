# Conformance vectors (signed decision receipts)

Every member of this suite in one table. The subject under test is a verifier of
signed decision receipts in the envelope shape of `draft-farley-acta-signed-receipts-03`, vendored at
`spec-vendored/draft-farley-acta-signed-receipts-03.txt` and pinned by digest in the manifest.

This corpus is 13 vectors, of which 6 a conformant verifier must not
fail closed on and 4 it must reject. The remaining members test a SHOULD and
are graded as the README describes.

Each member is judged twice: with `keys/jwks.json` and with
`keys/jwks-no-window.json`, the same keys without their validity windows. The
verifier contract is in `README.md`.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-receipt-signature/` from the repository root.

## Requirements

| id | section | level | sentence |
|---|---|---|---|
| `RS-R-001` | 6.6 | MUST | The signature MUST cover the canonical JCS bytes of the _signing input_ directly |
| `RS-R-002` | 9.2 | SHOULD | Verifiers SHOULD check key validity windows when available. |
| `RS-R-003` | 6.6 | MUST | implementations MUST NOT pre-hash the canonical bytes (for example with SHA-256) before signing. |
| `RS-R-004` | 6.6 | MUST | An implementation MUST determine the shape before computing the signing input, and MUST NOT apply one shape's rule to the other |
| `RS-R-005` | 6.6 | MUST | In either shape the object canonicalized MUST NOT contain a signature member, and that member MUST NOT be included as null or as the empty string |

## Conditions

| id | what it requires | requirements |
|---|---|---|
| `rs-c-1` | The signature is computed over JCS(payload), and a verifier recomputes that byte string rather than trusting the bytes the payload arrived in. | RS-R-001 |
| `rs-c-2` | A receipt whose issued_at falls outside its key's validity window, as the external key set publishes it, is not reported valid by a verifier that applies the window. | RS-R-002 |
| `rs-c-3` | The window includes valid_from and excludes valid_until, as RFC 7519 treats nbf and exp. Section 9.2 of the vendored text does not fix the boundary. | RS-R-002 |
| `rs-c-4` | The canonical bytes are the message given to Ed25519, with no intermediate hash, so a signature over their SHA-256 digest does not verify. | RS-R-001, RS-R-003 |
| `rs-c-5` | An envelope receipt is verified under the envelope rule. A signature made under the flat rule, over the receipt with its signature member removed, does not verify as an envelope. | RS-R-004 |
| `rs-c-6` | A payload that carries a signature member, null included, is refused even though a signature over its canonical bytes verifies. | RS-R-005 |

## Vectors

| id | kind | conditions | with windows | without windows | if the SHOULD is not honoured |
|---|---|---|---|---|---|
| `v03377fbbac6d12f8` | accept | rs-c-6 | valid | valid |  |
| `v0340fed8ef07e072` | reject | rs-c-4 | invalid `signature_invalid` | invalid `signature_invalid` |  |
| `v1adc0db0267a742b` | reject | rs-c-5 | invalid `signature_invalid` | invalid `signature_invalid` |  |
| `v4ec9fa36ae77ce07` | indeterminate | rs-c-2 | invalid `key_outside_validity_window` | valid | valid |
| `v4f9fe96e52a39bfb` | accept | rs-c-1 | valid | valid |  |
| `v5397adb77c3e6754` | reject | rs-c-6 | invalid `signature_in_signing_input` | invalid `signature_in_signing_input` |  |
| `vaafe541bbd74c320` | accept | rs-c-5 | valid | valid |  |
| `vad088133176d7114` | accept | rs-c-4 | valid | valid |  |
| `vb19450def8dcc5cd` | accept | rs-c-3 | valid | valid |  |
| `vbc25ef71da0567f9` | indeterminate | rs-c-3 | invalid `key_outside_validity_window` | valid | valid |
| `vc4b43c5739979581` | indeterminate | rs-c-2 | invalid `key_outside_validity_window` | valid | valid |
| `ve116653dd041dda0` | reject | rs-c-1 | invalid `signature_invalid` | invalid `signature_invalid` |  |
| `vea8370fb85e1b4b1` | accept | rs-c-2 | valid | valid |  |

## Lifted members

Written by giskard09 and taken from `giskard09/argentum-core` at `541ce84b4f970c1dd3d9e53f2a4562dbbc354e46`,
`examples/conformance/farley-receipt-signature`. The generator reproduces each file and refuses unless its
SHA-256 is the digest recorded upstream.

| upstream file | id |
|---|---|
| `signature-input-drift.reject.json` | `ve116653dd041dda0` |
| `signature-input-drift.conformant.json` | `v4f9fe96e52a39bfb` |
| `superseded-key.reject.json` | `vc4b43c5739979581` |
| `superseded-key.conformant.json` | `vea8370fb85e1b4b1` |
