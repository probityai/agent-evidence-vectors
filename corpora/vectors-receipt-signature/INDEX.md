# Conformance vectors (signed decision receipts)

Every member of this suite in one table. The subject under test is a verifier of
signed decision receipts in the envelope shape of `draft-farley-acta-signed-receipts-03`, vendored at
`spec-vendored/draft-farley-acta-signed-receipts-03.txt` and pinned by digest in the manifest.

This corpus is 25 vectors, of which 12 a conformant verifier must not
fail closed on and 8 it must reject. 3 test a SHOULD
and 2 test a question the draft does not decide; both are graded as the README
describes.

Each member is judged twice: with `keys/jwks.json` and with
`keys/jwks-no-window.json`, the same keys without their validity windows and
revocation instants. A member with a context is presented after the receipts
its chain names, and against the commitment it names. The verifier contract is
in `README.md`.

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
| `RS-R-006` | 6.7 | MUST | The previousReceiptHash field MUST be the string "sha256:" followed by the lowercase hex encoding of SHA-256(JCS(receipt)), where receipt is the entire signed receipt object including the signature member. |

## Gaps

Questions the draft does not decide. The closing rule is a proposal for its next
revision, and a verifier that applies it is reported by name, never failed.

| id | question | closing rule | code |
|---|---|---|---|
| `RS-G-001` | Was the key revoked before the receipt was issued? | A key in the external key set may carry revoked_at. A receipt whose issued_at is at or after its key's revoked_at is invalid. | `key_revoked` |
| `RS-G-002` | Was the receipt issued after a commitment its issuer recorded where the issuer cannot rewrite it? | A receipt at chain position p, with an issuer-signed commitment of count c less than p whose terminal_hash is the link to position c, recorded at commitmentLoggedAt somewhere the issuer cannot rewrite, was not issued before commitmentLoggedAt. If its issued_at is earlier, it is invalid. | `issued_at_precedes_excluding_commitment` |

## Conditions

| id | what it requires | requirements and gaps |
|---|---|---|
| `rs-c-1` | The signature is computed over JCS(payload), and a verifier recomputes that byte string rather than trusting the bytes the payload arrived in. | RS-R-001 |
| `rs-c-2` | A receipt whose issued_at falls outside its key's validity window, as the external key set publishes it, is not reported valid by a verifier that applies the window. | RS-R-002 |
| `rs-c-3` | The window includes valid_from and excludes valid_until, as RFC 7519 treats nbf and exp. Section 9.2 of the vendored text does not fix the boundary. | RS-R-002 |
| `rs-c-4` | The canonical bytes are the message given to Ed25519, with no intermediate hash, so a signature over their SHA-256 digest does not verify. | RS-R-001, RS-R-003 |
| `rs-c-5` | An envelope receipt is verified under the envelope rule. A signature made under the flat rule, over the receipt with its signature member removed, does not verify as an envelope. | RS-R-004 |
| `rs-c-6` | A payload that carries a signature member, whatever its value (null, the empty string, a string), is refused even though a signature over its canonical bytes verifies. | RS-R-005 |
| `rs-c-7` | A receipt signed inside its key's window and after the key's revoked_at verifies under the draft. A verifier that reads revoked_at refuses it; the same receipt issued before revoked_at verifies either way. | RS-G-001 |
| `rs-c-8` | A receipt presented at a chain position carries, in previousReceiptHash, the link to the receipt before it in that chain. A chain whose previous receipt is some other receipt is refused. | RS-R-006 |
| `rs-c-9` | One receipt, alone and at chain position 2, against an issuer-signed commitment to a chain of one logged before or after its issued_at. The draft accepts all of them; a verifier that reads the commitment's time refuses the one the commitment contradicts. | RS-G-002 |

## Vectors

| id | kind | conditions | context | with windows | without windows | if the SHOULD is not honoured | if the gap is closed (with / without windows) |
|---|---|---|---|---|---|---|---|
| `v0142580fad54af78` | accept | rs-c-8 |  | valid | valid |  |  |
| `v03377fbbac6d12f8` | accept | rs-c-6 |  | valid | valid |  |  |
| `v0340fed8ef07e072` | reject | rs-c-4 |  | invalid `signature_invalid` | invalid `signature_invalid` |  |  |
| `v1adc0db0267a742b` | reject | rs-c-5 |  | invalid `signature_invalid` | invalid `signature_invalid` |  |  |
| `v2c8c0aabb75e8aa0` | reject | rs-c-6 |  | invalid `signature_in_signing_input` | invalid `signature_in_signing_input` |  |  |
| `v2e98d2f14251c8d6` | reject | rs-c-6 |  | invalid `signature_in_signing_input` | invalid `signature_in_signing_input` |  |  |
| `v2f0a83c1364e52bc` | accept | rs-c-7 |  | valid | valid |  |  |
| `v3bb98f09b3068de5` | reject | rs-c-6 |  | invalid `signature_in_signing_input` | invalid `signature_in_signing_input` |  |  |
| `v4ec9fa36ae77ce07` | indeterminate | rs-c-2 |  | invalid `key_outside_validity_window` | valid | valid |  |
| `v4f9fe96e52a39bfb` | accept | rs-c-1 |  | valid | valid |  |  |
| `v5397adb77c3e6754` | reject | rs-c-6 |  | invalid `signature_in_signing_input` | invalid `signature_in_signing_input` |  |  |
| `v6d872b14889dc9e2` | gap | rs-c-9 | after `v0142580fad54af78`; commitment logged 2026-03-01T00:00:00Z | valid | valid |  | invalid `issued_at_precedes_excluding_commitment` / invalid `issued_at_precedes_excluding_commitment` |
| `v75158ebfd05a56e5` | accept | rs-c-8, rs-c-9 | after `v0142580fad54af78`; commitment logged 2026-02-01T00:00:00Z | valid | valid |  |  |
| `v814de39bf68212fc` | accept | rs-c-9 |  | valid | valid |  |  |
| `v9f2a63a5186a2fa8` | gap | rs-c-7 |  | valid | valid |  | invalid `key_revoked` / valid |
| `vaafe541bbd74c320` | accept | rs-c-5 |  | valid | valid |  |  |
| `vab0c4dde2038340e` | accept | rs-c-8 | after `v0142580fad54af78` | valid | valid |  |  |
| `vad088133176d7114` | accept | rs-c-4 |  | valid | valid |  |  |
| `vb19450def8dcc5cd` | accept | rs-c-3 |  | valid | valid |  |  |
| `vbc25ef71da0567f9` | indeterminate | rs-c-3 |  | invalid `key_outside_validity_window` | valid | valid |  |
| `vc4b43c5739979581` | indeterminate | rs-c-2 |  | invalid `key_outside_validity_window` | valid | valid |  |
| `vcc3cdb871ff27027` | accept | rs-c-6 |  | valid | valid |  |  |
| `ve116653dd041dda0` | reject | rs-c-1 |  | invalid `signature_invalid` | invalid `signature_invalid` |  |  |
| `ve24bce7210cacee9` | reject | rs-c-8 | after `v2f0a83c1364e52bc` | invalid `chain_link_mismatch` | invalid `chain_link_mismatch` |  |  |
| `vea8370fb85e1b4b1` | accept | rs-c-2 |  | valid | valid |  |  |

## Lifted files

Each file below was written upstream and is reproduced by the generator, which
refuses unless its SHA-256 is the digest recorded at that commit.

| author | upstream | upstream file | here |
|---|---|---|---|
| giskard09 | `giskard09/argentum-core` `examples/conformance/farley-receipt-signature` at `541ce84b4f97` | `signature-input-drift.conformant.json` | `receipts/v4f9fe96e52a39bfb.json` |
| giskard09 | `giskard09/argentum-core` `examples/conformance/farley-receipt-signature` at `541ce84b4f97` | `signature-input-drift.reject.json` | `receipts/ve116653dd041dda0.json` |
| giskard09 | `giskard09/argentum-core` `examples/conformance/farley-receipt-signature` at `541ce84b4f97` | `superseded-key.conformant.json` | `receipts/vea8370fb85e1b4b1.json` |
| giskard09 | `giskard09/argentum-core` `examples/conformance/farley-receipt-signature` at `541ce84b4f97` | `superseded-key.reject.json` | `receipts/vc4b43c5739979581.json` |
| tomjwxf | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/signing-input` at `56801e37a0c9` | `empty-member.json` | `receipts/v2c8c0aabb75e8aa0.json` |
| tomjwxf | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/signing-input` at `56801e37a0c9` | `no-member.json` | `receipts/vcc3cdb871ff27027.json` |
| tomjwxf | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/signing-input` at `56801e37a0c9` | `null-member.json` | `receipts/v2e98d2f14251c8d6.json` |
| tomjwxf | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/signing-input` at `56801e37a0c9` | `string-member.json` | `receipts/v3bb98f09b3068de5.json` |
| astrogilda | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/revocation` at `56801e37a0c9` | `after-revocation.json` | `receipts/v9f2a63a5186a2fa8.json` |
| astrogilda | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/revocation` at `56801e37a0c9` | `before-revocation.json` | `receipts/v2f0a83c1364e52bc.json` |
| astrogilda | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/timeliness` at `56801e37a0c9` | `commitment.json` | `context/ce0cdbb366659fa7c.json` |
| astrogilda | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/timeliness` at `56801e37a0c9` | `genesis.json` | `receipts/v0142580fad54af78.json` |
| astrogilda | `ScopeBlind/agent-governance-testvectors` `verifier-vectors/timeliness` at `56801e37a0c9` | `receipt.json` | `receipts/v814de39bf68212fc.json` |
