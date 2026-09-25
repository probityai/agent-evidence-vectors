# Conformance vectors (AI generation predicate v0.1)

Every member of this suite in one table. The subject under test is a verifier
of the generation predicate `https://open-fab.ai/attestation/generation/v0.1` at specification revision
0.1.3, in its default attest-only mode.

This corpus is 34 vectors, of which 9 a conformant verifier must not
fail closed on and 12 it must reject.

The remaining members are graded `proposed`: each declares what revision
0.1.3 says about it and what `../docs/proposals/ai-generation-v01-findings.md` proposes, and a
verifier is never failed on one.

The specification, its JSON Schema and its licence are vendored under
`spec-vendored/` and pinned by digest in the manifest. The golden member is
the upstream repository's pinned golden vector, transcribed from the test that
pins it.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-ai-generation/` from the repository root.

## Conditions

| id | what it requires | clause of revision 0.1.3, or the gap |
|---|---|---|
| `ofg-c-1` | The canonical form of the pinned golden statement is the pinned bytes. | Envelope encoding: the golden conformance vector, whose canonical form the upstream repository pins by length and sha256. |
| `ofg-c-2` | payload_sha256 is the sha256 of the canonical statement bytes. | Envelope encoding: the bytes the signatures cover, and that payload_sha256 digests, are the UTF-8 encoding of the canonical form of statement. |
| `ofg-c-3` | A signature covers the canonical bytes, not another serialization. | Envelope encoding: objects carry no insignificant whitespace. |
| `ofg-c-4` | Non-ASCII characters are emitted as literal UTF-8. | Envelope encoding: all other characters (including non-ASCII) emitted as literal UTF-8, not escaped. |
| `ofg-c-5` | String escaping is minimal; a solidus is not escaped. | Envelope encoding: standard JSON escaping, minimal. |
| `ofg-c-6` | No floating-point number appears in the statement. | Envelope encoding: the value domain contains no floating-point numbers. Producers MUST NOT introduce them. |
| `ofg-c-7` | No number of any kind appears in the statement. | Envelope encoding: the value domain is strings, booleans, objects, arrays only. |
| `ofg-c-8` | An empty acceptance or signoffs array is omitted. | Producer omission rule: empty acceptance / signoffs arrays are omitted entirely, never serialized as empty arrays. |
| `ofg-c-9` | An absent optional field is omitted, never serialized as null. | Producer omission rule: absent optional fields (agent.id, agent.tools, materials[].sha256) are omitted entirely, never serialized as null. |
| `ofg-c-10` | The statement is canonicalized as received, so a member added after signing is covered and breaks the digest. | Envelope encoding: verifiers canonicalize the statement as parsed. |
| `ofg-c-11` | Every ed25519 signature verifies over the canonical bytes. | Verification step 2: verify the ed25519 signatures against their keyid. |
| `ofg-c-12` | A keyid is an ed25519 did:key. | Verification step 2: signatures are verified against their keyid (did:key); the envelope algorithm is ed25519. |
| `ofg-c-13` | generated[].author is ai or human. | Predicate fields: author is one of ai or human. |
| `ofg-c-14` | In attest-only mode acceptance_passed is reported as the producer's self-report and the verdict records its mode. | Verification: in this mode acceptance_passed MUST be treated as the producer's self-report; a verifier MUST record which mode produced its verdict. |
| `ofg-p-1` | Each signature covers a stated part of the statement once sign-offs exist: the fab signature and payload_sha256 the statement without signoffs, the n-th sign-off signature the statement with the first n records. | gap: Revision 0.1.3 says every signature covers the canonical statement, so a verifier built from the text rejects every attestation that carries a sign-off. |
| `ofg-p-2` | Every sign-off record is covered by the signature of the key it names. | gap: Under the coverage both implementations use, the last record is covered by no signature and can be rewritten after signing. |
| `ofg-p-3` | There is exactly one sign-off signature per sign-off record. | gap: Nothing binds the number of records to the number of signatures. |
| `ofg-p-4` | signoffs[n].did is the keyid of the n-th sign-off signature. | gap: Nothing binds a record to the key that signed it. |
| `ofg-p-5` | N-of-M counts distinct signing keys, not records or names. | gap: The revision calls signoffs an N-of-M gate and never says what is counted. |
| `ofg-p-6` | Attribution ranges for one path do not overlap. | gap: The revision permits two ranges to claim different origins for one line. |
| `ofg-p-7` | A supplied Assisted-by trailer matches agent.id and agent.tools. | gap: The revision makes the cross-check a MAY, so a disagreeing trailer passes. |
| `ofg-p-8` | Member names are ordered by UTF-16 code units, as RFC 8785 orders them. | gap: The revision orders keys by code point and also says its form coincides with RFC 8785; for a member name outside the Basic Multilingual Plane the two orders differ. |
| `ofg-p-9` | An integer is permitted inside the I-JSON safe range and refused outside it. | gap: The revision's value domain has no numbers, while the reference tests sign an integer parameter. |
| `ofg-p-10` | A statement with a duplicate member name is refused. | gap: The revision does not say how a duplicate name is parsed, so two verifiers keeping different copies both conform. |

## Vectors

| id | kind | conditions | expected | parent |
|---|---|---|---|---|
| `v032d7f6446838c86` | reject | ofg-c-7 | invalid `number-outside-value-domain` | `v803b44c6310c58dd` |
| `v0bf84efb855e9983` | reject | ofg-c-4 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `v20dc6144915cb64e` | reject | ofg-c-11 | invalid `signature-invalid` | `v813737ad828668c4` |
| `v26773fbfe7219804` | proposed | ofg-p-9 | 0.1.3: invalid `number-outside-value-domain`; proposal: invalid `unsafe-integer` | `v7e8378a3cb6f3beb` |
| `v41ffc689ab691f38` | reject | ofg-c-10 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `v43c29d9aa9dab8e2` | accept | ofg-c-8 | valid |  |
| `v551d84ac66f33adf` | reject | ofg-c-13 | invalid `author-not-in-enum` | `v813737ad828668c4` |
| `v57ddc0d49453510f` | accept | ofg-c-9 | valid |  |
| `v67b343a989ac7a32` | proposed | ofg-p-7 | 0.1.3: valid; proposal: invalid `trailer-disagrees` | `ve290fc80af586834` |
| `v6898f23bf0d63e43` | proposed | ofg-p-2 | 0.1.3: invalid `payload-digest-mismatch`; proposal: invalid `signoff-signature-invalid` | `vc9321aca5c878ff9` |
| `v690a27cba702a6a1` | proposed | ofg-p-10 | 0.1.3: indeterminate; proposal: invalid `duplicate-member` | `v813737ad828668c4` |
| `v6bc1c5c4275d451d` | proposed | ofg-p-3 | 0.1.3: invalid `payload-digest-mismatch`; proposal: invalid `signoff-records-and-signatures-disagree` | `vc9321aca5c878ff9` |
| `v6e5279605cfa8ad5` | reject | ofg-c-6 | invalid `floating-point-number` | `vfe6a26f63e566bac` |
| `v7e8378a3cb6f3beb` | proposed | ofg-p-9 | 0.1.3: invalid `number-outside-value-domain`; proposal: valid |  |
| `v802e5eaf42a3c98f` | reject | ofg-c-5 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `v803b44c6310c58dd` | accept | ofg-c-7 | valid |  |
| `v80bef8e6efc805c4` | proposed | ofg-p-8 | 0.1.3: invalid `payload-digest-mismatch`; proposal: valid | `vb6ce4da91879b6b0` |
| `v813737ad828668c4` | accept | ofg-c-2, ofg-c-3, ofg-c-4, ofg-c-5, ofg-c-10, ofg-c-11, ofg-c-12, ofg-c-13, ofg-p-10 | valid |  |
| `v96859833d810730f` | reject | ofg-c-3 | invalid `signature-invalid` | `v813737ad828668c4` |
| `va169259bece657d5` | accept | ofg-c-14 | valid |  |
| `va18c8786b0c58d4e` | proposed | ofg-p-1 | 0.1.3: invalid `payload-digest-mismatch`; proposal: invalid `signoff-signature-invalid` | `vc9321aca5c878ff9` |
| `va35bcfb26910a2cb` | reject | ofg-c-8 | invalid `empty-array-serialized` | `v43c29d9aa9dab8e2` |
| `va8e599224ef5a13a` | reject | ofg-c-9 | invalid `null-optional-serialized` | `v57ddc0d49453510f` |
| `vb6ce4da91879b6b0` | proposed | ofg-p-8 | 0.1.3: valid; proposal: invalid `payload-digest-mismatch` | `v80bef8e6efc805c4` |
| `vc3f6b78452e8e684` | accept | ofg-p-6 | valid |  |
| `vc9321aca5c878ff9` | proposed | ofg-p-1, ofg-p-2, ofg-p-3, ofg-p-4, ofg-p-5 | 0.1.3: invalid `payload-digest-mismatch`; proposal: valid |  |
| `ve290fc80af586834` | accept | ofg-p-7 | valid |  |
| `ve519b6be46ced66e` | proposed | ofg-p-5 | 0.1.3: invalid `payload-digest-mismatch`; proposal: valid | `vc9321aca5c878ff9` |
| `ve654d0e0e28896ad` | accept | ofg-c-1 | canonical sha256 `7051cb7073a3` |  |
| `vef2bf7309281aaa1` | reject | ofg-c-2 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `vf1e654cbe3174418` | proposed | ofg-p-4 | 0.1.3: invalid `payload-digest-mismatch`; proposal: invalid `signoff-signer-mismatch` | `vc9321aca5c878ff9` |
| `vf7158c5a325fd632` | reject | ofg-c-12 | invalid `keyid-not-ed25519-did-key` | `v813737ad828668c4` |
| `vfddf8453d88a3605` | proposed | ofg-p-6 | 0.1.3: valid; proposal: invalid `attribution-ranges-overlap` | `vc3f6b78452e8e684` |
| `vfe6a26f63e566bac` | accept | ofg-c-6 | valid |  |
