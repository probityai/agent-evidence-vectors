# Conformance vectors (AI generation predicate v0.1)

Every member of this suite in one table. The subject under test is a verifier
of the generation predicate `https://open-fab.ai/attestation/generation/v0.1` at specification revision
0.1.5, in its default attest-only mode.

This corpus is 38 vectors, of which 18 a conformant verifier must not
fail closed on and 20 it must reject.

There are no proposed members. Revision 0.1.5 makes overlapping ranges and
supplied-trailer disagreement required refusals. The historical findings remain
in `../docs/proposals/ai-generation-v01-findings.md` with their adopted status.

The specification, its JSON Schema and its licence are vendored under
`spec-vendored/` and pinned by digest in the manifest. The golden member is
the upstream repository's pinned golden vector, transcribed from the test that
pins it. Four accept members were signed by the upstream implementations
themselves and are copied byte for byte from `docs/vectors/` at the pinned
commit; their manifest rows carry the upstream path and digest under `source`.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-ai-generation/` from the repository root.

## Conditions

| id | what it requires | clause of revision 0.1.5, or the gap |
|---|---|---|
| `ofg-c-1` | The canonical form of the pinned golden statement is the pinned bytes. | Envelope encoding: the golden conformance vector, whose canonical form the upstream repository pins by length and sha256. |
| `ofg-c-2` | payload_sha256 is the sha256 of the canonical statement bytes. | Envelope encoding: the bytes the signatures cover, and that payload_sha256 digests, are the UTF-8 encoding of the canonical form of statement. |
| `ofg-c-3` | A signature covers the canonical bytes, not another serialization. | Envelope encoding: objects carry no insignificant whitespace. |
| `ofg-c-4` | Non-ASCII characters are emitted as literal UTF-8. | Envelope encoding: all other characters (including non-ASCII) emitted as literal UTF-8, not escaped. |
| `ofg-c-5` | String escaping is minimal; a solidus is not escaped. | Envelope encoding: standard JSON escaping, minimal. |
| `ofg-c-6` | No floating-point number appears in the statement. | Envelope encoding, numbers: the value domain contains integers only, no floating-point numbers. Producers MUST NOT emit floats; canonicalizers and verifiers MUST refuse them. |
| `ofg-c-7` | An integer is inside the value domain within the I-JSON safe range and refused outside it. | Envelope encoding, numbers: every integer MUST lie within the I-JSON (RFC 7493) safe range, |n| <= 2^53 - 1; canonicalizers and verifiers MUST refuse out-of-range integers. |
| `ofg-c-8` | An empty acceptance or signoffs array is omitted. | Producer omission rule: empty acceptance / signoffs arrays are omitted entirely, never serialized as empty arrays. |
| `ofg-c-9` | An absent optional field is omitted, never serialized as null. | Producer omission rule: absent optional fields (agent.id, agent.tools, materials[].sha256) are omitted entirely, never serialized as null. |
| `ofg-c-10` | The statement is canonicalized as received, so a member added after signing is covered and breaks the digest. | Verifier input handling: the received statement bytes are authoritative; preimages are built from the statement as parsed from the received document, not from a typed round-trip. |
| `ofg-c-11` | Every ed25519 signature verifies over the bytes it covers. | Verification step 2: verify the ed25519 signatures against their keyid over the preimages defined in Signature coverage. |
| `ofg-c-12` | A keyid is an ed25519 did:key. | Verification step 2: signatures are verified against their keyid (did:key); the envelope algorithm is ed25519. |
| `ofg-c-13` | generated[].author is ai or human. | Predicate fields: author is one of ai or human. |
| `ofg-c-14` | In attest-only mode acceptance_passed is reported as the producer's self-report and the verdict records its mode. | Verification: in this mode acceptance_passed MUST be treated as the producer's self-report; a verifier MUST record which mode produced its verdict. |
| `ofg-c-15` | The fab signature and payload_sha256 cover the statement without signoffs; the n-th sign-off signature covers the statement with the first n records, its own included. | Signature coverage: role fab and payload_sha256 cover the canonical form with predicate.signoffs removed entirely; the n-th human-signoff signature covers it with predicate.signoffs truncated to its first n records, its own record included. Pre-0.1.4 sign-off signatures do not verify under this rule. |
| `ofg-c-16` | Every sign-off record is inside a signed preimage, so a record changed after signing breaks a signature. | Signature coverage: every record is thus inside at least one signed preimage; no record exists that no signature covers. |
| `ofg-c-17` | There is exactly one sign-off signature per sign-off record. | Signature coverage: the number of sign-off records equals the number of valid sign-off signatures; an appended record with no signature MUST fail. |
| `ofg-c-18` | signoffs[n].did is the keyid of the n-th sign-off signature. | Signature coverage: verifiers MUST check that signoffs[n].did equals the n-th sign-off signature's keyid; a record naming a DID that did not sign MUST fail. |
| `ofg-c-19` | N-of-M counts distinct signing keys, not records or names. | Signature coverage: any sign-off threshold MUST count distinct verified signing keys, never records or signature array entries. |
| `ofg-c-20` | Member names are ordered by UTF-16 code units, as RFC 8785 orders them. | Envelope encoding, objects: keys sorted ascending by UTF-16 code units, the RFC 8785 section 3.2.3 order. |
| `ofg-c-21` | A statement with a duplicate member name is refused. | Verifier input handling: verifiers MUST refuse documents containing duplicate object member names (I-JSON). |
| `ofg-c-22` | An attestation signed by either reference implementation verifies. | Signed conformance vectors: the reference repository's docs/vectors/ holds four complete signed attestations, one from each reference implementation, with and without sign-offs, cross-verified in its own CI. |
| `ofg-c-23` | Attribution ranges for one path do not overlap. | Predicate fields: ranges for one path MUST NOT overlap, and verifiers MUST refuse overlapping or malformed ranges (rev 0.1.5). |
| `ofg-c-24` | A supplied Assisted-by trailer matches agent.id and agent.tools. | Disclosure trailers: a verifier given Assisted-by trailer lines MUST compare them against the attestation; a disagreement fails verification (rev 0.1.5). |

## Vectors

| id | kind | conditions | expected | parent |
|---|---|---|---|---|
| `v032d7f6446838c86` | accept | ofg-c-7 | valid |  |
| `v041297f0f0ed52ca` | accept | ofg-c-2, ofg-c-11, ofg-c-12, ofg-c-22, ofg-c-15, ofg-c-16, ofg-c-17, ofg-c-18, ofg-c-19 | valid |  |
| `v0bf84efb855e9983` | reject | ofg-c-4 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `v20dc6144915cb64e` | reject | ofg-c-11 | invalid `signature-invalid` | `v813737ad828668c4` |
| `v26773fbfe7219804` | reject | ofg-c-7 | invalid `unsafe-integer` | `v7e8378a3cb6f3beb` |
| `v41ffc689ab691f38` | reject | ofg-c-10 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `v43c29d9aa9dab8e2` | accept | ofg-c-8 | valid |  |
| `v551d84ac66f33adf` | reject | ofg-c-13 | invalid `author-not-in-enum` | `v813737ad828668c4` |
| `v57ddc0d49453510f` | accept | ofg-c-9 | valid |  |
| `v67b343a989ac7a32` | reject | ofg-c-24 | invalid `trailer-disagrees` | `ve290fc80af586834` |
| `v6898f23bf0d63e43` | reject | ofg-c-16 | invalid `signoff-signature-invalid` | `vc9321aca5c878ff9` |
| `v690a27cba702a6a1` | reject | ofg-c-21 | invalid `duplicate-member` | `v813737ad828668c4` |
| `v6bc1c5c4275d451d` | reject | ofg-c-17 | invalid `signoff-records-and-signatures-disagree` | `vc9321aca5c878ff9` |
| `v6e5279605cfa8ad5` | reject | ofg-c-6 | invalid `floating-point-number` | `vfe6a26f63e566bac` |
| `v7e8378a3cb6f3beb` | accept | ofg-c-7 | valid |  |
| `v802e5eaf42a3c98f` | reject | ofg-c-5 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `v803b44c6310c58dd` | accept | ofg-c-7 | valid |  |
| `v80bef8e6efc805c4` | accept | ofg-c-20 | valid |  |
| `v813737ad828668c4` | accept | ofg-c-2, ofg-c-3, ofg-c-4, ofg-c-5, ofg-c-10, ofg-c-11, ofg-c-12, ofg-c-13, ofg-c-21 | valid |  |
| `v85612623f1594648` | accept | ofg-c-2, ofg-c-11, ofg-c-12, ofg-c-22, ofg-c-15, ofg-c-16, ofg-c-17, ofg-c-18, ofg-c-19 | valid |  |
| `v8ba9dcb28847aac2` | accept | ofg-c-2, ofg-c-11, ofg-c-12, ofg-c-22 | valid |  |
| `v96859833d810730f` | reject | ofg-c-3 | invalid `signature-invalid` | `v813737ad828668c4` |
| `va169259bece657d5` | accept | ofg-c-14 | valid |  |
| `va18c8786b0c58d4e` | reject | ofg-c-15 | invalid `signoff-signature-invalid` | `vc9321aca5c878ff9` |
| `va35bcfb26910a2cb` | reject | ofg-c-8 | invalid `empty-array-serialized` | `v43c29d9aa9dab8e2` |
| `va8e599224ef5a13a` | reject | ofg-c-9 | invalid `null-optional-serialized` | `v57ddc0d49453510f` |
| `vb6ce4da91879b6b0` | reject | ofg-c-20 | invalid `payload-digest-mismatch` | `v80bef8e6efc805c4` |
| `vc3f6b78452e8e684` | accept | ofg-c-23 | valid |  |
| `vc9321aca5c878ff9` | accept | ofg-c-15, ofg-c-16, ofg-c-17, ofg-c-18, ofg-c-19 | valid |  |
| `ve290fc80af586834` | accept | ofg-c-24 | valid |  |
| `ve519b6be46ced66e` | accept | ofg-c-19 | valid | `vc9321aca5c878ff9` |
| `ve654d0e0e28896ad` | accept | ofg-c-1 | canonical sha256 `7051cb7073a3` |  |
| `ve86dfb45f930fa44` | accept | ofg-c-2, ofg-c-11, ofg-c-12, ofg-c-22 | valid |  |
| `vef2bf7309281aaa1` | reject | ofg-c-2 | invalid `payload-digest-mismatch` | `v813737ad828668c4` |
| `vf1e654cbe3174418` | reject | ofg-c-18 | invalid `signoff-signer-mismatch` | `vc9321aca5c878ff9` |
| `vf7158c5a325fd632` | reject | ofg-c-12 | invalid `keyid-not-ed25519-did-key` | `v813737ad828668c4` |
| `vfddf8453d88a3605` | reject | ofg-c-23 | invalid `attribution-ranges-overlap` | `vc3f6b78452e8e684` |
| `vfe6a26f63e566bac` | accept | ofg-c-6 | valid |  |
