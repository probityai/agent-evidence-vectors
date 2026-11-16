# Judging a signed ARD or AI Catalog object

Profile identifier: `catalog-trust-manifest/v1`. Conformance vectors: `corpora/vectors-catalog-trust-manifest/`.

Two documents define signed agent catalogs today, and they sign different bytes. draft-bu-dawn-ard-discovery-00 section 3.5 signs the trust manifest with its `signature` member removed. The AI Catalog specification (Agent-Card/ai-catalog at commit `e2b425f9`, ADR 0027 and ADR 0028) signs each manifest in `trustManifests[]` with only its immediate `signature.jws` and `additionalSignatures` removed, requires a `typ`, and allows ES256 only. Signers in the field sign a third input, the whole entry minus `trustManifest.signature`, which no specification revision defines: the AI Catalog text before ADR 0028 (commit `769b1746`) also signed the manifest alone. One signature can therefore verify under one reading and fail under another, and a verdict that does not name its construction is not reproducible.

This profile makes the construction an input. A verdict is one decision over one signed object, a set of DID documents an offline resolver returned, the artifact bytes, any vendored attestation documents, a declared role and a check time.

## Constructions (a closed term)

| Construction | Source | Signing input | Protected `typ` |
| --- | --- | --- | --- |
| `ard-draft-bu-00` | draft-bu-dawn-ard-discovery-00 section 3.5 | RFC 8785 of `trustManifest` minus `signature` | not required |
| `field-whole-entry` | measured practice; no specification revision | RFC 8785 of the entry minus `trustManifest.signature` | not required |
| `ai-catalog-2026-11` | AI Catalog at `e2b425f9`, ADR 0028 | RFC 8785 of `trustManifests[i]` minus its immediate `signature.jws` and `additionalSignatures` | `ai-catalog-trust-manifest+jws` |
| `ai-catalog-snapshot` | AI Catalog at `e2b425f9`, "Catalog Snapshot Coverage" | RFC 8785 of the catalog minus its immediate `signature.jws` and `additionalSignatures` | `ai-catalog+jws` |

A verifier given any other construction refuses with `construction_unknown`. The JWS is detached compact serialization (RFC 7515 Appendix F) in every construction.

## Checks, in order

The first check that fails decides the reason. `construction_unknown` and `signature_missing` end the read; every other check can be switched off one at a time, and the corpus holds a case that changes verdict when it is.

1. `duplicate_member`: the catalog or a DID document repeats a member name (AI Catalog: parsers MUST reject duplicates).
2. `jws_malformed`: not detached compact serialization, padded or non-canonical base64url, or a header that is not a strict JSON object.
3. `typ_missing_or_mismatched`: AI Catalog constructions only; the `typ` must name the containing object, so a manifest signature cannot be replayed as a catalog signature.
4. `alg_not_allowed_for_profile`: ES256 or EdDSA under the draft constructions (ES256 is mandatory to implement, not exclusive); ES256 only under the AI Catalog did:web Signer Profile.
5. `key_source_in_header`: `jku`, `jwk`, `x5u` or `x5c`; the key comes from the identity's DID document only.
6. `b64_forbidden_for_profile`: `b64` in an AI Catalog header.
7. `jws_crit_unsupported`: `crit` names anything other than `b64`, or a parameter the header does not carry (RFC 7515 section 4.1.11).
8. `b64_without_crit`: `b64` present and not declared critical (RFC 7797 section 6); a verifier that ignores it checks other bytes.
9. `kid_not_under_identity`: `kid` is not the exact identity DID (draft `identity`, AI Catalog `signature.signer`) followed by a non-empty fragment.
10. `did_document_not_identity`: no document for the identity, or its `id` differs.
11. `kid_not_in_did_document`, 12. `key_not_assertion_method` (ADR 0027: a key under `verificationMethod` alone is not enough), 13. `alg_key_mismatch`.
14. `number_not_interoperable`: an integer, or a number whose parsed double is, past 2^53 - 1 in the signed bytes. This profile is the safe-integer reading of RFC 8785: such a value has more than one meaning across JSON parsers, so one signature could cover two records.
15. `no_canonical_form`: a value with no RFC 8785 form, such as a lone surrogate.
16. `signature_invalid`.
17. `signer_not_contributor` (AI Catalog), 18. `subject_missing`, 19. `subject_entry_mismatch`: identifier, type and digest equal, and version absent on both or equal on both.
20. `entry_digest_missing_for_url`: an entry referenced by `url` (or any AI Catalog entry) with no `digest` (draft 3.5.2 item 1).
21. `artifact_digest_mismatch`.
22. `url_origin_unbound`: draft constructions; the `url` origin is not `https://<publisher>` and the artifact there does not declare the entry identifier (draft 6.2).
23. `attestation_digest_mismatch`, 24. `attestation_unsigned` (the vendored statement is not a DSSE in-toto Statement signed by a key its DID document authorizes), 25. `attestation_transplanted` (its subject is another artifact).
26. `publisher_not_signer` (AI Catalog exact rule: the signer is exactly `did:web:<publisher>`) or `publisher_authorization_absent` (draft rule: the identity must match or be authorized by the publisher, and no authorization record is given offline). Judged only in the `publisher` role.
27. `issued_in_future`, 28. `manifest_expired` (rejected at or after `expiresAt`).

A pass is `signature_covers_release` for an entry and `snapshot_signature_valid` for a catalog snapshot.

## What a verdict establishes

It establishes which key signed which bytes under which construction, that the key is one the identity's DID document authorizes for assertions, and that the signed subject names the entry and its artifact. It does not establish that the artifact is safe, that the claims are true, or that a DID document served online today matches the one given.

## Conformance

`agent-evidence-vectors --corpus vectors-catalog-trust-manifest --verifier '<command>'` runs a verifier over every case. The external contract: the command receives the suite, a case directory and `--json`, prints `{"decision", "reason"}` and exits 0 for accept and 1 for reject.
