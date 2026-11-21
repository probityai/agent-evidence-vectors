# Judging a signed ARD or AI Catalog object

Profile identifier: `catalog-trust-manifest/v1`. Conformance vectors: `corpora/vectors-catalog-trust-manifest/`.

Two documents define signed agent catalogs today, and they sign different bytes. draft-bu-dawn-ard-discovery-00 section 3.5 signs the trust manifest with its `signature` member removed. The AI Catalog specification (Agent-Card/ai-catalog at commit `e2b425f9`, ADR 0027 and ADR 0028) signs each manifest in `trustManifests[]` with only its immediate `signature.jws` and `additionalSignatures` removed, requires a `typ`, and allows ES256 only. Signers in the field sign a third input, the whole entry minus `trustManifest.signature`, which no specification revision defines: the AI Catalog text before ADR 0028 (commit `769b1746`) also signed the manifest alone. One signature can therefore verify under one reading and fail under another, and a verdict that does not name its construction is not reproducible.

This profile makes the construction an input. A verdict is one decision over one signed object, a set of DID documents an offline resolver returned, the artifact bytes, any vendored attestation documents, a declared role and a check time.

The context names them: `construction`, `role`, `at` (the check time), `entry` and `manifest` (which entry of `entries` and which manifest of its `trustManifests` carry the signature, 0 when absent) and `attestationFiles` (the vendored file for each `attestations[]` item, by position). An index is a non-negative JSON integer; `1.0` is the integer 1, and a negative, fractional or non-numeric index selects nothing, so the read ends with `signature_missing`. A vendored file is named by one path segment of the case directory: no `/`, `\`, NUL, `.` or `..`.

## Constructions (a closed term)

| Construction | Source | Signing input | Protected `typ` |
| --- | --- | --- | --- |
| `ard-draft-bu-00` | draft-bu-dawn-ard-discovery-00 section 3.5 | RFC 8785 of `trustManifest` minus `signature` | not required |
| `field-whole-entry` | measured practice; no specification revision | RFC 8785 of the entry minus `trustManifest.signature` | not required |
| `ai-catalog-2026-11` | AI Catalog at `e2b425f9`, ADR 0028 | RFC 8785 of `trustManifests[i]` minus its immediate `signature.jws` and `additionalSignatures` | `ai-catalog-trust-manifest+jws` |
| `ai-catalog-snapshot` | AI Catalog at `e2b425f9`, "Catalog Snapshot Coverage" | RFC 8785 of the catalog minus its immediate `signature.jws` and `additionalSignatures` | `ai-catalog+jws` |

A verifier given any other construction refuses with `construction_unknown`. The role is a closed term too: `publisher` or `contributor`, and any other value refuses with `role_unknown`, because a verifier that reads an unknown role as "not the publisher" skips the publisher rule. The JWS is detached compact serialization (RFC 7515 Appendix F) in every construction.

## Checks, in order

The first check that fails decides the reason. `construction_unknown`, `role_unknown`, `json_invalid` (the catalog or the DID documents are not JSON: invalid UTF-8, `NaN`, a syntax error; or more than 64 arrays and objects are open at once, a limit stated so that every reader holds the same values) and `signature_missing` end the read; every other check can be switched off one at a time, and the corpus holds a case that changes verdict when it is.

1. `duplicate_member`: the catalog or a DID document repeats a member name (AI Catalog: parsers MUST reject duplicates).
2. `jws_malformed`: not detached compact serialization, padded or non-canonical base64url, a header that is not a strict JSON object, or a `b64` value that is not a boolean (RFC 7797 section 3).
3. `typ_missing_or_mismatched`: AI Catalog constructions only; the `typ` must exactly name the containing object, so a manifest signature cannot be replayed as a catalog signature.
4. `alg_not_allowed_for_profile`: ES256 or EdDSA under the draft constructions (ES256 is mandatory to implement, not exclusive); ES256 only under the AI Catalog did:web Signer Profile.
5. `key_source_in_header`: `jku`, `jwk`, `x5u` or `x5c`; the key comes from the identity's DID document only.
6. `b64_forbidden_for_profile`: `b64` in an AI Catalog header.
7. `jws_crit_unsupported`: `crit` names anything other than `b64`, or a parameter the header does not carry (RFC 7515 section 4.1.11).
8. `b64_without_crit`: `b64` present and not declared critical (RFC 7797 section 6); a verifier that ignores it checks other bytes.
9. `profile_unsupported`: AI Catalog constructions only; `signature.profile` is not exactly `did-web-v1`. Consumers select the procedure the profile names and never infer one (AI Catalog "Profile Selection"), so an absent or other profile is refused, not read as did:web.
10. `signer_not_root_did_web`: AI Catalog constructions only; `signature.signer` is not a root `did:web` DID: a lowercase ASCII domain (A-labels allowed) of at most 253 octets (RFC 1035 section 2.3.4) whose last label is not all digits (RFC 3696 section 2, which also rules out an IPv4 address), with no port, path or trailing dot.
11. `kid_not_under_identity`: `kid` is not the exact identity DID (draft `identity`, AI Catalog `signature.signer`) followed by a non-empty RFC 3986 fragment (unreserved characters, sub-delimiters, `:`, `@`, `/`, `?` and well-formed percent-escapes).
12. `did_document_not_identity`: no document for the identity, or its `id` differs.
13. `kid_not_in_did_document`: no verification method has the `kid` as its id, after relative DID URLs are resolved against the document id (DID Core section 3.2.2).
14. `verification_method_ambiguous`: more than one method has that id; a verifier must select exactly one, and a last-wins map selects whichever key the document lists last.
15. `key_not_assertion_method` (ADR 0027: a key under `verificationMethod` alone is not enough; an `assertionMethod` reference may be relative).
16. `method_controller_mismatch`: AI Catalog constructions only; the selected method's `controller` is not exactly the signer.
17. `jwk_not_signing_key`: the method's JWK carries private key material, `use` other than `sig`, `key_ops` without `verify`, an `alg` other than the header's, or an EC coordinate that is not exactly 32 octets (RFC 7517 section 4, RFC 7518 section 6.2.1).
18. `alg_key_mismatch`.
19. `number_not_interoperable`: an integer, or a number whose parsed double is, past 2^53 - 1 in the signed bytes. This profile is the safe-integer reading of RFC 8785: such a value has more than one meaning across JSON parsers, so one signature could cover two records.
20. `no_canonical_form`: a value with no RFC 8785 form, such as a lone surrogate.
21. `signature_invalid`.
22. `signer_not_contributor` (AI Catalog).
23. `subject_missing`.
24. `subject_entry_mismatch`: identifier and type are strings on the entry and equal on the subject, digest equal, and version absent on both or equal on both.
25. `entry_delivery_not_one`: the entry carries both `url` and `data`, or neither (draft section 3.1 and the AI Catalog Catalog Entry each require exactly one).
26. `entry_digest_missing_for_url`: an entry referenced by `url` (or any AI Catalog entry) with no `digest` (draft 3.5.2 item 1).
27. `artifact_digest_mismatch`: the entry's `digest` is not the SHA-256 of the artifact. For an entry with `url` the artifact is the bytes retrieved (the case's `artifact.json`); for an entry with `data` it is the UTF-8 RFC 8785 bytes of `data` (AI Catalog `digest`: "For `data`, hash the UTF-8 JCS-canonicalized JSON value"; the draft's digest is "of the target artifact referenced by url (or inline data)"). Inline data is not signed under `ard-draft-bu-00`, so the digest is what binds it.
28. `url_origin_unbound`: draft constructions, an entry with a `url`; its origin is not `https://<publisher>` and the artifact there does not declare the entry identifier (draft 6.2). The origin is RFC 6454's: the scheme and host compare case-insensitively and port 443 is the same origin as no port. A `url` with userinfo has no origin to bind (RFC 9110 section 4.2.4: a recipient treats https userinfo as an error), nor does a host with a percent-escape or an IP literal. An entry delivered as inline `data` has no origin to bind.
29. `attestation_digest_mismatch` (including a file name that is not one path segment of the case directory).
30. `attestation_unsigned` (the vendored statement is not a DSSE in-toto Statement signed by a key that the DID document of the keyid's DID, whose `id` is that DID, authorizes for assertions). The `payload` and each `sig` are padded base64 in the standard or the URL-safe alphabet, one alphabet per string ("verifiers MUST accept either", DSSE protocol); any other character, a line break included, refuses the field (RFC 4648 section 3.3). An ES256 `sig` is either raw `r || s` (as in JWS) or a DER ECDSA-Sig-Value (RFC 3279 section 2.2.3, as sigstore and in-toto signers write it); a DER value with a non-minimal length or integer, or trailing bytes, is refused.
31. `attestation_transplanted` (its subject is another artifact).
32. `publisher_not_signer` (AI Catalog exact rule: the signer is exactly `did:web:<publisher>`) or `publisher_authorization_absent` (draft rule: the identity must match or be authorized by the publisher, and no authorization record is given offline). Judged only in the `publisher` role.
33. `timestamp_invalid`: the check time, `issuedAt` or `expiresAt` is not an RFC 3339 date-time naming a real instant, the AI Catalog Signature object has no `issuedAt`, or `expiresAt` is not later than `issuedAt`. Times are compared as instants, so fractional seconds and numeric offsets are read, not refused. A second of `60` names a real instant only at 23:59:60 UTC on a day the IERS leap-second list (`leap-seconds.list`, expiring 28 June 2027) ends with a leap second, the last being 2016-12-31; it is read as the instant of the next second.
34. `issued_in_future`: the check time is before `issuedAt`. The check time is the context's `at`, an input, and no clock-skew tolerance is applied (the AI Catalog leaves one to local policy); a consumer that allows one moves `at`, so the verdict names the instant it judged.
35. `manifest_expired` (rejected at or after `expiresAt`).

A pass is `signature_covers_release` for an entry and `snapshot_signature_valid` for a catalog snapshot.

## What a verdict establishes

It establishes which key signed which bytes under which construction, that the key is one the identity's DID document authorizes for assertions, and that the signed subject names the entry and its artifact. It does not establish that the artifact is safe, that the claims are true, or that a DID document served online today matches the one given.

## Conformance

`agent-evidence-vectors --corpus vectors-catalog-trust-manifest --verifier '<command>'` runs a verifier over every case. The external contract: the command receives the suite, a case directory and `--json`, prints `{"decision", "reason"}` and exits 0 for accept and 1 for reject.
