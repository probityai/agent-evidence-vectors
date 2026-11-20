# vectors-catalog-trust-manifest

Suite `catalog-trust-manifest/v1`: 60 cases (15 accept, 45 reject) for a verifier of signed ARD and AI Catalog objects. The profile is [profiles/catalog-trust-manifest.md](../../profiles/catalog-trust-manifest.md).

Each case directory holds `catalog.json` (the bytes as published), `did-documents.json` (what an offline did:web resolver returned, keyed by DID), `artifact.json` (the bytes the entry names), any vendored attestation document, and `context.json` (construction, entry and manifest index, role, check time, attestation file names).

Run the reference reader or your own verifier:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-catalog-trust-manifest
agent-evidence-vectors --corpus vectors-catalog-trust-manifest --verifier 'python3 my_verifier.py'
```

Your verifier receives `catalog-trust-manifest/v1 <case directory> --json`, prints `{"decision": "accept" | "reject", "reason": "<code>"}` and exits 0 for accept and 1 for reject.

## Two generators, one corpus

`gen_vectors.py` builds the corpus from the case table with this package's dependency-free P-256 (RFC 6979) and Ed25519, and writes the table to `CASES.json`. `gen_vectors_independent.py` shares no code with it: it reads `CASES.json`, writes its own RFC 8785 and signs with `cryptography`. CI requires both to produce the committed bytes. A canonicalization or signing-input defect in either one shows up as a byte difference, not as a verdict someone has to notice.

## Cross-construction cases

The `contradict-` groups judge one catalog, byte for byte, under all four constructions. A manifest signed over the draft input verifies under `ard-draft-bu-00` and fails under `field-whole-entry`; one signed over the whole entry does the reverse. A verdict that does not name its construction cannot be replayed.

## Predicate identifiers in attestations

`accept-attestations-dsse-bound` carries two `attestations[]` items typed `https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt` and `https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect`, each a vendored DSSE in-toto Statement whose subject digest equals `entry.digest`.

## Keys

Test keys only: each is derived from the SHA-256 of a public label in `gen_vectors.py`.

## Cases

| Case | Decision | Reason | What it carries |
| --- | --- | --- | --- |
| `accept-draft-es256` | accept | `signature_covers_release` | control: ARD draft trust manifest, ES256, publisher DID |
| `accept-draft-eddsa` | accept | `signature_covers_release` | control: the draft names ES256 as mandatory to implement, not as the only algorithm, so EdDSA is accepted under it |
| `accept-draft-b64-false-with-crit` | accept | `signature_covers_release` | control: RFC 7797 unencoded payload declared critical; the draft does not forbid it |
| `accept-draft-utf16-member-order` | accept | `signature_covers_release` | control: member names that sort differently by UTF-16 code unit and by code point; RFC 8785 orders by UTF-16 |
| `accept-field-whole-entry` | accept | `signature_covers_release` | control: the whole-entry input measured in the field (entry minus trustManifest.signature) |
| `accept-cross-origin-url-bound` | accept | `signature_covers_release` | control: url on another origin, and the artifact fetched from it declares the entry identifier (draft 6.2) |
| `accept-attestations-dsse-bound` | accept | `signature_covers_release` | control: two attestations, each a DSSE in-toto statement whose subject digest equals entry.digest, typed by the agent-card-receipt and observed-effect predicate URIs |
| `accept-aic-publisher` | accept | `signature_covers_release` | control: AI Catalog trust manifest under the did:web Signer and Publisher Profiles |
| `accept-aic-assessor-as-contributor` | accept | `signature_covers_release` | control: an assessor manifest beside the publisher's, judged in the contributor role |
| `accept-aic-publisher-beside-assessor` | accept | `signature_covers_release` | control: the same catalog, the publisher's manifest in the publisher role |
| `accept-aic-nested-signature-kept` | accept | `signature_covers_release` | control: members named signature and additionalSignatures below the manifest stay in the payload (exclusions are not recursive) |
| `accept-aic-additional-signatures-ignored` | accept | `signature_covers_release` | control: the reserved immediate additionalSignatures member added after signing is outside the payload |
| `accept-snapshot` | accept | `snapshot_signature_valid` | control: a whole-catalog snapshot signature over a catalog carrying a signed manifest |
| `contradict-draft-signed-under-ard-draft-bu-00` | accept | `signature_covers_release` | one catalog signed over the draft input, judged under ard-draft-bu-00; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-draft-signed-under-field-whole-entry` | reject | `signature_invalid` | one catalog signed over the draft input, judged under field-whole-entry; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-draft-signed-under-ai-catalog-2026-11` | reject | `signature_missing` | one catalog signed over the draft input, judged under ai-catalog-2026-11; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-draft-signed-under-ai-catalog-snapshot` | reject | `signature_missing` | one catalog signed over the draft input, judged under ai-catalog-snapshot; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-whole-entry-signed-under-ard-draft-bu-00` | reject | `signature_invalid` | one catalog signed over the whole-entry input, judged under ard-draft-bu-00; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-whole-entry-signed-under-field-whole-entry` | accept | `signature_covers_release` | one catalog signed over the whole-entry input, judged under field-whole-entry; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-whole-entry-signed-under-ai-catalog-2026-11` | reject | `signature_missing` | one catalog signed over the whole-entry input, judged under ai-catalog-2026-11; the four contradict cases of this group carry byte-identical catalogs |
| `contradict-whole-entry-signed-under-ai-catalog-snapshot` | reject | `signature_missing` | one catalog signed over the whole-entry input, judged under ai-catalog-snapshot; the four contradict cases of this group carry byte-identical catalogs |
| `reject-construction-unknown` | reject | `construction_unknown` | the context names a construction outside the closed term |
| `reject-duplicate-identifier` | reject | `duplicate_member` | a second identifier member in the entry; a last-wins parser reads another publisher |
| `reject-unsigned` | reject | `signature_missing` | a trust manifest with no signature |
| `reject-jws-attached-payload` | reject | `jws_malformed` | the stored JWS carries its payload segment |
| `reject-jws-padded-base64url` | reject | `jws_malformed` | the signature segment is padded base64url |
| `reject-aic-typ-missing` | reject | `typ_missing_or_mismatched` | an AI Catalog manifest signature without typ |
| `reject-snapshot-typ-of-manifest` | reject | `typ_missing_or_mismatched` | a manifest-typed signature presented as the catalog snapshot signature |
| `reject-alg-none` | reject | `alg_not_allowed_for_profile` | alg none |
| `reject-aic-eddsa` | reject | `alg_not_allowed_for_profile` | EdDSA under the AI Catalog did:web Signer Profile, which allows ES256 only |
| `reject-key-source-jku` | reject | `key_source_in_header` | the protected header names a key source (jku) |
| `reject-key-source-jwk` | reject | `key_source_in_header` | the protected header names a key source (jwk) |
| `reject-key-source-x5u` | reject | `key_source_in_header` | the protected header names a key source (x5u) |
| `reject-key-source-x5c` | reject | `key_source_in_header` | the protected header names a key source (x5c) |
| `reject-aic-b64` | reject | `b64_forbidden_for_profile` | b64 in an AI Catalog protected header, even declared critical |
| `reject-crit-unknown` | reject | `jws_crit_unsupported` | crit names a parameter the verifier does not implement |
| `reject-b64-without-crit` | reject | `b64_without_crit` | b64 false without crit (RFC 7797 section 6): a verifier that ignores b64 checks other bytes |
| `reject-kid-not-under-identity` | reject | `kid_not_under_identity` | the kid names another DID than the manifest identity |
| `reject-did-document-not-identity` | reject | `did_document_not_identity` | the document served for the identity carries another id |
| `reject-kid-not-in-did-document` | reject | `kid_not_in_did_document` | the kid fragment names no verification method |
| `reject-key-not-assertion-method` | reject | `key_not_assertion_method` | the key is listed under verificationMethod but not under assertionMethod |
| `reject-alg-key-mismatch` | reject | `alg_key_mismatch` | an ES256 header over a signature from the Ed25519 key |
| `reject-number-not-interoperable` | reject | `number_not_interoperable` | the record carries 9007199254740993; the signature covers 9007199254740991 |
| `reject-lone-surrogate` | reject | `no_canonical_form` | a member value that is a lone surrogate has no UTF-8 form |
| `reject-signature-invalid` | reject | `signature_invalid` | issuedAt changed after signing |
| `reject-aic-signer-not-contributor` | reject | `signer_not_contributor` | the manifest names one contributor and is signed by another |
| `reject-subject-missing` | reject | `subject_missing` | a signed trust manifest with no subject |
| `reject-subject-version-absent` | reject | `subject_entry_mismatch` | the entry has a version and the subject does not |
| `reject-manifest-moved-to-other-release` | reject | `subject_entry_mismatch` | a valid manifest moved to an entry with the same identifier and another digest |
| `reject-entry-digest-missing-for-url` | reject | `entry_digest_missing_for_url` | an entry referenced by url with no digest, and a subject with no digest |
| `reject-artifact-digest-mismatch` | reject | `artifact_digest_mismatch` | the artifact bytes differ from entry.digest |
| `reject-url-origin-unbound` | reject | `url_origin_unbound` | url on another origin, and the artifact there does not declare the entry identifier (draft 6.2) |
| `reject-attestation-digest-mismatch` | reject | `attestation_digest_mismatch` | the vendored attestation differs from its signed digest |
| `reject-attestation-unsigned` | reject | `attestation_unsigned` | an unsigned scan result: neither a signature over the artifact nor a signed subject (draft 3.5.2 item 1) |
| `reject-attestation-transplanted` | reject | `attestation_transplanted` | a signed statement whose subject is another artifact |
| `reject-aic-www-signer` | reject | `publisher_not_signer` | a www. subdomain signer under the AI Catalog exact-match publisher rule |
| `reject-draft-www-signer` | reject | `publisher_authorization_absent` | a www. subdomain signer under the draft rule, with no authorization record offline |
| `reject-assessor-presented-as-publisher` | reject | `publisher_not_signer` | a valid assessor manifest judged in the publisher role |
| `reject-issued-in-future` | reject | `issued_in_future` | checked before issuedAt |
| `reject-manifest-expired` | reject | `manifest_expired` | checked at expiresAt |
