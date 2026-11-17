# vectors-catalog-trust-manifest

Suite `catalog-trust-manifest/v1`: 115 cases (28 accept, 87 reject) for a verifier of signed ARD and AI Catalog objects. The profile is [profiles/catalog-trust-manifest.md](../../profiles/catalog-trust-manifest.md).

Each case directory holds `catalog.json` (the bytes as published), `did-documents.json` (what an offline did:web resolver returned, keyed by DID), `artifact.json` (the bytes an entry with `url` names; an entry with inline `data` is digested over the RFC 8785 bytes of `data` instead), any vendored attestation document, and `context.json` (construction, entry and manifest index, role, check time, attestation file names; the profile says how each is read).

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
| `reject-number-not-interoperable` | reject | `number_not_interoperable` | the record carries 9007199254740993; the signature covers 9007199254740992, the double a parser reads it as |
| `reject-lone-surrogate` | reject | `no_canonical_form` | a member value that is a lone surrogate has no UTF-8 form |
| `reject-signature-invalid` | reject | `signature_invalid` | issuedAt changed after signing |
| `reject-aic-signer-not-contributor` | reject | `signer_not_contributor` | the manifest names one contributor and is signed by another |
| `reject-subject-missing` | reject | `subject_missing` | a signed trust manifest with no subject |
| `reject-subject-version-absent` | reject | `subject_entry_mismatch` | the entry has a version and the subject does not |
| `reject-manifest-moved-to-other-release` | reject | `subject_entry_mismatch` | a valid manifest moved to an entry with the same identifier and another digest, whose artifact it names is served |
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
| `reject-role-unknown` | reject | `role_unknown` | the context names a role outside the closed term (publisher, contributor); a verifier that skips the publisher rule for it accepts an assessor as the publisher |
| `reject-catalog-not-json` | reject | `json_invalid` | the catalog carries NaN, which is not JSON |
| `reject-b64-not-boolean` | reject | `jws_malformed` | b64 is the string "false" (RFC 7797 section 3: the value is a boolean), declared critical |
| `reject-aic-profile-unsupported` | reject | `profile_unsupported` | signature.profile names a procedure this verifier does not implement; AI Catalog consumers never infer another |
| `reject-aic-profile-absent` | reject | `profile_unsupported` | the Signature object has no profile member |
| `reject-snapshot-profile-unsupported` | reject | `profile_unsupported` | the catalog signature names a profile this verifier does not implement |
| `reject-aic-signer-path-did` | reject | `signer_not_root_did_web` | the signer is did:web:other.example:team, not a root did:web DID (lowercase ASCII domain, no port, no path) |
| `reject-aic-signer-uppercase-domain` | reject | `signer_not_root_did_web` | the signer is did:web:Other.example, not a root did:web DID (lowercase ASCII domain, no port, no path) |
| `reject-aic-signer-port` | reject | `signer_not_root_did_web` | the signer is did:web:other.example%3A8443, not a root did:web DID (lowercase ASCII domain, no port, no path) |
| `reject-aic-signer-ipv4` | reject | `signer_not_root_did_web` | the signer is did:web:192.0.2.1, not a root did:web DID (lowercase ASCII domain, no port, no path) |
| `reject-aic-signer-numeric-tld` | reject | `signer_not_root_did_web` | the signer is did:web:agents.2026, not a root did:web DID (lowercase ASCII domain, no port, no path) |
| `reject-aic-signer-domain-past-253-octets` | reject | `signer_not_root_did_web` | the signer is did:web:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.example, not a root did:web DID (lowercase ASCII domain, no port, no path) |
| `reject-snapshot-signer-path-did` | reject | `signer_not_root_did_web` | a catalog signature by a path-based did:web DID |
| `reject-verification-method-ambiguous` | reject | `verification_method_ambiguous` | two verification methods carry the kid as their id, the second holding another key that made the signature |
| `reject-aic-method-controller-other` | reject | `method_controller_mismatch` | the selected method's controller is another DID than the signer |
| `reject-jwk-use-enc` | reject | `jwk_not_signing_key` | the method's JWK is marked for encryption (use enc) |
| `reject-jwk-private-member` | reject | `jwk_not_signing_key` | the method's JWK carries a private member d |
| `reject-jwk-alg-other` | reject | `jwk_not_signing_key` | the method's JWK names ES384 while the header names ES256 |
| `reject-jwk-key-ops-sign-only` | reject | `jwk_not_signing_key` | the method's JWK permits sign but not verify |
| `reject-jwk-x-33-octets` | reject | `jwk_not_signing_key` | the method's JWK carries a 33-octet x coordinate holding the right integer |
| `reject-aic-issued-absent` | reject | `timestamp_invalid` | the Signature object has no issuedAt, which the AI Catalog requires |
| `reject-issued-not-a-date` | reject | `timestamp_invalid` | issuedAt is 2026-02-30, which matches the pattern and names no day |
| `reject-expires-not-after-issued` | reject | `timestamp_invalid` | expiresAt precedes issuedAt |
| `reject-draft-identifier-absent` | reject | `subject_entry_mismatch` | entry and subject both lack identifier, so the signed subject names no entry |
| `reject-attestation-signer-document-not-identity` | reject | `attestation_unsigned` | the DID document served for the attestation key's DID carries another id |
| `accept-assertion-method-relative-reference` | accept | `signature_covers_release` | control: assertionMethod names the key by the relative reference #es256, resolved against the document id (DID Core 3.2.2) |
| `reject-draft-url-and-data` | reject | `entry_delivery_not_one` | the entry carries both url and data; the draft requires exactly one |
| `reject-draft-neither-url-nor-data` | reject | `entry_delivery_not_one` | the entry carries neither url nor data |
| `accept-kid-fragment-with-colon` | accept | `signature_covers_release` | control: the kid fragment carries a colon, which an RFC 3986 fragment allows |
| `reject-kid-fragment-bad-escape` | reject | `kid_not_under_identity` | the kid fragment carries a malformed percent-escape |
| `accept-issued-with-fraction` | accept | `signature_covers_release` | control: an RFC 3339 issuedAt with fractional seconds |
| `accept-issued-with-offset` | accept | `signature_covers_release` | control: an RFC 3339 issuedAt with a numeric offset, compared as an instant |
| `accept-draft-inline-data` | accept | `signature_covers_release` | control: an entry delivered as inline data has no url, so there is no origin to bind (draft 3.3, 6.2), and its digest is of the RFC 8785 bytes of data (AI Catalog digest) |
| `reject-draft-inline-data-swapped` | reject | `artifact_digest_mismatch` | inline data changed after signing; the digest is of the RFC 8785 bytes of data, so it no longer matches (AI Catalog digest, draft 3.2 digest) |
| `accept-dsse-url-safe-base64` | accept | `signature_covers_release` | control: a DSSE envelope in URL-safe base64; DSSE verifiers MUST accept either alphabet (protocol.md) |
| `accept-dsse-der-signature` | accept | `signature_covers_release` | control: a DSSE ES256 signature in DER, as sigstore and in-toto signers write it |
| `reject-dsse-der-non-minimal` | reject | `attestation_unsigned` | a DER signature whose r carries a zero octet it does not need; DER has one encoding per value |
| `reject-dsse-payload-newline` | reject | `attestation_unsigned` | a DSSE payload with a line break inside the base64; RFC 4648 section 3.3 refuses characters outside the alphabet |
| `reject-attestation-file-not-one-segment` | reject | `attestation_digest_mismatch` | the context names the vendored file as ./attestation-0.dsse.json; a vendored file is named by one path segment |
| `accept-nesting-at-the-limit` | accept | `signature_covers_release` | control: 64 arrays and objects open at once |
| `reject-nesting-past-the-limit` | reject | `json_invalid` | 65 arrays and objects open at once, outside the signed bytes; readers hold different values past a nesting limit |
| `accept-context-entry-integral-number` | accept | `signature_covers_release` | control: the context names entry 1.0, the integer 1 (JSON does not tell 1.0 from 1) |
| `reject-context-entry-negative` | reject | `signature_missing` | the context names entry -1, which selects nothing (an index is a non-negative integer) |
| `reject-context-entry-boolean` | reject | `signature_missing` | the context names entry true, which is not a number |
| `reject-issued-second-60-not-leap` | reject | `timestamp_invalid` | issuedAt 2026-11-01T00:00:60Z: no leap second falls there, so it names no instant (RFC 3339 section 5.7) |
| `reject-issued-second-60-offset-not-leap` | reject | `timestamp_invalid` | issuedAt 2016-12-31T23:59:60+01:00 is 22:59:60 UTC, no leap second |
| `accept-issued-on-a-leap-second` | accept | `signature_covers_release` | control: 2016-12-31T23:59:60Z, the last leap second in the IERS list |
| `accept-issued-on-a-leap-second-with-offset` | accept | `signature_covers_release` | control: the same leap second written as 18:59:60-05:00 |
| `accept-url-origin-case-and-default-port` | accept | `signature_covers_release` | control: HTTPS://PUBLISHER.example:443 is the origin https://publisher.example (RFC 6454 section 4) |
| `reject-url-userinfo` | reject | `url_origin_unbound` | a url with userinfo before the publisher host; a recipient treats https userinfo as an error (RFC 9110 section 4.2.4) |
| `reject-aic-url-and-data` | reject | `entry_delivery_not_one` | an AI Catalog entry carrying both url and data; a Catalog Entry MUST contain exactly one |
| `reject-aic-neither-url-nor-data` | reject | `entry_delivery_not_one` | an AI Catalog entry with neither url nor data, whose digest still names artifact.json |
| `reject-issued-one-second-in-future` | reject | `issued_in_future` | checked one second before issuedAt; the profile applies no clock-skew tolerance, so the verdict names the instant |
| `accept-checked-at-the-issued-instant` | accept | `signature_covers_release` | control: checked at issuedAt itself, written with another offset |
| `reject-url-other-port` | reject | `url_origin_unbound` | a url on the publisher host at port 8443, another origin |
