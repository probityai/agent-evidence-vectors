# AEE vectors to AGNTCY

Mapping each AGNTCY surface that a record, a digest, a signature or a credential passes through to the member of this repository that tests it. Written 2026-10-28 against primary text and code, read from checkouts at the commits in the provenance section.

Offered as a basis for collaboration. The same rows, with the file path, line anchor and commit for every AGNTCY source, are in `aee-to-agntcy.json` beside this file.

## What this crosswalk says, and what it does not

It says which corpus tests a surface, and which case ids or reason codes inside that corpus do the testing. It says nothing about whether any AGNTCY software passes a member. A member is a published set of inputs with expected decisions; running it against an implementation is the job of whoever holds that implementation, and the corpus ships a runner for it (`agent-evidence-vectors --corpus <name> --verifier <command>`).

Denied cases are selected by reason code, not listed one by one. Each reason names the first check that fails, the manifest of the corpus lists every case with that reason, and every denied case has a conformant control beside it, so a verifier that denies everything fails the controls.

## Two members arrive in the next minor release

Two of the members below are not on `main` yet. `vectors-oasf-record` and `vectors-badge-vc-verify` are built and tested on their own branches and ship in the next minor release; their rows point at the directories `vectors-oasf-record/` and `vectors-badge-vc-verify/` at the repository root, and each directory carries a `MANIFEST.json` with the case ids the rows cite. Rows that cite them are marked `(next release)`. Every other member is on `main` now.

## How to read the rows

`TESTED` means a member judges the surface end to end. `PARTIALLY_TESTED` means a member judges part of it, and the Unmeasurable column says which part is left. `NOT_TESTED` means no member applies; the Unmeasurable column gives the reason, and where AGNTCY publishes no record format for the surface the reason says so. A surface with no published record, statement or credential format cannot be turned into a conformance case, which is why those rows are the point of the unmeasurable column and not gaps in effort.

## Rows by AGNTCY component

### OASF

| Surface | Member and case selection | Relation | Unmeasurable |
|---|---|---|---|
| Record object: the fields the schema marks required | `vectors-oasf-record` (next release): reasons `oasf_required_field`; cases `allow-plain`, `allow-optional-fields` | TESTED |  |
| Record bytes as JSON: duplicate members, non-UTF-8, non-finite numbers, integers outside the exact double range | `vectors-oasf-record` (next release): reasons `record_not_json`, `number_not_exact`; cases `allow-integer-at-exact-limit` | TESTED |  |
| Extension registry: names and UIDs reserved for schema extensions | none | NOT_TESTED | The registry is a table of names and UIDs that avoids collisions. No member judges extension registration or the payload an extension carries; the nearest artifact is the controlled vocabulary in agent-evidence-vocabulary, which is not a vectors member. |
| A2A Agent Card carried in a record (a2a_data.card_data, and the artifact reference that replaces it) | `vectors-a2a-jcs-v01`: groups `a2-signatures-exclusion`, `a3-object-key-ordering`, `a4-string-serialization`, `a5-number-serialization`, `a6-arrays-nesting-literals`<br>`vectors-agent-card-receipt`: reasons `card_digest_mismatch`, `card_malformed`; cases `accept-card-without-signatures`, `accept-signatures-excluded`, `accept-rfc8785-edges` | PARTIALLY_TESTED | How OASF resolves the artifact reference to the card bytes is not a record format any member judges. |

### Directory (DIR)

| Surface | Member and case selection | Relation | Unmeasurable |
|---|---|---|---|
| Record identity digest: the SHA-256 a record is named by | `vectors-oasf-record` (next release): reasons `digest_mismatch`; cases `allow-plain`, `allow-compact-bytes`<br>`vectors-a2a-jcs-v01`: groups `a3-object-key-ordering`, `a4-string-serialization`, `a5-number-serialization` | TESTED |  |
| Record CID: the digest wrapped as a content identifier | `vectors-oasf-record` (next release): reasons `digest_mismatch` | PARTIALLY_TESTED | The CID version, codec and multibase text are outside the corpus: the member judges the digest the CID carries, not the identifier's wrapping. |
| Signer identity (OIDC subject and issuer) a consumer pins when verifying a record signature | `vectors-oasf-record` (next release): reasons `signer_not_policy`; cases `allow-plain`, `allow-signer-plus-address`<br>`vectors-admission` | TESTED |  |
| Sigstore bundle, Fulcio certificate chain and transparency-log entry attached to a record | `vectors-receipt-signature` | NOT_TESTED | No member parses a Sigstore bundle, a Fulcio certificate or a Rekor entry. Receipt-signature checks signature mechanics for a different envelope, so it is context and not coverage. |
| Identity and ownership claims: a signed claim checked against the subject's current keys (DNS, HTTPS JWKS, did:web, did:key, SPIFFE, ANS), with expiry | `vectors-identity-binding`: reasons `key_not_authorized`, `key_rotated_out`, `did_unresolvable`, `signer_not_subject`, `signature_invalid`, `did_malformed`; cases `web-verified`, `web-signed-before-rotation`<br>`vectors-badge-vc-verify` (next release): reasons `not_yet_valid`, `expired`; cases `allow-expiration-in-future` | PARTIALLY_TESTED | The claim payload and its detached JWS, and the DNS TXT, JWKS, SPIFFE and ANS key channels, have no member. Identity-binding covers DID documents only. |
| Content policies (OPA or CEL) and the per-record verdict the node stores and serves | `vectors-admission` | PARTIALLY_TESTED | The member judges admission under a policy; it does not judge the stored verdict's encoding or the audit service's replies. |

### ADS draft

| Surface | Member and case selection | Relation | Unmeasurable |
|---|---|---|---|
| TrustManifest object: identity, trust_schema, attestations, provenance | `vectors` | PARTIALLY_TESTED | No member judges the TrustManifest object itself, only a statement placed in it. |
| TrustManifest detached JWS over the RFC 8785 serialization | `vectors-a2a-jcs-v01`: groups `a3-object-key-ordering`, `a4-string-serialization`, `a5-number-serialization`, `a6-arrays-nesting-literals`<br>`vectors-receipt-signature` | PARTIALLY_TESTED | The detached JWS form (a compact JWS with the payload omitted) has no member. |

### Identity

| Surface | Member and case selection | Relation | Unmeasurable |
|---|---|---|---|
| Agent badge: the issuer a verifier trusts | `vectors-badge-vc-verify` (next release): reasons `issuer_not_trusted`; cases `allow-plain` | TESTED |  |
| Agent badge: binding of the issuer to the key that signs | `vectors-badge-vc-verify` (next release): reasons `issuer_key_binding`; cases `allow-plain`, `allow-second-key-of-issuer`<br>`vectors-identity-binding`: reasons `key_not_authorized`, `signer_not_subject`; cases `web-verified` | TESTED |  |
| Agent badge: a credential in a compact JWS, its header, structure and signature | `vectors-badge-vc-verify` (next release): reasons `jws_malformed`, `credential_malformed`, `signature_invalid`; cases `allow-plain` | TESTED |  |
| Agent badge: issuance and expiry | `vectors-badge-vc-verify` (next release): reasons `not_yet_valid`, `expired`; cases `allow-expiration-in-future`, `allow-expiration-one-second-after`, `allow-issuance-equals-verification-time`, `allow-offset-timestamps` | TESTED |  |
| Agent badge: revocation recorded in the issuer's status store | `vectors-badge-vc-verify` (next release): reasons `revoked`; cases `allow-revoked-list-names-another`<br>`vectors-delegation-lifecycle`: reasons `grant_revoked`, `grant_revoked_dispute_open`, `revocation_incomplete`; cases `tree-parent-revoked-child-presented`, `tree-child-presented-before-revocation` | TESTED |  |
| Agent badge in the JSON-LD form with an embedded Data Integrity proof | none | NOT_TESTED | The badge member judges the compact JWS (EdDSA) form only. No member judges JSON-LD canonicalization or an embedded Data Integrity proof. |
| Agent badge wrapping an OASF record or an A2A Agent Card | `vectors-agent-card-receipt`: reasons `card_digest_mismatch`, `receipt_expired`, `receipt_revoked`; cases `accept-card-without-signatures`<br>`vectors-oasf-record` (next release): reasons `digest_mismatch`; cases `allow-plain` | PARTIALLY_TESTED | The wrapping credential's subject-to-card link is not judged; the members judge the card digest and the record digest. |
| Task-based access control: authority to act on a task | `vectors-delegation-lifecycle`: reasons `authority_valid`, `chain_broken`, `presenter_not_delegate`, `parent_inactive`; cases `tree-chain-valid` | PARTIALLY_TESTED | Task semantics and the policy language are not judged; the member judges the delegation chain. |

### SLIM

| Surface | Member and case selection | Relation | Unmeasurable |
|---|---|---|---|
| MLS group messages: what a message claims and who sent it | none | NOT_TESTED | AGNTCY publishes no record or statement format for an MLS message claim, and the drafts define a transport. The vectors corpora judge records and statements, not protocol messages. |
| KeyPackage and credential freshness: stale or expired ones are rejected | none | NOT_TESTED | A KeyPackage is an MLS (RFC 9420) structure and no member parses one. The validity-window logic in the badge member applies to a different object. |
| Node and client names derived from public-key hashes, with optional DIDs | none | NOT_TESTED | No published record format: the name is a derivation rule inside the protocol. Identity-binding judges DID documents, not this derivation. |

### Observe

| Surface | Member and case selection | Relation | Unmeasurable |
|---|---|---|---|
| OpenTelemetry attributes and metrics for agent observability | none | NOT_TESTED | The schema lists attribute and metric names with units and stability levels. It defines no record, digest or signature to judge, so no member applies; observed-effect judges state-change statements, not telemetry. |

## Where a pinned dependency or a CI job fits

Each member ships in the published package: `pip install agent-evidence-vectors` and `agent-evidence-vectors --corpus vectors-oasf-record` runs it, and the repository's GitHub Action runs a named corpus in any project's CI. For OASF records and agent badges those two commands are the whole adoption path. The Unmeasurable column marks where a new corpus would need an AGNTCY-published format first.

## Provenance

AGNTCY sources were read from local checkouts of the public repositories, cited in the JSON as a GitHub URL at the commit read: `agntcy/dir` at `6ae6ab04adfa`, `agntcy/dir-spec` at `846e47590f4c`, `agntcy/oasf` at `9f370e8ca1cc`, `agntcy/slim-spec` at `20d92915ef4b`, `agntcy/identity-spec` at `bdbf1457581f` and `agntcy/observe` at `e0af12080fcd`. Each can be re-read with `git -C <checkout> rev-parse HEAD`. Case ids and reason codes were read from each corpus's `MANIFEST.json`; the two next-release manifests were read from the branches that build them.

Section references and line anchors name a specific commit. A later revision of any source can move a line or fill a row marked `NOT_TESTED`, and nothing here detects that happening.
