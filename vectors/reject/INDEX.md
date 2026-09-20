# INVALID conformance vectors (adversarial-execution-evidence v0.7)

This directory is the conformance suite's `vectors/reject/` layout.

Ground truth: `spec/predicates/adversarial-execution-evidence.md` @
`0dbe10b`, reviewed as in-toto/attestation PR #570 and fetchable from
astrogilda/attestation at branch `predicate/adversarial-execution-evidence`,
version 0.7.0, type URI
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.
The commit is read from `spec/VENDOR-PIN.json`, which
`scripts/vendor-spec.py` derives from git at vendor time, so this
line cannot name a revision the vendored bytes did not come from.

That type URI does not resolve. The in-toto attestation catalog
redirects the URIs of vetted predicates whose specification is
merged, and this predicate is in review as the pull request named
above, so a request for the URI returns 404. The URI identifies the
predicate type, and dereferencing it is not part of verifying any
vector here; read the specification in the vendored copy this
repository carries at the path named above.

`Lnnn` anchors below are line refs into the vendored copy, in the
coordinate frame of the commit named above and no other. They are
remapped onto the new line numbers whenever the spec is re-vendored,
and `spec/ANCHOR-PINS.json` records the text each one addresses, so
`scripts/spec-anchor-gate.py` fails when an anchor comes to point at
prose it was not drawn around.

Every file is a COMPLETE in-toto Statement (UNWRAPPED, no outer DSSE;
the inner `observationRecords` carry real DSSE signatures) that a
conforming verifier MUST reject for exactly ONE declared reason. Each is
derived from a fully-valid parent statement by ONE mutation plus its
declared rederive chain, so no second fault exists; the generator's
self-check asserts second-fault ABSENCE (root recomputes, vocabulary and
corpus digests verify, record bindings equal the derived binding, every
signature verifies, result recompute matches) for every vector whose
declared conditions do not target that commitment, and full gate
validity for every parent. Regenerate byte-identically with:
`python3 gen_invalid_vectors.py`.

## Determinism recipe

- Test signing key (Ed25519/RFC 8032), seed DERIVED, never stored:
  `seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`, role
  `substrate-observation-test` for every record signature in this set.
  - public key (hex): `496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62`
  - keyid = SHA-256 of the raw public key: `7e2b0652d86716f47e35573ae0082d670706b7a548dcb685df7bf103923dcb9c`
  - `keyid` is an unauthenticated hint, never the check (spec L1901-1903).
- Fixed timestamps: `issuedAt: 2026-01-01T00:00:00Z`, `armedAt: 2025-12-31T23:59:00Z`
  (a later `armedAt` appears only in bad-702).
- Record `payloadType`: `application/vnd.example.aee-observation.v1+json`.
- Subject `example-agent-bundle`; attack ids `XA-EXAMPLE-*`,
  `XB-EXAMPLE-*` and `XC-EXAMPLE-*`, one class per detection
  channel; producer label/layer vocabulary is spec-verbatim
  (`egress_captured`, `no_egress`, `sinkhole`,
  `policy.egress_sinkhole`, `none`) or obviously synthetic
  (`example_label_a`, `example.method-x`).
- Committed files: UTF-8, LF, 2-space indent, lexicographic member
  order, std base64 with padding. For bad-201/202/203 the FAULT is a
  serialization property of the record payload bytes; those exact bytes
  travel base64-encoded, so the statement files themselves remain
  ordinary JSON and byte-replay is preserved (MANIFEST `rawBytes`).

## Derived digest preimages (all synthetic one-liners)

| digest | preimage |
|---|---|
| `35cc6fb260268f69a231fa0b9ead51b067c8455bff600c64978200f72ef2e9ff` | `sha256("example-admission-receipt-a/v1")` |
| `fd739b5b84603ccbd963159854e9113bac6795014f7023a56dc2897883be89c6` | `sha256("example-admission-receipt-b/v1")` |
| `81c6e914fe332c0a08a53c43fe0e6fa5d0e5fde533bb03ab664e3d924e8bf829` | `sha256("example-orphan-root/v1")` |
| `cca32c26b70e238a58249962a8da351bd8acc047b638276b3503c05bf3c6499e` | `sha256("example-other-posture-config/v1")` |
| `01b25de15d8bc69fb3cb12b323e61c2f05078a6296e7b3ff9f6197d587014738` | `sha256("example-run-start-checkpoint/v1")` |
| `93d3f174c7674310358525ffcba56656fc02a0bec3cedfd019557c925f7c1534` | `sha256("example-second-substrate-image/v1")` |
| `1821aa6ff38428b2bf7ea727903b6d82768ea55dc24d4435890adcfe5fd0cea5` | `sha256("example-stale-corpus/v1")` |
| `1cdb63348f9249f7dfafdc0f052d6610dbf824efa4f0b3839f4a4418807ae587` | `sha256("example-stale-vocabulary/v1")` |
| `d14fbbcd076c6bfe5e6aa52b169c0baf7f7044ea46fe279afd7629e92baac8fc` | `sha256("example-agent-bundle-content/v1")` |
| `cba949a58d23fdd49bf37f2f1195c926fec35d22f545c949c0c56df943c67794` | `sha256("example-agent-bundle-b-content/v1")` |
| `018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb` | `sha256("example-substrate-image-content/v1")` |
| `dc54fd0bf21192f62b024ea90782d98ddd1ca511b21d3f0cc38733c4a24b38dd` | `sha256("example-unchecked-binding/v1")` |
| `87359bb792677d9cf7e4118f2729821073530194403fda7a9530fa851f4a8b0f` | `sha256("in-toto-aee-test-commitment/example interception observation a/v1")` |
| `c4c7e5b539761d0c611daa1fb0f1f3a3a759ce353b6629076f6550a7d26c83a8` | `sha256("in-toto-aee-test-commitment/example interception observation b/v1")` |
| `a0d8baea7e8eef28c977dd5bad41139a3da498639ba012300853ffb978984529` | `sha256("in-toto-aee-test-commitment/example interception observation c/v1")` |
| `7098b7a783350f38d06a2045405521c0b39d6926b257f71a7d05fd1fd6d0e765` | `sha256("in-toto-aee-test-commitment/example interception observation d/v1")` |
| `abeebee717612337f51c6e16dd30ff53f1f4866a7ab8e4c0facd0589373591e5` | `sha256("in-toto-aee-test-commitment/example planted probe channel a/v1")` |
| `8769d763e6537b565cf3d88608a94e228bd8c5163fddb48448db4298efb0a17d` | `sha256("in-toto-aee-test-commitment/example planted probe channel b/v1")` |
| `4360248d6a437ca0f1d30a0b39e515f81d1ebb8c9fbc2f0bb045bbf960c3119c` | `sha256("in-toto-aee-test-commitment/example planted probe channel c/v1")` |
| `846c2ccf97b5a5f4da335fe733e7f4f786ffd224ce582fb5a9685d52184abdc3` | `sha256(JCS({"exampleCatchPolicy": {"mode": "enforce"}}))` |
| `a6ebfc845bfe910a099320fd7ec33e21282a8b56d82111527a80444ca18e4352` | `sha256(JCS({"exampleNetworkPosture": {"posture": "sinkhole"}}))` |

Corpus and vocabulary digests are JCS digests of the manifest and
`{"caught": [...], "labels": [...]}` objects embedded in each vector.
Run bindings derive per spec L174-182 from each statement's own values.
Negative known-answer for bad-303, the retired version-1 pre-image
that MUST NOT match (JCS, then SHA-256):

```json
{
  "aeeBindingVersion": "1",
  "catchPolicy": "846c2ccf97b5a5f4da335fe733e7f4f786ffd224ce582fb5a9685d52184abdc3",
  "corpus": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
  "networkPosture": "a6ebfc845bfe910a099320fd7ec33e21282a8b56d82111527a80444ca18e4352",
  "runEntropy": "01b25de15d8bc69fb3cb12b323e61c2f05078a6296e7b3ff9f6197d587014738",
  "subject": "d14fbbcd076c6bfe5e6aa52b169c0baf7f7044ea46fe279afd7629e92baac8fc",
  "substrate": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb"
}
```

## Condition registry (aee-c ids)

This table is the id-to-spec-line registry, and it is the only one:
no other file in this repository carries a second copy. It covers
EVERY id the suite cites, in either direction, so an id carried only
by an accept vector resolves here rather than nowhere. Until
2026-07-30 the table listed only the ids the reject set happened to
use and this paragraph named a table in the repository README that
has never existed, which left 17 ids cited by vectors and resolvable
to no rule at all.

`scripts/condition-registry-gate.py` fails when a condition a vector
cites has no row here, and when a row here names a condition no
vector cites, so neither direction can drift again unnoticed.

A row reading `UNRESOLVED` is one whose meaning could not be
established from the specification and the rails. It records the
candidate reading and says it is a candidate, because a registry row
that guesses is worse than one that is missing: it looks resolved.

| id | spec anchor | condition |
|---|---|---|
| aee-c-1 | L435 | closed lowercase result vocabulary |
| aee-c-2 | L390-393 | result must equal the recompute |
| aee-c-3 | L440-442 | a row carrying a label from the carried caught set contributes fail |
| aee-c-4 | L443-444 | fail-closed on out-of-vocabulary label |
| aee-c-5 | L443-444 | fail-closed on missing/out-of-vocab basis or method |
| aee-c-6 | L444-446 | degraded iff disclosed coverage gap |
| aee-c-7 | L447-450 | UNRESOLVED -- ok-002 is the sole carrier and the corpus does not separate this id from aee-c-2. Candidate reading, recorded rather than asserted: the third recompute condition, which contributes pass_indirect when some clean row is not (substrate, intercepted) and pass when none is |
| aee-c-10 | L552 | observationRefs non-empty on substrate rows |
| aee-c-11 | L552-553; L946-951 | every ref index in range (integer), on every row that carries the member and not only on the rows a gate resolves |
| aee-c-12 | L554-556 | caught intercepted row refs an interception record |
| aee-c-13 | L556-557 | reconstructed row refs an examination record |
| aee-c-14 | L557-560 | clean intercepted row refs arming AND covering sealed |
| aee-c-15 | L958-960 | one run-level arming/sealed/examination record covers every row earned under it |
| aee-c-16 | L953-958 | observationSelectors is producer vocabulary positionally parallel to observationRefs; no gate reads it |
| aee-c-17 | L561-562 | covering payload is canonical RFC 8785 |
| aee-c-18 | L1312-1316 | covering payload is valid I-JSON (RFC 7493) |
| aee-c-19 | L1317-1318 | covering media type ends in +json |
| aee-c-20 | L562-563 | covering payload carries the reserved aee members |
| aee-c-22 | L563-564 | aeeRunBinding equals the derived run binding |
| aee-c-23 | L565-566 | row method capped by weakest signed aeeMethod |
| aee-c-24 | L1742 | batchRoot required when records exist |
| aee-c-25 | L1744-1747 | RFC 6962 domain-separated hashing |
| aee-c-26 | L1747-1749 | RFC 6962 recursive split, never duplicate-pad |
| aee-c-27 | L1749 | leaves in array order |
| aee-c-28 | L1749 | a single-record tree's root is its leaf hash |
| aee-c-29 | L1751-1752 | duplicate byte-identical records invalid |
| aee-c-30 | L1754-1756 | batchRoot must recompute |
| aee-c-31 | L1758-1770 | batchRoot omitted exactly when records absent |
| aee-c-32 | L1744-1748 | batchRoot is over every carried record in array order, referenced by a row or not |
| aee-c-33 | L766-775 | the evidence tier is derived per row and never carried: artifact is declared, substrate is attested when every covering signature verifies under consumer policy and unattested otherwise, and the tier never alters result |
| aee-c-34 | L772-774 | no TOFU: a consumer with no policy-pinned substrate root treats every substrate row as unattested and MUST NOT infer the root from the predicate |
| aee-c-35 | L1901-1903 | keyid is an unauthenticated lookup hint, never the check |
| aee-c-36 | L1302-1304; L545-546 | a record signature is DSSE PAE over (payloadType, payload); the byte-pure validity gate never reads a signature, so a signature that does not verify is a tier fact and not a validity fault |
| aee-c-38 | L779-781 | a carried predicate-level evidenceTier member MUST be ignored |
| aee-c-41 | L992-993 | basis required, closed {substrate, artifact} |
| aee-c-42 | L1035-1036 | method required, closed {intercepted, reconstructed} |
| aee-c-43 | L1097-1101 | the retired 0.4 basis and method values are out-of-vocabulary, with no alias |
| aee-c-44 | L760-764 | fail-closed substrate row invalidates; artifact row stays a valid fail |
| aee-c-45 | L1046-1052 | weakest-input method composition |
| aee-c-47 | L1269-1277 | missing actualLayer = malformed statement, not fail |
| aee-c-48 | L1278-1283 | clean row actualLayer is the literal none |
| aee-c-49 | L1283-1286 | the literal none is valid on a caught row too, and states that the event was observed and no enforcement layer acted |
| aee-c-50 | L1269-1270 | actualLayer names the enforcement layer that acted on the row's containment event |
| aee-c-51 | L796-804 | observationVocabulary required |
| aee-c-52 | L800-802 | caught is a subset of labels |
| aee-c-53 | L802 | vocabulary arrays sorted ascending, no duplicates |
| aee-c-54 | L802-804 | vocabulary digest is JCS of {caught, labels} |
| aee-c-57 | L808-810 | runEntropy required with any substrate row |
| aee-c-58 | L210-213 | exactly one subject on a statement of any basis |
| aee-c-59 | L210-224 | binding digest inputs lowercase 64-hex sha256 |
| aee-c-60 | L174-182 | binding pre-image construction |
| aee-c-61 | L779-781 | a predicate-level member beginning with the reserved aee prefix MUST be ignored |
| aee-c-62 | L229-237 | binding is anti-splice |
| aee-c-63 | L1323-1327 | arming record kind constraints |
| aee-c-64 | L1330-1335 | sealed record required members |
| aee-c-65 | L1361-1366 | sealed covering conditions |
| aee-c-66 | L1336-1338 | examination signed aeeMethod reconstructed |
| aee-c-68 | L1187-1188 | each referenced record independently satisfies its class constraints |
| aee-c-71 | L1687-1691 | unknown aeeKind covers nothing |
| aee-c-73 | L1693-1695 | the aee payload member prefix is reserved; every other payload member is producer territory and does not stop a record covering |
| aee-c-75 | L237-241 | fail-closed on unimplemented binding version |
| aee-c-77 | L3; L313 | statement _type and predicateType URIs |
| aee-c-78 | L783-810 | observationEnvironment required members |
| aee-c-79 | L787-791 | corpus digest re-derives from embedded manifest |
| aee-c-80 | L789-791 | attackId under at most one manifest class |
| aee-c-81 | L920 | row attackId appears in the manifest |
| aee-c-82 | L963-966 | coverage exactly equals the manifest at attack granularity |
| aee-c-83 | L905-909 | coverage member required |
| aee-c-84 | L1772-1782 | doesNotAssert single canonical spelling |
| aee-c-85 | L1784; L1792-1795 | issuedAt required, under the Timestamp profile: uppercase separator and zone designator, and a zero offset spelled Z, +00:00 or -00:00 |
| aee-c-86 | L150-163 | vocabulary labels/caught entries BMP-only; a supplementary-plane entry is malformed |
| aee-c-87 | L150-163 | covering payload member names BMP-only; a supplementary-plane name covers nothing |
| aee-c-88 | L920-928 | row members are strictly typed; a wrong-JSON-type member is a malformed statement |
| aee-c-89 | L1611-1642 | arming chain-member syntax: positive aeeRunSeq; aeeChainScope required with it; aeePrevRunBinding lowercase 64-hex, absent exactly when aeeRunSeq is 1 |
| aee-c-90 | L941-943 | no two attackResults rows share an attackId |
| aee-c-91 | L1300-1302 | each observation record's signatures member carries at least one entry |
| aee-c-92 | L968-990 | the corpus manifest declares at least one attack identifier across all of its classes |
| aee-c-93 | L847-855 | networkPosture.posture is a registered value |
| aee-c-94 | L574-579 | a clean row resolves no observationRefs index to an interception record |
| aee-c-95 | L580-585 | every carried interception record is resolved by at least one observationRefs index on a caught row |
| aee-c-96 | L586-594 | a statement carrying a basis: substrate row carries a sealed record satisfying every constraint of its kind, whether or not a row resolves an index to it |
| aee-c-97 | L609-613 | aeeObservedSet on every carried sealed record equals the value recomputed over the carried interception and examination records |
| aee-c-98 | L1535-1542 | every attack the seal names in aeeObservedAttacks has a row whose containmentObserved is in the carried caught set; the rule reads in one direction only |
| aee-c-99 | L1467-1473 | the union of the manifest identifiers for the carried assessedClasses is a SUBSET of the arming record's aeeAssessedAttacks |
| aee-c-100 | L614-623 | a row declaring attribution: pinned resolves at least one interception record |
| aee-c-101 | L614-623 | a row declaring attribution: pinned names an attack the manifest carries an expectedPayloads entry for |
| aee-c-102 | L614-623 | every interception a pinned row resolves carries in aeePayloadCommitment at least one value from that attack's expectedPayloads entry |
| aee-c-103 | L815-821 | corpus.manifest.expectedPayloads is well formed: every key a declared attack, every array non-empty, sorted by UTF-16 code unit, duplicate-free and lowercase 64-hex |
| aee-c-104 | L1454-1465 | an interception record carries aeePayloadCommitment, non-empty, sorted by UTF-16 code unit, duplicate-free and lowercase 64-hex |
| aee-c-105 | L1093-1097 | attribution is required on every row and its vocabulary is closed; a missing or out-of-vocabulary value is fail-closed exactly as basis and method are |
| aee-c-106 | L1394-1408 | a moat-drop record covers nothing in every state and carries no constraint that could change that; it still contributes its leaf to batchRoot, never enters aeeObservedSet or the method cap, and the refusal a row earns by resolving one names the kind rather than reporting an unrecognized kind |
| aee-c-107 | L1394-1408 | an uncommitted-observation record covers nothing in every state on the same terms, and in particular cannot stand in for an interception: not for a caught row's coverage, not for the existence requirement a pinned row must satisfy, and not for the expectedPayloads comparison |
| aee-c-108 | L586-594; L1322-1366 | every carried record that binds to this run and whose aeeKind names a covering kind satisfies every constraint of that kind, whether or not any row resolves an observationRefs index to it. The universal partner of aee-c-96, over the same records on the same terms: that one asks whether a valid sealed record is present, this asks whether an invalid one is carried beside it |

## Vectors (209)

`parent` names the accept-suite shape the vector derives from (the
accept vectors land separately; the parent statements are built
in-memory by the generator and asserted fully valid before mutation).
`rederive` lists the derived commitments recomputed after the mutation
so the declared fault stays the ONLY fault.

| vector | parent | single mutation | rederive | conditions (aee-c ids) | expected rejection | spec |
|---|---|---|---|---|---|---|
| `vf35474dd75d6b14a` | vcc938c6038536dcb | result: "PASS" | - | aee-c-1 aee-c-2 | `result-vocabulary`, `result-recompute-mismatch` (COMPOUND) | L435; L390-393 |
| `vcb23d2c4509c9daf` | vcf20eae7df4f1f1b | carried result: "pass" over a caught row (recompute: fail) | - | aee-c-2 | `result-recompute-mismatch` | L390-393; L435-443 |
| `v27930cf8d66b2b90` | v87d0a19d4b41aafc | carried result: "pass" over a fail-closed out-of-vocabulary label | - | aee-c-2 aee-c-4 | `result-recompute-mismatch` | L443-444 |
| `v621854cac9e3b77b` | v51e9223d08fcc4e1 | carried result: "pass" over a fail-closed unknown method row | - | aee-c-2 aee-c-5 | `result-recompute-mismatch` | L443-444 |
| `va1d44b528c20101b` | v393e5fb361cedaae | carried result: "pass" with a non-empty coverage.outOfScope | - | aee-c-2 aee-c-6 | `result-recompute-mismatch` | L444-446 |
| `ve7d572bb5e39fe9e` | vcc938c6038536dcb | carried result: "fail" where the recompute derives pass | - | aee-c-2 | `result-recompute-mismatch` | L390-393 |
| `ve7fa00ccb08c9987` | vcc938c6038536dcb | carried result: "degraded" where the recompute derives pass | - | aee-c-2 | `result-recompute-mismatch` | L390-393 |
| `v87a339f53f689d9f` | vcc938c6038536dcb | result: "error" | - | aee-c-1 aee-c-2 | `result-vocabulary`, `result-recompute-mismatch` (COMPOUND) | L435 |
| `v14d9059f14696fe6` | vc2782e6c3cbdb9b7 | carried result: "pass" over a clean row that is artifact-basis and reconstructed (recompute: pass_indirect) | - | aee-c-2 | `result-recompute-mismatch` | L390-393 |
| `vaec3b6d70dfbbc47` | vcc938c6038536dcb | carried result: "pass_indirect" where every clean row is substrate-basis and intercepted (recompute: pass) | - | aee-c-2 | `result-recompute-mismatch` | L390-393 |
| `v131478f1be775746` | vcf20eae7df4f1f1b | caught substrate row observationRefs: [] | - | aee-c-10 aee-c-12 | `refs-empty`, `caught-row-uncovered` (COMPOUND) (also carries: `interception-record-orphaned`) | L552; L554-556 |
| `vbe54956653060e0c` | vcf20eae7df4f1f1b | observationRefs: [0, 7] with one record (valid cover kept) | - | aee-c-11 | `ref-out-of-range` | L552-553 |
| `va06ffeb35650b992` | vcf20eae7df4f1f1b | observationRefs: [0, -1] | - | aee-c-11 | `ref-malformed` (also carries: `interception-record-orphaned`) | L552-553 |
| `v59e16f48a28bec9d` | vcf20eae7df4f1f1b | append a fully-valid arming record; caught intercepted row refs only it | recompute-batch-root | aee-c-12 | `caught-row-uncovered` (also carries: `interception-record-orphaned`) | L554-556 |
| `vf362be6b8302b409` | v3fbc377adbe6dcf1 | append a fully-valid interception record; reconstructed row refs only it | recompute-batch-root | aee-c-13 | `reconstructed-row-uncovered` (also carries: `interception-record-orphaned`) | L556-557 |
| `ve025b4bed04cfb68` | vcc938c6038536dcb | clean row refs the arming record only | - | aee-c-14 | `clean-row-uncovered` | L557-560; L1031-1033 |
| `v132435a4d6d10043` | vcc938c6038536dcb | clean row refs the sealed record only | - | aee-c-14 | `clean-row-uncovered` | L557-560; L1031-1033 |
| `va507b8f9a9cc675c` | vcf20eae7df4f1f1b | observationRefs: [0, 1.5] | - | aee-c-11 | `ref-malformed` (also carries: `interception-record-orphaned`) | L552-553 |
| `v85caf3c6f7516ba2` | vcf20eae7df4f1f1b | covering payload re-serialized with reverse-sorted member order | re-sign-record, recompute-batch-root | aee-c-17 | `payload-not-canonical` (also emits: `caught-row-uncovered`, `observed-set-mismatch`) | L561-562; L1310-1317; L625-629 |
| `v61efcc48543d8cea` | vcf20eae7df4f1f1b | covering payload gains an integer member 2^53+1 | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L1312-1316; L99-102 |
| `v94d877ffcc3a30fe` | vcf20eae7df4f1f1b | byte-crafted duplicate aeeMethod member in the covering payload | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L1312-1316 |
| `vbea799eb2cd2852c` | vcf20eae7df4f1f1b | covering record payloadType: "application/octet-stream" | re-sign-record, recompute-batch-root | aee-c-19 | `payload-media-type` (also emits: `caught-row-uncovered`) | L1317-1318 |
| `v9d1f7c44f94cb929` | vcf20eae7df4f1f1b | covering payload gains a member whose NAME carries the supplementary-plane code point U+1F600 | re-sign-record, recompute-batch-root | aee-c-87 | `payload-not-canonical` (also emits: `caught-row-uncovered`, `observed-set-mismatch`) | L150-163 |
| `v08584c6c7d501f77` | vcf20eae7df4f1f1b | drop aeeRunBinding from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L562-563; L1318-1322 |
| `v6c900389fd3f9a1b` | vcf20eae7df4f1f1b | drop aeeKind from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` (also emits: `record-kind-unknown-covers-nothing`) | L562-563; L1322-1341 |
| `v2c7c29f498719ddf` | vcf20eae7df4f1f1b | drop aeeMethod from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L562-563; L1341-1342 |
| `v0cf043f1bc09bccb` | vcc938c6038536dcb | records signed under a binding derived from a DIFFERENT corpus digest (cross-run splice) | recompute-batch-root | aee-c-22 aee-c-62 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L563-564; L226-232 |
| `v5a93b650d229c1bf` | vcf20eae7df4f1f1b | row method "intercepted"; sole covering record signed "reconstructed" | re-sign-record, recompute-batch-root | aee-c-23 | `method-cap-exceeded` | L565-566 |
| `v89cc66f8a44a1977` | vcc938c6038536dcb | records signed with a binding derived from the retired "aeeBindingVersion": "1" pre-image | derive-binding-v1, re-sign-record, recompute-batch-root | aee-c-75 aee-c-22 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L237-241; L563-564 |
| `v081d9eeddbd5634f` | vcc938c6038536dcb | arming payload carries an explicit aeeBindingVersion: "3" the verifier does not implement (read-first, distinct from the bad-303 digest mismatch) | re-sign-record, recompute-batch-root | aee-c-75 | `arming-covers-nothing` | L237-244 |
| `v093aa7f10f378951` | v0099f25838779fcc | row method raised to "intercepted" while the records it resolves carry signed methods {reconstructed, intercepted}: exceeds the weakest | - | aee-c-23 aee-c-45 | `method-cap-exceeded` | L565-566 |
| `vdad33f132b5b08ef` | vcc938c6038536dcb | batchRoot member removed while observationRecords is non-empty | - | aee-c-24 | `batch-root-missing` | L1742; L1754-1756 |
| `v28b0cf874ea02de1` | v3bf3c0fa0e6a52b3 | root computed without the 0x00/0x01 domain-separation prefixes | - | aee-c-25 | `batch-root-mismatch` | L1744-1747 |
| `v4a2da6bda218a1fb` | v3bf3c0fa0e6a52b3 | 3-leaf root computed by duplicate-last-leaf padding instead of the RFC 6962 recursive split | - | aee-c-26 | `batch-root-mismatch` | L1747-1749 |
| `v0ec069decbfbc59f` | v3bf3c0fa0e6a52b3 | root computed over leaves in swapped order | - | aee-c-27 | `batch-root-mismatch` | L1749 |
| `vd70d546cef512eff` | vcc938c6038536dcb | two byte-identical records in the tree; root recomputes CORRECTLY over all three leaves | recompute-batch-root | aee-c-29 | `duplicate-record` | L1751-1752 |
| `v44881386e8e5c467` | vcc938c6038536dcb | one hex digit of batchRoot flipped | - | aee-c-30 | `batch-root-mismatch` | L1754-1756 |
| `v02fe83a8a13cd303` | vcf20eae7df4f1f1b | remove observationRecords AND batchRoot under a substrate row (2-op mutation) | - | aee-c-31 aee-c-11 | `records-absent`, `ref-out-of-range` (COMPOUND) | L1758-1770; L552-553 |
| `v577011f7dd9a08fe` | vc2782e6c3cbdb9b7 | orphan batchRoot added to a recordless artifact-only statement | - | aee-c-31 | `batch-root-orphaned` | L1758-1770; L1750 |
| `v090ca9dadcff9e20` | v9cc570167acf4ae8 | one hex digit off on an artifact-only-with-records statement | - | aee-c-30 aee-c-24 | `batch-root-mismatch` | L1754-1756 |
| `v7622b2c58c2e272d` | vcc938c6038536dcb | a byte-identical second copy of the arming record AND a fourth record, of an unknown kind, whose payload is re-encoded as non-canonical base64 so it no longer strict-decodes | - | aee-c-29 | `duplicate-record`, `record-undecodable` (COMPOUND) | L1751-1752; L1300-1302 |
| `vcac966c6b2ba6295` | vcf20eae7df4f1f1b | substrate row method: "example.method-x" (unknown value); refs, records, root, entropy intact; carried fail kept | - | aee-c-44 aee-c-5 aee-c-42 | `fail-closed-substrate-row` | L760-764; L1060-1097 |
| `v9df7fc4321c024c5` | vcf20eae7df4f1f1b | drop actualLayer from the row | - | aee-c-47 | `malformed-missing-actual-layer` | L927-928; L1269-1277 |
| `v8b78d15e86851925` | vcc938c6038536dcb | clean row actualLayer: "policy.egress_sinkhole" (MUST be the literal "none") | - | aee-c-48 | `clean-row-layer-not-none` | L1278-1283 |
| `vf44cfce2b3744894` | v097ad0cc5b7c0490 | the SECOND of two clean rows carries actualLayer: "policy.egress_sinkhole" while the first keeps the literal "none" | - | aee-c-48 | `clean-row-layer-not-none` | L1278-1283 |
| `v692f9605520a617d` | vc2782e6c3cbdb9b7 | artifact clean row actualLayer: "policy.egress_sinkhole" (a clean row MUST carry the literal "none" regardless of basis) | - | aee-c-48 | `clean-row-layer-not-none` | L1278-1283 |
| `v539055896bf3a954` | vcf20eae7df4f1f1b | substrate row containmentObserved: "example_label_a" (not in carried labels); carried fail kept | - | aee-c-4 aee-c-44 | `fail-closed-substrate-row` (also carries: `interception-record-orphaned`) | L443-444; L760-764 |
| `v84f40e16772e5f91` | vcf20eae7df4f1f1b | substrate row method member ABSENT | - | aee-c-5 aee-c-42 aee-c-44 | `fail-closed-substrate-row` | L443-444; L1060-1097; L760-764 |
| `v3eb268f467674845` | vcf20eae7df4f1f1b | caught row actualLayer carried as the JSON number 7 (wrong member type); refs, records, root, entropy intact; carried fail kept | - | aee-c-88 | `statement-malformed` (also carries: `malformed-missing-actual-layer`) | L920-928 |
| `v089e746847cd0af2` | vc2782e6c3cbdb9b7 | drop observationVocabulary; carried fail kept | - | aee-c-51 | `vocabulary-missing` | L796-804 |
| `v109b606952f6ee6c` | vcc938c6038536dcb | caught gains "example_label_x" which is not in labels; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-52 | `vocabulary-caught-not-subset` | L800-802 |
| `v62e5552063975fc9` | vcc938c6038536dcb | labels in descending order; digest recomputed | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-53 | `vocabulary-not-canonical` | L802 |
| `vded1d495746a647a` | vcc938c6038536dcb | duplicate entry in caught; digest recomputed | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-53 | `vocabulary-not-canonical` | L802 |
| `v7ecdfe261d1dcd84` | vcc938c6038536dcb | stale vocabulary digest over unchanged content | rederive-binding, re-sign-record, recompute-batch-root | aee-c-54 | `vocabulary-digest-mismatch` | L802-804 |
| `v3d70f1cdb9050246` | vcc938c6038536dcb | drop runEntropy on a substrate-row-carrying statement | - | aee-c-57 | `run-entropy-missing` (also emits: `sealed-record-absent`) | L808-810; L224-225 |
| `v6f6941efba2cbe28` | vcc938c6038536dcb | second subject appended to a substrate-row-carrying statement | - | aee-c-58 | `subject-cardinality` | L210-213 |
| `v495bb03f306ef6aa` | vcc938c6038536dcb | runEntropy digest upper-cased; binding rederived VERBATIM over the uppercase value and records re-signed with it | rederive-run-binding-verbatim, re-sign-record, recompute-batch-root | aee-c-59 | `digest-not-canonical` | L210-224 |
| `vbd93d974436e11eb` | vcc938c6038536dcb | substrate digest truncated to 63 hex chars; verbatim rederive chain | rederive-run-binding-verbatim, re-sign-record, recompute-batch-root | aee-c-59 | `digest-not-canonical` | L210-224 |
| `va54b6faefcfb1f9e` | vcf20eae7df4f1f1b | labels: [] and caught: [] (digest recomputed) under a substrate row whose label is now out-of-vocabulary | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-4 aee-c-44 aee-c-53 | `fail-closed-substrate-row` (also carries: `interception-record-orphaned`) | L760-764; L802 |
| `v886b2a92cf14bd54` | vcc938c6038536dcb | subject digest carries only sha512 | - | aee-c-59 aee-c-60 | `subject-sha256-missing` (also emits: `sealed-record-absent`) | L210-224 |
| `v4fb9c4caa3a2cd8d` | vcf20eae7df4f1f1b | labels gains the supplementary-plane entry U+1F600; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-86 | `vocabulary-not-canonical` | L150-163 |
| `v6b15bd108cb9c27a` | vcc938c6038536dcb | drop armedAt from the arming payload | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1323-1327; L1344-1347 |
| `v05f8f5c8bb0b1d43` | vcc938c6038536dcb | arming armedAt: "2026-01-01T00:01:00Z" (after issuedAt) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1326-1327 |
| `vb704d6c2420a1c43` | vcc938c6038536dcb | arming aeePostureDigest differs from the pinned posture digest | re-sign-record, recompute-batch-root | aee-c-63 aee-c-65 | `arming-covers-nothing`, `sealed-covers-nothing`, `clean-row-uncovered` (COMPOUND) (also emits: `sealed-record-absent`) | L1323-1327; L1361-1366 |
| `vb730e62ac8f072b0` | vcc938c6038536dcb | arming record signed aeeMethod: "reconstructed" | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1327; L1344-1347 |
| `vc994d0402bf6b129` | vcc938c6038536dcb | drop aeeDropCount from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L1330-1335 |
| `v1471516f09370430` | vcc938c6038536dcb | sealed aeeStillArmed: "true" (string, not boolean) | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L1330-1335 |
| `vea5ff2dabe340db7` | vcc938c6038536dcb | sealed aeeStillArmed: false | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1361-1366 |
| `vab69ab3304958ebd` | vcc938c6038536dcb | sealed aeeDropCount: 3 with no aeeDropBound declared | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1361-1366 |
| `v9982646034457eb6` | v02f2be8cd63828f4 | sealed aeeDropCount: 6 exceeding the declared aeeDropBound: 5 | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1361-1366 |
| `v9d0f50db6d287d35` | vcc938c6038536dcb | sealed aeePostureDigest edited (differs from the arming record's AND the pinned digest, which the arming constraint makes equivalent) | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` (COMPOUND) | L1361-1366 |
| `v205d5ea1079eb8e5` | v3fbc377adbe6dcf1 | examination record signed aeeMethod: "intercepted" | re-sign-record, recompute-batch-root | aee-c-66 | `examination-covers-nothing` | L1336-1338; L1344-1347 |
| `vc05cf94374f0d0d6` | vcc938c6038536dcb | clean row refs [good-arming, non-covering-sealed]; a fully-covering sealed record sits UNREFERENCED and EARLIER in the tree | recompute-batch-root | aee-c-68 | `sealed-covers-nothing` | L1187-1188; L557-560 |
| `v5dcc150714259e09` | vcc938c6038536dcb | the arming record's aeeKind becomes "aee-future-x" (record otherwise fully valid); the clean row's only arming ref now covers nothing | re-sign-record, recompute-batch-root | aee-c-71 | `record-kind-unknown-covers-nothing` | L1687-1691 |
| `v6a727606acc4b146` | vcc938c6038536dcb | drop aeeStillArmed from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L1330-1335 |
| `v73659435d1998490` | vcc938c6038536dcb | drop aeePostureDigest from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 aee-c-65 | `sealed-covers-nothing` | L1330-1335; L1361-1366 |
| `vc79ff8c5db77cc00` | vcc938c6038536dcb | drop aeePostureDigest from the arming payload | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1323-1327 |
| `v1b0b0cafb5ee8d08` | vcc938c6038536dcb | armedAt carries a non-zero UTC offset (+05:00): a valid instant no later than issuedAt, but not RFC 3339 UTC | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1326 |
| `v423dab49f4ed4d29` | vc2782e6c3cbdb9b7 | a second subject appended to an ARTIFACT-ONLY statement (no substrate rows) | - | aee-c-58 | `subject-cardinality` | L210-213 |
| `vf14f5310b2f02875` | vcf20eae7df4f1f1b | a second attackResults row carrying the SAME attackId as the first (one row per executed attack) | - | aee-c-90 | `statement-malformed` | L920-932 |
| `v70e970d18ae52833` | v393e5fb361cedaae | class XA appears in BOTH assessedClasses and outOfScope: the three coverage sets are not a disjoint partition | - | aee-c-82 | `coverage-incomplete` | L912-916 |
| `vef2571e9001d7bd1` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 0 with aeeChainScope present (a sequence number is a positive integer) | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1611-1642 |
| `v3cf298b019a0405f` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 1 with NO aeeChainScope (aeeChainScope is required whenever aeeRunSeq is present) | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1611-1642 |
| `v2bac3fa36d7a5947` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 2, aeeChainScope, and an aeePrevRunBinding that is not lowercase 64-hex | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1611-1642 |
| `v8a7008d1673711a9` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 1 with aeeChainScope as a free-form string, not the required array of registered dimension tokens | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1615-1619 |
| `v4360d4e15f84145f` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 1 with an aeeChainScope carrying a token outside the closed dimension vocabulary | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1615-1619 |
| `v04993666ec44cda9` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 1 with an aeeChainScope array whose tokens are not in canonical (UTF-16 code-unit) order | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1615-1619 |
| `v8a7532ae4cffa163` | vcc938c6038536dcb | arming payload gains aeeRunSeq: 1 with an aeeChainScope whose first token is registered and whose second is outside the closed dimension vocabulary | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1615-1619 |
| `v3300d78454ab852f` | v9cc570167acf4ae8 | an artifact row carries an observationRefs index out of range for observationRecords (fail-closed on any row, not only substrate rows) | - | aee-c-11 | `ref-out-of-range` | L552-553; L946-951 |
| `vc19ea5aaacc5b72a` | v9cc570167acf4ae8 | an artifact row carries an in-range observationRefs index and then one out of range for observationRecords | - | aee-c-11 | `ref-out-of-range` | L552-553; L946-951 |
| `v1a3d0ce04c3f7524` | vf1fcbad160189ca5 | the artifact row that follows a fully covered substrate row carries an observationRefs index out of range for observationRecords | - | aee-c-11 | `ref-out-of-range` | L552-553; L946-951 |
| `v5155dde01a4538fd` | vcc938c6038536dcb | raw statement bytes carrying a duplicate top-level predicateType member (the whole statement is parsed as strict I-JSON, not only record payloads) | - | aee-c-18 | `statement-malformed` | L100-106 |
| `v8a866332628b4b6f` | vcc938c6038536dcb | v0.5 predicateType URI on a v0.7-shaped statement | - | aee-c-77 | `predicate-type-unsupported` | L3; L317 |
| `v6275ec117f5e7e99` | vc2782e6c3cbdb9b7 | drop catchPolicy | - | aee-c-78 | `environment-incomplete` | L783-793 |
| `v02fd1bc1d7916002` | vc2782e6c3cbdb9b7 | corpus.digest is not the JCS digest of the embedded manifest | - | aee-c-79 | `corpus-digest-mismatch` | L787-791; L810-813 |
| `v3b58f7a2e30d8cad` | vc7a74e2cef5586ed | XA-EXAMPLE-1 appears under two manifest classes; corpus digest recomputed | recompute-corpus-digest | aee-c-80 | `manifest-duplicate-attack` | L789-791 |
| `v210a8e2d17bfcc47` | vcf20eae7df4f1f1b | row attackId: "XA-EXAMPLE-9" absent from the manifest | - | aee-c-81 aee-c-82 | `row-attack-unknown`, `coverage-incomplete` (COMPOUND) | L920; L963-966 |
| `vaf114f3145d4a55a` | vf88590533f7b3599 | one of the two rows of a 2-attack assessed class deleted (quiet omission) | - | aee-c-82 | `coverage-incomplete` (also emits: `interception-record-orphaned`) | L963-966 |
| `vbbbcb6a491ac43c0` | v393e5fb361cedaae | added artifact-basis clean row for the outOfScope class's attack; result stays degraded | - | aee-c-82 | `coverage-incomplete` | L963-966 |
| `v212f439c82b123ed` | v393e5fb361cedaae | manifest class XB dropped from all three coverage sets (not assessed, not outOfScope, not routedElsewhere), result forced to pass: the class-granularity coverage-partition fail-open | - | aee-c-82 | `coverage-incomplete` | L907-912; L963-966 |
| `v5a842871df5bfe33` | vcf20eae7df4f1f1b | assessedClasses padded with class XZ the manifest never carried | - | aee-c-82 | `coverage-incomplete` | L912-916; L963-966 |
| `vb3c92d4ecb62bbfb` | v393e5fb361cedaae | outOfScope carries class XZ the manifest never carried | - | aee-c-82 | `coverage-incomplete` | L912-916; L963-966 |
| `ved230b46692c0ada` | v393e5fb361cedaae | routedElsewhere carries class XZ the manifest never carried | - | aee-c-82 | `coverage-incomplete` | L912-916; L963-966 |
| `v5717f72827e39413` | vcc938c6038536dcb | vocabulary label carrying an unpaired high surrogate escape; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L104-130 |
| `v198c19b52cf8890e` | vcc938c6038536dcb | vocabulary label carrying an unpaired low surrogate escape; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L104-130 |
| `v86f3484735f41acb` | vcc938c6038536dcb | vocabulary label carrying a low surrogate followed by a high surrogate; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L104-130 |
| `vf5599bb2dbe66e12` | vcc938c6038536dcb | vocabulary label carrying a surrogate encoded directly in UTF-8 (CESU-8, ED A0 80); digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L104-130 |
| `vbc7012fb2fcbf1f8` | vcc938c6038536dcb | vocabulary label carrying the overlong encoding C0 AF; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L104-130 |
| `vb705b260669aedc7` | vcc938c6038536dcb | vocabulary label carrying a raw unescaped U+0001; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L104-130 |
| `vdef377fb4f572b4d` | vcf20eae7df4f1f1b | covering payload gains a member whose value carries an unpaired surrogate escape | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L1274-1277 |
| `v5e14357c80f6239b` | vcf20eae7df4f1f1b | covering payload gains a member whose value carries a surrogate encoded directly in UTF-8 (CESU-8, ED A0 80) | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L1274-1277 |
| `v08251931ec038e91` | vcf20eae7df4f1f1b | covering payload nested 129 deep, one level past the normative bound | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L145-152 |
| `v83f4b7fe6068ef86` | vcf20eae7df4f1f1b | covering payload nested 129 deep with an empty-container leaf, one past the bound | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L145-152 |
| `va501d76c995de6d3` | vcc938c6038536dcb | vocabulary label carrying the noncharacter U+FFFF | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L110-137 |
| `v0e731123ead5b96e` | vcf20eae7df4f1f1b | covering payload gains a member whose value carries the noncharacter U+FFFF | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` (also carries: `observed-set-mismatch`) (also emits: `caught-row-uncovered`) | L110-137 |
| `vca61adf35d265632` | vcf20eae7df4f1f1b | covering record's signatures array emptied to [] | - | aee-c-91 | `record-signatures-empty` | L1300-1302 |
| `ve0e5dddf8f3b812a` | vcf20eae7df4f1f1b | covering record's signatures member replaced with the JSON string "sig" | - | aee-c-91 | `record-signatures-empty` | L1300-1302 |
| `v3418101227718535` | vc2782e6c3cbdb9b7 | corpus manifest emptied to {"classes": {}}; the row it declared and that row's coverage entry come out with it | drop-undeclared-rows, rebuild-coverage-partition, recompute-corpus-digest | aee-c-92 | `corpus-manifest-no-attacks` | L968-990 |
| `v22f545b6ff400646` | vc2782e6c3cbdb9b7 | corpus manifest keeps class XA but empties its attack-id array; the row it declared and that row's coverage entry come out with it | drop-undeclared-rows, rebuild-coverage-partition, recompute-corpus-digest | aee-c-92 | `corpus-manifest-no-attacks` | L968-990 |
| `v4ff6cb70764bf703` | v3fbc377adbe6dcf1 | covering record payload re-encoded as non-canonical base64 (nonzero trailing bits); the record no longer strict-decodes | - | aee-c-19 | `record-undecodable` (also carries: `observed-set-mismatch`) (also emits: `payload-not-canonical`, `reconstructed-row-uncovered`) | L1288-1291 |
| `v7236a3440b6a398a` | vcc938c6038536dcb | drop coverage | - | aee-c-83 | `coverage-missing` | L905-909 |
| `v3c3a76f63bf8dda8` | vcc938c6038536dcb | statement carries the rejected snake_case spelling of doesNotAssert | - | aee-c-84 | `member-spelling` | L1772-1782 |
| `vd873c2f37814b8f8` | vc2782e6c3cbdb9b7 | drop issuedAt | - | aee-c-85 | `issued-at-missing` | L1784 |
| `v2729ba35eb041b05` | vc2782e6c3cbdb9b7 | issuedAt: "yesterday" | - | aee-c-85 | `issued-at-malformed` | L1784 |
| `vb2f1fb954c994515` | vc2782e6c3cbdb9b7 | drop networkPosture | - | aee-c-78 | `environment-incomplete` | L783-794 |
| `v2adb319fc7515885` | vc2782e6c3cbdb9b7 | drop corpus | - | aee-c-78 | `environment-incomplete` | L783-791 |
| `v8966a040c3decefc` | vc2782e6c3cbdb9b7 | drop substrate | - | aee-c-78 | `environment-incomplete` | L783-787 |
| `v2be8b19383a5c613` | vcc938c6038536dcb | _type is not the in-toto Statement/v1 URI | - | aee-c-77 | `statement-type-unsupported` | L313 |
| `v3c527c28aa2da8db` | vcc938c6038536dcb | arming armedAt: "2025-12-31t23:59:00Z" (lowercase date-time separator) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1326 |
| `v65fa8117aa487fbe` | vcc938c6038536dcb | arming armedAt: "2025-12-31T23:59:00z" (lowercase zone designator) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1326 |
| `vc9f401685f448104` | vc2782e6c3cbdb9b7 | issuedAt: "2026-01-01T05:00:00+05:00" (a non-zero UTC offset) | - | aee-c-85 | `issued-at-malformed` | L1784 |
| `v28d48cc69a324b81` | vc2782e6c3cbdb9b7 | issuedAt: "2026-01-01t00:00:00Z" (lowercase date-time separator) | - | aee-c-85 | `issued-at-malformed` | L1784 |
| `v7d4d7d92a346c7a5` | vc2782e6c3cbdb9b7 | issuedAt: "2026-01-01T00:00:00z" (lowercase zone designator) | - | aee-c-85 | `issued-at-malformed` | L1784 |
| `v1d1ba5041819e108` | vcc938c6038536dcb | networkPosture.posture: "example_posture_x", a value the registry does not carry | rederive-binding, re-sign-record, recompute-batch-root | aee-c-93 | `posture-vocabulary` | L847-855 |
| `vc0340fb3e51cb2b3` | vcc938c6038536dcb | networkPosture.posture: 3, a value of the wrong JSON type | rederive-binding, re-sign-record, recompute-batch-root | aee-c-93 | `posture-vocabulary` | L847-855 |
| `va729442fd496e59a` | vcc938c6038536dcb | networkPosture.posture: ["sinkhole"], an array wrapping a registered value | rederive-binding, re-sign-record, recompute-batch-root | aee-c-93 | `posture-vocabulary` | L847-855 |
| `vc8e3b44ea967460b` | vcc938c6038536dcb | networkPosture.posture swapped from "sinkhole" to "allowlist"; every digest, signature and record left exactly as the producer signed them | - | aee-c-22 aee-c-60 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L174-182; L563-564 |
| `v51dd58a56a16716d` | vcc938c6038536dcb | caught narrowed to [] with the vocabulary digest re-derived over the narrowed arrays; the records keep the binding they were signed with | recompute-vocabulary-digest | aee-c-22 aee-c-60 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L174-182; L563-564 |
| `v77fb0077815e78cc` | vcc938c6038536dcb | networkPosture gains a producer member the records do not commit to | - | aee-c-22 aee-c-60 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L174-182; L563-564 |
| `v26f7c477598f8207` | v3bf3c0fa0e6a52b3 | a fully covered clean row also resolves the caught row's interception record | - | aee-c-94 | `clean-row-contradicted` | L574-579 |
| `v2d1f9da3e912c63a` | vcf20eae7df4f1f1b | the caught row is re-pointed at the sealed record, leaving the interception record resolved by nobody | - | aee-c-95 | `caught-row-uncovered`, `interception-record-orphaned` (COMPOUND) | L580-585 |
| `vdec5ea66f3ff63d5` | vcf20eae7df4f1f1b | the sealed record is deleted from a statement carrying a substrate row | recompute-batch-root | aee-c-96 | `sealed-record-absent` | L586-594 |
| `vc66a19c407888f78` | vf88590533f7b3599 | one interception is deleted with its row and the root recomputed over what remains, while the seal still commits to the deleted record | rederive-binding, re-sign-record, recompute-batch-root | aee-c-97 | `observed-set-mismatch` | L609-613; L1499-1508 |
| `vc2432d962eedc6a8` | vcf20eae7df4f1f1b | an interception record the seal does not commit to is appended and resolved by the caught row | recompute-batch-root | aee-c-97 | `observed-set-mismatch` | L609-613; L1499-1508 |
| `vea599b89dfdc6a0a` | vcc938c6038536dcb | a second sealed record bound to this run commits to an observed set one digit away from the recompute, while the first still commits to it | recompute-batch-root | aee-c-97 | `observed-set-mismatch` | L609-613; L1499-1508 |
| `v98eef7d31c9870b6` | vcc938c6038536dcb | a second sealed record bound to this run names an attack whose only row reports a clean containment, while the first names none | recompute-batch-root | aee-c-98 | `observed-attack-uncaught` | L1535-1542 |
| `v559ea641021fea75` | vcc938c6038536dcb | a second arming record bound to this run declares an empty assessed set while the first declares the identifier the coverage assesses | recompute-batch-root | aee-c-99 | `assessed-set-exceeds-declaration` | L1467-1473 |
| `v41de149d50373e9e` | vcc938c6038536dcb | the seal names an attack whose only row reports a clean containment | re-sign-record, recompute-batch-root | aee-c-98 | `observed-attack-uncaught` | L1535-1542 |
| `v320cc6344593c639` | v73244f2068e58c68 | the seal keeps its first named attack, whose row reports a catch, and replaces the second with the declared attack whose row is clean | re-sign-record, recompute-batch-root | aee-c-98 | `observed-attack-uncaught` | L1535-1542 |
| `vde0891384c1018ae` | vf88590533f7b3599 | the seal names two attacks and the statement carries a row for only one | re-sign-record, recompute-batch-root | aee-c-98 | `coverage-incomplete`, `observed-attack-uncaught` (COMPOUND) | L1535-1542 |
| `vfae885f5e5f78197` | v393e5fb361cedaae | the arming record declares only the class the run did NOT assess, so the assessed set is not a subset of the run-start declaration | re-sign-record, recompute-batch-root | aee-c-99 | `assessed-set-exceeds-declaration` | L1467-1473 |
| `v99fb4ac5cb385049` | v9383066da404cbda | the interception is deleted and the pinned row re-pointed at the seal | recompute-batch-root | aee-c-100 | `caught-row-uncovered`, `attribution-pinned-recordless` (COMPOUND) | L614-623 |
| `va246c9dbdf73e8cf` | v9383066da404cbda | the corpus manifest carries no expectedPayloads entry for the attack the pinned row names | rederive-binding, re-sign-record, recompute-batch-root | aee-c-101 | `attribution-unpinnable` | L614-623; L815-821 |
| `v4730792ca7a8691e` | v9383066da404cbda | the interception the pinned row resolves commits to a value the corpus did not declare for that attack | rederive-binding, re-sign-record, recompute-batch-root | aee-c-102 | `attribution-pin-unmatched` | L614-623 |
| `v6662e73ba03dfd36` | vcf20eae7df4f1f1b | the manifest's expectedPayloads names an attack its own classes do not declare | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-103 | `manifest-expected-payloads-malformed` | L815-821 |
| `v2dd443f340e8a1c7` | vcf20eae7df4f1f1b | an expectedPayloads array carries its two entries in descending order | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-103 | `manifest-expected-payloads-malformed` | L815-821 |
| `vf8029fa61d5f1b13` | vcf20eae7df4f1f1b | an expectedPayloads entry is not lowercase 64-hex | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-103 | `manifest-expected-payloads-malformed` | L815-821 |
| `v1a8005dac6c3e806` | vcf20eae7df4f1f1b | an expectedPayloads array carries no entry | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-103 | `manifest-expected-payloads-malformed` | L815-821 |
| `vc7111b58eecb4d0c` | vcf20eae7df4f1f1b | the interception record's aeePayloadCommitment carries an entry that is not lowercase 64-hex | re-sign-record, recompute-batch-root | aee-c-104 | `payload-commitment-malformed` | L1454-1465 |
| `vf6717a2ded406b68` | vcf20eae7df4f1f1b | the interception record's aeePayloadCommitment carries the parent's valid entry and then one that is not lowercase 64-hex | re-sign-record, recompute-batch-root | aee-c-104 | `payload-commitment-malformed` | L1454-1465 |
| `v0ac6d948f2af5b6f` | vcf20eae7df4f1f1b | the interception record's aeePayloadCommitment is an empty array | re-sign-record, recompute-batch-root | aee-c-104 | `payload-commitment-malformed` | L1454-1465 |
| `v244bd03c59cd03cc` | vcf20eae7df4f1f1b | the interception record carries no aeePayloadCommitment at all | re-sign-record, recompute-batch-root | aee-c-104 | `payload-missing-reserved` | L1454-1465 |
| `v590d80afd6a67f0f` | vcf20eae7df4f1f1b | the caught substrate row carries no attribution member | - | aee-c-105 | `fail-closed-substrate-row` | L1093-1097 |
| `vb370622a59690b75` | vcf20eae7df4f1f1b | the caught substrate row carries attribution: "example_strong" | - | aee-c-105 | `fail-closed-substrate-row` | L1093-1097 |
| `v9d92e2e234987c76` | vc2782e6c3cbdb9b7 | an artifact-only clean row carries no attribution member, so the row fail-closes and the carried result no longer recomputes | - | aee-c-105 | `result-recompute-mismatch` | L1093-1097 |
| `v38dc376c7746314b` | vc2782e6c3cbdb9b7 | an artifact-only clean row carries attribution: "example_strong" | - | aee-c-105 | `result-recompute-mismatch` | L1093-1097 |
| `vbc974f64e9105f97` | vcf20eae7df4f1f1b | a second interception record is carried that no caught row resolves, while the caught row keeps its own | recompute-batch-root | aee-c-95 | `interception-record-orphaned` | L580-585 |
| `vacd28b5127a54254` | vcc938c6038536dcb | a fully covered CLEAN row declares attribution: pinned and therefore resolves no interception record | rederive-binding, re-sign-record, recompute-batch-root | aee-c-100 | `attribution-pinned-recordless` | L614-623 |
| `v42c1c063e3ecf305` | vcc938c6038536dcb | drop aeeObservedSet from the sealed payload | re-sign-record, recompute-batch-root | aee-c-97 | `sealed-covers-nothing` | L1499-1508 |
| `v81c4d6a0592c51d9` | vcc938c6038536dcb | drop aeeObservedAttacks from the sealed payload | re-sign-record, recompute-batch-root | aee-c-98 | `sealed-covers-nothing` | L1535-1542 |
| `v1b77d64eede0add3` | vcc938c6038536dcb | the sealed aeeObservedAttacks names an identifier the manifest does not declare | re-sign-record, recompute-batch-root | aee-c-98 | `sealed-covers-nothing` | L1535-1542 |
| `v84c52616decf0653` | vcc938c6038536dcb | drop aeeAssessedAttacks from the arming payload | re-sign-record, recompute-batch-root | aee-c-99 | `arming-covers-nothing` | L1467-1473 |
| `v37b29638601ce5ba` | v9cc570167acf4ae8 | an artifact-only statement carries an interception record that no caught row resolves | recompute-batch-root | aee-c-95 | `interception-record-orphaned` | L569-585 |
| `va763626ffc99b681` | v097ad0cc5b7c0490 | the arming aeeAssessedAttacks carries its two entries in descending order | re-sign-record, recompute-batch-root | aee-c-99 | `arming-covers-nothing` | L1467-1473 |
| `vea9deaa7d7ef8934` | v097ad0cc5b7c0490 | the arming aeeAssessedAttacks names the two identifiers the manifest declares and then a third the manifest does not | re-sign-record, recompute-batch-root | aee-c-99 | `arming-covers-nothing` | L1467-1473 |
| `v0639562eb10e87fb` | vcf20eae7df4f1f1b | the caught row's only resolved record is a moat-drop, which covers nothing in every state | rederive-binding, re-sign-record, recompute-batch-root | aee-c-106 | `moat-drop-covers-nothing` | L1394-1408; L1410-1423 |
| `vece82b6a9a07327a` | vcf20eae7df4f1f1b | the caught row's only resolved record is an uncommitted-observation, which covers nothing in every state | rederive-binding, re-sign-record, recompute-batch-root | aee-c-107 | `uncommitted-observation-covers-nothing` | L1394-1408; L1425-1438 |
| `v6ed1e2626b2af5ad` | vd1aa74416099f3f0 | the two pinned rows exchange observationRefs; the record set, every signature and the batch root are untouched | - | aee-c-102 | `attribution-pin-unmatched` | L614-623 |
| `v1e9751e918994a98` | v36fe88ae1da31194 | the second interception the pinned row resolves commits to the value the corpus declared for the OTHER attack; the first still matches | re-sign-record, recompute-batch-root | aee-c-102 | `attribution-pin-unmatched` | L614-623 |
| `v3772d801e5cae557` | v36fe88ae1da31194 | an expectedPayloads array carries the parent's two valid entries and then one that is not lowercase 64-hex | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-103 | `manifest-expected-payloads-malformed` (also emits: `attribution-unpinnable`) | L815-821 |
| `v113349f8afb946bf` | v36fe88ae1da31194 | expectedPayloads gains, after the two attacks the manifest declares, an entry keyed on an identifier it does not | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-103 | `manifest-expected-payloads-malformed` (also emits: `attribution-unpinnable`) | L815-821 |
| `v1043dbabae5f8ace` | vda285efc96ac6e75 | the middle channel's interception commits to a value the corpus declared for no attack, with the first and last channels left satisfied | re-sign-record, recompute-batch-root | aee-c-102 | `attribution-pin-unmatched` | L614-623 |
| `v0e22ac9c30338ad5` | vda285efc96ac6e75 | the corpus drops the last channel's expectedPayloads entry while its row keeps declaring pinned | recompute-corpus-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-101 | `attribution-unpinnable` | L614-623; L815-821 |
| `v21e964dddeba0d08` | vda285efc96ac6e75 | the middle channel's interception is deleted and its row re-pointed at the seal, which still names the channel's attack | recompute-batch-root | aee-c-100 | `caught-row-uncovered`, `attribution-pinned-recordless` (COMPOUND) | L614-623 |
| `v7f62f32c0ccda2fb` | vcc938c6038536dcb | sealed record signed aeeMethod: "reconstructed" | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1330-1335; L1344-1347 |
| `v1ec06de44fe4000d` | v02f2be8cd63828f4 | sealed aeeDropCount: -1 inside a declared aeeDropBound: 5 | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1361-1366 |
| `v7f35f318b31ca92a` | vcc938c6038536dcb | a second arming record carrying a posture digest the run never pinned, referenced by the clean row alongside the valid arming and sealed pair | recompute-batch-root | aee-c-65 | `sealed-covers-nothing` (also carries: `arming-covers-nothing`) (also emits: `sealed-record-absent`) | L1361-1366 |
| `v300ab22f5f2fe523` | vc7a74e2cef5586ed | drop labels from an observationVocabulary that is otherwise present; digest re-derived over the truncated object | recompute-vocabulary-digest | aee-c-51 | `vocabulary-not-canonical` | L796-804 |
| `v03547f8918e0d7dc` | vc7a74e2cef5586ed | drop corpus.manifest, keeping the corpus name, uri and digest | - | aee-c-78 | `environment-incomplete` | L783-793 |
| `v59b24935f1fa8a4b` | vcc938c6038536dcb | as `bad-705-sealed-missing-dropcount`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v755ceccd7c4da990` | vcc938c6038536dcb | as `bad-706-stillarmed-non-boolean`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v4da2f99ac2897154` | vcc938c6038536dcb | as `bad-707-sealed-stillarmed-false`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v80e2a3fba582ed4d` | vcc938c6038536dcb | as `bad-708-sealed-drops-no-bound`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `vd7be865fc69eacc2` | v02f2be8cd63828f4 | as `bad-709-sealed-drops-exceed-bound`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v7258b9f4ed52a08d` | vcc938c6038536dcb | as `bad-710-sealed-posture-mismatch`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `vfb979cb9ce40f1be` | vcc938c6038536dcb | as `bad-713-only-sealed-ref-noncovering`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v7fefd467a21566ca` | vcc938c6038536dcb | as `bad-715-sealed-missing-stillarmed`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v0d364d8f9d815092` | vcc938c6038536dcb | as `bad-716-sealed-missing-posture`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `veb0e5002608390cc` | vcc938c6038536dcb | as `bad-900-sealed-method-reconstructed`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `vb1337e5ecad985c2` | v02f2be8cd63828f4 | as `bad-901-sealed-negative-dropcount`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `vd9041fbad8a6b721` | vcc938c6038536dcb | as `bad-974-sealed-missing-observedset`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `va62d3b1847c9e0bd` | vcc938c6038536dcb | as `bad-975-sealed-missing-observedattacks`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `v47fc43d883b16a9b` | vcc938c6038536dcb | as `bad-976-sealed-observedattacks-unknown`, with the clean row's seal reference moved to the healthy seal the statement already carries; the defective seal stays carried and stays signed | - | aee-c-108 | `sealed-covers-nothing` | L586-594; L1322-1366 |
| `vc325d584b58dcc99` | vcc938c6038536dcb | a second arming record carrying no armedAt, referenced by no row; the clean row keeps its healthy arming and sealed pair | recompute-batch-root | aee-c-108 | `arming-covers-nothing` | L586-594; L1322-1366 |
| `vb877a9c1703557b2` | vcc938c6038536dcb | an examination record signed aeeMethod: "intercepted", referenced by no row; the clean row keeps its healthy arming and sealed pair | recompute-batch-root | aee-c-108 | `examination-covers-nothing` | L586-594; L1336-1338 |
| `vd538496f284b4761` | vcf20eae7df4f1f1b | the statement's only sealed record carries aeeStillArmed false; every row is caught, so no clean row is left uncovered and nothing fires ahead of the run-level checks | recompute-batch-root | aee-c-96 | `sealed-record-absent` (also carries: `sealed-covers-nothing`) | L586-594; L595-608; L634-643; L1361-1366 |
| `vb79f5508ae0c97d4` | va4d6b048f2e9cc5f | subject[0].digest.sha256 moved from admission receipt A to admission receipt B; every record left exactly as the producer signed it for A | - | aee-c-22 aee-c-60 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L174-182; L563-564 |
| `v399c693cbf60143b` | vcc938c6038536dcb | a second subject entry naming an external admission receipt appended beside the executed artifact | - | aee-c-58 | `subject-cardinality` | L210-213 |
| `vf6d46cca59bd2748` | vcc938c6038536dcb | observationEnvironment.substrate.digest.sha256 replaced with a second observation-substrate digest; every record left exactly as the producer signed it | - | aee-c-22 aee-c-60 | `run-binding-mismatch` (also carries: `sealed-record-absent`) | L174-182; L563-564 |

## Notes on specific vectors

- **bad-001-result-uppercase**: uppercase token is both out-of-vocabulary and not the recompute.
- **bad-006-result-fail-on-pass**: equality is two-directional.
- **bad-009-result-pass-on-indirect-clean-row**: this is the statement a party holding only the enclosing envelope key produces by moving every row to artifact basis and dropping the records: valid before the fourth result value existed, and a recompute mismatch after it.
- **bad-010-result-pass-indirect-on-direct-clean-row**: the new token is not a floor a producer may volunteer down to; equality is two-directional here exactly as it is for bad-006.
- **bad-101-refs-empty**: an empty ref set on a caught row inherently also uncovers it.
- **bad-201-payload-unsorted-keys**: rawBytes: the committed base64 payload bytes are the fault; identical content, non-JCS order.
- **bad-202-payload-bignum**: rawBytes.
- **bad-203-payload-duplicate-member**: rawBytes.
- **bad-204-payload-media-type**: PAE covers payloadType, so the record is re-signed: the media type is the ONLY fault.
- **bad-208-payload-member-non-bmp**: rawBytes; BMP-only string profile: the name sorts last under BOTH the UTF-16 and the code-point member order, so the payload bytes stay canonical under either reading and the supplementary-plane member NAME is the single fault (a supplementary-plane member VALUE stays legal).
- **bad-301-run-binding-splice**: the statement's own corpus is unchanged; the records were earned under another run's environment.
- **bad-303-binding-version-1**: negative known-answer: version 1 is retired with no alias and no dual-accept window, so its pre-image MUST NOT match; a verifier has exactly one construction and never tries a second. The vector is named for the construction its records were minted under, and it is the retired one rather than a future one on purpose: a vector minted under a version nobody has implemented rejects whether or not the rule holds, because its digest matches no construction at all, while this one is a digest a real producer could have emitted last revision.
- **bad-726-arming-binding-version-carried**: an explicit binding-version declaration the verifier does not implement is read before deriving and makes the arming record cover nothing, distinguishably from a run-binding digest mismatch. The declared version has to be one no verifier implements, so it moves whenever the implemented construction does: it read "2" while the implemented construction was version 1, and left that value in place the version 2 landed, at which point the record declared exactly what the verifier derives and the vector asserted nothing.
- **bad-304-method-cap-multirecord**: min-composition: a max()/any() rail wrongly accepts this.
- **bad-405-duplicate-records**: single fault: duplicate identity, not root arithmetic.
- **bad-407-substrate-row-no-records**: precedence pin: records-absent is reported when the array is absent entirely; ref-out-of-range only when records exist.
- **bad-409-artifact-records-bad-root**: the root check is statement-level: it runs even with zero substrate rows.
- **bad-410-duplicate-and-undecodable-record**: inherently compound, and the pairing is the whole vector: a statement carrying a duplicate and an undecodable record at once is what separates a rail that scans for duplicates among the records that DID decode from one that waits for all of them to. The second answers the decode failure and drops the duplicate finding entirely, and until this vector no statement in the corpus asked. The undecodable record is a fourth one rather than one of the duplicated pair, because faulting either half of a duplicate leaves no duplicate to find; and the pair is byte-identical rather than a second undecodable copy, because two records that do not decode hold the same absent leaf and reading THAT as a duplicate would be a finding about the scan rather than about the statement. It cites one condition and carries two anchors, which is not an oversight: the duplicate rule is aee-c-29 and the rule a record's payload breaks by not decoding, at L1300-1302, has no id in the registry above. bad-817 cites aee-c-19 for it, and aee-c-19 is the media-type rule that bad-204 forces, so citing it here would be repeating a wrong answer rather than giving one.
- **bad-501-substrate-unknown-method**: pairs with ok-008: the SAME fail-closed axis on an artifact row is a VALID fail.
- **bad-502-missing-actual-layer**: malformed STATEMENT, deliberately NOT a fail-closed row: a verifier answering result:fail here fails conformance.
- **bad-994-second-clean-row-layer-not-none**: the altitude rule is stated over every row, and bad-503 and bad-818 each put the offending row first, where a rail that reads one row and stops reports the same answer. The parent's rows are otherwise identical, so the row INDEX is the only thing separating the two vectors.
- **bad-818-artifact-clean-row-layer-not-none**: pairs with bad-503, the substrate twin: the clean-row none rule is not scoped to a basis (L1278-1283 says 'a row', no basis qualifier), so an artifact clean row is held to it too.
- **bad-504-substrate-oov-label**: pairs with ok-009 (artifact twin stays valid).
- **bad-505-substrate-missing-method**: pairs with ok-027 (artifact row with absent method is a VALID fail).
- **bad-506-actuallayer-json-number**: type-strictness pin: row members are strings, and a wrong-typed member is a decode-layer fault, deliberately a DIFFERENT altitude than an absent one, a rail that maps the number to member absence (malformed-missing-actual-layer) fails conformance here.
- **bad-601-vocabulary-absent**: artifact-only parent: no digest or binding cascade.
- **bad-605-vocabulary-digest-mismatch**: the binding is rederived over the STALE carried digest, not over the digest the arrays recompute to, because that is the value a verifier reading the statement folds into the pre-image; deriving over the honest one would leave every record mismatched and the vector would report a binding fault instead of the digest fault.
- **bad-606-missing-runentropy**: precedence pin: a missing binding INPUT reports its member code, never run-binding-mismatch.
- **bad-607-two-subjects-substrate**: subject[0] unchanged, so record bindings still derive: the cardinality rule is the ONLY fault.
- **bad-608-digest-uppercase**: a rail that derives verbatim finds the binding EQUAL; only the lowercase-64-hex format rule fails.
- **bad-610-empty-labels-substrate**: empty vocabulary is internally canonical (vacuously sorted, vacuously a subset); the fault is the fail-closed substrate row.
- **bad-611-subject-no-sha256**: precedence pin: missing binding input reports the member code; records keep the parent binding (unreachable check).
- **bad-612-labels-non-bmp**: BMP-only string profile: the entry sorts last under BOTH the UTF-16 and the code-point order, so sortedness, the caught subset, and the digest all still verify and the supplementary-plane entry is the single fault.
- **bad-703-arming-posture-mismatch**: inherently compound: the sealed record must equal BOTH the arming record's and the pinned digest, so one arming edit un-covers the sealed record too.
- **bad-710-sealed-posture-mismatch**: both posture sub-clauses fire together; they are distinguishable only in already-invalid statements.
- **bad-713-only-sealed-ref-noncovering**: discriminates rails that scan all records instead of the row's referenced set, and specifically one that stops at the first seal that covers: the covering seal precedes the referenced one.
- **bad-714-unknown-kind-sole-cover**: pairs with ok-013: an unknown kind that no row NEEDS is ignored and only contributes its leaf.
- **bad-727-armedat-non-utc-offset**: RFC 3339 UTC means a zero offset; +05:00 parses as a valid instant (18:59Z, before issuedAt) but is not UTC, so the arming record covers nothing, distinct from a late armedAt (bad-702).
- **bad-728-artifact-two-subjects**: subject cardinality is unconditional (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530): exactly one subject on a statement of any basis. bad-607 keeps a substrate row; this locks the previously substrate-scoped rule as unconditional on an artifact-only statement.
- **bad-729-duplicate-attackid-rows**: two rows share attackId XA-EXAMPLE-1. Coverage integrity set-compares row attackIds to the manifest, so a duplicate collapses under set semantics and would pass silently; uniqueness is a well-formedness invariant detected before the set is built.
- **bad-730-coverage-class-overlap**: the from-spec checker accepts overlap (completeness-only); our two rails reject it (disjoint partition). A class both assessed and disclosed as a gap is contradictory. Keeping the reject reading is the converged debate recommendation, reversible at vetting.
- **bad-718-chain-runseq-zero**: pairs with the genesis accept vector ok-034 (aeeRunSeq 1, scope present, no predecessor).
- **bad-719-chain-missing-scope**: an unscoped counter makes every chain rule vacuous, so the syntax check rejects it fail-closed.
- **bad-720-chain-prev-not-hex**: a predecessor binding is a lowercase 64-hex run binding digest, present exactly when aeeRunSeq exceeds 1.
- **bad-721-chain-scope-not-array**: the old free-form string form is rejected fail-closed; array of registered tokens is the sole accepted shape (no alias).
- **bad-722-chain-scope-unknown-dimension**: an unrecognized dimension token fails closed, as every closed vocabulary in this spec does.
- **bad-723-chain-scope-not-canonical**: canonical order is corpus < networkPosture < subject; the same canonicality rule as observationVocabulary.labels.
- **bad-988-chain-scope-later-token-unknown**: the scope rule is quantified over EVERY token, and bad-722 carries a one-token array, where a universal and an existential agree. A rail that reads the first token and stops accepts this one: the array opens with a registered dimension and closes with a token no minor version has defined, which is the shape a producer reaches for when it wants a dimension the vocabulary does not grant.
- **bad-724-artifact-ref-out-of-range**: an out-of-range reference is a structural integrity fault on any row regardless of basis; a reference that does not resolve is never silently ignored. The second anchor is the sentence that quantifies the rule over every row rather than the schema line that introduces the member, and it is what this vector is written against: the substrate-row anchor alone reads as a duplicate of bad-102.
- **bad-990-artifact-refs-later-out-of-range**: the statement-level scan is quantified over every index a row carries, and bad-724 hands it a single index that is already the faulty one, so a rail reading only the first index reports the same answer. Here the first index resolves and the second does not, which is the only shape that separates the two readings. The row is artifact-basis deliberately: on a substrate row the per-row gate reports the same code from its own scan, and the statement-level quantifier would be measured through a check that is not it.
- **bad-993-second-row-refs-out-of-range**: the ROW quantifier of the same scan bad-990 measures inside one row. Every vector carrying this condition put the offending index on the first row, where a rail that reads one row and stops still finds it. Here the first row's indexes all resolve, so only a rail that walks every row reports anything at all.
- **bad-725-statement-duplicate-member**: rawStatement: the dict form cannot carry a duplicate member; a lenient parser keeps the last silently, so a duplicate anywhere in the statement is a malformed statement, fail-closed.
- **bad-801-wrong-predicatetype**: a verifier MUST NOT process this as v0.7.
- **bad-802-missing-catchpolicy**: artifact-only parent: no binding cascade; defeats the empty-vs-enforcing policy distinguishability.
- **bad-803-corpus-digest-mismatch**: statement-side lie, vs bad-301's record-side splice.
- **bad-804-attackid-two-classes**: artifact-only degraded parent avoids any binding cascade; coverage over the assessed class is unchanged.
- **bad-805-row-unknown-attackid**: precedence pin: row-attack-unknown.
- **bad-806-coverage-attack-omitted**: the second interception record stays in the tree (unreferenced records are legal), so the root is untouched: single fault.
- **bad-807-coverage-attack-superset**: superset direction of exactly-equal coverage.
- **bad-816-coverage-class-dropped**: distinct from bad-806/807 (attack granularity within an assessed class): a whole manifest class left silently unaccounted.
- **bad-819-assessed-class-not-in-manifest**: mirror of bad-816 (a manifest class dropped from every coverage set): here a fabricated class pads assessedClasses. Coverage must be an exhaustive, disjoint partition of the manifest's real classes, so a class in a coverage set that the manifest never carried is the same class-granularity coverage-partition fault.
- **bad-731-outofscope-unknown-class**: reason-map mirror of bad-819 (which forces the assessedClasses side). The three coverage sets are a disjoint partition of the manifest's classes, so membership runs both ways; nothing forced the outOfScope side until now (in-toto/attestation#570 round-8, Rul1an). Both rails already enforce it (Go statement.go, Python _coverage_partition_ok); this vector locks the rule and mutation-proves the rails..
- **bad-732-routedelsewhere-unknown-class**: reason-map mirror of bad-819 for the routedElsewhere side (see bad-731). Closes the second untested consequence of the partition-membership rule (in-toto/attestation#570 round-8)..
- **bad-733-statement-lone-high-surrogate-escape**: rawStatement: the file is valid UTF-8 and parses as JSON, so only a check on the raw bytes sees it. A lenient parse yields a lone surrogate that no later comparison can tell from a written one..
- **bad-734-statement-lone-low-surrogate-escape**: rawStatement: a low surrogate with no preceding high surrogate..
- **bad-735-statement-reversed-surrogate-pair**: rawStatement: both halves are present, in the wrong order, so a check that counts surrogates rather than pairing them passes..
- **bad-736-statement-cesu8-vocabulary-label**: rawBytes: not valid UTF-8. A lenient decoder substitutes U+FFFD, and because the vocabulary digest is recomputed from the decoded strings the statement is self-consistent afterwards. This is the exact construction that verified valid on one rail and invalid on three..
- **bad-737-statement-overlong-utf8**: rawBytes: the overlong form is the other half of the UTF-8 well-formedness rule, and a length-only scanner steps over it..
- **bad-738-statement-raw-control-character**: rawBytes: JSON forbids an unescaped character below U+0020..
- **bad-739-payload-lone-surrogate-escape**: rawBytes: the payload position of the rule bad-733 covers statement-wide. The code differs because a payload that is not a parseable I-JSON value covers nothing..
- **bad-740-payload-cesu8**: rawBytes: the payload path byte-compares against the carried bytes, so a substitution cannot round-trip there; this vector pins the CODE rather than the verdict..
- **bad-741-payload-nesting-exceeds-max-depth**: rawBytes: the bound is normative because it was not. The reference rails chose 128 and the independent from-spec checker chose 256, so identical bytes were evidence to one conforming verifier and malformed to another across 127 depths..
- **bad-742-payload-nesting-empty-container-leaf**: rawBytes: the empty-container companion to bad-741. A rail that charges a level per parsed child rather than per open container never charges an empty container, so it accepts at depth 129 what the bracket-counting rails reject. bad-741's scalar leaf could not discriminate it..
- **bad-743-statement-noncharacter-vocabulary-label**: rawBytes: a noncharacter is a valid scalar that nothing substitutes, so this is not a live cross-rail split; it is the RFC 7493 label made true, so a from-spec verifier reading the label does not reject a record we accept..
- **bad-744-payload-noncharacter**: rawBytes: the payload position of bad-743. RFC 7493 section 2.1 forbids noncharacters in every string literal, not only member names..
- **bad-745-record-signatures-empty**: the count is byte-pure and verifies nothing: a record carrying one fabricated signature entry passes it and is caught only at the tier, so this vector closes the literal zero-signature case and no more. It is also the suite's one vector with an empty rederive chain, because signatures are outside the PAE pre-image and so outside batchRoot.
- **bad-749-record-signatures-not-an-array**: the wrong-type spelling of zero entries. It reads as the more likely producer bug of the three, since a substrate that emits one signature object where the schema wants an array of them produces exactly this. The expected set names the specific condition rather than the parse catch-all, because the catch-all identifies neither the record nor the member, and because an ABSENT signatures member already reports the specific condition on the same reasoning.
- **bad-746-manifest-empty-classes**: the bare shape of the bypass. Every other check on this statement passes: the corpus digest re-derives over the emptied manifest, coverage is a partition of nothing, the recompute returns pass, and with no substrate row nothing requires runEntropy, observationRecords or a batchRoot. Only the manifest floor rejects it, which is why the floor sits in well-formedness and not in result: a corpus declaring no adversarial inputs is not an adversarial corpus, and scoring it would concede that the run is a legitimate statement that merely scores badly.
- **bad-747-manifest-class-declares-no-attacks**: the twin bad-746 cannot catch, and the reason the rule counts identifiers rather than classes. This manifest carries a real class name and assessedClasses names it, so the coverage partition is exactly satisfied and the statement reads like an assessment that found nothing rather than like an empty object; a rule phrased as "an empty classes object is malformed" would admit it.
- **bad-817-payload-noncanonical-base64**: encoding-layer divergence: Go decodes with StdEncoding.Strict() and the Python rail re-encode-compares, so both reject; a lenient decoder would accept. The stale signature and batch root are unreachable because a decode failure short-circuits both checks (validity.go:120).
- **bad-809-snake-case-doesnotassert**: single-canonicalization rule: no alias.
- **bad-810-missing-issuedat**: artifact-only parent: no armedAt comparison cascade.
- **bad-750-armedat-lowercase-separator**: the parent's instant with the separator lowercased. The profile is uppercase and this was already a rejection before the profile was written down, since the clause names Z and +00:00 and admits no lowercase spelling; the Python reference rail accepted it anyway, which is the divergence this vector exists to hold shut.
- **bad-751-armedat-lowercase-zone-designator**: the separator's twin: the other half of the case rule, isolated so a rail that enforces the case of one designator and not the other is caught. Distinct from bad-727 (a non-zero offset), which is the zone half of the same profile.
- **bad-820-issuedat-non-utc-offset**: the parent's instant at a non-zero offset. issuedAt is typed as the framework Timestamp, which requires the UTC timezone, so a valid instant in a non-UTC spelling is malformed. The counterpart on the arming record is bad-727, which every rail rejected while every rail accepted this one.
- **bad-821-issuedat-lowercase-separator**: the spelling the Go reference rail refused and the Python reference rail accepted with result pass, an accept-on-one reject-on-another split inside one repository that no vector reached.
- **bad-822-issuedat-lowercase-zone-designator**: the separator's twin on the predicate field, isolated for the same reason as bad-751: a rail enforcing the case of one designator and not the other passes every both-lowercase mutant.
- **bad-823-posture-unregistered**: the pinned digest member is untouched, so both covering records still compare equal on aeePostureDigest and the unregistered string is the single fault.
- **bad-824-posture-not-a-string**: a wrong-type posture is the same requirement failing as an unregistered one, so it reports the same condition rather than the parse catch-all; a rail that decodes the member into a string field and lets the decode failure escape names a different condition than its peers for these exact bytes.
- **bad-825-posture-array**: the shape that separated the rails before it was fixed: testing membership of an unhashable value against a set raises rather than returning false, so two rails crashed on it while a third rejected it cleanly, which is a crash and a cross-rail split at once. It is kept distinct from the wrong-type vector because a scalar of the wrong type and a container of the wrong type reach a membership test by different paths.
- **bad-305-posture-swapped**: both values are registered, so this is the swap no vocabulary rule can see. Under the version-1 binding this statement was VALID and the substitution cost nothing: it changed no digest and broke no signature. It is a mismatch now because the binding covers the carried posture object rather than the value of that object's own digest member.
- **bad-306-vocabulary-caught-narrowed**: the caught set decides which labels are caught, and both the recompute and the coverage validity requirements read it, so a producer that narrows it after the run turns a caught row into a clean one. Nothing resisted that under version 1: the vocabulary's own digest re-derives from the arrays beside it and no record's binding moved. Binding the carried digest is what closes it.
- **bad-307-posture-member-added-after-arming**: the consequence the binding change makes normative, in the direction that must fail. The binding covers the carried object, so a member added to the posture after arming invalidates the producer's own statement. Its accepted twin is ok-043, which carries the same member with records committing to it, and the pair is what makes this a rule about WHEN the member was added rather than about whether the posture may carry one at all.
- **bad-950-clean-row-refs-interception**: the relabelling attack the requirement is written against: the row and the record it cites state the two halves of a contradiction, and the check is a membership test that reads no signature and no key. It is stated over every row because the contradiction does not depend on the vantage the row declares.
- **bad-951-interception-no-caught-row**: inherently compound: a caught row that resolves no interception is uncovered by the older requirement at the same moment the record it abandoned becomes an orphan under the newer one. The pair is what the anti-orphan rule is for, since dropping the reference and dropping the record are the same withdrawal from two sides.
- **bad-952-substrate-row-no-seal**: before 0.7 a sealed record was required only to cover a clean intercepted row, so a statement whose rows were all caught carried none and the run-end commitment had nowhere to live on exactly the statements a record deletion works against.
- **bad-953-observed-set-drops-a-record**: the attack the run-end commitment is for. batchRoot recomputes over the carried records and can never detect a missing member; the seal is signed by a party that does not control the carried set, so a dropped record removes a leaf and the two values diverge.
- **bad-996-second-seal-observed-set-mismatch**: the record quantifier of the equality. A producer that cannot make its seal say what it wants can carry a second one that does, and a rail comparing the first bound seal it meets never reads it.
- **bad-997-second-seal-attack-uncaught**: the record quantifier of bad-955. Both seals satisfy every constraint their kind imposes, so nothing older refuses either of them, and only a rail that reads every carried seal finds the claim.
- **bad-998-second-arming-declares-nothing**: a run-start declaration a producer can add to is not a declaration. A rail that compares the first arming record it meets and stops accepts a statement carrying two contradictory ones.
- **bad-955-seal-names-clean-attack**: the seal claims the run attributed an observation to this attack while the row says nothing was caught. The rule reads one way only, so it is the naming that obliges the caught row and never the omission that obliges a clean one.
- **bad-995-seal-later-attack-uncaught**: the rule is quantified over every identifier the seal names, and bad-955 names one, where a universal and an existential agree. Both identifiers here are declared and the array stays canonical, so the shape rule the kind imposes is untouched; a rail that reads the first named attack, finds its caught row and stops accepts a seal claiming a catch the statement's own rows deny.
- **bad-956-seal-names-rowless-attack**: inherently compound: an attack the manifest declares under an assessed class and no row reports is a coverage-integrity fault at the older gate, and the seal naming it is the newer one. The pair is unavoidable, because the only way to carry a seal naming an attack with no row is to carry a statement with no row for it.
- **bad-957-assessed-exceeds-declaration**: coverage inflation is the withdrawal's mirror image and the only half of that pair a commitment can reach: inflation must keep the run-level records its fabricated rows point at, and withdrawal need keep nothing at all.
- **bad-958-pinned-row-resolves-no-interception**: inherently compound, and the compounding is the point: the older requirement catches this shape only because the row is CAUGHT, and a producer that also relabels the row escapes it while keeping the stronger attribution. The existence part is what does not depend on the label.
- **bad-959-pinned-without-expectation**: a row whose attackId carries no such entry MUST declare paired. Where the corpus declares nothing there is nothing to compare, and the stronger value would be a claim about a check that cannot run.
- **bad-960-pinned-commitment-unmatched**: the borrowed-record case the stronger value narrows: re-pointing a row at an interception signed for a different attack raises nothing here, because the borrowed record must also carry this attack's committed value.
- **bad-962-expected-payloads-unsorted**: the sortedness rule is the canonicality rule the vocabulary arrays already carry, so two rails deriving the manifest digest from the same entries in different orders is not a thing that can happen.
- **bad-964-expected-payloads-empty-array**: an empty expectation is not a weaker expectation. It reads as a declaration that no commitment can match, which every pinned row for that attack would then fail while the manifest looked complete.
- **bad-965-commitment-not-hex**: the ABSENCE of the member keeps reporting payload-missing-reserved, which is the code every other missing reserved member takes. A present-but-malformed value is a different fault: a producer told its record is missing a value the record plainly carries has been told the wrong thing.
- **bad-989-commitment-later-entry-not-hex**: the entry rule is quantified over the whole array, and every commitment array this corpus carried held one entry, where a universal and an existential agree. bad-965 replaces that single entry, so a rail reading the first entry and stopping reports the same answer. Here the first entry is the parent's own commitment and the malformed value follows it, so only a rail that reads every entry refuses.
- **bad-967-commitment-absent**: the absent half of the pair above, kept as its own vector because the two report different conditions and a rail collapsing them passes whichever one it implemented.
- **bad-968-substrate-row-missing-attribution**: absence is not a value, so the row cannot be classified and fail-closes exactly as an out-of-vocabulary one does. The result still recomputes to fail, because a caught row forced fail already.
- **bad-972-second-interception-unresolved**: an interception the statement carries and no caught row accounts for is an observation the substrate signed and the producer then reported nothing about.
- **bad-973-pinned-clean-row**: the vacuity the existence part is written against, on the one row shape where no older requirement fires first: a universally quantified rule over an empty set is true, so without this part a producer resolves only run-level records and keeps the stronger value with nothing checking it.
- **bad-974-sealed-missing-observedset**: the member is required on the kind, so its ABSENCE makes the record cover nothing rather than making the recompute disagree. bad-953 and bad-954 carry the disagreement; nothing carried the absence, so a rail could implement the equality and never require the member.
- **bad-975-sealed-missing-observedattacks**: the empty array is the honest value and is REQUIRED rather than omissible: a substrate holding no probe-to-record correspondence says so on the wire. Allowing the member to be absent would make the whole control escapable by omission, which is the defect the mandatory sealed record exists to close, reintroduced one level down.
- **bad-977-arming-missing-assessedattacks**: bad-957 carries the subset comparison failing; nothing carried the member missing, so a rail could implement the comparison over a member it never required and skip every statement that omitted it.
- **bad-979-artifact-only-interception-orphaned**: the requirement holds on the statement rather than on a substrate row, and this is the only vector that reaches it on a statement with no substrate row at all. Without it the artifact-only arm is dead code the corpus never exercises.
- **bad-978-arming-assessedattacks-unsorted**: sorted ascending by UTF-16 code unit, the canonicality rule the vocabulary arrays already carry. Two entries are the fewest that can be out of order, and a one-attack manifest cannot express it.
- **bad-987-arming-assessedattacks-later-undeclared**: the membership rule is quantified over every identifier the array names, and bad-976 carries a one-entry array where a universal and an existential agree. The two declared identifiers stay first and stay in place, so the subset comparison the statement rule makes against the carried coverage is untouched and the undeclared identifier is the only fault: a rail that reads the first entry and stops accepts a run-start declaration naming an attack the corpus never carried.
- **bad-980-moat-drop-sole-cover**: the kind is registered rather than unknown, so the refusal names it rather than reporting the unrecognized-kind condition. A rail that routes both through one condition passes bad-714 and fails here, and the producer it answers is told to upgrade a verifier that is already current. It also pins what the record cannot buy: a drop the containment layer performed is not an interception of the traffic, so it cannot make a caught row caught.
- **bad-981-uncommitted-observation-sole-cover**: an observation the substrate declined or was unable to commit to cannot stand in for an interception anywhere. The record is bound to the run and signed by the substrate, which is exactly what makes the substitution tempting and is why the refusal is worth a vector.
- **bad-982-pinned-assignment-spliced**: the permutation a consumer policy keyed on attack class would act on. Where the corpus declares no expectation the same operator is invisible and stays so, which is what cell U7 records; here the corpus predicted what each attack's interception would commit to, so each row now resolves a record carrying the other attack's value.
- **bad-986-pinned-second-interception-unmatched**: the quantifier boundary of the pinned rule. Authorisation for this attack is valid and one observed effect corresponds to it, while a second effect on the same row corresponds to a different declared attack, so a rail reading `every` as `some` calls this conformant.
- **bad-991-expected-payloads-later-entry-not-hex**: bad-963 replaces the sole entry of a one-entry array, so a rail that reads the first entry and stops reports the same answer. ok-055 is the only accept vector whose manifest declares more than one value for an attack, and appending the malformed value to it leaves both records still matching what the manifest declares: the array shape is the only fault, and it is not the first entry.
- **bad-992-expected-payloads-later-key-undeclared**: bad-961 carries a single undeclared key, which is also the first key, so a rail that reads one entry and stops still finds it. Here the two declared keys sort ahead of it and both are well formed, so the fault is reachable only by a rail that walks the whole map. The added entry names no row and its value is a well-formed commitment, which keeps the undeclared key the sole fault.
- **bad-983-liveness-middle-channel-commitment-unmatched**: bad-960 is this fault on a statement with one channel, where the first pinned row and the only pinned row are the same row. A rail that decides the attribution rule on the first row it meets, or that stops at the first row it can satisfy, passes that vector and reports this statement valid while the middle channel's detector is evidenced by a value nobody predicted.
- **bad-984-liveness-last-channel-unpinnable**: the per-channel form of bad-959. A channel whose probe the corpus no longer predicts cannot be shown live by comparison, and a producer that keeps the stronger value there is claiming a check that has no input. The two channels before it are unchanged, so a rail deciding the run on the channels it has already satisfied accepts this.
- **bad-985-liveness-middle-channel-probe-uncaught**: the dead detector papered over: the channel produced nothing, the producer reported a catch anyway, and every universally quantified clause about the records the row resolves is true over an empty set. ok-053 is the honest report of the same run -- the same three planted probes, the middle channel's row clean and its attack absent from the seal -- and it is accepted, so what this vector refuses is the claim and never the outcome.
- **bad-900-sealed-method-reconstructed**: the sealed twin of bad-704 and bad-712. Every other kind's method constraint had a vector and this one did not, so a rail that read the sealed record's aeeMethod and did nothing with it passed.
- **bad-901-sealed-negative-dropcount**: a count of dropped observations below zero is not a count. The corpus tested the bound from above (bad-709) and never from below, so a rail comparing only against the bound accepted it.
- **bad-902-sealed-posture-ne-arming**: the sealed-vs-arming half of the posture equality, which bad-710 cannot separate. A rule can go unforced because the corpus SHAPE cannot express its precondition rather than because nobody wrote the vector, and the two need different fixes.
- **bad-905-vocabulary-labels-absent**: bad-601 drops the whole vocabulary and every array vector edits an array that is there. The half-present object sat between them: a rail checking that the member exists, then reading labels, accepted a statement carrying no label set at all.
- **bad-906-corpus-manifest-absent**: one statement two rails read two ways: the Go rail called the environment incomplete and the Python rail accepted it, and nothing in the corpus made them disagree out loud.
- **bad-1001-sealed-missing-dropcount-unreferenced**: the laundering of `bad-705-sealed-missing-dropcount`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1002-stillarmed-non-boolean-unreferenced**: the laundering of `bad-706-stillarmed-non-boolean`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1003-sealed-stillarmed-false-unreferenced**: the laundering of `bad-707-sealed-stillarmed-false`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1004-sealed-drops-no-bound-unreferenced**: the laundering of `bad-708-sealed-drops-no-bound`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1005-sealed-drops-exceed-bound-unreferenced**: the laundering of `bad-709-sealed-drops-exceed-bound`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1006-sealed-posture-mismatch-unreferenced**: the laundering of `bad-710-sealed-posture-mismatch`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1007-sealed-noncovering-unreferenced**: the laundering of `bad-713-only-sealed-ref-noncovering`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1008-sealed-missing-stillarmed-unreferenced**: the laundering of `bad-715-sealed-missing-stillarmed`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1009-sealed-missing-posture-unreferenced**: the laundering of `bad-716-sealed-missing-posture`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1010-sealed-method-reconstructed-unreferenced**: the laundering of `bad-900-sealed-method-reconstructed`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1011-sealed-negative-dropcount-unreferenced**: the laundering of `bad-901-sealed-negative-dropcount`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1012-sealed-missing-observedset-unreferenced**: the laundering of `bad-974-sealed-missing-observedset`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1013-sealed-missing-observedattacks-unreferenced**: the laundering of `bad-975-sealed-missing-observedattacks`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1014-sealed-observedattacks-unknown-unreferenced**: the laundering of `bad-976-sealed-observedattacks-unknown`. A rule read only where a row points is a rule whose subject the producer selects, and this pair is the same defective record judged twice: refused when the row names it, admitted when the row names its healthy twin.
- **bad-1015-arming-carried-missing-armedat**: the arming half of the same defect. `bad-701` breaks the arming record the row resolves; this one carries the identical record beside the row instead, which every rail admitted.
- **bad-1016-examination-carried-method-intercepted**: the examination half. `bad-712` breaks the examination record a reconstructed row resolves; this one carries it where no row resolves anything of the kind. Note it also enters the seal's aeeObservedSet, so the record is committed to and still unread.
- **bad-1017-sole-seal-moat-down-all-caught**: the vector the existential had no witness for. Its expectation is a single code deliberately: a reject vector is graded by intersecting the emitted set with `codes`, so naming both conditions there would be satisfied by either reading and would measure nothing. `sealed-record-absent` alone is the measurement, and the companion fault is declared in `also carries` so the second-fault self-check reads it as intended rather than as a stray. The distinction the vector pins is a repair: where a satisfying seal is carried beside the defective one, dropping the defective record reaches validity, and here it does not -- drop this seal and the statement carries none, which is `bad-952` from the other side.
- **vate-1a-admission-receipt-substituted-splice**: prompted by VATE case `post-execution-admission-digest-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. Its parent is `vate-1d`, which the generator reads from the accept set rather than rebuilding, so the two statements differ in `subject[0].digest.sha256` and in nothing else and the two objects in the relation are both admission receipts, as they are in the pinned case. That literal one-field relation is what makes the pair a control: a rail's refusal here is attributable to the substituted admission digest, because nothing else moved. What it establishes is narrow and worth stating narrowly: AEE binds its sole subject against record splicing, so records produced under receipt A cannot be presented under receipt B. It does NOT perform the pinned case's referenced-admission-receipt digest comparison, it does not establish that either receipt is genuine, and its accepted bound is `vate-3c`, where the whole run is re-bound to a substituted digest and re-signed and nothing is detected.
- **vate-1c-two-subjects-artifact-and-admission**: prompted by VATE case `post-execution-admission-digest-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. The general cardinality rule is already carried by `bad-607` and `bad-728` and this vector does not extend it; what it adds is the PRICE, made executable: binding an admission receipt is not additive, because the pre-image reads only the first subject and a second entry is malformed. Its accepted partner is `vate-1d`, the receipt as sole subject, which is valid and names no executed artifact at all.
- **vate-3a-substrate-substituted-splice**: prompted by VATE case `post-execution-runtime-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. The field it moves, `observationEnvironment.substrate.digest.sha256`, is the observation-substrate identity: an ADJACENT AEE binding surface, not an equivalent of that case's admitted-runtime versus observed-runtime comparison. Within one statement that identity is bound and a record signed under a different one cannot be spliced in. Admitted-versus-observed is a different question and is not native: it needs two runtimes named in one statement, and `vate-3b` is the accepted vector that pins exactly that.

## Compound vectors and precedence pins

`expected` codes form a SET: a rail conforms when its code is in the
set and the verdict matches. Vectors marked COMPOUND carry more than
one condition; every other vector is single-fault by construction.
Most are compound because deriving them singly is impossible without
introducing a different fault. No vector in this directory is compound
in order to pin a precedence: a statement whose two conditions the
specification does not order between belongs in `vectors/indeterminate/`,
where every reading a conformant rail may take is declared and the rail
is held to one of them. Registry precedence pins applied here:

1. A missing binding INPUT reports its member code, never
   `run-binding-mismatch` (bad-606, bad-611); binding mismatch is
   reserved for derivable-but-unequal (bad-301, bad-303).
2. `records-absent` is reported when `observationRecords` is absent
   entirely; `ref-out-of-range` only when records exist (bad-407).
3. The method cap reads COVERING records only: the referenced records
   of the class(es) the row's class-match rule requires; extras are
   payload-checked but neither cap nor tier-gate (bad-304).
4. The two sealed posture equalities are jointly enforced given the
   arming constraint (bad-710); distinguishable only in
   already-invalid statements.

Signature VERIFICATION failure is NEVER a failure code in this suite:
whether a record's signature verifies against a consumer-named key is
the evidence tier's separate, trust-relative question. Every committed
signature here verifies under the derived test public key above. How
many entries the array carries is a different question, answered
without key material and therefore inside validity: `bad-745` carries
a record with zero of them and no signature to verify, and `bad-749`
carries a member of the wrong JSON type that holds none either. Which
condition a rail reports when a record with no entries shares a
statement with one whose payload does not decode is not settled by the
specification and is not settled here: it is the indeterminate family
`ind-001` / `ind-002` in `vectors/indeterminate/`.

## Deferred coverage (no vector, by design)

- **Missing or out-of-vocabulary `basis` on a SUBSTRATE-carrying
  statement**: the fail-closed branch split (substrate => the
  attestation is invalid vs artifact => a valid `fail`) turns on a
  classification the row itself refuses to supply, and the spec
  text does not state which branch applies. Shipping a reject
  vector here would silently resolve that reading, so there is
  none; it is a formal spec-edit ask on the PR thread.
  This bullet has NARROWED. The accept suite now ships
  `ok-901-row-missing-basis`, a recordless statement whose single
  row carries no `basis` member, no refs and no substrate
  participation of any kind: it is VALID and it recomputes to
  `fail`. That decides the half of the question a statement with
  no substrate vantage can even ask, and it was shipped because
  the rail's basis branch was measured to have no vector behind
  it in either direction. What stays open is the half this
  directory would have to answer: the same row inside a statement
  that does carry substrate evidence. The out-of-vocab METHOD and
  LABEL substrate twins (bad-501, bad-504) plus the valid
  artifact-row twins in the accept suite cover the decidable rest
  of the fail-closed axis.
- **Duplicate-record identity discriminator** (leaf-hash vs
  byte-identical): bad-405 is invalid under BOTH readings; the
  discriminating vector waits on the spec answer.
- **observationSelectors length mismatch**: unstated in the spec;
  formal ask, no vector.
- **Artifact-only multi-subject**: the one-subject rule is scoped to
  substrate-carrying statements (L210); whether artifact-only
  multi-subject is legal is an open ask (bad-607 keeps a substrate
  row precisely so the rule undeniably applies).
- **Replay of a genuine runEntropy** (stateful-consumer concern) and
  **coherence checks** (MAY): behavior/harness territory, not
  statement-shape vectors.

