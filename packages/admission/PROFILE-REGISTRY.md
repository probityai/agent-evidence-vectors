# Profile registry: what each rail enforces

95 obligations, 4 rails, and one row per pair. Every disposition below is measured by `scripts/gen_profile_map.py` from a live run of every rail over this bundle's corpus projection, and `scripts/profile-map-gate.py` refuses a map that claims more than the measurement supports.

Corpus digest `bf3e5befd716`, predicate type `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`. Re-derive the registry with `scripts/gen_condition_registry.py --corpus <vectors checkout>` and this document with `scripts/gen_profile_registry.py`.

## What the three dispositions mean

**enforced** the rail matched the oracle on every vector citing the obligation, and the map names a rule in that rail's own artifact that the gate opens the artifact and finds. A rail that answers differently from the oracle on any vector citing an obligation may not carry this value, and the gate makes that a hard error.

**approx** the rail matched the oracle on every vector citing the obligation and no rule has been named for it. This is the default for a rail that behaves correctly, because agreement on the vectors that happen to exist is a weaker claim than a named rule. Promoting a row costs one line in `profiles/rule-index.json`.

**unreachable** the rail is not shown to enforce the obligation here, and the row names an obstruction from a closed vocabulary saying which of the two reasons applies: the rail answers differently from the oracle on a vector citing the obligation, or no vector citing it appears in this projection at all. The second is a gap in what has been measured and says nothing about the rail, which is why it has its own value and is never folded into the first.

## Totals

| rail | enforced | approx | unreachable |
|---|---|---|---|
| `cue` | 0 | 69 | 26 |
| `kyverno-cel` | 0 | 91 | 4 |
| `kyverno-jmespath` | 0 | 74 | 21 |
| `rego` | 5 | 90 | 0 |

## The obligations

| obligation | spec anchor | condition | `cue` | `kyverno-cel` | `kyverno-jmespath` | `rego` |
|---|---|---|---|---|---|---|
| `aee-c-1` | L435 | closed lowercase result vocabulary | approx | approx | approx | approx |
| `aee-c-2` | L390-393 | result must equal the recompute | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | enforced (recomputed_result) |
| `aee-c-3` | L440-442 | a row carrying a label from the carried caught set contributes fail | approx | approx | approx | approx |
| `aee-c-4` | L443-444 | fail-closed on out-of-vocabulary label | approx | approx | approx | approx |
| `aee-c-5` | L443-444 | fail-closed on missing/out-of-vocab basis or method | approx | approx | approx | approx |
| `aee-c-6` | L444-446 | degraded iff disclosed coverage gap | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | enforced (_coverage_incomplete) |
| `aee-c-7` | L447-450 | UNRESOLVED -- ok-002 is the sole carrier and the corpus does not separate this id from aee-c-2. Candidate reading, recorded rather than asserted: the third recompute condition, which contributes pass_indirect when some clean row is not (substrate, intercepted) and pass when none is | approx | approx | approx | approx |
| `aee-c-10` | L552 | observationRefs non-empty on substrate rows | approx | approx | approx | approx |
| `aee-c-11` | L552-553; L946-951 | every ref index in range (integer), on every row that carries the member and not only on the rows a gate resolves | approx | approx | approx | approx |
| `aee-c-12` | L554-556 | caught intercepted row refs an interception record | approx | approx | approx | approx |
| `aee-c-13` | L556-557 | reconstructed row refs an examination record | approx | approx | approx | approx |
| `aee-c-14` | L557-560 | clean intercepted row refs arming AND covering sealed | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | enforced (clean_row_coverage_ok) |
| `aee-c-15` | L958-960 | one run-level arming/sealed/examination record covers every row earned under it | approx | approx | approx | approx |
| `aee-c-16` | L953-958 | observationSelectors is producer vocabulary positionally parallel to observationRefs; no gate reads it | approx | approx | approx | approx |
| `aee-c-17` | L561-562 | covering payload is canonical RFC 8785 | approx | approx | approx | approx |
| `aee-c-18` | L1312-1316 | covering payload is valid I-JSON (RFC 7493) | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | approx |
| `aee-c-19` | L1317-1318 | covering media type ends in +json | approx | approx | approx | approx |
| `aee-c-20` | L562-563 | covering payload carries the reserved aee members | approx | approx | approx | approx |
| `aee-c-22` | L563-564 | aeeRunBinding equals the derived run binding | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-23` | L565-566 | row method capped by weakest signed aeeMethod | approx | approx | approx | enforced (_method_cap_exceeded) |
| `aee-c-24` | L1742 | batchRoot required when records exist | unreachable (oracle-divergence-declared) | approx | approx | approx |
| `aee-c-25` | L1744-1747 | RFC 6962 domain-separated hashing | approx | approx | approx | approx |
| `aee-c-26` | L1747-1749 | RFC 6962 recursive split, never duplicate-pad | approx | approx | approx | approx |
| `aee-c-27` | L1749 | leaves in array order | approx | approx | approx | approx |
| `aee-c-28` | L1749 | a single-record tree's root is its leaf hash | approx | approx | approx | approx |
| `aee-c-29` | L1751-1752 | duplicate byte-identical records invalid | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | approx |
| `aee-c-30` | L1754-1756 | batchRoot must recompute | approx | approx | approx | approx |
| `aee-c-31` | L1758-1770 | batchRoot omitted exactly when records absent | approx | approx | approx | approx |
| `aee-c-32` | L1744-1748 | batchRoot is over every carried record in array order, referenced by a row or not | approx | approx | approx | approx |
| `aee-c-33` | L766-775 | the evidence tier is derived per row and never carried: artifact is declared, substrate is attested when every covering signature verifies under consumer policy and unattested otherwise, and the tier never alters result | approx | approx | approx | approx |
| `aee-c-34` | L772-774 | no TOFU: a consumer with no policy-pinned substrate root treats every substrate row as unattested and MUST NOT infer the root from the predicate | approx | approx | approx | approx |
| `aee-c-35` | L1901-1903 | keyid is an unauthenticated lookup hint, never the check | approx | approx | approx | approx |
| `aee-c-36` | L1302-1304; L545-546 | a record signature is DSSE PAE over (payloadType, payload); the byte-pure validity gate never reads a signature, so a signature that does not verify is a tier fact and not a validity fault | approx | approx | approx | approx |
| `aee-c-38` | L779-781 | a carried predicate-level evidenceTier member MUST be ignored | approx | approx | approx | approx |
| `aee-c-41` | L992-993 | basis required, closed {substrate, artifact} | approx | approx | approx | approx |
| `aee-c-42` | L1035-1036 | method required, closed {intercepted, reconstructed} | approx | approx | approx | approx |
| `aee-c-43` | L1097-1101 | the retired 0.4 basis and method values are out-of-vocabulary, with no alias | approx | approx | approx | approx |
| `aee-c-44` | L760-764 | fail-closed substrate row invalidates; artifact row stays a valid fail | approx | approx | approx | approx |
| `aee-c-45` | L1046-1052 | weakest-input method composition | approx | approx | approx | approx |
| `aee-c-47` | L1269-1277 | missing actualLayer = malformed statement, not fail | approx | approx | approx | approx |
| `aee-c-48` | L1278-1283 | clean row actualLayer is the literal none | unreachable (oracle-divergence-declared) | approx | approx | approx |
| `aee-c-49` | L1283-1286 | the literal none is valid on a caught row too, and states that the event was observed and no enforcement layer acted | approx | approx | approx | approx |
| `aee-c-50` | L1269-1270 | actualLayer names the enforcement layer that acted on the row's containment event | approx | approx | approx | approx |
| `aee-c-51` | L796-804 | observationVocabulary required | approx | approx | approx | approx |
| `aee-c-52` | L800-802 | caught is a subset of labels | approx | approx | approx | approx |
| `aee-c-53` | L802 | vocabulary arrays sorted ascending, no duplicates | approx | approx | approx | approx |
| `aee-c-54` | L802-804 | vocabulary digest is JCS of {caught, labels} | approx | approx | approx | approx |
| `aee-c-57` | L808-810 | runEntropy required with any substrate row | unreachable (oracle-divergence-declared) | approx | approx | approx |
| `aee-c-58` | L210-213 | exactly one subject on a statement of any basis | approx | approx | approx | approx |
| `aee-c-59` | L210-224 | binding digest inputs lowercase 64-hex sha256 | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-60` | L174-182 | binding pre-image construction | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-61` | L779-781 | a predicate-level member beginning with the reserved aee prefix MUST be ignored | approx | approx | approx | approx |
| `aee-c-62` | L229-237 | binding is anti-splice | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-63` | L1323-1327 | arming record kind constraints | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-64` | L1330-1335 | sealed record required members | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-65` | L1361-1366 | sealed covering conditions | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-66` | L1336-1338 | examination signed aeeMethod reconstructed | approx | approx | approx | approx |
| `aee-c-68` | L1187-1188 | each referenced record independently satisfies its class constraints | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-71` | L1687-1691 | unknown aeeKind covers nothing | unreachable (oracle-divergence-declared) | approx | approx | approx |
| `aee-c-73` | L1693-1695 | the aee payload member prefix is reserved; every other payload member is producer territory and does not stop a record covering | approx | approx | approx | approx |
| `aee-c-75` | L237-241 | fail-closed on unimplemented binding version | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-77` | L3; L313 | statement _type and predicateType URIs | approx | approx | approx | approx |
| `aee-c-78` | L783-810 | observationEnvironment required members | approx | approx | approx | approx |
| `aee-c-79` | L787-791 | corpus digest re-derives from embedded manifest | approx | approx | approx | enforced (coverage_digest_ok) |
| `aee-c-80` | L789-791 | attackId under at most one manifest class | approx | approx | approx | approx |
| `aee-c-81` | L920 | row attackId appears in the manifest | approx | approx | approx | approx |
| `aee-c-82` | L963-966 | coverage exactly equals the manifest at attack granularity | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-83` | L905-909 | coverage member required | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-84` | L1772-1782 | doesNotAssert single canonical spelling | approx | approx | approx | approx |
| `aee-c-85` | L1784; L1792-1795 | issuedAt required, under the Timestamp profile: uppercase separator and zone designator, and a zero offset spelled Z, +00:00 or -00:00 | approx | approx | approx | approx |
| `aee-c-86` | L150-163 | vocabulary labels/caught entries BMP-only; a supplementary-plane entry is malformed | approx | approx | approx | approx |
| `aee-c-87` | L150-163 | covering payload member names BMP-only; a supplementary-plane name covers nothing | approx | approx | approx | approx |
| `aee-c-88` | L920-928 | row members are strictly typed; a wrong-JSON-type member is a malformed statement | approx | approx | approx | approx |
| `aee-c-89` | L1611-1642 | arming chain-member syntax: positive aeeRunSeq; aeeChainScope required with it; aeePrevRunBinding lowercase 64-hex, absent exactly when aeeRunSeq is 1 | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-90` | L941-943 | no two attackResults rows share an attackId | approx | approx | approx | approx |
| `aee-c-91` | L1300-1302 | each observation record's signatures member carries at least one entry | approx | approx | approx | approx |
| `aee-c-92` | L968-990 | the corpus manifest declares at least one attack identifier across all of its classes | unreachable (oracle-divergence-declared) | approx | approx | approx |
| `aee-c-93` | L847-855 | networkPosture.posture is a registered value | approx | approx | approx | approx |
| `aee-c-94` | L574-579 | a clean row resolves no observationRefs index to an interception record | approx | approx | approx | approx |
| `aee-c-95` | L580-585 | every carried interception record is resolved by at least one observationRefs index on a caught row | approx | approx | approx | approx |
| `aee-c-96` | L586-594 | a statement carrying a basis: substrate row carries a sealed record satisfying every constraint of its kind, whether or not a row resolves an index to it | approx | approx | approx | approx |
| `aee-c-97` | L609-613 | aeeObservedSet on every carried sealed record equals the value recomputed over the carried interception and examination records | approx | approx | approx | approx |
| `aee-c-98` | L1535-1542 | every attack the seal names in aeeObservedAttacks has a row whose containmentObserved is in the carried caught set; the rule reads in one direction only | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-99` | L1467-1473 | the union of the manifest identifiers for the carried assessedClasses is a SUBSET of the arming record's aeeAssessedAttacks | unreachable (oracle-divergence-declared) | approx | unreachable (oracle-divergence-declared) | approx |
| `aee-c-100` | L614-623 | a row declaring attribution: pinned resolves at least one interception record | unreachable (oracle-divergence-declared) | approx | approx | approx |
| `aee-c-101` | L614-623 | a row declaring attribution: pinned names an attack the manifest carries an expectedPayloads entry for | approx | approx | approx | approx |
| `aee-c-102` | L614-623 | every interception a pinned row resolves carries in aeePayloadCommitment at least one value from that attack's expectedPayloads entry | approx | approx | approx | approx |
| `aee-c-103` | L815-821 | corpus.manifest.expectedPayloads is well formed: every key a declared attack, every array non-empty, sorted by UTF-16 code unit, duplicate-free and lowercase 64-hex | approx | approx | approx | approx |
| `aee-c-104` | L1454-1465 | an interception record carries aeePayloadCommitment, non-empty, sorted by UTF-16 code unit, duplicate-free and lowercase 64-hex | approx | approx | approx | approx |
| `aee-c-105` | L1093-1097 | attribution is required on every row and its vocabulary is closed; a missing or out-of-vocabulary value is fail-closed exactly as basis and method are | approx | approx | approx | approx |
| `aee-c-106` | L1394-1408 | a moat-drop record covers nothing in every state and carries no constraint that could change that; it still contributes its leaf to batchRoot, never enters aeeObservedSet or the method cap, and the refusal a row earns by resolving one names the kind rather than reporting an unrecognized kind | approx | approx | approx | approx |
| `aee-c-107` | L1394-1408 | an uncommitted-observation record covers nothing in every state on the same terms, and in particular cannot stand in for an interception: not for a caught row's coverage, not for the existence requirement a pinned row must satisfy, and not for the expectedPayloads comparison | approx | approx | approx | approx |
| `aee-c-108` | L586-594; L1322-1366 | every carried record that binds to this run and whose aeeKind names a covering kind satisfies every constraint of that kind, whether or not any row resolves an observationRefs index to it. The universal partner of aee-c-96, over the same records on the same terms: that one asks whether a valid sealed record is present, this asks whether an invalid one is carried beside it | approx | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | approx |
| `aee-c-109` | L388 | an absent `predicate` member, `"predicate": null` and `"predicate": {}` are ONE input: all three decode to the empty predicate object and a verifier emits the identical verdict and the identical reason codes for all three. The anchor is the predicate's own opt-in to the framework parsing rules, which is what makes the framework's sentence binding here; the rule is stated in full, with the in-toto and SLSA text it lifts, at spec/v1/statement.md | approx | approx | approx | approx |
| `aee-c-110` | L1300-1302 | a record's payload is the base64 of the exact bytes the substrate signed, spelled the one canonical RFC 4648 way: standard alphabet, minimal padding, zero trailing bits, no line break and no other non-alphabet byte. A payload spelled any other way carries no bytes and the record is undecodable. The vendored revision states the base64 member; the registry entry on the pull request branch states the canonical clause | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | unreachable (oracle-divergence-declared) | approx |

A row reading `unreachable (no-vector-in-projection)` is a hole in the measurement, not a finding about the rail. Closing one means adding a vector that forces the obligation, which is work in the conformance corpus rather than work here.


## The verifier isolation family

9 obligations, 3 rails. These are not conditions of the adversarial-execution-evidence corpus above. Each closes one reward-tampering vector of [terminal-bench issue 2086](https://github.com/harbor-framework/terminal-bench/issues/2086), and the family has its own registry (`registry/verifier-isolation.json`), vectors (`rego/verifier_isolation_vectors.json`) and measurement (`verifier-isolation/PROFILE-MAP.json`, written by `conformance/run_verifier_isolation_conformance.py`). [docs/VERIFIER-ISOLATION.md](docs/VERIFIER-ISOLATION.md) says what a report must carry.

The `rego` rail is the reference. The `kyverno-cel` and `cue` rails answer the same 56 vectors and give the reference's verdict on all 56. The `cue` column is `cue vet`. policy-controller's CUE evaluator leaves an absent member incomplete instead of failing it, admits 10 vectors that `cue vet` refuses, and agrees with the reference on 46 of 56. Every obligation is open to a report that omits its fact, so no obligation is `enforced` on the `cue` rail. The reason is in [docs/VERIFIER-ISOLATION.md](docs/VERIFIER-ISOLATION.md#the-cue-gap).

| rail | enforced | unreachable |
|---|---|---|
| `cue` | 0 | 9 |
| `kyverno-cel` | 9 | 0 |
| `rego` | 9 | 0 |

| obligation | vector | hardening | what it closes | `cue` | `kyverno-cel` | `rego` |
|---|---|---|---|---|---|---|
| `vi-1` | V1 Overwrite | none | The trusted tests, runner and dependencies are restored from the contract before grading, and the names a protected directory excludes (for example bytecode caches) are reset with them. | unreachable (absent-member-not-denied) | enforced (2 rules, 4 vectors) | enforced (2 rules, 4 vectors) |
| `vi-2` | V2 Patch | H2, H4 | Submitted code runs as an unprivileged uid other than the verifier's, with no supplementary groups; the assertions run in the trusted parent, under isolated Python; and that parent, which runs the task's own test code, runs in a container of its own, as a uid that is neither root nor the verifier's, with neutral environment names only. | unreachable (absent-member-not-denied) | enforced (7 rules, 16 vectors) | enforced (7 rules, 16 vectors) |
| `vi-3` | V3 Reward | H1 | The result directory is closed to group and other, cleared before the run, written by the verifier, and exactly one result file is read. | unreachable (absent-member-not-denied) | enforced (4 rules, 8 vectors) | enforced (4 rules, 8 vectors) |
| `vi-4` | V4 Fail-open | H7 | The suite is non-empty, every expected test was collected, none was skipped, and exit status zero alone is never a verdict. | unreachable (absent-member-not-denied) | enforced (4 rules, 6 vectors) | enforced (4 rules, 6 vectors) |
| `vi-5` | V5 Sleeper | H5 | Every worker process is dead, and was killed at a step before the result was read. | unreachable (absent-member-not-denied) | enforced (3 rules, 5 vectors) | enforced (3 rules, 5 vectors) |
| `vi-6` | V6 Staging | H6 | Submitted files enter without following links, into destinations removed first, with special files rejected. | unreachable (absent-member-not-denied) | enforced (3 rules, 4 vectors) | enforced (3 rules, 4 vectors) |
| `vi-7` | V7 Forgery | H2 | No measurement or pass flag is taken from the worker's own output, the worker's environment holds none of the verifier's secrets, and the worker runs on a scratch copy. | unreachable (absent-member-not-denied) | enforced (3 rules, 5 vectors) | enforced (3 rules, 5 vectors) |
| `vi-8` | V8 Disclosure | H3 | Reference outputs and hidden inputs are closed to group and other and sit outside any artifact directory. | unreachable (absent-member-not-denied) | enforced (2 rules, 4 vectors) | enforced (2 rules, 4 vectors) |
| `vi-9` | V9 Exploit | none | Untrusted data reaches only loaders declared safe, and the report lists at least one loader. | unreachable (absent-member-not-denied) | enforced (2 rules, 5 vectors) | enforced (2 rules, 5 vectors) |
