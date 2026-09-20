# Citation migration inventory: line numbers out, anchors in

Every citation the Go and Python source made into the predicate specification by LINE
NUMBER, with the anchor and digest that replaced it. Derived after the migration from the
previous revision at `25ac858` (2,383 lines) and from `spec/CITATION-ANCHORS.json`.

**119 citation sites migrated, 57 anchors.** Zero line-number citations and
zero orphaned line-number tails remain, and `scripts/spec-drift-gate.py` fails closed on
either.

One old range can appear against two anchors where the cited text spans two companion files,
and two old ranges can share one anchor where both fall inside the same markdown block.
Both are expected: an anchor names a unit of text, not a line span.

| source | old citation | anchor(s) | digest prefix | file |
|---|---|---|---|---|
| `aee/codes.go:111` | `spec:1403-1408` | `req-fields-record-violating-constraint-declared-aeekind` | `4d3303cb6087db63` | fields.md |
| `aee/commitments.go:3` | `spec:569-623` | `req-fields-six-further-coverage-validity-requirements` | `415eace88255cb8a` | fields.md |
| `aee/commitments.go:126` | `spec:574-579` | `req-fields-clean-row-resolves-observationrefs-index` | `156f05c55b1207d7` | fields.md |
| `aee/commitments.go:147` | `spec:580-585` | `req-fields-clean-row-resolves-observationrefs-index` | `156f05c55b1207d7` | fields.md |
| `aee/commitments.go:178` | `spec:1499-1504` | `req-fields-both-registrations-verdict-preserving-what` | `3f3cfef70326695f` | fields.md |
| `aee/commitments.go:209` | `spec:609-613` | `req-fields-clean-row-resolves-observationrefs-index` | `156f05c55b1207d7` | fields.md |
| `aee/commitments.go:242` | `spec:586-594` | `req-fields-clean-row-resolves-observationrefs-index` | `156f05c55b1207d7` | fields.md |
| `aee/commitments.go:268` | `spec:1394-1408, 1687-1691` | `req-fields-aeerunbinding-string-run-binding-digest` + `req-fields-arming-record-s-payload-additionally` | `19184ed4961dd3e4` + `09cfae859933aba4` | fields.md |
| `aee/commitments.go:280` | `spec:586-594` | `req-fields-clean-row-resolves-observationrefs-index` | `156f05c55b1207d7` | fields.md |
| `aee/commitments.go:281` | `spec:1322-1366` | `req-fields-fields-divide-identity-whose-signature-3` | `ab95391e07e8db81` | fields.md |
| `aee/commitments.go:315` | `spec:1361-1366` | `req-fields-dsse-envelope-per-observation-payload` | `b25ccffb96b860aa` | fields.md |
| `aee/commitments.go:373` | `spec:1469-1471, 1537-1539` | `req-fields-what-neither-kind-used-claim` + `req-fields-comparison-subset-rather-than-equality` | `0af0cebb0785e202` + `b518035679b715d4` | fields.md |
| `aee/commitments.go:390` | `spec:1539-1542` | `req-fields-comparison-subset-rather-than-equality` | `b518035679b715d4` | fields.md |
| `aee/commitments.go:430` | `spec:1471-1473` | `req-fields-what-neither-kind-used-claim` | `0af0cebb0785e202` | fields.md |
| `aee/commitments.go:470` | `spec:614-623` | `req-fields-clean-row-resolves-observationrefs-index` | `156f05c55b1207d7` | fields.md |
| `aee/commitments.go:539` | `spec:1454-1458` | `req-fields-neither-kind-carries-constraints-because` | `09116e23544e2120` | fields.md |
| `aee/jcs.go:59` | `spec:100-102` | `req-wireprofile-toto-attestation-framework-plus-understanding` | `9b70dfbc01b9a3f6` | wire-profile.md |
| `aee/jcs.go:63` | `spec:100-102,1311-1313` | `req-wireprofile-toto-attestation-framework-plus-understanding` + `req-fields-fields-divide-identity-whose-signature` | `9b70dfbc01b9a3f6` + `80666d820c397ce5` | fields.md + wire-profile.md |
| `aee/jcs.go:78` | `spec:100-102,1311-1313` | `req-wireprofile-toto-attestation-framework-plus-understanding` + `req-fields-fields-divide-identity-whose-signature` | `9b70dfbc01b9a3f6` + `80666d820c397ce5` | fields.md + wire-profile.md |
| `aee/jcs_number_test.go:9` | `spec:100-102,1311-1313` | `req-wireprofile-toto-attestation-framework-plus-understanding` + `req-fields-fields-divide-identity-whose-signature` | `9b70dfbc01b9a3f6` + `80666d820c397ce5` | fields.md + wire-profile.md |
| `aee/merkle.go:5` | `spec:1744-1749` | `req-fields-within-attestation-these-members-syntax` | `5c41c3e34a850fd5` | fields.md |
| `aee/merkle.go:13` | `spec:1750-1753` | `req-fields-within-attestation-these-members-syntax` | `5c41c3e34a850fd5` | fields.md |
| `aee/pae.go:11` | `spec:1302-1304, 1744-1746` | `req-fields-fields-divide-identity-whose-signature` + `req-fields-within-attestation-these-members-syntax` | `80666d820c397ce5` + `5c41c3e34a850fd5` | fields.md |
| `aee/pae.go:23` | `spec:213-214` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/recompute.go:3` | `spec:435-454` | `req-fields-fail-degraded-pass-indirect-pass` | `1496facaec24f2da` | fields.md |
| `aee/recompute.go:6` | `spec:395-398` | `req-verification-predicate-opts-framework-s-standard` | `4d8aec44d869cd35` | verification.md |
| `aee/recompute.go:98` | `spec:502-511` | `req-fields-attribution-enters-recompute-through-fail` | `d14e1c2f86d9cebc` | fields.md |
| `aee/runbinding.go:9` | `spec:236-240` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/runbinding.go:13` | `spec:174-182` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/runbinding.go:21` | `spec:222-224` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/runbinding.go:37` | `spec:225-226` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/statement.go:23` | `spec:1786-1795` | `req-fields-precedent-informative-reserved-members-inside` | `535994a66179a0d9` | fields.md |
| `aee/statement.go:51` | `spec:313,317` | `req-statement-schema` | `6a9adc2545078f65` | adversarial-execution-evidence.md |
| `aee/statement.go:66` | `spec:1777-1781` | `req-fields-precedent-informative-reserved-members-inside` | `535994a66179a0d9` | fields.md |
| `aee/statement.go:71` | `spec:433-435` | `req-fields-result-string-required-fail-degraded` | `efb1dcd61c2e1d19` | fields.md |
| `aee/statement.go:76` | `spec:785-804` | `req-fields-limit-common-all-four-stronger` | `5e7dea1f752df369` | fields.md |
| `aee/statement.go:102` | `spec:796-804` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:107` | `spec:787-791, 789-791` | `req-fields-further-limit-belongs-member-here` + `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` + `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:112` | `spec:905-908` | `req-fields-networkposture-posture-vocabulary-closed-four` | `70e087cfa806b7ae` | fields.md |
| `aee/statement.go:117` | `spec:918` | `req-fields-set-closed-rather-than-illustrative` | `b18e334448088624` | fields.md |
| `aee/statement.go:122` | `spec:210-213` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/statement.go:130` | `spec:1269-1280` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/statement.go:144` | `spec:963-966` | `req-fields-coverage-object-required-coverage-bound` | `8e3b5d6f5d2bec5f` | fields.md |
| `aee/statement.go:152` | `spec:210-225, 808-810` | `req-wireprofile-run-binding-statement-carrying-least` + `req-fields-further-limit-belongs-member-here` | `4a906dd0fb911530` + `8b73aef98ce43cf7` | fields.md + wire-profile.md |
| `aee/statement.go:157` | `spec:1799-1801` | `req-fields-precedent-informative-reserved-members-inside` | `535994a66179a0d9` | fields.md |
| `aee/statement.go:227` | `spec:802-804` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:260` | `spec:789-791` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:284` | `spec:978-981, 808-810` | `req-fields-row-per-executed-attack-attackid-2` + `req-fields-further-limit-belongs-member-here` | `8177bcb6a7441371` + `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:303` | `spec:815-821` | `req-fields-caught-row-whose-containmentobserved-label` | `ac678ffd07ea2cf0` | fields.md |
| `aee/statement.go:341` | `spec:912-916, 787-791` | `req-fields-networkposture-posture-vocabulary-closed-four-2` + `req-fields-further-limit-belongs-member-here` | `591aef9c088d9164` + `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:380` | `spec:941-946` | `req-fields-typing-discipline-predicate-commits-stated` | `22ef77d9eb2d99d7` | fields.md |
| `aee/statement.go:406` | `spec:808-810` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/statement.go:414` | `spec:210-213` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/statement.go:435` | `spec:213-214` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/tier.go:3` | `spec:766-775` | `req-fields-there-second-use-these-three` | `260bfd9c41c35939` | fields.md |
| `aee/tier.go:10` | `spec:771-774` | `req-fields-there-second-use-these-three` | `260bfd9c41c35939` | fields.md |
| `aee/tier.go:11` | `spec:1901-1903` | `req-verification-consumer-pin-out-band-set` | `263aa86dc614e465` | verification.md |
| `aee/tier.go:25` | `spec:775-779` | `req-fields-closure-against-producer-consumer-obligation` | `eae11109144a622f` | fields.md |
| `aee/tier.go:58` | `spec:1122-1123` | `req-fields-attribution-axis-acquires-such-reader` | `dded35f82974eac5` | fields.md |
| `aee/types.go:9` | `spec:313` | `req-statement-schema` | `6a9adc2545078f65` | adversarial-execution-evidence.md |
| `aee/types.go:13` | `spec:3` | `req-type-uri` | `49df4c4db713a87b` | adversarial-execution-evidence.md |
| `aee/types.go:14` | `spec:236-240` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `aee/types.go:17` | `spec:417-429, 992-1044` | `req-verification-design-invariant-follows-recompute-per` + `req-fields-row-per-executed-attack-attackid` | `defbae512ee38603` + `73a2f29b13fa08fa` | fields.md + verification.md |
| `aee/types.go:30` | `spec:1063-1072` | `req-fields-substrate-input-row-s-claim` | `5d07a2e68d1623d7` | fields.md |
| `aee/types.go:43` | `spec:1375-1447` | `req-fields-dsse-envelope-per-observation-payload-2` | `6ad791ea2fe1f425` | fields.md |
| `aee/types.go:101` | `spec:783-813` | `req-fields-limit-common-all-four-stronger` | `5e7dea1f752df369` | fields.md |
| `aee/types.go:127` | `spec:787-791` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/types.go:138` | `spec:815-828` | `req-fields-caught-row-whose-containmentobserved-label-2` | `853cd39a636c0f55` | fields.md |
| `aee/types.go:158` | `spec:793-795` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/types.go:160` | `spec:847-855` | `req-fields-digest-pinned-context-evidence-was` | `64df74fb15323223` | fields.md |
| `aee/types.go:200` | `spec:847-855` | `req-fields-digest-pinned-context-evidence-was` | `64df74fb15323223` | fields.md |
| `aee/types.go:233` | `spec:796-804` | `req-fields-further-limit-belongs-member-here` | `8b73aef98ce43cf7` | fields.md |
| `aee/types.go:253` | `spec:907-916` | `req-fields-networkposture-posture-vocabulary-closed-four-2` | `591aef9c088d9164` | fields.md |
| `aee/types.go:262` | `spec:1093-1097` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/types.go:288` | `spec:1298-1302` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/types.go:296` | `spec:1300-1302` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/types.go:333` | `spec:1901-1903` | `req-verification-consumer-pin-out-band-set` | `263aa86dc614e465` | verification.md |
| `aee/validity.go:3` | `spec:542-629` | `req-fields-coverage-validity-derived-carried-bytes` | `d0ffa1e57be1f4e6` | fields.md |
| `aee/validity.go:9` | `spec:544-547` | `req-fields-coverage-validity-derived-carried-bytes-2` | `c6e2553188dd254a` | fields.md |
| `aee/validity.go:25` | `spec:1320-1342` | `req-fields-fields-divide-identity-whose-signature-2` | `fda9d561e208e9e4` | fields.md |
| `aee/validity.go:36` | `spec:1449-1452` | `req-fields-moat-drop-drop-containment-layer` | `5c9e1e0b596d6f4e` | fields.md |
| `aee/validity.go:146` | `spec:1300-1302` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/validity.go:147` | `spec:1742` | `req-fields-within-attestation-these-members-syntax` | `5c41c3e34a850fd5` | fields.md |
| `aee/validity.go:148` | `spec:1754-1756` | `req-fields-within-attestation-these-members-syntax` | `5c41c3e34a850fd5` | fields.md |
| `aee/validity.go:149` | `spec:1767-1770` | `req-fields-within-attestation-these-members-syntax` | `5c41c3e34a850fd5` | fields.md |
| `aee/validity.go:168` | `spec:1302-1309` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/validity.go:176` | `spec:413-415` | `req-verification-verifier-proceeds-two-stages-stage` | `001da26fd6fb6158` | verification.md |
| `aee/validity.go:272` | `spec:1309-1318` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/validity.go:336` | `spec:1322-1366` | `req-fields-fields-divide-identity-whose-signature-3` | `ab95391e07e8db81` | fields.md |
| `aee/validity.go:338` | `spec:1344-1347` | `req-fields-actuallayer-names-enforcement-layer-acted` | `fcb00b09c3b370f0` | fields.md |
| `aee/validity.go:340` | `spec:1687-1689` | `req-fields-arming-record-s-payload-additionally-2` | `5a96403832635f13` | fields.md |
| `aee/validity.go:359` | `spec:1469-1471, 1537-1539` | `req-fields-what-neither-kind-used-claim` + `req-fields-comparison-subset-rather-than-equality` | `0af0cebb0785e202` + `b518035679b715d4` | fields.md |
| `aee/validity.go:369` | `spec:1454-1458` | `req-fields-neither-kind-carries-constraints-because` | `09116e23544e2120` | fields.md |
| `aee/validity.go:390` | `spec:1394-1408` | `req-fields-aeerunbinding-string-run-binding-digest` | `19184ed4961dd3e4` | fields.md |
| `aee/validity.go:419` | `spec:1326-1327` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `aee/validity.go:431` | `spec:1467-1471` | `req-fields-neither-kind-carries-constraints-because-2` | `07ab497d65ebb3b5` | fields.md |
| `aee/validity.go:456` | `spec:1361-1366` | `req-fields-dsse-envelope-per-observation-payload` | `b25ccffb96b860aa` | fields.md |
| `aee/validity.go:466` | `spec:1499-1506, 1535-1539` | `req-fields-both-registrations-verdict-preserving-what` + `req-fields-comparison-subset-rather-than-equality` | `3f3cfef70326695f` + `b518035679b715d4` | fields.md |
| `aee/validity.go:556` | `spec:554-560` | `req-fields-observationrefs-non-empty-index-range` | `03ce53b6ce12e42c` | fields.md |
| `aee/validity.go:564` | `spec:760-764, 1093-1097` | `req-fields-expectedpayloads-aeepayloadcommitment-attribution-bind-permut` + `req-fields-method-states-how-row-s` | `580f5b43bf5b03e0` + `d35548444900b334` | fields.md |
| `aee/validity.go:602` | `spec:552-553` | `req-fields-observationrefs-non-empty-index-range` | `03ce53b6ce12e42c` | fields.md |
| `aee/validity.go:628` | `spec:561-564` | `req-fields-observationrefs-non-empty-index-range` | `03ce53b6ce12e42c` | fields.md |
| `aee/validity.go:641` | `spec:1344-1366, 554-560` | `req-fields-actuallayer-names-enforcement-layer-acted-2` + `req-fields-observationrefs-non-empty-index-range` | `37221bc432684004` + `03ce53b6ce12e42c` | fields.md |
| `aee/validity.go:712` | `spec:565-566` | `req-fields-observationrefs-non-empty-index-range` | `03ce53b6ce12e42c` | fields.md |
| `aee/vectors_test.go:661` | `spec:766-775` | `req-fields-there-second-use-these-three` | `260bfd9c41c35939` | fields.md |
| `aee/vectors_test.go:664` | `spec:1122-1123` | `req-fields-attribution-axis-acquires-such-reader` | `dded35f82974eac5` | fields.md |
| `aee/verify.go:13` | `spec:625-629` | `req-fields-these-requirements-consumption-preconditions-optional` | `0d960383b00e82b9` | fields.md |
| `packaging/run_vectors.py:1015` | `spec:1786-1795` | `req-fields-precedent-informative-reserved-members-inside` | `535994a66179a0d9` | fields.md |
| `packaging/run_vectors.py:1494` | `spec:968-990` | `req-fields-coverage-bound-assessedclasses-array-class` | `be2e39f3e7439e24` | fields.md |
| `packaging/run_vectors.py:1572` | `spec:912-916` | `req-fields-networkposture-posture-vocabulary-closed-four-2` | `591aef9c088d9164` | fields.md |
| `packaging/run_vectors.py:1609` | `spec:941-946` | `req-fields-typing-discipline-predicate-commits-stated` | `22ef77d9eb2d99d7` | fields.md |
| `packaging/run_vectors.py:1658` | `spec:210-213` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |
| `packaging/run_vectors.py:1723` | `spec:1300-1302` | `req-fields-fields-divide-identity-whose-signature` | `80666d820c397ce5` | fields.md |
| `scripts/count-gate.py:83` | `spec:1023-1028` | `req-fields-row-per-executed-attack-attackid` | `73a2f29b13fa08fa` | fields.md |
| `scripts/spec_anchors.py:5` | `spec:1302-1304` | `req-fields-there-second-use-these-three` | `260bfd9c41c35939` | fields.md |
| `vectors/accept/gen_valid_vectors.py:1237` | `spec:1687-1689` | `req-fields-arming-record-s-payload-additionally-2` | `5a96403832635f13` | fields.md |
| `vectors/accept/gen_valid_vectors.py:1239` | `spec:565-566` | `req-fields-observationrefs-non-empty-index-range` | `03ce53b6ce12e42c` | fields.md |
| `vectors/gen_manifest.py:46` | `spec:726-735` | `req-fields-basis-vantage-claim-s-weakest` | `05d61e84eea58c1e` | fields.md |
| `vectors/reject/gen_invalid_vectors.py:2075` | `spec:210-213` | `req-wireprofile-run-binding-statement-carrying-least` | `4a906dd0fb911530` | wire-profile.md |

Sites not migrated: **0**.

## The anchors

| anchor | file | blocks | sha256 | text |
|---|---|---|---|---|
| `req-fields-actuallayer-names-enforcement-layer-acted` | `fields.md` | 1 | `fcb00b09c3b370f0` | `actualLayer` names the enforcement layer that acted on the row's containment event. It is |
| `req-fields-actuallayer-names-enforcement-layer-acted-2` | `fields.md` | 3 | `37221bc432684004` | `actualLayer` names the enforcement layer that acted on the row's containment event. It is |
| `req-fields-aeeobservedattacks-binds-deletion-relabelling-member` | `fields.md` | 2 | `05c15d9150a03971` | `aeeObservedAttacks` binds the deletion and the relabelling in one member, because deletin |
| `req-fields-aeerunbinding-string-run-binding-digest` | `fields.md` | 2 | `19184ed4961dd3e4` | - `aeeRunBinding` _string_: the run binding digest defined under Prerequisites. - `aeeKind |
| `req-fields-arming-record-s-payload-additionally` | `fields.md` | 2 | `09cfae859933aba4` | An `arming` record's payload MAY additionally carry three reserved members that chain runs |
| `req-fields-arming-record-s-payload-additionally-2` | `fields.md` | 1 | `5a96403832635f13` | An `arming` record's payload MAY additionally carry three reserved members that chain runs |
| `req-fields-attribution-axis-acquires-such-reader` | `fields.md` | 1 | `dded35f82974eac5` | `attribution` is the axis that acquires such a reader at this version. It states how firml |
| `req-fields-attribution-enters-recompute-through-fail` | `fields.md` | 1 | `d14e1c2f86d9cebc` | `attribution` enters the recompute through the fail-closed arm of the first condition and  |
| `req-fields-basis-vantage-claim-s-weakest` | `fields.md` | 1 | `05d61e84eea58c1e` | `basis` is the vantage of the claim's weakest input. A derived observation inherits `artif |
| `req-fields-both-registrations-verdict-preserving-what` | `fields.md` | 1 | `3f3cfef70326695f` | Both registrations are verdict-preserving, which is what makes them additions a minor revi |
| `req-fields-caught-row-whose-containmentobserved-label` | `fields.md` | 1 | `ac678ffd07ea2cf0` | A caught row is one whose `containmentObserved` label is in the carried caught set (`obser |
| `req-fields-caught-row-whose-containmentobserved-label-2` | `fields.md` | 2 | `853cd39a636c0f55` | A caught row is one whose `containmentObserved` label is in the carried caught set (`obser |
| `req-fields-clean-row-resolves-observationrefs-index` | `fields.md` | 1 | `156f05c55b1207d7` | - a clean row resolves no `observationRefs` index to an `interception` record. A row stati |
| `req-fields-closure-against-producer-consumer-obligation` | `fields.md` | 1 | `eae11109144a622f` | The closure against that producer is the consumer obligation stated under Consumer policy  |
| `req-fields-comparison-subset-rather-than-equality` | `fields.md` | 1 | `b518035679b715d4` | The comparison is a subset rather than an equality, and the choice is load-bearing in both |
| `req-fields-coverage-bound-assessedclasses-array-class` | `fields.md` | 3 | `be2e39f3e7439e24` | The coverage bound: `assessedClasses` (array of class codes actually assessed), `outOfScop |
| `req-fields-coverage-object-required-coverage-bound` | `fields.md` | 2 | `8e3b5d6f5d2bec5f` | `coverage` _object, required_ The coverage bound: `assessedClasses` (array of class codes  |
| `req-fields-coverage-validity-derived-carried-bytes` | `fields.md` | 5 | `d0ffa1e57be1f4e6` | **Coverage validity (derived from carried bytes; a violation is malformed).** For every `b |
| `req-fields-coverage-validity-derived-carried-bytes-2` | `fields.md` | 1 | `c6e2553188dd254a` | **Coverage validity (derived from carried bytes; a violation is malformed).** For every `b |
| `req-fields-digest-pinned-context-evidence-was` | `fields.md` | 1 | `64df74fb15323223` | The digest-pinned context the evidence was earned under. Five required members: `substrate |
| `req-fields-dsse-envelope-per-observation-payload` | `fields.md` | 1 | `b25ccffb96b860aa` | One DSSE envelope per observation: `payload` (base64 of the exact canonical bytes the subs |
| `req-fields-dsse-envelope-per-observation-payload-2` | `fields.md` | 7 | `6ad791ea2fe1f425` | One DSSE envelope per observation: `payload` (base64 of the exact canonical bytes the subs |
| `req-fields-expectedpayloads-aeepayloadcommitment-attribution-bind-permut` | `fields.md` | 1 | `580f5b43bf5b03e0` | `expectedPayloads`, `aeePayloadCommitment` and `attribution` bind the permutation of the r |
| `req-fields-fail-degraded-pass-indirect-pass` | `fields.md` | 1 | `1496facaec24f2da` | One of `fail`, `degraded`, `pass_indirect`, `pass` (lowercase), ordered `fail` < `degraded |
| `req-fields-fields-divide-identity-whose-signature` | `fields.md` | 1 | `80666d820c397ce5` | Fields divide by the identity whose signature backs them. Substrate-covered, through the c |
| `req-fields-fields-divide-identity-whose-signature-2` | `fields.md` | 2 | `fda9d561e208e9e4` | Fields divide by the identity whose signature backs them. Substrate-covered, through the c |
| `req-fields-fields-divide-identity-whose-signature-3` | `fields.md` | 4 | `ab95391e07e8db81` | Fields divide by the identity whose signature backs them. Substrate-covered, through the c |
| `req-fields-further-limit-belongs-member-here` | `fields.md` | 1 | `8b73aef98ce43cf7` | A further limit belongs to no member here and would not be closed by adding one. `basis` n |
| `req-fields-limit-common-all-four-stronger` | `fields.md` | 2 | `5e7dea1f752df369` | One limit is common to all four and is stronger than any of them. A property that compares |
| `req-fields-method-states-how-row-s` | `fields.md` | 2 | `d35548444900b334` | `method` states how the row's claim was established, with a closed two-value vocabulary: - |
| `req-fields-moat-drop-drop-containment-layer` | `fields.md` | 1 | `5c9e1e0b596d6f4e` | `moat-drop` is a drop the containment layer performed and the substrate observed from the  |
| `req-fields-neither-kind-carries-constraints-because` | `fields.md` | 1 | `09116e23544e2120` | Neither kind carries constraints, because there is no state in which either covers anythin |
| `req-fields-neither-kind-carries-constraints-because-2` | `fields.md` | 2 | `07ab497d65ebb3b5` | Neither kind carries constraints, because there is no state in which either covers anythin |
| `req-fields-networkposture-posture-vocabulary-closed-four` | `fields.md` | 1 | `70e087cfa806b7ae` | The `networkPosture.posture` vocabulary is closed. Four values are registered: `allowlist` |
| `req-fields-networkposture-posture-vocabulary-closed-four-2` | `fields.md` | 2 | `591aef9c088d9164` | The `networkPosture.posture` vocabulary is closed. Four values are registered: `allowlist` |
| `req-fields-observationrefs-non-empty-index-range` | `fields.md` | 1 | `03ce53b6ce12e42c` | - its `observationRefs` is non-empty and every index is in range for `observationRecords`; |
| `req-fields-precedent-informative-reserved-members-inside` | `fields.md` | 1 | `535994a66179a0d9` | _Precedent (informative)._ Reserved members inside a producer-defined signed payload follo |
| `req-fields-record-violating-constraint-declared-aeekind` | `fields.md` | 1 | `4d3303cb6087db63` | A record violating any constraint of its declared `aeeKind` (including a missing `armedAt` |
| `req-fields-result-string-required-fail-degraded` | `fields.md` | 2 | `efb1dcd61c2e1d19` | `result` _string, required_ One of `fail`, `degraded`, `pass_indirect`, `pass` (lowercase) |
| `req-fields-row-per-executed-attack-attackid` | `fields.md` | 2 | `73a2f29b13fa08fa` | One row per executed attack: `attackId` (must appear in the manifest), `containmentObserve |
| `req-fields-row-per-executed-attack-attackid-2` | `fields.md` | 1 | `8177bcb6a7441371` | One row per executed attack: `attackId` (must appear in the manifest), `containmentObserve |
| `req-fields-set-closed-rather-than-illustrative` | `fields.md` | 1 | `b18e334448088624` | The set is closed rather than illustrative for a reason that is not housekeeping. A consum |
| `req-fields-six-further-coverage-validity-requirements` | `fields.md` | 2 | `415eace88255cb8a` | Six further coverage validity requirements hold on the statement, or on every row rather t |
| `req-fields-substrate-input-row-s-claim` | `fields.md` | 2 | `5d07a2e68d1623d7` | - `substrate`: every input the row's claim depends on was obtained at a vantage the execut |
| `req-fields-there-second-use-these-three` | `fields.md` | 1 | `260bfd9c41c35939` | There is a second use of these three members, found by implementing them rather than by de |
| `req-fields-these-requirements-consumption-preconditions-optional` | `fields.md` | 1 | `0d960383b00e82b9` | These requirements are consumption preconditions, not optional lints: a consumer that cons |
| `req-fields-typing-discipline-predicate-commits-stated` | `fields.md` | 2 | `22ef77d9eb2d99d7` | A typing discipline this predicate commits to, stated here so that a later reader inherits |
| `req-fields-what-neither-kind-used-claim` | `fields.md` | 1 | `0af0cebb0785e202` | What neither kind may be used to claim is the half worth stating, because a record that co |
| `req-fields-within-attestation-these-members-syntax` | `fields.md` | 1 | `5c41c3e34a850fd5` | Within one attestation these members are syntax-checked in the reserved-member walk and no |
| `req-statement-schema` | `adversarial-execution-evidence.md` | 1 | `6a9adc2545078f65` | ```jsonc { "_type": "https://in-toto.io/Statement/v1", "subject": [ { "name": "<artifact-n |
| `req-type-uri` | `adversarial-execution-evidence.md` | 1 | `49df4c4db713a87b` | Type URI: https://in-toto.io/attestation/adversarial-execution-evidence/v0.7 |
| `req-verification-consumer-pin-out-band-set` | `verification.md` | 1 | `263aa86dc614e465` | A consumer MUST pin, out of band, the set of assessment classes it requires a run to have  |
| `req-verification-design-invariant-follows-recompute-per` | `verification.md` | 1 | `defbae512ee38603` | A design invariant follows from the recompute: any per-observation property that the recom |
| `req-verification-predicate-opts-framework-s-standard` | `verification.md` | 1 | `4d8aec44d869cd35` | The predicate opts in to the framework's standard parsing rules, including the monotonic p |
| `req-verification-verifier-proceeds-two-stages-stage` | `verification.md` | 1 | `001da26fd6fb6158` | A verifier proceeds in two stages. Stage one is byte-pure: four validity steps, each a fun |
| `req-wireprofile-run-binding-statement-carrying-least` | `wire-profile.md` | 1 | `4a906dd0fb911530` | **Run binding.** For any statement carrying at least one `basis: substrate` row, the run b |
| `req-wireprofile-toto-attestation-framework-plus-understanding` | `wire-profile.md` | 1 | `9b70dfbc01b9a3f6` | The in-toto Attestation Framework, plus an understanding of [DSSE](https://github.com/secu |
