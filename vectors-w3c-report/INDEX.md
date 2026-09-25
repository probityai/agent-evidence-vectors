# Conformance vectors (v0.1 per-check report)

Every member of this suite in one table, rejected and accepted alike. Ground
truth: 14 texts vendored in `spec-vendored/` and pinned by sha256 in
`MANIFEST.json`: 12 messages of the W3C public-agent-conformance list that
together fix what v0.1 of the reporting format freezes, and the two
Internet-Drafts the format's editor holds.

This corpus is 232 vectors, of which 116 a conformant verifier must not fail closed
on and 116 it must reject.

**Three subject types, one manifest.** 166 members are whole
v0.1 reports, judged by the rows of the format; 44
are Run objects of the agent-run-metrics draft; 22
are discovery snapshots of the context-discovery draft. Each member names its
subject type and the reader selects the validator by it.

**A report member is a whole report**, not one record, because two of the rules
v0.1 carries are properties of the report: whether its roll-up says its checks
could have gone negative, and whether the digest over its check set binds the
leaf count and names the tree shape. A record-level corpus could not express
either.

**Every reject member names exactly one row.** The generator runs the validator
over each member before writing it and refuses a reject that fires two rows or
an accept that fires one, so a member here demonstrates which requirement is
live rather than the fact of rejection. `MUTATION-SWEEP.md`, regenerated with
the vectors, relaxes each row in turn and records that only the members naming
it flip.

**Identifiers are minted here and bound to a sentence.** The texts carry no
requirement identifiers, so each row below quotes its sentence, the generator
locates it in the vendored copy and hashes it, and a reword stops the build.

**The 84 members of family `w3c-f-disensor`** are re-cut from the
42 delta-related pairs Nicolas Rocchia counted in his own corpus at
`NicolasRocchia/disensor@1e36257`: each pair appears once as
emitted before the freeze, rejected under the declared-slot rule with its cause,
and once re-cut against v0.1, accepted. `origin/derive_pairs.py` derives the
pairs from that repository and `origin/disensor-1e36257-pairs.json` is what it
wrote.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-w3c-report/` from the repository root, or
`python3 packaging/run_vectors.py --corpus vectors-w3c-report`; the two print
the same lines.

## Vendored text

| key | author | path | sha256 | source |
|---|---|---|---|---|
| `0001` | Kenne Ives | `spec-vendored/0001-ives-2026-09-01-coverage-block.txt` | `62bafb6e88629bda` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0001.html |
| `0025` | Nicolas Rocchia | `spec-vendored/0025-rocchia-2026-09-13-state-cause-pair-table.txt` | `2ee9306408474a69` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0025.html |
| `0036` | Evgenii Arsentev | `spec-vendored/0036-arsentev-2026-09-14-discrimination-and-populations.txt` | `7a034174eb5f27f8` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0036.html |
| `0043` | Nicolas Rocchia | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `76f5af49f11108fc` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0043.html |
| `0050` | Kenne Ives | `spec-vendored/0050-ives-2026-09-15-recomputed-delta.txt` | `1399c56136e7aa76` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0050.html |
| `0060` | Nicolas Rocchia | `spec-vendored/0060-rocchia-2026-09-16-freeze-list.txt` | `47f96e10c2ac5dc0` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0060.html |
| `0062` | Evgenii Arsentev | `spec-vendored/0062-arsentev-2026-09-17-editor-freeze-list.txt` | `b92f4a6ca926eaa8` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0062.html |
| `0069` | Evgenii Arsentev | `spec-vendored/0069-arsentev-2026-09-18-late-additions.txt` | `40153b17403b0e65` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0069.html |
| `0072` | Nicolas Rocchia | `spec-vendored/0072-rocchia-2026-09-18-handover.txt` | `27cea4f3ffd48ed4` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0072.html |
| `0073` | Evgenii Arsentev | `spec-vendored/0073-arsentev-2026-09-18-fixed-scope.txt` | `42fa833367e0e1d5` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0073.html |
| `0076` | Roel Schuurkes | `spec-vendored/0076-schuurkes-2026-09-22-v01-comments.txt` | `7622d0dc1cf7fc1d` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0076.html |
| `0077` | Nicolas Rocchia | `spec-vendored/0077-rocchia-2026-09-23-v01-answers.txt` | `88531111f9d8c424` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0077.html |
| `draft-arsentev-agent-run-metrics-00` | Evgenii Arsentev | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `0ef9e7fbc39d04bf` | https://datatracker.ietf.org/doc/draft-arsentev-agent-run-metrics/ |
| `draft-arsentev-llm-context-discovery-00` | Evgenii Arsentev | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `13081268c70a19e9` | https://datatracker.ietf.org/doc/draft-arsentev-llm-context-discovery/ |

## Requirements

The class column is the handover's sort of the rows: consistency rows read
declared slots against each other, evidence rows read a declared slot against
a recomputed or resolved one, form rows are decidable from the object alone.
The status column says whether the list agreed the row or this corpus proposes
it (the numbering of rows 13 and 14, and the class of rows 4, 10, 11, 12 and
13, which the handover left unclassified).

| id | row | class | status | vendored in | sentence digest | normative sentence |
|---|---|---|---|---|---|---|
| `W3C-R-001` | 1 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `87893835a3e13451` | a non-verdict state with no cause |
| `W3C-R-002` | 2 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `05fb9274ff0859d9` | void with not_applicable, out_of_scope or withheld |
| `W3C-R-003` | 3 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `587e9bc351daaed2` | not-exercised with integrity-failure |
| `W3C-R-004` | 4 | consistency | proposed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `32dd6b74795b02bd` | a confinement control that failed while the check ran |
| `W3C-R-005` | 5 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `ed9007c6e8a11eb2` | a declared exclusion with any state but not-exercised |
| `W3C-R-006` | 6 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `4ef6f3c9383ae454` | a non-verdict state carrying either qualifier |
| `W3C-R-007` | 7 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `831dc816ea23fa26` | a verdict state carrying a cause |
| `W3C-R-008` | 8 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `2c6f812fc2752889` | other-verdict foreclosed with discrimination demonstrated |
| `W3C-R-009` | 9 | consistency | agreed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `111e3eb11cdcc313` | discrimination demonstrated with other-verdict unknown |
| `W3C-R-010` | 10 | consistency | proposed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `139eba59f4dc4345` | foreclosed without a constraint set and a domain |
| `W3C-R-011` | 11 | consistency | proposed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `f68cd56a997a5773` | an asserted value without its evidence reference |
| `W3C-R-012` | 12 | consistency | proposed | `spec-vendored/0043-rocchia-2026-09-15-consolidated-table.txt` | `d2268e7db1d50fe5` | whose changed slot is the checker |
| `W3C-R-013` | (a) roll-up | evidence | agreed | `spec-vendored/0069-arsentev-2026-09-18-late-additions.txt` | `f73fd10347201018` | a roll-up states whether the checks it aggregates were capable of a negative verdict |
| `W3C-R-014` | (a) prior run | consistency | agreed | `spec-vendored/0069-arsentev-2026-09-18-late-additions.txt` | `2da5682dbbb4be1f` | a prior discriminating run only counts where check identity survives across runs |
| `W3C-R-015` | (b) set binding | evidence | agreed | `spec-vendored/0069-arsentev-2026-09-18-late-additions.txt` | `c6fe2b8552666e81` | digest match establishes a set only when the count of leaves is bound too, and a report says which tree shape it uses |
| `W3C-R-016` | declared slots | consistency | agreed | `spec-vendored/0062-arsentev-2026-09-17-editor-freeze-list.txt` | `303d488c14eed0d2` | an object whose moved is not contained in its declared set is rejected |
| `W3C-R-017` | roll-up denominator | evidence | agreed | `spec-vendored/0060-rocchia-2026-09-16-freeze-list.txt` | `526d7694de57f6c5` | never emitted without its complete denominator |
| `W3C-R-018` | roll-up counter | evidence | agreed | `spec-vendored/0060-rocchia-2026-09-16-freeze-list.txt` | `31c3dfd19fc59147` | the counter over carried against referenced |
| `W3C-R-019` | closed vocabulary | form | agreed | `spec-vendored/0025-rocchia-2026-09-13-state-cause-pair-table.txt` | `1b376a60d7520ff7` | because free text does not aggregate |
| `W3C-R-020` | reference mismatch | evidence | agreed | `spec-vendored/0062-arsentev-2026-09-17-editor-freeze-list.txt` | `af507f1056e619da` | resolves with a mismatch (an integrity failure) |
| `W3C-R-021` | recomputed delta | evidence | agreed | `spec-vendored/0050-ives-2026-09-15-recomputed-delta.txt` | `bc4afdb28cee9c30` | they read moved as recomputed from the two observations the object names |
| `W3C-R-022` | coverage block | form | agreed | `spec-vendored/0001-ives-2026-09-01-coverage-block.txt` | `50c6f490bcf092b2` | a sampled / full_coverage flag with the count of scannable files recorded before the per-repo cap |
| `W3C-R-023` | population denominator | evidence | agreed | `spec-vendored/0036-arsentev-2026-09-14-discrimination-and-populations.txt` | `04fa2499c017be72` | a claim over an empty population is reported as not claimable, not as satisfied |
| `W3C-R-024` | delta-related pair | consistency | agreed | `spec-vendored/0036-arsentev-2026-09-14-discrimination-and-populations.txt` | `d75ca465cf824295` | Unrelated pass and fail records in one corpus must not qualify |
| `W3C-R-025` | 13 (proposed) | evidence | proposed | `spec-vendored/0072-rocchia-2026-09-18-handover.txt` | `01119b86460f6112` | other-verdict demonstrated citing an evidence object whose moved does not contain the verdict |
| `W3C-R-026` | 14 (proposed) | form | proposed | `spec-vendored/0072-rocchia-2026-09-18-handover.txt` | `021af13381601bcf` | 14 moved asserted on an evidence object that neither carries both observations nor references them with digests |
| `W3C-R-029` | (a) control binding | consistency | proposed | `spec-vendored/0076-schuurkes-2026-09-22-v01-comments.txt` | `c3507c44c022f601` | say that the control uses the same checker revision and relevant configuration and constraints as the checks whose negative capability is being reported |
| `W3C-R-027` | arity recomputed | form | agreed | `spec-vendored/0072-rocchia-2026-09-18-handover.txt` | `8d4a3be209be152c` | so arity is recomputed from the delta |
| `W3C-R-028` | domain once | form | agreed | `spec-vendored/0072-rocchia-2026-09-18-handover.txt` | `fc883a4e2664fb33` | The domain is declared once at run level |
| `ARM-R-001` | 5.1 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `f313511759b2f6ce` | Reporter MUST emit "1" while conforming to this specification |
| `ARM-R-002` | 3.1 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `a82c8c4e90b439d6` | The "end" member MUST be present when "status" is "completed",    "failed" or "aborted", and MUST NOT be present when "status" is    "running" |
| `ARM-R-003` | 3.1 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `1651e4aa28aef3c5` | When present, "end" MUST NOT be earlier than "start" |
| `ARM-R-004` | 3.1 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `532a0c7a01289d79` | a Reporter MUST NOT emit    a value other than the four listed |
| `ARM-R-005` | 3.1 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `b0245f78d559c0cf` | When the "steps" array is present, "step_count" MUST be    greater than or equal to the length of that array |
| `ARM-R-006` | 3.2 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `de2c45f5dcc4d136` | Within one Run, "index" values MUST be unique and MUST be assigned in    the order in which Steps began |
| `ARM-R-007` | 3.2 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `bb47f3459eea16f1` | When "kind" is "model_invocation", the "usage" and "model" members    MUST be present |
| `ARM-R-008` | 3.2 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `cbf735970617d21d` | When "kind" is "tool_call", the "tool" member MUST    be present and the "usage" member MUST NOT be present |
| `ARM-R-009` | 3.4 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `0748102d1586a9c5` | All members of a Usage object MUST be non-negative integers |
| `ARM-R-010` | 3.4 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `912e608876053400` | "cache_read_tokens" is a subset of "input_tokens" and therefore        MUST be less than or equal to it |
| `ARM-R-011` | 3.4 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `ab264faa892721d2` | "cache_read_tokens" and "cache_write_tokens"        denote disjoint subsets of "input_tokens" and their sum MUST be        less than or equal to "input_tokens" |
| `ARM-R-012` | 3.4 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `e6b6a4c51dfe30f7` | "totals" object MUST be, member by member, the sum of the    corresponding members of every Step's Usage object |
| `ARM-R-013` | 3.5 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `89119163b621c774` | One    "lifetime" value MUST NOT appear in more than one element of the same    array |
| `ARM-R-014` | 3.5 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `17816ade45921f0d` | The sum of the "tokens" members of "cache_writes" MUST equal the    "cache_write_tokens" member of the same Usage object |
| `ARM-R-015` | 3.3 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `0883bbd19a653019` | A Reporter MUST NOT    emit two Steps of one Run with the same "invocation_id" |
| `ARM-R-016` | 3.6 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `546781f078f7e248` | A Run that emits "root_run_id" and has no       parent MUST set it equal to its own "run_id" |
| `ARM-R-017` | 3.7 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `f15b1c8c7a0cfe45` | The "amount" member MUST be a JSON string matching the ABNF [RFC5234]    rule |
| `ARM-R-018` | 3.12 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `4d1f574a3f6c8983` | Its value MUST be a JSON object whose members all    have string values |
| `ARM-R-019` | 5 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `af8a371a7c03ddaa` | Timestamps MUST be strings conforming to the "date-time" production    of [RFC3339].  They MUST use the "Z" time offset |
| `ARM-R-020` | 5 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `f45b4290574244a8` | MUST be non-empty strings of at most 128    characters |
| `ARM-R-021` | 5.1 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `a9283399f2f72c8c` | A Reporter MUST NOT use an unprefixed member    name for a purpose other than the one specified here |
| `ARM-R-022` | 3.4 | - | - | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `77239d6671db6001` | "reasoning_tokens" is a subset of "output_tokens" and        therefore MUST be less than or equal to it |
| `LCD-R-001` | 3.1 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `dea0684290a3e21a` | A context file MUST NOT be served with a "Content-Type" of "text/    html" |
| `LCD-R-002` | 3.2 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `993eae7ed8a98e13` | A discovery mechanism defined in Section 4 MUST point at an index       resource, never directly at a detail resource |
| `LCD-R-003` | 4.1 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `b75a01b97d999548` | A publisher advertising a context file through this mechanism MUST    arrange that a GET request for "/.well-known/llm-context" on the    origin returns either |
| `LCD-R-004` | 4.3 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `cbf9300432d96463` | Its value MUST be an absolute    URI |
| `LCD-R-005` | 4.3 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `6c62b556add0487c` | A publisher MUST NOT use this record to advertise a context file    whose retrieval the same robots.txt disallows |
| `LCD-R-006` | 4.4 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `bc76905fa3c30441` | a consumer MUST    apply the following precedence, highest first |
| `LCD-R-007` | 4.4 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `9303b76c717a46a4` | A consumer MUST NOT retrieve more than one index resource per origin    per retrieval cycle |
| `LCD-R-008` | 7.2 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `de7f08a1b2a8a663` | A consumer MUST NOT attribute the content of a cross-origin index    resource to the advertising origin |
| `LCD-R-009` | 7.4 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `6bf3ffe5624cb4d3` | A consumer MUST impose its own ceiling on the size of any retrieved    context file |
| `LCD-R-010` | 3.3 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `1f8ceb1482c75131` | the response MUST carry an appropriate "Content-Language" |
| `LCD-R-011` | 4.4 | - | - | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `1cb26bd4e4ca5526` | a consumer MUST evaluate the exclusion    rules of [RFC9309] against the index resource's URI before retrieving    it |

## Families

| id | what the family is |
|---|---|
| `w3c-f-1` | row 1: a non-verdict state with no cause |
| `w3c-f-2` | row 2: void with a cause that describes a unit never examined |
| `w3c-f-3` | row 3: not-exercised with integrity-failure |
| `w3c-f-4` | row 4: a confinement failure during the check as the cause, and the state is not void |
| `w3c-f-5` | row 5: a declared exclusion whose state is not not-exercised |
| `w3c-f-6` | row 6: a non-verdict state carrying a qualifier |
| `w3c-f-7` | row 7: a verdict state carrying a cause |
| `w3c-f-8` | row 8: other-verdict foreclosed beside discrimination demonstrated |
| `w3c-f-9` | row 9: discrimination demonstrated beside an other-verdict that is not demonstrated |
| `w3c-f-10` | row 10: foreclosed without its constraint set and domain |
| `w3c-f-11` | row 11: an asserted qualifier value without its evidence reference |
| `w3c-f-12` | row 12: discrimination demonstrated citing evidence whose changed slot is the checker |
| `w3c-f-13` | late addition (a): a roll-up says whether its checks could have gone negative |
| `w3c-f-14` | late addition (a): a prior discriminating run binds the check identity that survived |
| `w3c-f-15` | late addition (b): a digest over a set binds its leaf count and names its tree shape; domain separation alone is not the fix |
| `w3c-f-16` | declared slots: moved is contained in the declared compared set |
| `w3c-f-29` | late addition (a), amended in the comment window: a control built to fail is bound to the checker and constraint set of the checks it speaks for |
| `w3c-f-17` | roll-up: the aggregate carries its complete denominator |
| `w3c-f-18` | roll-up: the counter over carried against referenced recomputes |
| `w3c-f-19` | closed vocabulary: a value outside a registry is not read |
| `w3c-f-20` | carry-or-reference: a digest that resolves with a mismatch is an integrity failure, over the check set and over a referenced observation alike |
| `w3c-f-21` | recomputed delta: moved is read as recomputed over the observations, not as declared |
| `w3c-f-22` | coverage block: scope disclosure in controlled fields, with the pre-cap file count |
| `w3c-f-23` | population denominator: a completeness claim carries the size of its population |
| `w3c-f-24` | delta-related pair: unrelated pass and fail records do not witness discrimination |
| `w3c-f-25` | row 13 (proposed): other-verdict demonstrated citing an object whose recomputed moved does not contain the verdict; unresolvable, the row degrades |
| `w3c-f-26` | row 14 (proposed): moved asserted on an object that neither carries its observations nor references them with digests |
| `w3c-f-27` | arity: recomputed from the delta, never declared |
| `w3c-f-28` | domain: declared once at run level, named by identifier and never restated |
| `w3c-f-gaps` | the two known gaps of the reference emitter, closed: void has a slot and not-exercised carries a cause |
| `w3c-f-disensor` | the 42 delta-related pairs of the disensor corpus at 1e36257, re-cut against v0.1 |
| `arm-f-run` | agent run metrics: the Run object's own members |
| `arm-f-steps` | agent run metrics: the Step objects and their order |
| `arm-f-usage` | agent run metrics: the Usage invariants and the cache-write ledger |
| `arm-f-totals` | agent run metrics: the totals as the sum of the steps |
| `arm-f-serialization` | agent run metrics: timestamps, identifiers, labels, cost and extensions |
| `lcd-f-publisher` | context discovery: what the origin advertises and serves |
| `lcd-f-consumer` | context discovery: what a consumer resolves, retrieves and attributes |

## Vectors

| id | kind | subject | family | requirements | rejected under |
|---|---|---|---|---|---|
| `v0090b52048ca1f51` | accept | report | w3c-f-10 | W3C-R-010 | none |
| `v0120d95db38b892b` | reject | agent-run-metrics | arm-f-usage | ARM-R-010 | ARM-R-010 |
| `v04934d23180f6d9c` | accept | report | w3c-f-14 | W3C-R-014 | none |
| `v04b7811e691bd2c9` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v050e5667630b8bf7` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v068436e239f3711a` | accept | agent-run-metrics | arm-f-run | ARM-R-005 | none |
| `v086f61b528d28efd` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v0e286b53de78162a` | reject | report | w3c-f-8 | W3C-R-008 | W3C-R-008 |
| `v0f620037c42bbfc3` | accept | report | w3c-f-22 | W3C-R-022 | none |
| `v0f648c5f3080e1b1` | accept | agent-run-metrics | arm-f-steps | ARM-R-015 | none |
| `v1032eb59a7cdb30f` | accept | report | w3c-f-15 | W3C-R-015 | none |
| `v10aaaebb49b0bcd3` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v1158315f2ce233a8` | reject | report | w3c-f-22 | W3C-R-022 | W3C-R-022 |
| `v12f1e7e27b3f59c5` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-006 | LCD-R-006 |
| `v148fc59046a8548a` | accept | report | w3c-f-15 | W3C-R-015 | none |
| `v1660acd2e4efb7c7` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `v183b37dea5ad4159` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v1910c8190bcd1b5c` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-002 | none |
| `v191fc069115f8706` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-007 | none |
| `v1a0f984d88bb9fe2` | accept | report | w3c-f-8 | W3C-R-008 | none |
| `v1a5c0a7b37f5d2c4` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v1bb2e51524055d00` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v1bc07a427d07bb7f` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v1c020dd1ed49874c` | reject | report | w3c-f-17 | W3C-R-017 | W3C-R-017 |
| `v20a798b25fc2ec0b` | reject | report | w3c-f-27 | W3C-R-027 | W3C-R-027 |
| `v20f99b9d22c842a3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v21fe5a5de5f50124` | accept | agent-run-metrics | arm-f-serialization | ARM-R-018 | none |
| `v22f803622ac75918` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v239dc2ee7b28a2bb` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v254933bf314c82fc` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v25ba541b9d311416` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v2652b0b04c946504` | reject | agent-run-metrics | arm-f-serialization | ARM-R-020 | ARM-R-020 |
| `v265c2e6f0a3d31f6` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v27a01b14321f6ae5` | reject | report | w3c-f-19 | W3C-R-019 | W3C-R-019 |
| `v28820b464a335617` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v28824a66a84f4b8c` | reject | agent-run-metrics | arm-f-usage | ARM-R-013 | ARM-R-013 |
| `v2a251ae413920da5` | accept | report | w3c-f-19 | W3C-R-019 | none |
| `v2a90adc95b2fbdaf` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v2b052236457b678c` | accept | agent-run-metrics | arm-f-usage | ARM-R-009 | none |
| `v2ddb14c9194e0341` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v320406e03fff4faa` | accept | report | w3c-f-5 | W3C-R-005 | none |
| `v32c1e0be1a7bf104` | reject | agent-run-metrics | arm-f-run | ARM-R-016 | ARM-R-016 |
| `v32c6afab9eb5888a` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v36999d5568e9aacf` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v388dee224f53c2c1` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-005 | LCD-R-005 |
| `v3a14f94887e53e0d` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v3add8861d36c2543` | reject | agent-run-metrics | arm-f-steps | ARM-R-008 | ARM-R-008 |
| `v3aef8ba9ac745dbf` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v3d5079f23e498451` | accept | agent-run-metrics | arm-f-run | ARM-R-002 | none |
| `v3fef7c8cc4ed5e4b` | reject | report | w3c-f-25 | W3C-R-025 | W3C-R-025 |
| `v42d2d180b1c0b5b3` | accept | report | w3c-f-22 | W3C-R-022 | none |
| `v44f7a4acc7f66fa4` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v472759709d82c585` | accept | report | w3c-f-20 | W3C-R-020 | none |
| `v48877f27bbd03b55` | reject | report | w3c-f-18 | W3C-R-018 | W3C-R-018 |
| `v48d22035dc3a5f54` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v494ac13464d685ee` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v499412698a1dd50e` | reject | report | w3c-f-20 | W3C-R-020 | W3C-R-020 |
| `v49afe44cc51bc376` | accept | report | w3c-f-29 | W3C-R-029 | none |
| `v4a06b866afca0d49` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v4c778d3ee20deb35` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v4e4face5dd4ff492` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `v4f343e8bd3d6af08` | accept | report | w3c-f-20 | W3C-R-020 | none |
| `v518aa8d55ab5460b` | accept | report | w3c-f-16 | W3C-R-016 | none |
| `v5390d3d7133f3963` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v54dea8bab0674755` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v568e8a1311ecb396` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v56b6337b612b1ee3` | accept | report | w3c-f-12 | W3C-R-012 | none |
| `v56f37afaff2a6ca8` | accept | report | w3c-f-25 | W3C-R-025 | none |
| `v5a2ff35648828621` | reject | report | w3c-f-9 | W3C-R-009 | W3C-R-009 |
| `v5a678e8560a4f0f1` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v5c26b11179a2277a` | reject | report | w3c-f-23 | W3C-R-023 | W3C-R-023 |
| `v668c618f2a50e26e` | accept | agent-run-metrics | arm-f-run | ARM-R-003 | none |
| `v66fd68ad7d106fac` | reject | report | w3c-f-14 | W3C-R-014 | W3C-R-014 |
| `v67727ceb5f2f7932` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v67e996a3fa03e959` | reject | report | w3c-f-22 | W3C-R-022 | W3C-R-022 |
| `v696c5dd5918c854b` | reject | agent-run-metrics | arm-f-run | ARM-R-002 | ARM-R-002 |
| `v6cd84ff1aea45153` | reject | report | w3c-f-20 | W3C-R-020 | W3C-R-020 |
| `v6cfd1d72b49d8853` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v70533f1029ed78e6` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-009 | LCD-R-009 |
| `v7257ad4efb1d0638` | accept | agent-run-metrics | arm-f-serialization | ARM-R-020 | none |
| `v7351d22d2343dfb5` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v735efb00ce85d044` | accept | report | w3c-f-17 | W3C-R-017 | none |
| `v737955ac1c0d9c2e` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v76c0022fb2a7f21e` | accept | report | w3c-f-25 | W3C-R-025 | none |
| `v77f27a301818a512` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v79266aba771310af` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-011 | LCD-R-011 |
| `v796a6048345b8f58` | accept | report | w3c-f-29 | W3C-R-029 | none |
| `v7aca350e00458527` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v7bc7c1460093e973` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-003 | LCD-R-003 |
| `v7c22f1451e51aeb5` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v7cac3bda7403c268` | reject | report | w3c-f-5 | W3C-R-005 | W3C-R-005 |
| `v7ead0086cb766b10` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v7ec5cc451c0c1564` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v804ca6858fa22efe` | accept | report | w3c-f-2 | W3C-R-002 | none |
| `v81c7f6fc68ea35a7` | accept | agent-run-metrics | arm-f-serialization | ARM-R-019 | none |
| `v8224d0f41c80f492` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v822b02c01fe9ddd2` | accept | report | w3c-f-3 | W3C-R-003 | none |
| `v827901388ec40c23` | accept | agent-run-metrics | arm-f-totals | ARM-R-012 | none |
| `v828ec4d8309aa2e3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v838fe3be3393696c` | accept | agent-run-metrics | arm-f-steps | ARM-R-007 | none |
| `v84f8c68bc5fc2810` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v85c0428fc7fdabc7` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-001 | none |
| `v85db98532abea6d9` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-007 | LCD-R-007 |
| `v86e1560a0d27b432` | accept | report | w3c-f-15 | W3C-R-015 | none |
| `v88935f0b29397a80` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v8981e0830c69b869` | reject | report | w3c-f-6 | W3C-R-006 | W3C-R-006 |
| `v8a7442b19984a1ff` | accept | report | w3c-f-7 | W3C-R-007 | none |
| `v8b06a7e78dc8d039` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v8c15455bb3d933cb` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v8d4e61737e9ee6a6` | reject | agent-run-metrics | arm-f-serialization | ARM-R-019 | ARM-R-019 |
| `v96087777a4afe26f` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `v9815e1f08a7e0664` | reject | agent-run-metrics | arm-f-run | ARM-R-003 | ARM-R-003 |
| `v98252c989e84999d` | reject | report | w3c-f-3 | W3C-R-003 | W3C-R-003 |
| `v9b7c8cf7d1b9f679` | accept | report | w3c-f-26 | W3C-R-026 | none |
| `v9c68a108ed63da63` | reject | report | w3c-f-21 | W3C-R-021 | W3C-R-021 |
| `v9cfb2c8197757948` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-005 | none |
| `v9dc96e6ca225e6e2` | accept | agent-run-metrics | arm-f-run | ARM-R-016 | none |
| `v9f618dfd3e44b84a` | accept | report | w3c-f-23 | W3C-R-023 | none |
| `va0620b488f2ff2f5` | accept | report | w3c-f-28 | W3C-R-028 | none |
| `va18bfa567e0405b7` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va19ba1b3f9f382bb` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va1e910d25ebbb2c4` | accept | report | w3c-f-23 | W3C-R-023 | none |
| `va213bada85cc9abe` | accept | report | w3c-f-13 | W3C-R-013 | none |
| `va32bdaeb5f8aed8f` | accept | agent-run-metrics | arm-f-steps | ARM-R-006 | none |
| `va3c277aa6743807a` | reject | report | w3c-f-24 | W3C-R-024 | W3C-R-024 |
| `va4fc9fc8f711bd58` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va86e962a5024f152` | reject | report | w3c-f-29 | W3C-R-029 | W3C-R-029 |
| `va91d537fa714f2d3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va934761de6c65857` | reject | agent-run-metrics | arm-f-run | ARM-R-001 | ARM-R-001 |
| `vaac3a24b2552738b` | reject | agent-run-metrics | arm-f-serialization | ARM-R-017 | ARM-R-017 |
| `vaad2cb64c5b0646b` | accept | report | w3c-f-6 | W3C-R-006 | none |
| `vab06fd8893fe7da9` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vab508347e605c0af` | reject | report | w3c-f-20 | W3C-R-020 | W3C-R-020 |
| `vac685ed4f2b7b142` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vaca8620fefade22f` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vaeb76896b202e837` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `vb11134a37e7c0c2b` | reject | report | w3c-f-1 | W3C-R-001 | W3C-R-001 |
| `vb195f23e8436fd19` | accept | report | w3c-f-13 | W3C-R-013 | none |
| `vb1c8d4729c06472c` | accept | agent-run-metrics | arm-f-usage | ARM-R-010 | none |
| `vb450f39bace98641` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-011 | none |
| `vb4de5d37845a1546` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vb608f4ddfcc00a20` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-004 | LCD-R-004 |
| `vb684dfb39487fcb1` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vb6be26b7111909cb` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vb6e8cb7973f1fab5` | accept | agent-run-metrics | arm-f-usage | ARM-R-022 | none |
| `vb7065104515600ba` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-004 | none |
| `vb7ec64962345ec63` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vb8c546609d4103b0` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vbb1688d0226174aa` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbba71aa9e6a41e1c` | accept | agent-run-metrics | arm-f-serialization | ARM-R-017 | none |
| `vbbeed17aecbe9848` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vbca0a5030104e2f3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbdcffc81f99b2078` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vbdf5d0dc993f1310` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vbe6937292f4f1614` | reject | report | w3c-f-10 | W3C-R-010 | W3C-R-010 |
| `vbec908a03edd1250` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vbf88ec51ebd083b6` | accept | agent-run-metrics | arm-f-steps | ARM-R-008 | none |
| `vc17bb5b854981008` | reject | agent-run-metrics | arm-f-usage | ARM-R-009 | ARM-R-009 |
| `vc2cab6dea09f0a3b` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc39c75a8c00ab957` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc58647a590befbb7` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `vc653bb099d9c5839` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc7c310827b9dbd10` | accept | agent-run-metrics | arm-f-run | ARM-R-001 | none |
| `vc938b2ab36cae34a` | accept | report | w3c-f-27 | W3C-R-027 | none |
| `vcbd0eaef95bc9181` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-010 | LCD-R-010 |
| `vcc4002f4776bac10` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vccc374459c05dd52` | reject | agent-run-metrics | arm-f-steps | ARM-R-006 | ARM-R-006 |
| `vcd6021208e8e8a6e` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-006 | none |
| `vcdb9ae63a12852a8` | accept | agent-run-metrics | arm-f-serialization | ARM-R-021 | none |
| `vcf1cbb85d729dcd1` | reject | report | w3c-f-26 | W3C-R-026 | W3C-R-026 |
| `vd02cc7abe1dbc2bf` | reject | agent-run-metrics | arm-f-usage | ARM-R-011 | ARM-R-011 |
| `vd1eb6a3fb13eb97d` | reject | report | w3c-f-12 | W3C-R-012 | W3C-R-012 |
| `vd27e483fe63e78c0` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd2ae28ba9140bc89` | reject | report | w3c-f-28 | W3C-R-028 | W3C-R-028 |
| `vd2e50306dcd6c470` | reject | report | w3c-f-23 | W3C-R-023 | W3C-R-023 |
| `vd302fdc2d7a97e6e` | reject | agent-run-metrics | arm-f-serialization | ARM-R-018 | ARM-R-018 |
| `vd3e84d6a85cb6a0f` | accept | report | w3c-f-24 | W3C-R-024 | none |
| `vd4eb88d206b3abdd` | reject | report | w3c-f-16 | W3C-R-016 | W3C-R-016 |
| `vd53bcd623743858d` | accept | agent-run-metrics | arm-f-usage | ARM-R-014 | none |
| `vd64679c8b7f9e736` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd7d23c0d86701fc6` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd841f2eea4d0651e` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vd85d62c0213a9749` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vd88fd757419269aa` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-009 | none |
| `vd8d93fd735111aa5` | accept | report | w3c-f-13 | W3C-R-013 | none |
| `vdcb0849fc754aaea` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vdcbd067d047bfbd0` | reject | report | w3c-f-7 | W3C-R-007 | W3C-R-007 |
| `vdec1361509de89d4` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vdf05d359490e7833` | accept | report | w3c-f-18 | W3C-R-018 | none |
| `ve14d385f9bcbd83b` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `ve2460634487d8a8f` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `ve2b3a699bc06e53d` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-008 | LCD-R-008 |
| `ve2c7ff41cba0be5d` | reject | agent-run-metrics | arm-f-steps | ARM-R-007 | ARM-R-007 |
| `ve3fcd2bc70913ea2` | reject | agent-run-metrics | arm-f-run | ARM-R-005 | ARM-R-005 |
| `ve4744745405812b9` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `ve4b9c82536808f52` | reject | agent-run-metrics | arm-f-totals | ARM-R-012 | ARM-R-012 |
| `ve53f0521c7e3a30c` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `ve5819dc9edb1f47b` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-003 | none |
| `ve5d916a50130739e` | accept | report | w3c-f-gaps | W3C-R-001, W3C-R-005 | none |
| `ve70386fdb6f071d3` | accept | report | w3c-f-1 | W3C-R-001 | none |
| `ve7520b18160365d2` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `ve784e75da615e795` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `ve9c436f93e42e394` | reject | report | w3c-f-29 | W3C-R-029 | W3C-R-029 |
| `ve9cefed56bbc8359` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `ve9ebdb7db94e0b9d` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vea3ee7919ceb2e10` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vea598711b897286e` | accept | agent-run-metrics | arm-f-usage | ARM-R-011 | none |
| `vea80ece35200e349` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vec36e393a92b69eb` | reject | report | w3c-f-4 | W3C-R-004 | W3C-R-004 |
| `vecd8b7bb20fed3a3` | accept | report | w3c-f-21 | W3C-R-021 | none |
| `vecddffbd8678e5ef` | reject | agent-run-metrics | arm-f-run | ARM-R-004 | ARM-R-004 |
| `vee997c119f09258b` | reject | report | w3c-f-11 | W3C-R-011 | W3C-R-011 |
| `vef09761654b57a92` | reject | agent-run-metrics | arm-f-usage | ARM-R-022 | ARM-R-022 |
| `vf0793a8c5fc26e52` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vf1e99cf0310cc1c6` | reject | agent-run-metrics | arm-f-usage | ARM-R-014 | ARM-R-014 |
| `vf2fde28af69a1348` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vf374114fe7f28e7d` | reject | report | w3c-f-2 | W3C-R-002 | W3C-R-002 |
| `vf3af943ff1bf7375` | reject | agent-run-metrics | arm-f-serialization | ARM-R-021 | ARM-R-021 |
| `vf414a4c9065ad7b8` | reject | agent-run-metrics | arm-f-steps | ARM-R-015 | ARM-R-015 |
| `vf7334aa7dcf00826` | accept | agent-run-metrics | arm-f-run | ARM-R-004 | none |
| `vf753bb908231e0a1` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-008 | none |
| `vf82e507d268fed9d` | accept | report | w3c-f-4 | W3C-R-004 | none |
| `vf86d92beb5a12905` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-002 | LCD-R-002 |
| `vf9b5623144960dda` | accept | report | w3c-f-9 | W3C-R-009 | none |
| `vfa24e4f45c2e826e` | accept | report | w3c-f-20 | W3C-R-020 | none |
| `vfa79ad0a7bd957b9` | accept | report | w3c-f-11 | W3C-R-011 | none |
| `vfbc5db1c2a012359` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `vfbd7379026575f04` | accept | report | w3c-f-gaps | W3C-R-001, W3C-R-002 | none |
| `vfbf04f56b585e3fa` | reject | report | w3c-f-disensor | W3C-R-016 | W3C-R-016 |
| `vfeb5d1872929ab35` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-010 | none |
| `vff5545c0760d7544` | accept | agent-run-metrics | arm-f-usage | ARM-R-013 | none |
| `vff8f75223d6658ef` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-001 | LCD-R-001 |
