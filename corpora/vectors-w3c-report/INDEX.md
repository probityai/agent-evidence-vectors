# Conformance vectors (v0.1 per-check report)

Every member of this suite in one table, rejected and accepted alike. Ground
truth: 18 texts vendored in `spec-vendored/` and pinned by sha256 in
`MANIFEST.json`: 14 messages of the W3C public-agent-conformance list that
together fix what v0.1 of the reporting format freezes, 2 messages that
propose the digest encoding after it froze, and the two Internet-Drafts the
format's editor holds.

This corpus is 273 vectors, of which 175 a conformant verifier must not fail closed
on and 98 it must reject.

**Three subject types, one manifest.** 206 members are whole
v0.1 reports, judged by the rows of the format; 45
are Run objects of the agent-run-metrics draft; 22
are discovery snapshots of the context-discovery draft. Each member names its
subject type and the reader selects the validator by it.

**The section 10 selection is 169 members**:
the report members whose requirements are all agreed, 43 to
reject and 126 to accept. A report member that cites a
proposed requirement rests on a rule the v0.1 text does not hold, so it is
counted apart, as excluded-under-proposed-rule, 37 members:

| proposed requirement cited | reject | accept |
|---|---|---|
| W3C-R-022 | 2 | 2 |
| W3C-R-030 | 9 | 9 |
| W3C-R-031 | 9 | 4 |
| W3C-R-032 | 1 | 1 |

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
emitted before the freeze, with the error list declared moved, and once re-cut
against v0.1. Both are accepted: moved is recomputed, not declared, and the
recomputed moved of each is contained in its compared set.
`origin/derive_pairs.py` derives the pairs from that repository and `origin/disensor-1e36257-pairs.json` is what it
wrote.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check from the repository root: `aee-verify vectors-w3c-report/`,
`python3 packaging/run_vectors.py --corpus vectors-w3c-report`, or the Rust
reader, `cargo run --release --locked --manifest-path
readers/w3c-report-rs/Cargo.toml -- vectors-w3c-report`; the three print the
same lines.

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
| `0087` | Evgenii Arsentev | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `35625d73baa56f27` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0087.html |
| `0088` | Roel Schuurkes | `spec-vendored/0088-schuurkes-2026-09-30-v01-row4.txt` | `d22914e6146f1fb1` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0088.html |
| `2026Oct-0038` | Lars Kersten Kroehl | `spec-vendored/2026Oct-0038-kroehl-2026-10-10-digest-encoding.txt` | `9b71fe89b22c9f8b` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0038.html |
| `2026Oct-0040` | Kenne Ives | `spec-vendored/2026Oct-0040-ives-2026-10-10-numeric-profile.txt` | `051ff39f291884c2` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0040.html |
| `draft-arsentev-agent-run-metrics-00` | Evgenii Arsentev | `spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | `0ef9e7fbc39d04bf` | https://datatracker.ietf.org/doc/draft-arsentev-agent-run-metrics/ |
| `draft-arsentev-llm-context-discovery-00` | Evgenii Arsentev | `spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | `13081268c70a19e9` | https://datatracker.ietf.org/doc/draft-arsentev-llm-context-discovery/ |

## Requirements

The class column is the sort of v0.1 section 2.2: consistency rows read
declared slots against each other, evidence rows read a declared slot against
a recomputed or resolved one, form rows are decidable from the object alone.
Section 4 of v0.1 numbers and classes rows 1 to 14. The status column says
whether the v0.1 text adopts the row (agreed) or only this corpus carries it
(proposed). Every agreed row is anchored to the v0.1 text, `0087`.

| id | row | class | status | vendored in | sentence digest | normative sentence |
|---|---|---|---|---|---|---|
| `W3C-R-001` | 1 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `87893835a3e13451` | a non-verdict state with no cause |
| `W3C-R-002` | 2 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `05fb9274ff0859d9` | void with not_applicable, out_of_scope or withheld |
| `W3C-R-003` | 3 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `587e9bc351daaed2` | not-exercised with integrity-failure |
| `W3C-R-004` | 4 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `fa7afadb72dcc56f` | cause confinement-failed-during-check with any       state but void |
| `W3C-R-005` | 5 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `2824f710983d7d64` | a declared exclusion with any state but       not-exercised |
| `W3C-R-006` | 6 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `4ef6f3c9383ae454` | a non-verdict state carrying either qualifier |
| `W3C-R-007` | 7 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `831dc816ea23fa26` | a verdict state carrying a cause |
| `W3C-R-008` | 8 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `971c3d8c232fe9dc` | other-verdict foreclosed with discrimination       demonstrated |
| `W3C-R-009` | 9 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `4cb5ee4206feba7a` | discrimination demonstrated with other-verdict       unknown or possible-not-demonstrated |
| `W3C-R-010` | 10 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `139eba59f4dc4345` | foreclosed without a constraint set and a domain |
| `W3C-R-011` | 11 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `82c27c355fd56b7d` | an asserted value without its evidence reference,       on either field, foreclosed included |
| `W3C-R-012` | 12 | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `6931e04547093403` | discrimination demonstrated citing an evidence       object whose changed slot is the checker |
| `W3C-R-025` | 13 | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `75f4aaa3f705171a` | 13 other-verdict demonstrated citing an evidence object whose       moved does not contain the verdict |
| `W3C-R-026` | 14 | form | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `2f6eb3b103bf0ce1` | 14 moved asserted on an evidence object that neither carries both       observations nor references them with digests |
| `W3C-R-019` | 1.2 closed vocabulary | form | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `c0c29df61ecbc5f4` | Free text is refused in place of a disposition |
| `W3C-R-024` | 1.3 delta-related pair | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `5a597f4b8de5f831` | Unrelated pass and fail records in one corpus do not qualify |
| `W3C-R-016` | 2 recomputed moved contained | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `913913ec0dc014c2` | an object whose moved is not contained in its declared compared set is rejected |
| `W3C-R-021` | 2 recomputed moved | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `67d001c7a474766f` | moved is recomputed, not declared |
| `W3C-R-027` | 2 arity recomputed | form | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `7ad91a2f2b6ce5f0` | arity is recomputed from the delta |
| `W3C-R-028` | 2 domain once | form | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `88ed23692510e454` | The domain is a declared object, declared once at run level |
| `W3C-R-020` | 3 reference mismatch | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `30544d50d0ecb7ca` | resolves, digests differ integrity failure |
| `W3C-R-015` | 3.1 set binding | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `bae0f589fd14116e` | A digest match establishes a set only when the count of leaves is bound into what is signed or hashed, and a report MUST declare which tree shape it uses |
| `W3C-R-017` | 5.1 denominator | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `9f8ec623178bd2fc` | It is never emitted without its complete denominator |
| `W3C-R-023` | 5.2 population | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `7e37adc3e17eea94` | A claim over an empty population is reported as not claimable, not as satisfied |
| `W3C-R-018` | 5.3 counter | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `f3cd13017eef9aab` | carried against referenced is recomputable by anyone holding the report and cannot be understated |
| `W3C-R-013` | 5.4 roll-up | evidence | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `9b00061b244165aa` | A roll-up states whether the checks it aggregates were capable of producing a negative verdict |
| `W3C-R-014` | 5.4 prior run | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `cc10241a9f88472c` | A prior run only counts where check identity survives across     runs |
| `W3C-R-029` | 5.4 control binding | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `4160b21d27d64e6a` | The control runs under the same checker revision and the same     relevant configuration and constraints as the declared checks     whose negative capability it is reported for |
| `W3C-R-033` | 5.4 prior-run binding | consistency | agreed | `spec-vendored/0087-arsentev-2026-09-30-v01.txt` | `7c74646f727411df` | The reference lets the reader     establish the same revision and configuration binding for the     declared checks it supports |
| `W3C-R-022` | coverage block | form | proposed | `spec-vendored/0001-ives-2026-09-01-coverage-block.txt` | `50c6f490bcf092b2` | a sampled / full_coverage flag with the count of scannable files recorded before the per-repo cap |
| `W3C-R-030` | 3.1 digest encoding | evidence | proposed | `spec-vendored/2026Oct-0038-kroehl-2026-10-10-digest-encoding.txt` | `b53c8bf547875a59` | A digest taken over a JSON value is computed over the RFC 8785 canonical form of that value. |
| `W3C-R-031` | 3.1 numeric profile | form | proposed | `spec-vendored/2026Oct-0040-ives-2026-10-10-numeric-profile.txt` | `9c35050921fdefb7` | A reader rejects a report whose digested value violates this, under W3C-R-020, naming the cause. |
| `W3C-R-032` | 3.1 declared encoding | form | proposed | `spec-vendored/2026Oct-0038-kroehl-2026-10-10-digest-encoding.txt` | `42f9ab8f012587a9` | A reader that does not implement a report's declared digest encoding rejects the report and says so. |
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
| `w3c-f-13` | section 5.4: a roll-up says whether its checks could have gone negative |
| `w3c-f-14` | section 5.4: a prior discriminating run binds the check identity that survived |
| `w3c-f-15` | section 3.1: a digest over a set binds its leaf count and names its tree shape; domain separation alone is not the fix |
| `w3c-f-16` | section 2: moved, recomputed, is contained in the declared compared set |
| `w3c-f-29` | section 5.4: a control built to fail is bound to the checker and constraint set of the checks it speaks for |
| `w3c-f-33` | section 5.4: a prior discriminating run is bound to the checker and constraint set of the checks it speaks for |
| `w3c-f-17` | roll-up: the aggregate carries its complete denominator |
| `w3c-f-18` | roll-up: the counter over carried against referenced recomputes |
| `w3c-f-19` | closed vocabulary: a value outside a registry is not read |
| `w3c-f-20` | carry-or-reference: a digest that resolves with a mismatch is an integrity failure, over the check set and over a referenced observation alike |
| `w3c-f-21` | recomputed delta: moved is read as recomputed over the observations, not as declared |
| `w3c-f-22` | coverage block: scope disclosure in controlled fields, with the pre-cap file count |
| `w3c-f-23` | population denominator: a completeness claim carries the size of its population |
| `w3c-f-24` | delta-related pair: unrelated pass and fail records do not witness discrimination |
| `w3c-f-25` | row 13: other-verdict demonstrated citing an object whose recomputed moved does not contain the verdict; unresolvable, the row degrades |
| `w3c-f-26` | row 14: moved asserted on an object that neither carries its observations nor references them with digests |
| `w3c-f-27` | arity: recomputed from the delta, never declared |
| `w3c-f-28` | domain: declared once at run level, named by identifier and never restated |
| `w3c-f-gaps` | the two known gaps of the reference emitter, closed: void has a slot and not-exercised carries a cause |
| `w3c-f-disensor` | the 42 delta-related pairs of the disensor corpus at 1e36257, re-cut against v0.1 |
| `arm-f-run` | agent run metrics: the Run object's own members |
| `arm-f-steps` | agent run metrics: the Step objects and their order |
| `arm-f-usage` | agent run metrics: the Usage invariants and the cache-write ledger |
| `arm-f-totals` | agent run metrics: the totals as the sum of the steps |
| `arm-f-serialization` | agent run metrics: timestamps, identifiers, labels, cost and extensions |
| `w3c-f-jcs-u007f` | digest encoding (proposed): RFC 8785 writes U+007F as itself, where an ASCII-escaping encoder writes \u007f |
| `w3c-f-jcs-non-ascii` | digest encoding (proposed): RFC 8785 writes a character above U+007F as UTF-8, where an ASCII-escaping encoder writes \uXXXX or a surrogate pair |
| `w3c-f-jcs-member-order` | digest encoding (proposed): RFC 8785 orders member names by UTF-16 code unit, which parts from code-point order on a supplementary-plane name |
| `w3c-f-jcs-number-value` | digest encoding (proposed): a number is written as its value, so -0 and -0.0 read 0 and 1.0 and 1e2 read 1 and 100, never as the token written |
| `w3c-f-jcs-safe-range` | numeric profile (proposed): an integer of magnitude 2^53 or more is refused, both boundaries and their neighbours, and travels as a string |
| `w3c-f-jcs-1e21` | numeric profile (proposed): 10^21 is refused in digits and as an exponent, so its two spellings never reach a digest, and travels as a string |
| `w3c-f-jcs-non-integer` | numeric profile (proposed): a number whose exact value is not an integer is refused, a token that rounds to an integer double included, and travels as a string |
| `w3c-f-jcs-declaration` | declared encoding (proposed): a set binding declares jcs-sha256 or nothing; any other declaration is refused rather than read as the reader's own |
| `lcd-f-publisher` | context discovery: what the origin advertises and serves |
| `lcd-f-consumer` | context discovery: what a consumer resolves, retrieves and attributes |

## Vectors

| id | kind | subject | family | requirements | rejected under |
|---|---|---|---|---|---|
| `v0090b52048ca1f51` | accept | report | w3c-f-10 | W3C-R-010 | none |
| `v0120d95db38b892b` | reject | agent-run-metrics | arm-f-usage | ARM-R-010 | ARM-R-010 |
| `v04934d23180f6d9c` | accept | report | w3c-f-14 | W3C-R-014 | none |
| `v050e5667630b8bf7` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v068436e239f3711a` | accept | agent-run-metrics | arm-f-run | ARM-R-005 | none |
| `v0a887e6b24bdd940` | reject | report | w3c-f-jcs-safe-range | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v0e286b53de78162a` | reject | report | w3c-f-8 | W3C-R-008 | W3C-R-008 |
| `v0f620037c42bbfc3` | accept | report | w3c-f-22 | W3C-R-022 | none |
| `v0f648c5f3080e1b1` | accept | agent-run-metrics | arm-f-steps | ARM-R-015 | none |
| `v1032eb59a7cdb30f` | accept | report | w3c-f-15 | W3C-R-015 | none |
| `v1158315f2ce233a8` | reject | report | w3c-f-22 | W3C-R-022 | W3C-R-022 |
| `v12f1e7e27b3f59c5` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-006 | LCD-R-006 |
| `v13b3c66e7fc7dae2` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v148fc59046a8548a` | accept | report | w3c-f-15 | W3C-R-015 | none |
| `v159bcd24a7e74a43` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v1660acd2e4efb7c7` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `v16bbc5bfef80043e` | reject | report | w3c-f-jcs-safe-range | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v17b2ad943b1f051d` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v183b37dea5ad4159` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v187e4435786b17f9` | accept | report | w3c-f-jcs-safe-range | W3C-R-020, W3C-R-031 | none |
| `v1910c8190bcd1b5c` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-002 | none |
| `v191fc069115f8706` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-007 | none |
| `v1a0f984d88bb9fe2` | accept | report | w3c-f-8 | W3C-R-008 | none |
| `v1afbcaac4b0d514d` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v1afe0d60b2df5d39` | reject | report | w3c-f-jcs-non-integer | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v1c020dd1ed49874c` | reject | report | w3c-f-17 | W3C-R-017 | W3C-R-017 |
| `v20a798b25fc2ec0b` | reject | report | w3c-f-27 | W3C-R-027 | W3C-R-027 |
| `v20f99b9d22c842a3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v21fe5a5de5f50124` | accept | agent-run-metrics | arm-f-serialization | ARM-R-018 | none |
| `v22e6c34b776baff7` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v22f803622ac75918` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v254933bf314c82fc` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v2652b0b04c946504` | reject | agent-run-metrics | arm-f-serialization | ARM-R-020 | ARM-R-020 |
| `v265c2e6f0a3d31f6` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v26a379aeeebabd1e` | reject | report | w3c-f-jcs-non-integer | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v27a01b14321f6ae5` | reject | report | w3c-f-19 | W3C-R-019 | W3C-R-019 |
| `v28820b464a335617` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v28824a66a84f4b8c` | reject | agent-run-metrics | arm-f-usage | ARM-R-013 | ARM-R-013 |
| `v2a251ae413920da5` | accept | report | w3c-f-19 | W3C-R-019 | none |
| `v2b052236457b678c` | accept | agent-run-metrics | arm-f-usage | ARM-R-009 | none |
| `v2b4990ad53fbf28b` | reject | report | w3c-f-jcs-non-integer | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v2ddb14c9194e0341` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v2f563dc0b6fc9ec8` | accept | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | none |
| `v320406e03fff4faa` | accept | report | w3c-f-5 | W3C-R-005 | none |
| `v32c1e0be1a7bf104` | reject | agent-run-metrics | arm-f-run | ARM-R-016 | ARM-R-016 |
| `v36ba5fca23b6a162` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v37729703d471ba9b` | reject | report | w3c-f-23 | W3C-R-023 | W3C-R-023 |
| `v37d8ddc87ed265e8` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v388dee224f53c2c1` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-005 | LCD-R-005 |
| `v392e5b863085868b` | accept | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | none |
| `v3add8861d36c2543` | reject | agent-run-metrics | arm-f-steps | ARM-R-008 | ARM-R-008 |
| `v3aef8ba9ac745dbf` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v3cf361bbfb973f7d` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v3d5079f23e498451` | accept | agent-run-metrics | arm-f-run | ARM-R-002 | none |
| `v3fd6a6a262a72f91` | reject | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v3fef7c8cc4ed5e4b` | reject | report | w3c-f-25 | W3C-R-025 | W3C-R-025 |
| `v40ab7c6deec16438` | reject | report | w3c-f-jcs-1e21 | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v4193637206138b32` | reject | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v42d2d180b1c0b5b3` | accept | report | w3c-f-22 | W3C-R-022 | none |
| `v44f7a4acc7f66fa4` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v472759709d82c585` | accept | report | w3c-f-20 | W3C-R-020 | none |
| `v48877f27bbd03b55` | reject | report | w3c-f-18 | W3C-R-018 | W3C-R-018 |
| `v494ac13464d685ee` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v499412698a1dd50e` | reject | report | w3c-f-20 | W3C-R-020 | W3C-R-020 |
| `v49afe44cc51bc376` | accept | report | w3c-f-29 | W3C-R-029 | none |
| `v4a06b866afca0d49` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v4c778d3ee20deb35` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v4e4face5dd4ff492` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `v4e8fc1ab4f3fc5b3` | accept | report | w3c-f-jcs-number-value | W3C-R-020, W3C-R-030 | none |
| `v4f343e8bd3d6af08` | accept | report | w3c-f-20 | W3C-R-020 | none |
| `v5196f1761ea14b2b` | reject | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v522b0a6b91e74c95` | reject | report | w3c-f-jcs-safe-range | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `v53dd1aa630064e4c` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v55772816f872150f` | accept | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | none |
| `v568e8a1311ecb396` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v56b6337b612b1ee3` | accept | report | w3c-f-12 | W3C-R-012 | none |
| `v56f37afaff2a6ca8` | accept | report | w3c-f-25 | W3C-R-025 | none |
| `v59b5c22988c70b05` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v5a2ff35648828621` | reject | report | w3c-f-9 | W3C-R-009 | W3C-R-009 |
| `v5a678e8560a4f0f1` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v5c26b11179a2277a` | reject | report | w3c-f-23 | W3C-R-023 | W3C-R-023 |
| `v5f92e1d7ef255730` | accept | report | w3c-f-jcs-safe-range | W3C-R-020, W3C-R-031 | none |
| `v606504b1125a3885` | accept | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | none |
| `v60bd06deca6e832d` | reject | report | w3c-f-jcs-u007f | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v6397c3de47a1882c` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v64e02942221729d2` | reject | report | w3c-f-jcs-declaration | W3C-R-015, W3C-R-032 | W3C-R-015 |
| `v668c618f2a50e26e` | accept | agent-run-metrics | arm-f-run | ARM-R-003 | none |
| `v66fd68ad7d106fac` | reject | report | w3c-f-14 | W3C-R-014 | W3C-R-014 |
| `v67e996a3fa03e959` | reject | report | w3c-f-22 | W3C-R-022 | W3C-R-022 |
| `v696c5dd5918c854b` | reject | agent-run-metrics | arm-f-run | ARM-R-002 | ARM-R-002 |
| `v6b1ea60273861c5a` | reject | report | w3c-f-23 | W3C-R-023 | W3C-R-023 |
| `v6cd84ff1aea45153` | reject | report | w3c-f-20 | W3C-R-020 | W3C-R-020 |
| `v6f15889cec93060d` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v6f4ff1db603ecfec` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v70533f1029ed78e6` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-009 | LCD-R-009 |
| `v70bdf863fb9cd6ac` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v719b5f3fe23d8c03` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v7257ad4efb1d0638` | accept | agent-run-metrics | arm-f-serialization | ARM-R-020 | none |
| `v7351d22d2343dfb5` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v735efb00ce85d044` | accept | report | w3c-f-17 | W3C-R-017 | none |
| `v737955ac1c0d9c2e` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v76c0022fb2a7f21e` | accept | report | w3c-f-25 | W3C-R-025 | none |
| `v79266aba771310af` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-011 | LCD-R-011 |
| `v796a6048345b8f58` | accept | report | w3c-f-29 | W3C-R-029 | none |
| `v79bebd0793e2fa7b` | accept | report | w3c-f-jcs-number-value | W3C-R-020, W3C-R-030 | none |
| `v7bc7c1460093e973` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-003 | LCD-R-003 |
| `v7c22f1451e51aeb5` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v7cac3bda7403c268` | reject | report | w3c-f-5 | W3C-R-005 | W3C-R-005 |
| `v7ce1218057f32f1c` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v804ca6858fa22efe` | accept | report | w3c-f-2 | W3C-R-002 | none |
| `v81c7f6fc68ea35a7` | accept | agent-run-metrics | arm-f-serialization | ARM-R-019 | none |
| `v8224d0f41c80f492` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v822b02c01fe9ddd2` | accept | report | w3c-f-3 | W3C-R-003 | none |
| `v822c4bed9ba714d3` | accept | report | w3c-f-jcs-u007f | W3C-R-020, W3C-R-030 | none |
| `v827901388ec40c23` | accept | agent-run-metrics | arm-f-totals | ARM-R-012 | none |
| `v828ec4d8309aa2e3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v838fe3be3393696c` | accept | agent-run-metrics | arm-f-steps | ARM-R-007 | none |
| `v8474a83c45f293fc` | reject | report | w3c-f-jcs-non-ascii | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v84f8c68bc5fc2810` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v85c0428fc7fdabc7` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-001 | none |
| `v85db98532abea6d9` | reject | llm-context-discovery | lcd-f-consumer | LCD-R-007 | LCD-R-007 |
| `v86e1560a0d27b432` | accept | report | w3c-f-15 | W3C-R-015 | none |
| `v876f8aa31676cf48` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v88935f0b29397a80` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `v8981e0830c69b869` | reject | report | w3c-f-6 | W3C-R-006 | W3C-R-006 |
| `v8a7442b19984a1ff` | accept | report | w3c-f-7 | W3C-R-007 | none |
| `v8a8da062cba9fce5` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v8aec53e0502ced65` | reject | report | w3c-f-33 | W3C-R-033 | W3C-R-033 |
| `v8c15455bb3d933cb` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v8d4e61737e9ee6a6` | reject | agent-run-metrics | arm-f-serialization | ARM-R-019 | ARM-R-019 |
| `v8ec1375690daa188` | reject | report | w3c-f-16 | W3C-R-016 | W3C-R-016 |
| `v8f818aaaa7cdc7ed` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v900fc651cea938e9` | accept | report | w3c-f-jcs-1e21 | W3C-R-020, W3C-R-031 | none |
| `v91f45fe53b9cb4f7` | accept | report | w3c-f-jcs-non-integer | W3C-R-020, W3C-R-031 | none |
| `v920852737e02ae49` | reject | report | w3c-f-jcs-number-value | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v9614879a484c4fc0` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v973e82c1857b0a7e` | reject | report | w3c-f-33 | W3C-R-033 | W3C-R-033 |
| `v9815e1f08a7e0664` | reject | agent-run-metrics | arm-f-run | ARM-R-003 | ARM-R-003 |
| `v98252c989e84999d` | reject | report | w3c-f-3 | W3C-R-003 | W3C-R-003 |
| `v98ee154eeceb9c55` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `v9b7c8cf7d1b9f679` | accept | report | w3c-f-26 | W3C-R-026 | none |
| `v9c68a108ed63da63` | reject | report | w3c-f-21 | W3C-R-021 | W3C-R-021 |
| `v9cfb2c8197757948` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-005 | none |
| `v9d05fc7c9c249317` | reject | report | w3c-f-jcs-member-order | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `v9dc96e6ca225e6e2` | accept | agent-run-metrics | arm-f-run | ARM-R-016 | none |
| `v9f618dfd3e44b84a` | accept | report | w3c-f-23 | W3C-R-023 | none |
| `v9ff65c5b03dd074c` | reject | report | w3c-f-jcs-number-value | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `va0620b488f2ff2f5` | accept | report | w3c-f-28 | W3C-R-028 | none |
| `va18bfa567e0405b7` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va19ba1b3f9f382bb` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va1e910d25ebbb2c4` | accept | report | w3c-f-23 | W3C-R-023 | none |
| `va213bada85cc9abe` | accept | report | w3c-f-13 | W3C-R-013 | none |
| `va2ba93081d3a6c13` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va32bdaeb5f8aed8f` | accept | agent-run-metrics | arm-f-steps | ARM-R-006 | none |
| `va3c277aa6743807a` | reject | report | w3c-f-24 | W3C-R-024 | W3C-R-024 |
| `va4fc9fc8f711bd58` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va64493c76c57f982` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va83db4001b89e73e` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va86e962a5024f152` | reject | report | w3c-f-29 | W3C-R-029 | W3C-R-029 |
| `va8dfb25c6d62d458` | reject | report | w3c-f-jcs-safe-range | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `va91d537fa714f2d3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `va934761de6c65857` | reject | agent-run-metrics | arm-f-run | ARM-R-001 | ARM-R-001 |
| `vaac3a24b2552738b` | reject | agent-run-metrics | arm-f-serialization | ARM-R-017 | ARM-R-017 |
| `vaad2cb64c5b0646b` | accept | report | w3c-f-6 | W3C-R-006 | none |
| `vab508347e605c0af` | reject | report | w3c-f-20 | W3C-R-020 | W3C-R-020 |
| `vac146420618655c5` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vaca8620fefade22f` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vad9b72227e24e32f` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vaeb76896b202e837` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `vb11134a37e7c0c2b` | reject | report | w3c-f-1 | W3C-R-001 | W3C-R-001 |
| `vb195f23e8436fd19` | accept | report | w3c-f-13 | W3C-R-013 | none |
| `vb1c8d4729c06472c` | accept | agent-run-metrics | arm-f-usage | ARM-R-010 | none |
| `vb37f841c9e91bf18` | reject | report | w3c-f-jcs-1e21 | W3C-R-020, W3C-R-031 | W3C-R-020 |
| `vb450f39bace98641` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-011 | none |
| `vb4de5d37845a1546` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vb608f4ddfcc00a20` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-004 | LCD-R-004 |
| `vb684dfb39487fcb1` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vb6e8cb7973f1fab5` | accept | agent-run-metrics | arm-f-usage | ARM-R-022 | none |
| `vb7065104515600ba` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-004 | none |
| `vb7ef2cf28c013f46` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vba057012581af13b` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbb1688d0226174aa` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbb5bb72ed5c3bcb1` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbba71aa9e6a41e1c` | accept | agent-run-metrics | arm-f-serialization | ARM-R-017 | none |
| `vbca0a5030104e2f3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbe6937292f4f1614` | reject | report | w3c-f-10 | W3C-R-010 | W3C-R-010 |
| `vbee48753abe90e1a` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vbf88ec51ebd083b6` | accept | agent-run-metrics | arm-f-steps | ARM-R-008 | none |
| `vc12a1c0f00be35f3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc17bb5b854981008` | reject | agent-run-metrics | arm-f-usage | ARM-R-009 | ARM-R-009 |
| `vc2cab6dea09f0a3b` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc34eb74f8bbc70ca` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc39c75a8c00ab957` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc3fa59108d1ead8a` | reject | report | w3c-f-jcs-number-value | W3C-R-020, W3C-R-030 | W3C-R-020 |
| `vc46bee7a31918d67` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc55768118bb88e53` | accept | report | w3c-f-16 | W3C-R-016 | none |
| `vc58647a590befbb7` | reject | report | w3c-f-13 | W3C-R-013 | W3C-R-013 |
| `vc653bb099d9c5839` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc66120fe5e1af394` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc7c310827b9dbd10` | accept | agent-run-metrics | arm-f-run | ARM-R-001 | none |
| `vc82b6b45a103ce1d` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vc938b2ab36cae34a` | accept | report | w3c-f-27 | W3C-R-027 | none |
| `vcbd0eaef95bc9181` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-010 | LCD-R-010 |
| `vccb24c478c736bc5` | accept | report | w3c-f-jcs-member-order | W3C-R-020, W3C-R-030 | none |
| `vccc374459c05dd52` | reject | agent-run-metrics | arm-f-steps | ARM-R-006 | ARM-R-006 |
| `vcd6021208e8e8a6e` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-006 | none |
| `vcdb9ae63a12852a8` | accept | agent-run-metrics | arm-f-serialization | ARM-R-021 | none |
| `vcf1cbb85d729dcd1` | reject | report | w3c-f-26 | W3C-R-026 | W3C-R-026 |
| `vd02cc7abe1dbc2bf` | reject | agent-run-metrics | arm-f-usage | ARM-R-011 | ARM-R-011 |
| `vd1eb6a3fb13eb97d` | reject | report | w3c-f-12 | W3C-R-012 | W3C-R-012 |
| `vd27e483fe63e78c0` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd2a25cb35e1b8bce` | accept | report | w3c-f-23 | W3C-R-023 | none |
| `vd2ae28ba9140bc89` | reject | report | w3c-f-28 | W3C-R-028 | W3C-R-028 |
| `vd2e50306dcd6c470` | reject | report | w3c-f-23 | W3C-R-023 | W3C-R-023 |
| `vd302fdc2d7a97e6e` | reject | agent-run-metrics | arm-f-serialization | ARM-R-018 | ARM-R-018 |
| `vd3e84d6a85cb6a0f` | accept | report | w3c-f-24 | W3C-R-024 | none |
| `vd53bcd623743858d` | accept | agent-run-metrics | arm-f-usage | ARM-R-014 | none |
| `vd5cc438bcd34a9d5` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd64679c8b7f9e736` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd7d23c0d86701fc6` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vd88fd757419269aa` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-009 | none |
| `vd8d93fd735111aa5` | accept | report | w3c-f-13 | W3C-R-013 | none |
| `vda5261ec1d0bd74e` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vda6c078e77700b28` | reject | agent-run-metrics | arm-f-usage | ARM-R-014 | ARM-R-014 |
| `vdca2c29b3d1d31b7` | accept | report | w3c-f-33 | W3C-R-033 | none |
| `vdcb0849fc754aaea` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vdcbd067d047bfbd0` | reject | report | w3c-f-7 | W3C-R-007 | W3C-R-007 |
| `vdd9207f5aa2fc9e3` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vdec1361509de89d4` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vdf05d359490e7833` | accept | report | w3c-f-18 | W3C-R-018 | none |
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
| `ve75a143e2bdb4d61` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `ve9c436f93e42e394` | reject | report | w3c-f-29 | W3C-R-029 | W3C-R-029 |
| `ve9cefed56bbc8359` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vea3ee7919ceb2e10` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vea598711b897286e` | accept | agent-run-metrics | arm-f-usage | ARM-R-011 | none |
| `vea80ece35200e349` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `veaee43cdb4a113d0` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vec36e393a92b69eb` | reject | report | w3c-f-4 | W3C-R-004 | W3C-R-004 |
| `vecd8b7bb20fed3a3` | accept | report | w3c-f-21 | W3C-R-021 | none |
| `vecddffbd8678e5ef` | reject | agent-run-metrics | arm-f-run | ARM-R-004 | ARM-R-004 |
| `vee997c119f09258b` | reject | report | w3c-f-11 | W3C-R-011 | W3C-R-011 |
| `vef09761654b57a92` | reject | agent-run-metrics | arm-f-usage | ARM-R-022 | ARM-R-022 |
| `vef3f22a57a308f45` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vf1e99cf0310cc1c6` | reject | agent-run-metrics | arm-f-usage | ARM-R-014 | ARM-R-014 |
| `vf374114fe7f28e7d` | reject | report | w3c-f-2 | W3C-R-002 | W3C-R-002 |
| `vf3af943ff1bf7375` | reject | agent-run-metrics | arm-f-serialization | ARM-R-021 | ARM-R-021 |
| `vf3fbd991d8e666a4` | accept | report | w3c-f-jcs-number-value | W3C-R-020, W3C-R-030 | none |
| `vf407ebb4a9cb8a3d` | accept | report | w3c-f-disensor | W3C-R-016 | none |
| `vf414a4c9065ad7b8` | reject | agent-run-metrics | arm-f-steps | ARM-R-015 | ARM-R-015 |
| `vf7334aa7dcf00826` | accept | agent-run-metrics | arm-f-run | ARM-R-004 | none |
| `vf753bb908231e0a1` | accept | llm-context-discovery | lcd-f-consumer | LCD-R-008 | none |
| `vf82e507d268fed9d` | accept | report | w3c-f-4 | W3C-R-004 | none |
| `vf86d92beb5a12905` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-002 | LCD-R-002 |
| `vf9b5623144960dda` | accept | report | w3c-f-9 | W3C-R-009 | none |
| `vfa24e4f45c2e826e` | accept | report | w3c-f-20 | W3C-R-020 | none |
| `vfa79ad0a7bd957b9` | accept | report | w3c-f-11 | W3C-R-011 | none |
| `vfacf2b3dafdb5c0a` | accept | report | w3c-f-jcs-declaration | W3C-R-015, W3C-R-032 | none |
| `vfbc5db1c2a012359` | reject | report | w3c-f-15 | W3C-R-015 | W3C-R-015 |
| `vfbd7379026575f04` | accept | report | w3c-f-gaps | W3C-R-001, W3C-R-002 | none |
| `vfeb5d1872929ab35` | accept | llm-context-discovery | lcd-f-publisher | LCD-R-010 | none |
| `vff1d02d89ab42ef7` | accept | report | w3c-f-33 | W3C-R-033 | none |
| `vff5545c0760d7544` | accept | agent-run-metrics | arm-f-usage | ARM-R-013 | none |
| `vff8f75223d6658ef` | reject | llm-context-discovery | lcd-f-publisher | LCD-R-001 | LCD-R-001 |

## Worked digests for the digest-encoding members

Each block recomputes one member's check-set root from nothing but `printf`,
`openssl` and `sha256sum`. A member carries two checks, and each check is one
leaf: the bytes `jcs-sha256` writes for it, RFC 8785 under the integer profile.
The root is the flat construction, SHA-256 over the SHA-256 of each leaf in
order, and the comment under each command is the `check-set.sha256` the member
declares. In the leaf bytes, printable ASCII is itself and any other byte is
written as a POSIX octal escape, so U+007F is `\177`, U+00E9 is `\303\251` and
U+1F600 is `\360\237\230\200`: RFC 8785 writes them as UTF-8, never as `\u`
escapes. The commands run in any POSIX shell; where `sha256sum` is missing, use
`shasum -a 256`.

**`v822c4bed9ba714d3`** (accept, `w3c-f-jcs-u007f`): the root over the leaf with U+007F written as the byte 0x7f, as RFC 8785 writes it.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"text":"delete \177"},"check":"c-u007f","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# fe92923b2a1cdb0f712e0376f2e69c30511cedec57333cea3f5e06c15c9e5df2
```

**`v60bd06deca6e832d`** (reject, `w3c-f-jcs-u007f`): a root over the leaf with U+007F written as \u007f, as the readers wrote it before RFC 8785.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `raw-u007f` switched off:

```
( printf '{"annotations":{"text":"delete \134u007f"},"check":"c-u007f","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# ab3e727343286160d3125b031825a32b52fd40ce4bb425e003b1959718811d15
```

**`v2f563dc0b6fc9ec8`** (accept, `w3c-f-jcs-non-ascii`): the root over the leaf with U+20AC, three bytes of UTF-8 written as UTF-8, as RFC 8785 writes it.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"text":"\342\202\254"},"check":"c-u20ac","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# ca0d6b586510a862453b102da4a47c25796f154c3a183a28d1a054b172beb3ea
```

**`v392e5b863085868b`** (accept, `w3c-f-jcs-non-ascii`): the root over the leaf with U+2028, the line separator ECMAScript once refused raw written as UTF-8, as RFC 8785 writes it.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"text":"\342\200\250"},"check":"c-u2028","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# d61c64ba947d0d6d3785158bbf68d5a5a4d1c97181e78887f2d23891d84ea172
```

**`v55772816f872150f`** (accept, `w3c-f-jcs-non-ascii`): the root over the leaf with U+00E9, two bytes of UTF-8 written as UTF-8, as RFC 8785 writes it.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"text":"\303\251"},"check":"c-u00e9","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 5512c1d32b57f1a892e8ba08c94210127f28eef76018cf44221fa6446624e88a
```

**`v606504b1125a3885`** (accept, `w3c-f-jcs-non-ascii`): the root over the leaf with U+1F600, a supplementary-plane character written as UTF-8, as RFC 8785 writes it.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"text":"\360\237\230\200"},"check":"c-u1f600","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 3122f6fb9b6db83f31e1765df2460a4c31e9d34264adc15acac52c1506b4fe97
```

**`v3fd6a6a262a72f91`** (reject, `w3c-f-jcs-non-ascii`): a root over the leaf with U+00E9, two bytes of UTF-8 written as \uXXXX escapes, as the readers wrote it before RFC 8785.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `raw-non-ascii` switched off:

```
( printf '{"annotations":{"text":"\134u00e9"},"check":"c-u00e9","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 41566def05bd68ea0f54108d4c72f4436c2f4de4d1c461f8bae5321016664107
```

**`v4193637206138b32`** (reject, `w3c-f-jcs-non-ascii`): a root over the leaf with U+1F600, a supplementary-plane character written as \uXXXX escapes, as the readers wrote it before RFC 8785.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `raw-non-ascii` switched off:

```
( printf '{"annotations":{"text":"\134ud83d\134ude00"},"check":"c-u1f600","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 1905f671aa32b5080565a1bc08e160db730c4c5651d2818be22494de1caa6894
```

**`v5196f1761ea14b2b`** (reject, `w3c-f-jcs-non-ascii`): a root over the leaf with U+20AC, three bytes of UTF-8 written as \uXXXX escapes, as the readers wrote it before RFC 8785.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `raw-non-ascii` switched off:

```
( printf '{"annotations":{"text":"\134u20ac"},"check":"c-u20ac","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# af862a9337409b0085f71e59e1bf6d6987107082ef29fa38917f1f591fa25743
```

**`v8474a83c45f293fc`** (reject, `w3c-f-jcs-non-ascii`): a root over the leaf with U+2028, the line separator ECMAScript once refused raw written as \uXXXX escapes, as the readers wrote it before RFC 8785.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `raw-non-ascii` switched off:

```
( printf '{"annotations":{"text":"\134u2028"},"check":"c-u2028","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 0414dddd295e811975c8aef2ef3611d82e97a260e1aa6847b78b00784dca24ff
```

**`vccb24c478c736bc5`** (accept, `w3c-f-jcs-member-order`): the root over the same names sorted by UTF-16 code unit, which puts U+1F600 first (its lead surrogate is 0xD83D).

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"\360\237\230\200":"U+1F600","\357\254\263":"U+FB33"},"check":"c-member-order","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 1d65402962c1f4e69b8528785d59ebfef5418804b6497c7f1d73c89141fe63fd
```

**`v9d05fc7c9c249317`** (reject, `w3c-f-jcs-member-order`): a root over member names U+FB33 and U+1F600 sorted by code point, which puts U+FB33 first.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `utf16-member-order` switched off:

```
( printf '{"annotations":{"\357\254\263":"U+FB33","\360\237\230\200":"U+1F600"},"check":"c-member-order","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 111ec757ffa63d4cc2406347ae29346caf6f35e224195b788c0929195403b4e1
```

**`v4e8fc1ab4f3fc5b3`** (accept, `w3c-f-jcs-number-value`): the root over the leaf with 1.0 and 1e2 written as 1 and 100, their values.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"hundred":100,"one":1},"check":"c-integral-tokens","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# b54538004454c320169716ff4478156f8d1f3b909cfd011f299a3f8357fee5b9
```

**`v79bebd0793e2fa7b`** (accept, `w3c-f-jcs-number-value`): the root over the leaf with the integer token -0 alone written as 0, its value, as RFC 8785 writes it.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"zero":0},"check":"c-negative-zero-integer","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# fe4364855784f38ad1b261d47195bf8c591820c4219396410f47b7d474bbed1d
```

**`vf3fbd991d8e666a4`** (accept, `w3c-f-jcs-number-value`): the root over the leaf with -0 and -0.0 written as 0, their value, as RFC 8785 writes them.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"zero":0,"zero-fraction":0},"check":"c-negative-zero","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 38eaa15ae7fb4eb3cbd84e05737eb010cfff672d94059ae782a481869bd26796
```

**`v920852737e02ae49`** (reject, `w3c-f-jcs-number-value`): a root over the leaf with the integer token -0 alone written as its token, as a reader that keeps the literal writes it.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `number-by-value` switched off:

```
( printf '{"annotations":{"zero":-0},"check":"c-negative-zero-integer","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 650fedb105e5acd49dbc88d6d499c7fb1e62457cfc3812fae66bbb0670f61d60
```

**`v9ff65c5b03dd074c`** (reject, `w3c-f-jcs-number-value`): a root over the leaf with -0 and -0.0 written as their tokens.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `number-by-value` switched off:

```
( printf '{"annotations":{"zero":-0,"zero-fraction":-0.0},"check":"c-negative-zero","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# ed7f15f63f99a08b8f8cb178a411fee9eb2af9dda5c83f045cbb0657c8bb2dcf
```

**`vc3fa59108d1ead8a`** (reject, `w3c-f-jcs-number-value`): a root over the leaf with 1.0 and 1e2 written as their tokens.

A conforming reader rejects it: W3C-R-020 (digests-differ). The root it declares is the one a reader writes with `number-by-value` switched off:

```
( printf '{"annotations":{"hundred":1e2,"one":1.0},"check":"c-integral-tokens","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 7d7fa2151131235f20831e52e863b12d783befd530e11c3b84f6992f56d7b7c5
```

**`v187e4435786b17f9`** (accept, `w3c-f-jcs-safe-range`): the neighbours outside the range carried as strings, which no reader parses as numbers.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"minus-two-to-the-53":"-9007199254740992","negative-zero":"-0","two-to-the-53":"9007199254740992","two-to-the-53-plus-one":"9007199254740993"},"check":"c-safe-range-as-strings","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 28ef9c84eb4d6865d3fd571e695ddd5b2f4d688a6f864e02d41a73ca58c3b35f
```

**`v5f92e1d7ef255730`** (accept, `w3c-f-jcs-safe-range`): both boundaries of the range, 2^53-1 and -(2^53-1), and the neighbours inside them.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"above-min":-9007199254740990,"below-max":9007199254740990,"max":9007199254740991,"min":-9007199254740991},"check":"c-safe-range-boundaries","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# bfcdf3672f8cd2e7e0bb2494a8a4008b1cd293212ae932b10f69ab14b6015d54
```

**`v0a887e6b24bdd940`** (reject, `w3c-f-jcs-safe-range`): -(2^53+1), whose nearest double is -2^53.

A conforming reader rejects it: W3C-R-020 (integer-outside-safe-range: -9007199254740993). The root it declares is the one a reader writes with `safe-range` switched off:

```
( printf '{"annotations":{"count":-9007199254740992},"check":"c-minus-two-to-the-53-minus-one","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# d4e4df938d0247432b02f03e7060283d07fd93dd45a49330edd4278df4a22812
```

**`v16bbc5bfef80043e`** (reject, `w3c-f-jcs-safe-range`): 2^53+1, whose nearest double is 2^53: a reader without the bound writes the root of a different integer, the one written here.

A conforming reader rejects it: W3C-R-020 (integer-outside-safe-range: 9007199254740993). The root it declares is the one a reader writes with `safe-range` switched off:

```
( printf '{"annotations":{"count":9007199254740992},"check":"c-two-to-the-53-plus-one","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# b14d98d192a24a4d221d3c599d26c4156881d2602557bb8676ae1b4e70ac4f17
```

**`v522b0a6b91e74c95`** (reject, `w3c-f-jcs-safe-range`): -2^53, the neighbour just outside the range below.

A conforming reader rejects it: W3C-R-020 (integer-outside-safe-range: -9007199254740992). The root it declares is the one a reader writes with `safe-range` switched off:

```
( printf '{"annotations":{"count":-9007199254740992},"check":"c-minus-two-to-the-53","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 4e95b7e7588e1cb58f3c42e457bd2319a3068a177097d0b1a536688ce8fa3aea
```

**`va8dfb25c6d62d458`** (reject, `w3c-f-jcs-safe-range`): 2^53, the neighbour just outside the range, with the root a reader without the bound writes over it.

A conforming reader rejects it: W3C-R-020 (integer-outside-safe-range: 9007199254740992). The root it declares is the one a reader writes with `safe-range` switched off:

```
( printf '{"annotations":{"count":9007199254740992},"check":"c-two-to-the-53","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# ce2e85b6b9ddaebb2915f8390e23d4c2ab8c133c24bb70925c69303406b45a08
```

**`v900fc651cea938e9`** (accept, `w3c-f-jcs-1e21`): 10^21 carried as a string in both spellings, so no digest has to choose one.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"digits":"1000000000000000000000","exponent":"1e+21"},"check":"c-1e21-as-strings","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 4b40f06cdab32dca09e356bf48097b24b8ab6d52c6c3c5f4f3f58e88bd80f163
```

**`v40ab7c6deec16438`** (reject, `w3c-f-jcs-1e21`): 10^21 as the exponent token 1e21, refused; a reader without the bound writes 1e+21, as RFC 8785 writes it.

A conforming reader rejects it: W3C-R-020 (integer-outside-safe-range: 1e21). The root it declares is the one a reader writes with `safe-range` switched off:

```
( printf '{"annotations":{"count":1e+21},"check":"c-1e21-as-exponent","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 662b1133786ad34ca24fa9a66c7ec2adffcceddbf36a99923d1811fde972d7c7
```

**`vb37f841c9e91bf18`** (reject, `w3c-f-jcs-1e21`): 10^21 in digits, the spelling the readers wrote before RFC 8785, refused; a reader without the bound writes 1e+21 for it, the root written here.

A conforming reader rejects it: W3C-R-020 (integer-outside-safe-range: 1000000000000000000000). The root it declares is the one a reader writes with `safe-range` switched off:

```
( printf '{"annotations":{"count":1e+21},"check":"c-1e21-in-digits","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 948f9c609fb120621bfba31a4589c6d0332c0728a10fc5a2979810ac599f79b6
```

**`v91f45fe53b9cb4f7`** (accept, `w3c-f-jcs-non-integer`): non-integral numbers carried as strings.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"half":"0.5","nines":"0.99999999999999999","small":"1e-7"},"check":"c-fractions-as-strings","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 86aa0c036510812f8460f10d0ac0363827c3cca313e79d41db9f99b837996395
```

**`v1afe0d60b2df5d39`** (reject, `w3c-f-jcs-non-integer`): 0.99999999999999999, whose nearest double is 1: refused on its exact value, which a reader that judges the double instead would admit and write as 1.

A conforming reader rejects it: W3C-R-020 (non-integer-number: 0.99999999999999999). The root it declares is the one a reader writes with `integers-only` switched off:

```
( printf '{"annotations":{"ratio":1},"check":"c-seventeen-nines","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 023a50bdc5ebe43bad9e31769fec689f5419cceedf39c7ae0635a97bab44f474
```

**`v26a379aeeebabd1e`** (reject, `w3c-f-jcs-non-integer`): 0.5, a non-integral number in a check leaf.

A conforming reader rejects it: W3C-R-020 (non-integer-number: 0.5). The root it declares is the one a reader writes with `integers-only` switched off:

```
( printf '{"annotations":{"ratio":0.5},"check":"c-one-half","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# c4378bce9ce7194998cde17674ba03f1c923d735f49c238f90badbdbf616ca30
```

**`v2b4990ad53fbf28b`** (reject, `w3c-f-jcs-non-integer`): 1e-7, which RFC 8785 writes in exponent form.

A conforming reader rejects it: W3C-R-020 (non-integer-number: 1e-7). The root it declares is the one a reader writes with `integers-only` switched off:

```
( printf '{"annotations":{"ratio":1e-7},"check":"c-1e-7","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 9cbd43e7fd1cf63941f3065e4bc3f13d2ac948c772614ea82e0d69d1285698be
```

**`vfacf2b3dafdb5c0a`** (accept, `w3c-f-jcs-declaration`): a binding that declares jcs-sha256, the one member of the closed set.

The root it declares, which a conforming reader recomputes:

```
( printf '{"annotations":{"text":"plain"},"check":"c-declared","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 6e497f370b7c37ef0bc9455cb001052fe02dcc87d65b2a31cd6d4d3e4bc3d0e5
```

**`v64e02942221729d2`** (reject, `w3c-f-jcs-declaration`): a binding that declares the encoding the readers used before RFC 8785, outside the closed set: refused by name, never read as the reader's own.

A conforming reader rejects it: W3C-R-015 (unsupported-digest-encoding). The root it declares is the one a reader writes with `closed-encoding-set` switched off:

```
( printf '{"annotations":{"text":"plain"},"check":"c-declared","state":"pass"}' | openssl dgst -sha256 -binary; printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary; ) | sha256sum
# 6e497f370b7c37ef0bc9455cb001052fe02dcc87d65b2a31cd6d4d3e4bc3d0e5
```
