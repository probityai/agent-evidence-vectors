---
title: "A green test suite can contain negative conclusions"
subtitle: "Reproduce the difference between a correct test, a valid record and a successful action"
status: "Historical package replay and two diagnostic rule controls, 6 October 2026."
description: "A complete 272-case replay separates test outcomes from evidence conclusions. Two reader changes expose specific control dependencies."
toc: true
---

A payments team wants an agent to issue refunds within an approved limit. Its
tests cover a permitted refund, a refused refund, an altered approval and a
repeated request. Each test can pass. That does not mean each refund succeeded.
A test also passes when the checker correctly refuses the altered approval.

The distinction matters after an incident. A valid record can describe a failed
action. An invalid record cannot establish whether the action succeeded. Probity
keeps the test outcome, the record's validity and the recorded result separate,
with the inputs and reader needed to repeat the check.

This note shows those meanings on published conformance fixtures. The
refund workflow is an example of the customer problem. The measurements below
come from synthetic artifacts.

Read the [retained Lab record](runs.html#record-w3c-report-replay-2026-10-06) or [check its retained accounting](experiments/w3c-report-replay-2026-10-06/README.md). The maintained checker reads the original outputs; it does not rerun captured reader code.

## Reproduce the historical report

We replayed all 272 cases in `agent-evidence-vectors==0.12.0` on CPython 3.13.7
and 3.14.3. Both runs reproduced the complete historical report and harness
bytes. All 272 test outcomes passed. The report contained 31 passing, 239 failing
and two inconclusive checks.

| Record kind | Reader verdict | Recorded result | Report state | Cases |
| --- | --- | --- | --- | ---: |
| accept | valid | pass | pass | 25 |
| accept | valid | pass_indirect | pass | 6 |
| accept | valid | fail | fail | 27 |
| accept | valid | degraded | fail | 3 |
| reject | invalid | absent | fail | 209 |
| indeterminate | invalid | absent | inconclusive | 2 |

Thirty valid artifacts described a failing or degraded result. The other 209
negative checks came from invalid artifacts. The test suite passed because each
case produced its expected answer. The two indeterminate cases retained the
historical `unsupported_input` cause.

The [original report](experiments/w3c-report-replay-2026-10-06/original-report.json),
[original harness output](experiments/w3c-report-replay-2026-10-06/original-conformance-report.json)
and [complete case table](experiments/w3c-report-replay-2026-10-06/per-case-outcomes.csv)
retain each conclusion. The report SHA-256 is
`37288d8dfc01f56cb5ef553232258dc596928bc962e2309e0c7dc09ae588baf2`.
The harness SHA-256 is
`ee349e66697a2f4f95dd8223fd261810f99f5f2807e03bde03c9a9f57359529d`.

The source is commit `2f3aee40a454df6de0f571d119f057d7dbb8dd67`.
Its 61 accepting, 209 rejecting and two indeterminate fixtures have corpus
digest `8b035678def9e5ac00ba761b8c640e4412c57163134afb9d2c1a90f49d573a52`.
The measured installation used the published wheel with SHA-256
`cb346a41f715029f8e68542150560b08a71ac23eb7660eaa411aea4fd2ec1f59`.
All 1,191 package files matched that wheel and their source Git blobs. The
[replay configuration](experiments/w3c-report-replay-2026-10-06/report-replay-configuration.json)
records the exact package, environment and command:

```sh
agent-evidence-vectors --emit-w3c-report report.json
```

Run it from an empty directory with that installed package. The experiment used
the reference reader, removed `AEE_EXTERNAL_VERIFIER` and `AEE_SUBSTRATE_KEYS`,
and exposed the expected answers. It ran no model inference or new agent task.

## Check which rules change the result

A separate experiment used the 232 fixtures in the published 0.13.0 report
corpus. We copied its reader twice and disabled one predicate in each copy.
The fixture documents, resolution stores and all other checks stayed fixed.
Each actual reader ran over every fixture.

| Disabled rule | Original rejection | Rejecting cases changed | Cases unchanged |
| --- | --- | ---: | ---: |
| A failed control witness must have state `fail` | `W3C-R-013` | 1 | 231 |
| A declared control and run must name the same checker and constraint set | `W3C-R-029` | 2 | 230 |

The first change accepted a witness whose state was `inconclusive`. The second
accepted a control that named another checker or constraint set. All 116
accepting fixtures and every other rejecting fixture stayed unchanged.

The [rule configuration](experiments/w3c-report-replay-2026-10-06/logic-control-configuration.json),
[complete rule results](experiments/w3c-report-replay-2026-10-06/logic-control-evidence.json)
and [source record](experiments/w3c-report-replay-2026-10-06/SOURCE-ORIGIN.json)
identify the exact readers and modifications. These controls test the predicates
themselves. They do not remove rejection labels after the reader runs.

## What a customer can use

A release test answers whether the system produced the expected decision for
the selected case. An incident report answers what the retained evidence
supports. Keeping those answers separate prevents a dashboard from turning a
correct refusal into a successful agent action.

The retained files let another reader check the same inputs, rules and results.
This experiment used the same reference implementation on two runtimes. A
[second-party replay](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0089.html)
also reported the historical file digests. Repeated output supports
reproducibility; it does not establish an independently written implementation.

The [September 30 draft](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0087.html)
provides the reporting context. It remains draft correspondence. These fixture
results establish no live refund, customer deployment or independent custody.
A deployed workflow needs its own permitted action, refusal, retry and fault
results, with records checked at the actual effect boundary.
