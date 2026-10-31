---
title: "Schema validity leaves policy and grounding unresolved"
subtitle: "A reproducible finite finding from the retained boundary experiment"
status: "Author-operated diagnostic finding, 2 October 2026. Original scores unchanged; no general benchmark or model-action approval."
description: "Exact original outputs distinguish schema compliance, semantic pair correctness, policy vocabulary and shared resource costs."
toc: true
---

The [original boundary report](experiments/model-boundary-cpu-2026-10-02/report.json)
contains 384 actual-weight CPU attempts. Its 192 schema-constrained outputs all
satisfy the declared syntax/type schemas, while no policy or grounded pair has
both cases strictly correct. This is useful evidence for a host gate: complete
measurement can permit publishing this diagnostic report while the host still
holds model decisions that fail its selected semantic requirements.

The population contains 48 authored case identities and 46 distinct literal
inputs, including two repeated positive controls. Each model, cap and decoder
sees the same cases. The [protocol](https://github.com/probityai/agent-evidence-observer/blob/f63ff5a7c236c8f0122dec71fbaabde8c2feb6a3/interop/local-model-boundary-tasks-2026-10-02/protocol.json)
and source were frozen before inference; expected targets were public and
selection was informed by earlier public failures. These results describe this
finite diagnostic population. They are not a representative benchmark estimate.

## Separate semantic cases and pairs

Every row below represents three separately retained family rows. Case counts
use sixteen attempts per family; pair counts use eight pairs per family.
No model, decoder or family is pooled into an overall acceptance score.

| Model | Cap | Decoder | Typed correct / pairs | Policy correct / pairs | Grounded correct / pairs | JSON valid | Schema valid |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 135M | 24 | unconstrained | 0/16; 0/8 | 0/16; 0/8 | 0/16; 0/8 | 0/48 | 0/48 |
| 135M | 24 | schema | 16/16; 8/8 | 0/16; 0/8 | 3/16; 0/8 | 48/48 | 48/48 |
| 135M | 96 | unconstrained | 0/16; 0/8 | 0/16; 0/8 | 0/16; 0/8 | 0/48 | 0/48 |
| 135M | 96 | schema | 16/16; 8/8 | 0/16; 0/8 | 3/16; 0/8 | 48/48 | 48/48 |
| 360M | 24 | unconstrained | 0/16; 0/8 | 0/16; 0/8 | 1/16; 0/8 | 34/48 | 10/48 |
| 360M | 24 | schema | 13/16; 5/8 | 2/16; 0/8 | 1/16; 0/8 | 48/48 | 48/48 |
| 360M | 96 | unconstrained | 0/16; 0/8 | 0/16; 0/8 | 1/16; 0/8 | 48/48 | 10/48 |
| 360M | 96 | schema | 13/16; 5/8 | 2/16; 0/8 | 1/16; 0/8 | 48/48 | 48/48 |

The [machine-readable finding](experiments/model-boundary-cpu-2026-10-02/finite-findings.json)
preserves all 24 original rows, all 192 pair records and both members of each
pair. The Atlas checker requires independent row bindings and recomputes each
row's counts and resource totals from the original attempts. Schema success,
an omitted failed pair, an invented custody role or a substituted source cannot
satisfy this selected retention gate.

## Output caps and typed failures

All 96 constrained short-versus-long comparisons have exactly identical output
text and verdicts in this run. Unconstrained comparisons retain 41 identical
texts and 82 identical verdict tuples across 96 comparisons. Raising the cap
changed some unconstrained formatting without making any policy pair fully
correct. This is a descriptive finding over original paired outputs; it does
not isolate a general causal cap effect or predict future outputs.

The larger constrained model has three typed failures at each cap:

| Frozen case | Original output | Frozen target |
| --- | --- | --- |
| `typed-empty-list` | `{"value":["payload"]}` | `{"value":[]}` |
| `typed-string-null` | `{"value":null}` | `{"value":"null"}` |
| `typed-empty-string` | `{"value":"payload"}` | `{"value":""}` |

Every output in this table is schema-valid. Exact value and type distinctions
remain observable failures. The readout retains all six original attempt
pointers and untouched output text, including whitespace, in its JSON artifact.

## Policy labels and decisions

A disclosed post hoc diagnostic checks case-sensitive membership in the seven
action labels from the frozen policy contract: `admit`, `dispatch`, `hold`,
`inspect`, `publish`, `reject` and `retry`. It changes no original score.

| Constrained model | Cap | Labels outside the frozen vocabulary | Valid label, wrong decision | Original strict correct |
| --- | --- | --- | --- | --- |
| 135M | 24 | 16/16 | 0/16 | 0/16 |
| 135M | 96 | 16/16 | 0/16 | 0/16 |
| 360M | 24 | 9/16 | 5/16 | 2/16 |
| 360M | 96 | 9/16 | 5/16 | 2/16 |

It tests the interface change on its own, apart from decision reasoning.
Constraining outputs to host-selected valid action labels could remove the
first class of failures. The five wrong decisions using valid labels already
show that vocabulary compliance alone cannot satisfy the original task rubric.
Any vocabulary intervention must be a new named experiment: it would add
semantic contract information beyond the original syntax/type-only grammar.
It must preserve all pairs, current authority requirements and no-dispatch
controls. No intervention has been executed or accepted here.

## Resources and retained originals

The separate [installed boundary report](experiments/installed-boundary-policy-2026-10-02/report.json)
now demonstrates the evidence/quality distinction with actual installed reader
0.0.4 and selected publication policy. Reader 0.0.3 refuses the boundary profile
before launch; the ordinary upgrade preserves the older 48/96/192-call reports
and verifies this unchanged 384-call original without inference.

The example quality policy requires eight correct cases and four fully correct
pairs in each constrained family row, as well as sixteen format/schema-valid
outputs. Its eight policy/grounded rows still produce sixteen separate
case/pair failures, so quality publication stays held despite all 192
schema-valid outputs. These selected host thresholds do not replace the
original strict scores: the larger typed model's thirteen cases/five pairs pass
the example threshold while failing the original all-sixteen/all-eight claim.
The Atlas gate preserves both interpretations and refuses promoting a held
quality result, complete evidence or a truthful unrelated field into action,
adoption or custody acceptance.

The [installed provenance](experiments/installed-boundary-policy-2026-10-02/provenance.json)
and [selected original capsule](experiments/installed-boundary-policy-2026-10-02/selected-capsule.zip)
retain actual wheel/build and reader/gate bytes with complete original-member
omission accounting. Installation does not establish an external operator,
registry release, protected decision authority or independent effect custody.

The original run used 257.401173568 seconds wall time and 497.394631919 seconds
total process CPU. Returned-call CPU sums to 496.051239620 seconds; the difference
includes work outside returned calls. Shared lifetime peak RSS was 567,192 KiB.
Neither CPU nor RSS is an allocation of memory or initialization cost to an
individual model or task. Native token totals remain 35,280 prompt tokens and
7,498 completion tokens.

The current preparation transferred 472,221,945 response-body bytes. Five
separately budgeted acquisition attempts total 2,167,006,362 bytes, including the
earlier failed preparation. A cumulative total exceeding one envelope cannot
be described as one preparation within that envelope.

The [byte-exact compact original](experiments/model-boundary-cpu-2026-10-02/original-artifact.zip)
retains 871 members. The [provenance](experiments/model-boundary-cpu-2026-10-02/provenance.json)
maps each member to the authenticated complete 901-member preparation original
and discloses all thirty omissions. Model weights, preparation source/dependency
wheels and complete preparation records remain in the separately archived
private complete original. Their hashes do not make them reconstructible from
this compact archive. Same-operator private retention is not independent custody.

## Reproduce and continue

From this Atlas checkout, run:

```sh
python3 tools/check_lab.py
python3 tools/derive_boundary_findings.py --check
python3 tools/build.py --check
```

The selected reader in the original packet also reproduces the original report
using separately selected manifest, protocol, declaration and terminal digests.
The installed reader upgrade and its host policy belong to the separate
consumer lane. That upgrade must continue refusing unsupported sources and
hold policy/grounded pair failures even when evidence verification passes.

The next research route is a preregistered policy vocabulary intervention with
the same original cases and separately declared inference/resource budgets.
Freeze the host's action vocabulary before inference, keep case-specific target
constants out of the grammar, retain unrestricted schema decoding as a control,
and score strict cases plus both members of every pair. Publish new outputs and
resources under a new identity. The native runner and framework-free reader
must first add explicit enum validation and an independently selected protocol
pin; the original runner's syntax/type acceptance check does not validate enums.
Until those source changes, peer review and a new freeze land, no new inference
result or host acceptance is claimed. Earlier 48/96/192/384 scores stay intact.
