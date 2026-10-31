---
title: "A fixed action vocabulary improves this authored score; quality still holds"
description: "Original policy vocabulary scores, strict quality holds and a source-bound installed replay."
toc: true
---

The native CPU run on 2026-10-03 scored 18 of 64 decisions with a fixed action
vocabulary, versus 4 of 64 with a broad string schema. It scored 2 of 32 complete
contrast pairs, versus 0 of 32. All 128 outputs satisfy their selected JSON
schema. All eight rows fail the default semantic quality gate.

These are exposed, authored policy cases. The vocabulary intervention follows
the earlier 384-call [boundary diagnosis](boundary-findings.html). It does not
establish general model quality or authorize model-directed publication,
admission, dispatch, recovery or effects. Scoped evidence-report publication
has a separate decision. [Claims P-43–P-50](claims.html) record the sources, read times and limits.

## What changed before inference

The frozen protocol copies the original sixteen policy inputs, targets, pair
identities and roles into two modes. The control permits any string decision.
The vocabulary mode permits the same seven case-sensitive labels for every
case: `publish`, `hold`, `admit`, `reject`, `retry`, `inspect` and `dispatch`.
It exposes no case-specific answer through its grammar.

The protocol declares 32 case identities and 128 unique model calls. Each of the sixteen
policy-case blocks rotates the eight model/cap/mode cells. Each cell occupies
each position twice. The prompts remain identical between modes. The contrast
analysis contains sixteen matching policy pair identities, without the older
arithmetic or grounded pairs. These choices precede inference and the normal
protected merge. The [provenance](experiments/model-vocabulary-cpu-2026-10-03/provenance.json)
records the frozen protocol, reviewed source, merge and authenticated workflow
run separately.

All 128 calls started and scored. None has an error, incomplete, unknown-start
or unsupported outcome. A complete run can still contain wrong policy decisions.

## Original semantic scores

Each row contains sixteen decisions and eight contrast pairs. Every row has
sixteen schema-valid outputs. The native caps allow 24 or 96 completion tokens
per call.

| Model | Cap | Control correct | Vocabulary correct | Control complete pairs | Vocabulary complete pairs |
|---|---:|---:|---:|---:|---:|
| smol135-q4 | 24 | 0/16 | 2/16 | 0/8 | 0/8 |
| smol135-q4 | 96 | 0/16 | 2/16 | 0/8 | 0/8 |
| smol360-q4 | 24 | 2/16 | 7/16 | 0/8 | 1/8 |
| smol360-q4 | 96 | 2/16 | 7/16 | 0/8 | 1/8 |

The table copies all eight original quality rows. It does not select a better
cap, change the rubric, or count schema success as semantic correctness. The
same outputs and correct-case identities recur across the two caps in this
run. These observations are descriptive, not independent trials.

## Evidence acceptance and quality refusal

The ordinary installed reader accepts the scoped evidence and reconstructs the
exact producer report. Its default host policy needs sixteen correct decisions
and eight complete pairs per row. It reports `hold-quality` for all eight rows
and exits with code 1. A second replay returns byte-identical stdout.

`--evidence-only` exits with code 0 while it still reports the quality hold.
Changed terminal bytes fail the original host pins. A reselected over-budget
terminal and a changed helper with new outer hashes both produce
`hold-evidence`. The [installed replay receipt](experiments/model-vocabulary-cpu-2026-10-03/installed-replay.json)
records these actual model-free checks. The
[source contract](experiments/model-vocabulary-cpu-2026-10-03/source-contract.json)
pins the wheel's selected source bytes independently of packet declarations.

A fresh checkout can run the downstream consumer without a model runtime.
Use Python with the standard `venv` and `ensurepip` modules. On Debian or Ubuntu,
install the `python3-venv` package for the selected Python first.

```sh
python3 tools/replay_vocabulary.py --output /tmp/probity-vocabulary-replay
```

Use a new output directory. The command checks the source-bound Atlas register
before it creates files or installs the retained wheel. It uses a clean virtual
environment and an offline installation. It repeats the actual packet, retains
the quality hold, checks evidence-only behavior, and refuses a changed terminal.
The ordinary pull-request workflow declares this path without model inference.
These remain checks by the same operator. They do not establish outside
producer acceptance, recurring adoption, effect execution or independent custody.

## Native resource scope

The native run uses 45.317547439 seconds wall time and 84.910453532 seconds
whole-process CPU time. Its shared lifetime peak is 557,932 KiB. Returned native
responses account for 10,624 prompt tokens and 1,172 completion tokens.
CPU includes whole-process deltas. RSS is a shared lifetime peak, not a task or
model allocation.

The current preparation transfers 472,221,945 response-body bytes in
8.880832051 seconds, rounded to nine decimal places. Its selected totals are 376,044,704 model bytes,
50,688,636 source bytes, 45,457,867 dependency bytes and 30,738 metadata bytes.
The five earlier preparations total 2,167,006,362 bytes. The six-preparation
cumulative total is 2,639,228,307 bytes. Failed earlier preparation stays in the
history. These are separate preparation envelopes.

The frozen limits remain 512 MiB and 180 seconds for preparation, 335 seconds
for the build, 600 seconds for native wall time and process CPU, 1 GiB lifetime
RSS, 65,536 prompt tokens and 7,680 completion tokens. Each network operation
has a 30-second limit. Paid provider calls and provider dollars are zero.
The complete retained evidence passes these run limits. That pass grants no
policy decision authority.

## What the public retention contains

The [original native ZIP](experiments/model-vocabulary-cpu-2026-10-03/original-artifact.zip)
is the exact 2,248,748-byte provider artifact. It retains all 346 members,
including every started/returned call record and the selected runner, helper,
preparation, protocol builder, native grammars and compiler. Its SHA-256 is
`eef05226335f9e2de6783ee797d891cbd1fe47058264e2d57eb41f1ec39131d8`.

The complete preparation original contains 376 members and 465,478,943 ZIP
bytes. The public native packet maps exactly to 346 members under `run/`.
The thirty omitted members include weights, dependency wheels and the source
archive. The same operator separately retains the full original. Hashes cannot
recreate omitted bytes.

The [installed capsule](experiments/model-vocabulary-cpu-2026-10-03/installed-capsule.zip)
is a 120,616-byte author-assembled selection with 37 members. It retains sixteen
original installed-artifact members and the separate actual replay receipts.
The original installed artifact contains 2,088 members and 9,441,817 ZIP bytes.
All 2,072 omissions are explicit. The capsule omits the CI virtual environment
and authored synthetic packet. The selected reader wheel is 35,389 bytes.
Its full-byte reproducibility is scoped to its recorded toolchain. The box and
CI wheels share selected source bytes but differ in complete wheel hashes.

The [provider inventory](experiments/model-vocabulary-cpu-2026-10-03/provider-inventory.json)
and provenance account for every member of all three provider originals.
Provider retention expiry and separately retained originals are disclosed.
This is the eighteenth bounded [Lab record](lab.html). It preserves all
seventeen earlier literal record objects and their artifact bytes. Original
measurements, quality acceptance, model actions, adoption and custody remain
separate.
