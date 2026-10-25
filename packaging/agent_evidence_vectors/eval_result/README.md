# Evaluation result readings: direction declared, origin per item, held-out three-state

This directory holds a reference reader and a frozen corpus for three properties of a
`gen_ai.evaluation.result` event and the evidence items under it. The attribute names
are the working names in the OpenTelemetry GenAI evaluation discussion; they are
fixture names here, not proposed registry entries.

| File | Holds |
| --- | --- |
| `reader.py` | `read(input)`: derives the readings, an ordering when two results are compared, and reason codes. Stdlib-only and offline. |
| `run.py` | The `agent-evidence-vectors evalresult` command: `read` and `run`. |
| `corpus/cases.json` | Every case: the input, the expected readings and reasons, and for a negative its positive twin and the operations that repair it. |
| `corpus/manifest.json` | The sha256 of every other member. The runner refuses a corpus whose members differ. |

## What the cases pin

- **Score direction.** Two results order only under a declared `maximize` or `minimize`. A
  metric named `toxicity` with no declaration is not comparable. An unregistered value, two
  results of one evaluator id and version that disagree, and two results from different
  evaluator versions are each refused with their own code.
- **Evidence origin.** Origin belongs to each evidence item: `self_reported`,
  `system_generated`, `evaluator_obtained` or `external`. A result that rests on two origins
  lists both. A single value over a mixed set, a missing origin and an unregistered origin
  are refused.
- **Producer and verifier.** `produced_by` and `verified_by` are separate fields. A verifier
  that is a different party leaves a `self_reported` item `self_reported`. A verifier equal
  to the producer is not a second party, and relabelling an item because someone checked it
  contradicts who produced it.
- **Held-out status.** `true`, `false` and absent are three states. Absent reads as
  unknown, never as false, and a relying party that requires a held-out set refuses
  unknown and false under different codes. The string `"false"` is not a boolean.

## How the cases are built

`scripts/eval-result-build.py` writes the corpus and CI checks that the committed files are
what it writes. The expected answers are written out in that script; no reader produces
them. Each negative starts from a positive twin and makes one change, and carries `repair`,
the operations that undo it. `scripts/eval-result-test.py` proves that the repaired input is
the twin and reads as the twin does, that every reason code is carried alone by a negative,
that disabling any rule changes a negative, and that a naive reader fails a negative in every
group.

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors evalresult run --output evalresult-report
agent-evidence-vectors evalresult read --input my-result.json
```

`run` checks every corpus member against `corpus/manifest.json`, reads every case without its
expected answer, writes `report.json` and exits 1 if any case differs. `read` prints the
reading and exits 1 when it carries a reason. From a checkout, run
`python -m agent_evidence_vectors.eval_result.run run` inside `packaging/` with
`--implementation-revision "$(git rev-parse HEAD)"`.

A reader that agrees with the corpus is a same-code reproduction when it shares this
reader's logic. The corpus separates a reader that re-derives from one that repeats; it does
not establish that any producer's records are true.
