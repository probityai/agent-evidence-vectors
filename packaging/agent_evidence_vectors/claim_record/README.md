# Evaluation claim record: every coordinate present, absence refused

The normative definition is [spec/predicates/evaluation-claim.md](../../../spec/predicates/evaluation-claim.md),
served at the type URI
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/evaluation-claim`.
This directory holds the reference verifier and its frozen corpus.

| File | Holds |
| --- | --- |
| `reader.py` | The verifier: `verify(record, rule, profiles, case_sets)` and `emit(...)`. Stdlib-only and offline. |
| `run.py` | The `agent-evidence-vectors claim` command: `verify`, `emit` and `run`. |
| `ops.py` | The two JSON edits (`set`, `del`) a negative case uses to state its defect and its repair. |
| `corpus/profiles/` | The published `conformance/v1` and `execution/v1` profiles. |
| `corpus/case-sets/` | Sample case sets: two revisions of one set, a producer's reduced set that drops a required case, and an empty set. |
| `corpus/rules/` | Acceptance rules a relying party would pin, each naming a profile, the case sets and the vantages it accepts. |
| `corpus/cases.json` | Every case: the record, the rule it is judged under, and its expected result, verdict and reason codes. |
| `corpus/manifest.json` | The sha256 of every other member. The runner refuses a corpus whose members differ. |

## How the cases are built

`scripts/claim-record-build.py` writes the corpus; CI checks that the committed files
are what it writes. Each positive case states one way a record is admitted: a full
pass, an honest incomplete or fail, an optional case excluded under an authorised
reason, a superseded case-set revision still bound by its digest, an alias beside the
digest of older bytes, a reference outside the profile's immutable set given by tag,
self-report under a rule that accepts it, and authority transitions after an action
settled.

Each negative case starts from a base record (`bases` in `cases.json`) and makes one
change, its defect, and names exactly one reason code. It carries `repair`, the
operations that undo the change. `scripts/claim-record-test.py` proves, for every
negative, that the repaired record is admitted, so no negative refuses for a reason
other than the one it names. It also proves every reason code and every coordinate has
positive and negative cases, and it disables each rule in the verifier in turn and
requires at least one negative to stop reporting that rule's reason.

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors claim run --output claim-record-result
```

The command checks every corpus member against `corpus/manifest.json`, judges every
case without reading its expected answer, judges every negative again with its repair
applied, writes `report.json`, and exits 1 if any case differs. From a checkout, run
`python -m agent_evidence_vectors.claim_record.run run` inside `packaging/` with
`--implementation-revision "$(git rev-parse HEAD)"`.

To judge your own record, write the acceptance rule you require (or take one from
`corpus/rules/` as a template), and run `agent-evidence-vectors claim verify --record
<record> --rule <rule> --case-set <case set>`. To produce a record from a test run,
`agent-evidence-vectors claim emit` lists every case the results do not name as not
run.
