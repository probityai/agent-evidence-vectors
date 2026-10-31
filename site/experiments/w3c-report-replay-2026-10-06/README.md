# Historical report replay and diagnostic rule controls

A passing conformance comparison can correctly retain a negative evidence
conclusion. This finite record keeps the original harness, emitted report and
per-case crosswalk separate from two later diagnostic reader changes.

The original Vectors 0.12.0 outputs cover 272 synthetic cases. All 272 harness
comparisons pass; report states are 31 pass, 239 fail and two inconclusive.
The separate Vectors 0.13.0 diagnostic outputs cover 232 fixtures. Disabling
the failed-control-witness predicate changes one rejection; disabling the
checker/configuration predicate changes two. All 116 accepting controls stay
unchanged in each diagnostic output. These are author-operated, exposed-answer
records. They establish no real refund, production effect or independent custody.

## Check the retained accounting

From the Atlas repository root, use Python 3.10 or later:

```sh
python3 tools/check_report_replay.py
python3 tools/check_lab.py --record w3c-report-replay-2026-10-06 --json
```

The first command authenticates all 17 selected public files and recomputes
accounting from the original rows. It does not execute the retained reader
copies. The second checks the complete register, then displays this record.
A refused binding raises an error; successful accounting does not authorize
action. [Source manifest](source-manifest.json) paths resolve from its parent.
[Original run](original-RUN.json), [historical configuration](report-replay-configuration.json)
and [diagnostic configuration](logic-control-configuration.json) retain the
historical invocation, package/source identities and exact predicate changes.
Those historical source versions are distinct from the maintained data-only
consumer used by the commands above.

[Report](report.json) and [provenance](provenance.json) bind the scopes and roles.
The source copies retain their [Apache-2.0 license](LICENSE) and
[source notice](SOURCE-ORIGIN.json). No new study or current-package result is added.
