# R6-v01: R6's posted report in the v0.1 shape

`posted-records.v0.1.json` is R6's report as posted, byte for byte (sha256
`d81ea91d...`, the same file at both R6 pins of Rul1an/assay). Every reader in
`../matrix/` stops it on shape. `report-v01.json` is the same report re-encoded
into the v0.1 shape. No check is re-run and no value is added:

| v0.1 slot | taken from the posted field |
|---|---|
| `format` | the `public-agent-conformance/report/v0.1` string, for the prose name |
| `domain` | `run.domain`, moved to run level |
| `checks[].check`, `.state` | `records[].check_id`, `.state` |
| `checks[].other-verdict.value`, `.discrimination.value` | `records[].other_verdict`, `.discrimination` (all `unknown`) |
| `roll-up` counts, `carried`, `referenced` | `rollup.aggregate`, `rollup.carried_vs_referenced` |
| `roll-up.negative-capable.kind` | `rollup.discriminating_power.answer` (`nothing`) |
| `roll-up.completeness` | `rollup.completeness`, `satisfied` as `satisfied` or `not-satisfied` |
| `check-set` | computed: the flat root over the four checks |

Every other posted field is kept verbatim under its posted name.

    python3 -I reencode_r6.py posted-records.v0.1.json --out report-v01.json

prints `conforms` (the reference reader's `shape_errors` and `rejections` are
both empty) and writes the committed bytes. `../tests/test_r6_v01.py` holds it
to that.
