# Packslip host test and development dependency

Did Packslip's recorded host CI run its DSSE regression suite, and did its
published package declare the DSSE library as a development dependency?

The [retained report](report.json) answers two narrow questions. The recorded
GitHub test step completed successfully at source
`7b32cd29a9240927882ee18b3db1dcfd8e0328b4`; Packslip `1.7.0` declares `dsse`
`^0.1.1` as a **development** dependency. This is a historical host-maintained
test dependency, with an author-contributed regression. It is not a production
runtime dependency or an independently authored test.

The [provenance](provenance.json) links the five exact retained public response
bodies, captured on October 14, 2026. The historical host job completed on
October 11. Its `cargo test --all-features` step has a provider success
conclusion; this packet retains neither a numeric process exit nor the original
process stdout/stderr. The report keeps that numeric exit null.

Read the [original regression](raw/regression.rs), [host workflow](raw/host-workflow.yml),
[job metadata](raw/host-job.json), [contribution](raw/contribution-pr.json) and
[published dependency response](raw/reverse-dependencies.json). The regression
checks a malformed signature entry before a valid signature and a wrong key-ID
hint. Packslip maintains the host tests; `astrogilda` contributed the regression,
and `jdx` merged it. The Atlas metadata reader is Probity-operated. Those roles
do not establish separate witness custody, repeated current operation, an
observed production effect or paid use.

Check the retained source and report without running Packslip:

```sh
python3 experiments/packslip-dsse-host-ci-2026-10-11/validate_capsule.py
python3 tools/check_lab.py
```

The first command re-derives the report from fixed public-source hashes and
refuses a changed report, attribution, dependency kind or repinned source. It
does not repeat the host test or turn a metadata conclusion into native output.

The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-packslip-dsse-host-ci-2026-10-11)
returns to this packet. New evidence uses the existing
[claim and question intake](https://probityai.github.io/agent-evidence-atlas/lab.html#choose-the-claim-you-are-submitting)
and [retained-run protocol](https://probityai.github.io/agent-evidence-atlas/lab.html#technical-protocol-and-retained-run-notes).
