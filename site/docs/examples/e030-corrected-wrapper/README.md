# Check a wrapper's process and report

This finite regression checks the corrected Frequency wrapper against failed commands and bad reports.
It is for a consumer or another operator who wants a check to keep in CI.

Install the exact development environment from this checkout:

```sh
uv sync --locked --group dev
.venv/bin/python -m scripts.fetch_inputs
.venv/bin/python -m e030_case.regression --operator 'your operator identity' \
  .inputs/review .inputs/aps .inputs/priorseal run-results
```

The command writes raw process output, each comparison and `run-results/receipt.json`.
It runs 14 cases against unchanged pinned source. Failed install, self-test and verifier commands,
absent or malformed reports, wrong input or claim fields, old generation times, linked reports,
and an existing attempt stay separate. One matching report projection is the positive control.

The injected `npm` and `node` commands do not run the producer verifier.
The reports are our fixtures. A zero exit with `PASS` does not make one a usable result.

For the locked source, test and coverage gate, run `bash scripts/run-gate.sh`.
Its retained `gate-results` identify actual command exits and the case observations.

Version: `0.1.0`. The operator is caller-declared and distinct from
the vector maintainer. A matching timestamp window does not authenticate a report or bind it to
an invocation. The native report has no invocation token.

| Detail | Link |
| --- | --- |
| Inputs, field meanings and ownership | [Source map](docs/SOURCE-MAP.md) |
| Run and comparison contract | [Contract](docs/CONTRACT.md) |
| Historical vector, preserved at its original pin | [Original Atlas vector](https://github.com/probityai/agent-evidence-atlas/blob/89250120e9cafe14eafb87eaa9c1454bab64683c/experiments/aps-priorseal-source-replay/check-run-contract.mjs) |
| Already kept outside check | [E030 run](https://github.com/probityai/agent-evidence/issues/31) |
