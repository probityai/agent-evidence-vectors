# Run the suite from a source checkout

From a reviewed source checkout, build the Go verifier and a wheel, then run the installed harness outside the checkout. You need Go 1.26+, Python 3.11+ and [uv](https://docs.astral.sh/uv/). Record the checkout's full commit ID with your report.

```bash
git rev-parse HEAD
run_dir="$(mktemp -d)"
GOWORK=off go build -o "$run_dir/aee-verify" ./cmd/aee-verify
uv build --wheel --out-dir "$run_dir"
wheel="$(find "$run_dir" -maxdepth 1 -name 'agent_evidence_vectors-*.whl')"
cd "$run_dir"
uv run --no-project --with "$wheel" agent-evidence-vectors --verifier "$run_dir/aee-verify -validity-only --json"
```

Open `conformance-report.json` for the per-vector results. A complete external run has `rail: external`, `verifier.vectorsExecuted` equal to `totals.vectors`, and zero `totals.suiteRefusals`. The report separates conformance from reason-code agreement.

To run the released package without a checkout, see [Try it](../../README.md#try-it) in the README.
