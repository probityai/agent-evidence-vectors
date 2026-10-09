# Probity Vectors

Test an agent-evidence verifier against saved records with known outcomes. The corpora cover valid records, altered bytes, missing evidence and open specification interpretations.

<a name="run-the-suite-against-your-verifier"></a>

## Try it

From a reviewed source checkout, build the Go verifier and a wheel, then run the installed harness outside the checkout. You need Go 1.24+, Python 3.13+ and [uv](https://docs.astral.sh/uv/). Record the checkout's full commit ID with your report.

```bash
git rev-parse HEAD
run_dir="$(mktemp -d)"
GOWORK=off go build -o "$run_dir/aee-verify" ./cmd/aee-verify
uv build --wheel --out-dir "$run_dir"
wheel="$(find "$run_dir" -maxdepth 1 -name 'agent_evidence_vectors-*.whl')"
cd "$run_dir"
uv run --no-project --with "$wheel" agent-evidence-vectors --verifier "$run_dir/aee-verify --json"
```

Open `conformance-report.json` for the per-vector results. A complete external run has `rail: external`, `verifier.vectorsExecuted` equal to `totals.vectors`, and zero `totals.suiteRefusals`. The report separates conformance from reason-code agreement.

See [installation routes and release identity](DISTRIBUTION.md) for package availability and signature checks.

Select `v0.17.5` on [GitHub](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.17.5) and [PyPI](https://pypi.org/project/agent-evidence-vectors/0.17.5/). Install the matching release with Go's executable directory on your `PATH`:

```bash
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.17.5
uvx agent-evidence-vectors==0.17.5 --verifier "aee-verify --json"
```

<a name="what-a-conformance-claim-must-show"></a>
<a name="the-verification-pipeline"></a>
<a name="the-failure-code-contract"></a>
<a name="what-the-suite-compares"></a>
<a name="two-layers-one-set-of-bytes-statementlayer"></a>
<a name="the-registry"></a>
<a name="indeterminate-vectors"></a>

## Test your verifier

The harness calls your executable with a vector-file path. Return a verdict through the exit status and a JSON object on the last line of stdout. The [verifier contract](docs/reference/verifier-contract.md) covers output fields, key policy and comparison rules.

Use the [GitHub Action](action.yml) to run the same check in your build and retain its report. The [CI guide](docs/guides/runner.md) gives a workflow step and the available inputs.

## Choose your next step

| I want to | Read |
| --- | --- |
| Pick a format and corpus | [Corpus guide](docs/guides/corpora.md) |
| Implement the verifier interface | [Verifier contract](docs/reference/verifier-contract.md) |
| Understand what the fixtures test | [Corpus measurements](https://github.com/probityai/agent-evidence-vectors/blob/v0.17.5/docs/research/corpus-measurements.md) |
| Check release bytes and signatures | [Release verification](docs/reference/release-verification.md) |
| Report a run or disagreement | [Run reporting](docs/guides/report-run.md) |
| See who runs and uses the corpora | [Independent runs](docs/INDEPENDENT-RUNS.json), [Adopters](docs/ADOPTERS.md) |

<a name="what-the-suite-judges"></a>
<a name="one-harness-judges-every-corpus-here"></a>

Each corpus manifest records its source revision, digest and expected outcomes. [DISTRIBUTION.md](DISTRIBUTION.md) lists the shipped corpora and installation routes.

<a name="conformance-vectors"></a>
<a name="what-the-corpus-forces-as-a-measured-number"></a>
<a name="detector-liveness-and-the-anchor-beside-every-refusal"></a>
<a name="condition-ids"></a>
<a name="used-by"></a>
<a name="on-independence"></a>
<a name="verify-a-release-without-trusting-us"></a>

For fixture coverage, see [Corpus measurements](https://github.com/probityai/agent-evidence-vectors/blob/v0.17.5/docs/research/corpus-measurements.md). To check signed release bytes, use [Release verification](docs/reference/release-verification.md).

<a name="layout"></a>
<a name="the-go-witness-attestor-witnessattestor"></a>

Source maps: [repository layout](docs/reference/layout.md), [corpus readers](docs/reference/corpus-readers.md) and [witness attestor](docs/reference/witness-attestor.md).

<a name="how-this-suite-is-maintained"></a>
<a name="arriving-from-somewhere-else"></a>
<a name="cite-this"></a>

## Contribute

[Open an issue](https://github.com/probityai/agent-evidence-vectors/issues/new) with the corpus revision, verifier build and report. For patches, start with [CONTRIBUTING.md](CONTRIBUTING.md). For citations, use the [citation guide](docs/reference/citing.md).

Need to check a supplied claim against saved evidence? See [Probity Verify](https://github.com/probityai/probity-verify). Browse the [Probity projects](https://github.com/probityai) for records, vocabulary and admission tools.

Apache-2.0. [LICENSE](LICENSE).
