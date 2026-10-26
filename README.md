# Agent Evidence Vectors

[![CI](https://img.shields.io/github/actions/workflow/status/probityai/agent-evidence-vectors/ci.yml?label=CI)](https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-evidence-vectors)](https://pypi.org/project/agent-evidence-vectors/)
[![Monthly](https://img.shields.io/pypi/dm/agent-evidence-vectors?label=downloads)](https://pepy.tech/projects/agent-evidence-vectors)
[![Total](https://static.pepy.tech/badge/agent-evidence-vectors)](https://pepy.tech/projects/agent-evidence-vectors)
[![Licence](https://img.shields.io/github/license/probityai/agent-evidence-vectors)](LICENSE)
[![Stars](https://img.shields.io/github/stars/probityai/agent-evidence-vectors?style=flat)](https://github.com/probityai/agent-evidence-vectors/stargazers)

[![Verified by Probity](https://raw.githubusercontent.com/probityai/agent-evidence/main/assets/verified-by-probity.svg)](https://github.com/probityai/probity)
Verified by Probity (github.com/probityai/probity): [latest passing run](https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml)

Test an agent-evidence verifier against saved records with known outcomes. The corpora cover valid records, altered bytes, missing evidence and open specification interpretations.

![Four-arm demo: an intact archive verifies, a changed byte fails, a missing artifact is not established, and a changed verifier keeps both outcomes](demo/four-arms.gif)

The recording is `demo/four-arms.sh` from a fresh clone; `vhs demo/four-arms.tape` re-records it.

Add it to a project with `uv add agent-evidence-vectors==0.25.0`, then `pip install agent-evidence-vectors==0.25.0`. The `probityai` command line is planned, not yet released: `uv add probityai`, then `pip install probityai`.

<a name="run-the-suite-against-your-verifier"></a>

## Try it

Run every vector in the default corpus through the bundled reference verifier. You need Python 3.11+ and [uv](https://docs.astral.sh/uv/); there is nothing to clone or build, and a cold run takes about six seconds:

```bash
uvx agent-evidence-vectors==0.25.0
```

At v0.25.0 the default corpus is suiteRevision 32, and the run prints one row per vector and ends with:
```text
totals: 288 vectors, 288 pass, 0 fail; report written to conformance-report.json
```

Now run the same corpus against a verifier other than the reference. The Go reference verifier installs with Go 1.26+ and Go's executable directory on your `PATH`; put your own command in its place:

```bash
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.25.0
uvx agent-evidence-vectors==0.25.0 --verifier "aee-verify -validity-only -json"
```

Open `conformance-report.json` for the per-vector results. A complete external run has `rail: external`, `verifier.vectorsExecuted` equal to `totals.vectors`, and zero `totals.suiteRefusals`. The report separates conformance from reason-code agreement. `--list-corpora` names the other shipped corpora and `--corpus <name>` selects one.

The release is `v0.25.0` on [GitHub](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.25.0) and [PyPI](https://pypi.org/project/agent-evidence-vectors/0.25.0/). To run from a reviewed source checkout instead, follow the [source build](docs/guides/source-build.md). [Installation routes and release identity](DISTRIBUTION.md) covers package availability and signature checks.

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

```yaml
- uses: probityai/agent-evidence-vectors@v0.22.0
  with:
    verifier: VERIFIER_COMMAND --json
```

Replace VERIFIER_COMMAND with the command that runs your verifier.

## Verifiers that pin this corpus

agmi, Rul1an/aee-checker and MoltyCel/moltrust-api run a corpus from this repository in their own CI at a pinned release or commit, and this repository's CI runs agmi's anchored-chain verifier back against `vectors-anchored-chain`. The [verifier table](docs/VERIFIERS.md) gives each one's corpus, pin and CI run.

## Choose your next step

| I want to | Read |
| --- | --- |
| Start a project with this Action already in CI | [evidence-starter template](https://github.com/new?template_name=evidence-starter&template_owner=probityai) |
| Pick a format and corpus | [Corpus guide](docs/guides/corpora.md) |
| Implement the verifier interface | [Verifier contract](docs/reference/verifier-contract.md) |
| Understand what the fixtures test | [Corpus measurements](https://github.com/probityai/agent-evidence-vectors/blob/v0.25.0/docs/research/corpus-measurements.md) |
| Check release bytes and signatures | [Release verification](docs/reference/release-verification.md) |
| Report a run or disagreement | [Run reporting](docs/guides/report-run.md) |
| Check a W3C intake record | [W3C intake checker](docs/reference/w3c-intake.md) |
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

For fixture coverage, see [Corpus measurements](https://github.com/probityai/agent-evidence-vectors/blob/v0.25.0/docs/research/corpus-measurements.md). To check signed release bytes, use [Release verification](docs/reference/release-verification.md).

<a name="layout"></a>
<a name="the-go-witness-attestor-witnessattestor"></a>

Source maps: [repository layout](docs/reference/layout.md), [corpus readers](docs/reference/corpus-readers.md) and [witness attestor](docs/reference/witness-attestor.md).

<a name="how-this-suite-is-maintained"></a>
<a name="arriving-from-somewhere-else"></a>
<a name="cite-this"></a>

## Contribute

[Open an issue](https://github.com/probityai/agent-evidence-vectors/issues/new) with the corpus revision, verifier build and report. For patches, start with [CONTRIBUTING.md](CONTRIBUTING.md). For citations, use the [citation guide](docs/reference/citing.md).

Need to check a supplied claim against saved evidence? See [Probity Verify](https://github.com/probityai/probity). Browse the [Probity projects](https://github.com/probityai) for records, vocabulary and admission tools.

Apache-2.0. [LICENSE](LICENSE).
