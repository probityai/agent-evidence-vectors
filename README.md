<p align="center">
  <img src=".github/assets/banner.svg" alt="agent-evidence-vectors" width="820">
</p>

<p align="center">
  <a href="https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/probityai/agent-evidence-vectors/ci.yml?branch=main&label=build" alt="build status"></a>
  <a href="https://pypi.org/project/agent-evidence-vectors/"><img src="https://img.shields.io/pypi/v/agent-evidence-vectors?label=PyPI&color=3775a9" alt="agent-evidence-vectors on PyPI"></a>
  <a href="https://doi.org/10.5281/zenodo.22758687"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.22758687.svg" alt="DOI 10.5281/zenodo.22758687"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0">
</p>

Conformance vectors and a reference verifier for signed evidence of what an AI agent did. Each
vector is an in-toto statement with the verdict and failure codes a correct verifier must return.

It's for anyone who writes a verifier, admission policy or specification for agent attestations
and needs to show that it rejects forged, tampered and malformed evidence as well as it accepts
good evidence.

## Quick start

Add the suite as a pinned dependency, then run its self-test:

```bash
pip install agent-evidence-vectors==0.16.0
agent-evidence-vectors --self-test
```

The last line reads `self-test: 20 checks, 0 failed`. To replay the corpus against your own
verifier, pass its command line:

```bash
agent-evidence-vectors --verifier './your-verifier --json'
```

In CI, pin the GitHub Action to the same release:

```yaml
- uses: probityai/agent-evidence-vectors@v0.16.0
  with:
    verifier: ./your-verifier --json
```

Your verifier reads one vector file, sets its exit status to the verdict, and prints the
failure codes as one line of JSON. [Running the suite](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/RUNNING.md) has the full contract.

## Status

Release `v0.16.0`, on [PyPI](https://pypi.org/project/agent-evidence-vectors/) and archived at
[10.5281/zenodo.22758687](https://doi.org/10.5281/zenodo.22758687). The main corpus implements
the in-toto Adversarial Execution Evidence predicate, proposed in
[in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570). The in-toto AI Agent
Action proposal, [#588](https://github.com/in-toto/attestation/pull/588/files), names this suite
as its conformance corpus and makes passing it a MUST. Other corpora cover SCITT and COSE
carriage, artifact binding, signed receipts and more; `agent-evidence-vectors --list-corpora`
prints them all.

To require conformance in a specification of your own, name a pinned release, for example:
"a conforming verifier passes `agent-evidence-vectors==0.16.0` with the report's `rail` field
reading `external`".
[What a conformance claim must show](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/RUNNING.md#what-a-conformance-claim-must-show) lists
the report fields to require.

## Documentation

| page | read it to |
| --- | --- |
| <a name="run-the-suite-against-your-verifier"></a><a name="one-harness-judges-every-corpus-here"></a>[Running the suite](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/RUNNING.md) | wire your verifier in, read the report, and judge a corpus directory with the `aee-verify` Go verifier |
| <a name="what-the-suite-judges"></a>[The corpora](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/CORPORA.md) | see what each corpus tests and which specification it follows |
| <a name="the-failure-code-contract"></a><a name="what-the-suite-compares"></a><a name="the-registry"></a><a name="indeterminate-vectors"></a><a name="condition-ids"></a>[The verifier contract](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/VERIFIER-CONTRACT.md) | implement the failure codes, the comparison rules and indeterminate vectors |
| <a name="conformance-vectors"></a><a name="what-the-corpus-forces-as-a-measured-number"></a>[What the corpus forces](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/FORCING.md) | see which rules the corpus forces a verifier to get right |
| <a name="verify-a-release-without-trusting-us"></a><a name="cite-this"></a>[Verify a release and cite it](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/VERIFY-A-RELEASE.md) | check the signed corpus digests yourself, and cite the exact bytes you ran |
| <a name="layout"></a><a name="the-verification-pipeline"></a>[Architecture](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/ARCHITECTURE.md) | find your way around the Go core, the CLI and the go-witness attestor |
| <a name="used-by"></a><a name="on-independence"></a>[Adoption and independent runs](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/ADOPTION.md) | see who uses the suite and every outside implementation's score |
| <a name="how-this-suite-is-maintained"></a><a name="arriving-from-somewhere-else"></a>[All documentation](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/README.md) | find governance, the record of outside objections, citation guidance and the run scoreboard |

Report a run of your own implementation with the
[independent-run form](https://github.com/probityai/agent-evidence-vectors/issues/new?template=independent-run.yml).
Contributions follow [CONTRIBUTING.md](https://github.com/probityai/agent-evidence-vectors/blob/main/CONTRIBUTING.md), and security reports follow
[SECURITY.md](https://github.com/probityai/agent-evidence-vectors/blob/main/SECURITY.md). Agents working in this repository start at [AGENTS.md](https://github.com/probityai/agent-evidence-vectors/blob/main/AGENTS.md).

## License

Apache-2.0. The citation metadata is in [CITATION.cff](https://github.com/probityai/agent-evidence-vectors/blob/main/CITATION.cff).
