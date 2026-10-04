# Install, verify and cite Probity Vectors

Use this page to choose an installation route or identify the corpus you ran. For the verifier interface, see the [verifier contract](docs/reference/verifier-contract.md).

## The tag to cite

`v0.15.0`, also recorded in [CITATION.cff](CITATION.cff). Use a release tag or commit and the corpus digest when reporting a result.

## The one-command run

Install the Go verifier, then run the packaged harness:

```bash
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.15.0
uvx agent-evidence-vectors==0.15.0 --verifier "aee-verify --json"
```

Or run the same harness from a checkout:

```bash
git clone https://github.com/probityai/agent-evidence-vectors
cd agent-evidence-vectors && git checkout v0.15.0
python3 packaging/run_vectors.py --verifier "aee-verify --json"
```

The [runner guide](docs/guides/runner.md) covers the GitHub Action, its inputs and report fields. [Probity Admission](https://github.com/probityai/agent-evidence-admission) uses pinned corpora to check policy-engine enforcement.

If your verifier disagrees with a vector, [report the run](docs/guides/report-run.md) with its source revision and report. We can then check the verifier and the fixture against the same specification.

## Verify a release without trusting us

Recompute the corpus digests, then check the signature and timestamp proofs:

```bash
git clone https://github.com/probityai/agent-evidence-vectors && cd agent-evidence-vectors
git checkout v0.15.0

# 1. the digest list is what the vector files on disk hash to, recomputed
python3 scripts/release-digests.py --check

# 2. the maintainer signed exactly those bytes
cosign verify-blob --key release/cosign.pub \
  --signature release/CORPUS-DIGESTS.txt.sig \
  --insecure-ignore-tlog=true release/CORPUS-DIGESTS.txt

# 3. an RFC 3161 authority saw that signature at a stated time
openssl ts -verify -in release/CORPUS-DIGESTS.txt.sig.tsr \
  -digest "$(base64 -d release/CORPUS-DIGESTS.txt.sig | sha256sum | cut -d' ' -f1)" \
  -CAfile spec/tsa-roots.pem

# 4. so did a public calendar nobody here controls
ots verify -d "$(base64 -d release/CORPUS-DIGESTS.txt.sig | sha256sum | cut -d' ' -f1)" \
  release/CORPUS-DIGESTS.txt.sig.ots
```

[Release verification](docs/reference/release-verification.md) explains the checks and their requirements. Its recipe must match this block exactly; `scripts/distribution-gate.py` checks both copies. The digest check needs only Python.

## How to cite it

Name the repository URL, the corpus's `suiteRevision` or release tag, and its `corpusDigest`. Read those values from the manifest you ran. [CITATION.cff](CITATION.cff) supplies the citation metadata; the [citation guide](docs/reference/citing.md) gives examples.

## The corpora this repository ships

Choose a corpus for the format your verifier supports. Each has its own manifest, source pin and digest.

| Directory | Suite name in its manifest | What it tests |
| --- | --- | --- |
| `vectors/` | `adversarial-execution-evidence-conformance` | the adversarial-execution-evidence predicate this repository vendors, tracked at in-toto/attestation#570 |
| `vectors-agent-audit-record/` | `agent-audit-record-conformance` | the agent audit record of draft-gilda-wimse-agent-audit-record-02: the fifty-five members of its Appendix B, each carrying its Appendix B identifier, covering the canonical form, the request-digest and write-chain recomputes, the derived agreement, the recomputed tier, and whether the decision point could evaluate |
| `vectors-aci/` | `aci` | the agent capability interface levels and their serialization |
| `vectors-acs-core/` | `acs-core-negative-conformance` | the mandatory profile of the agent control standard, by negative members against vendored specification text |
| `vectors-ai-agent-action/` | `ai-agent-action-conformance` | the AI Agent Action predicate proposed at in-toto/attestation#588, plus the canonicalization text this repository puts forward for it |
| `vectors-ai-generation/` | `ai-generation-v01-conformance` | the generation predicate for AI-authored code under discussion at ossf/tac#628, at specification revision 0.1.5 in its attest-only mode, with the signed attestations both upstream implementations publish, plus the text this repository proposes for the two rules that revision leaves open |
| `vectors-anchor-stream/` | `anchor-stream-conformance` | the anchor-stream verification contract published by aos-standard/catalog |
| `vectors-artifact-binding/` | `artifact-binding-conformance` | the artifact-binding contract, over three verdicts rather than two |
| `vectors-mcp-record-contract/` | `cross-run-record-contract` | what a cross-implementation run record has to carry to mean anything |
| `vectors-mcp-response-phase/` | `mcp-response-phase-interception` | whether a response-phase MCP interceptor is invoked on JSON-RPC error frames, and whether its decision governs what the caller receives |
| `vectors-observed-effect/` | `observed-effect-conformance` | the observed-effect predicate: a mutation interval recorded from a vantage the observed party does not control, with the authority tier recomputed rather than read as a claim |
| `vectors-receipt-signature/` | `receipt-signature-conformance` | signed decision receipts under draft-farley-acta-signed-receipts-03: the signing input, the key's validity window and the Section 6.6 rules, judged against an external key set with and without its windows |
| `vectors-scitt-cose/` | `scitt-cose-carriage-conformance` | carriage of the predicate over SCITT and COSE receipts |
| `vectors-source-coverage/` | `source-text-coverage/v1` | selected source passages against a consumer-pinned capture, report, and time window |
| `vectors-self-reported-record/` | `self-reported-record-conformance` | a self-reported agent record: turn signatures under the named key, memory-read digests over the bytes at the named path, an attesting key outside the observed runtime's reach, ledgers that name one change set, and covering signatures on declared substrate coverage |
| `vectors-w3c-report/` | `w3c-report-v01-conformance` | the v0.1 per-check report of the W3C public-agent-conformance group: the five states, the cause rule, the twelve rejection rows and the two late additions, as whole reports |

The distribution gate checks the directory and suite names against the tracked manifests. Read vector counts and digests from those manifests or [release/CORPUS-DIGESTS.txt](release/CORPUS-DIGESTS.txt). The [corpus guide](docs/guides/corpora.md) describes the formats and packaged readers.

## Adding a corpus of your own

Add a sibling `vectors-<name>/` directory using the [corpus pull-request template](.github/PULL_REQUEST_TEMPLATE/vectors-directory.md). Include a manifest, reproducible generator, specification pin and a digest routine that works without third-party packages. Register it in the count gate and release digest list. See [maintenance](docs/reference/maintenance.md) for the checks.

## Reporting a run

Use the [run form](.github/ISSUE_TEMPLATE/independent-run.yml) and retain the full report. [RUNS.md](RUNS.md) records outside implementation results; the [independence record](docs/research/independence.md) explains how they were produced.

## Archive and identifiers

| Surface | Identifier |
| --- | --- |
| Source and Go module | `github.com/probityai/agent-evidence-vectors` |
| Go verifier | `cmd/aee-verify` |
| Python package | [agent-evidence-vectors](https://pypi.org/project/agent-evidence-vectors/) |
| Releases | [GitHub releases](https://github.com/probityai/agent-evidence-vectors/releases) |
| Signed digests | [release/CORPUS-DIGESTS.txt](release/CORPUS-DIGESTS.txt) |
| Archive | [Zenodo concept DOI](https://doi.org/10.5281/zenodo.22758687), with release-specific identifiers on the archive record |
