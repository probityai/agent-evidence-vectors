# Install, verify and cite Agent Evidence Vectors

Use this page to choose an installation route or identify the corpus you ran. For the verifier interface, see the [verifier contract](docs/reference/verifier-contract.md).

## The tag to cite

`v0.31.0`, the published version named by the preferred citation in [CITATION.cff](CITATION.cff). Cite its signed tag or full source commit and corpus digest when reporting a result.

The installation examples are pinned to the version above. The corpus table
describes this checkout; a release tag or installed wheel identifies its own
population.

This checkout prepares an unreleased source version with package metadata and
criterion-document repairs. Those changes are not part of the published release.
For a release run, select the matching [GitHub release](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.31.0) and
[PyPI wheel and source archive](https://pypi.org/project/agent-evidence-vectors/0.31.0/).
Use the installation route below or build from a reviewed source checkout.
The [source-wheel recipe](README.md#try-it) builds the verifier and harness
from a reviewed checkout, then runs the installed harness outside it. Record
that checkout's full commit ID. A source pin identifies selected bytes; it
does not authenticate their author. The failed prior release tag is retained
unchanged as historical evidence.

## Install the published release

Install matching published versions:

```bash
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.31.0
uvx agent-evidence-vectors==0.31.0 --verifier "aee-verify -validity-only -json"
```

Run the same harness from the published release checkout:

```bash
git clone https://github.com/probityai/agent-evidence-vectors
cd agent-evidence-vectors && git checkout v0.31.0
python3 packaging/run_vectors.py --verifier "aee-verify -validity-only -json"
```

The [runner guide](docs/guides/runner.md) covers the GitHub Action, its inputs and report fields. [Probity Admission](https://github.com/probityai/agent-evidence/tree/main/packages/admission) uses pinned corpora to check policy-engine enforcement.

If your verifier disagrees with a vector, [report the run](docs/guides/report-run.md) with its source revision and report. We can then check the verifier and the fixture against the same specification.

## Verify a release without trusting us

Recompute the corpus digests, then check the signature and timestamp proofs:

```bash
git clone https://github.com/probityai/agent-evidence-vectors && cd agent-evidence-vectors
git checkout v0.31.0

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
| `vectors-agent-audit-record/` | `agent-audit-record-conformance` | the agent audit record of draft-gilda-audit-agent-audit-record-00: one member per row of its Appendix B, each carrying its Appendix B identifier, then members for sentences of Section 5.4 that Appendix B has no row for, then rows of revision 01 that bind consumption state to an operation key, covering the canonical form, the request-digest and write-chain recomputes, the derived agreement, the recomputed tier, whether the decision point could evaluate and how fresh each input was, the withinLimit a cumulative limit derives, and the dating check over a retained record's anchors |
| `vectors-agent-decision/` | `agent-decision-conformance` | the `args_hash` rule of the agent-decision predicate proposed at in-toto/attestation#554: SHA-256 over the RFC 8785 bytes of the arguments, number forms across the exponent range and the 2^53 - 1 boundary, and an `args_state` that keeps a redacted call apart from an unrecorded one |
| `vectors-ietf-agent-record-drafts/` | `ietf-agent-record-drafts-conformance` | three SCITT-wave Internet-Drafts: the AgentInteractionRecord hash chain of draft-emirdag-scitt-ai-agent-execution-01, checkpoint registration in draft-mih-scitt-checkpointed-local-log-02, and statement references across equivalent encodings in draft-gruszka-scitt-statement-identification-02; each member records the verdict the draft's own steps reach and what its expected verdict does not assert |
| `vectors-aci/` | `aci` | the agent capability interface levels and their serialization |
| `vectors-acs-core/` | `acs-core-negative-conformance` | the mandatory profile of the agent control standard, by negative members against vendored specification text |
| `vectors-ai-agent-action/` | `ai-agent-action-conformance` | the AI Agent Action predicate proposed at in-toto/attestation#588, plus the canonicalization text this repository puts forward for it |
| `vectors-ai-generation/` | `ai-generation-v01-conformance` | the generation predicate for AI-authored code under discussion at ossf/tac#628, at specification revision 0.1.5 in its attest-only mode, with the signed attestations both upstream implementations publish, plus the text this repository proposes for the two rules that revision leaves open |
| `vectors-anchor-stream/` | `anchor-stream-conformance` | the anchor-stream verification contract published by aos-standard/catalog |
| `vectors-artifact-binding/` | `artifact-binding-conformance` | the artifact-binding contract, over three verdicts rather than two |
| `vectors-dependency-selection/` | `artifact-binding-conformance` | one signed record of an AI-assisted dependency change (lockfiles, instructions in force, check outputs, approval) and its refusing twins, under the `dependency-selection/v1` profile |
| `vectors-mcp-record-contract/` | `cross-run-record-contract` | what a cross-implementation run record has to carry to mean anything |
| `vectors-mcp-response-phase/` | `mcp-response-phase-interception` | whether a response-phase MCP interceptor is invoked on JSON-RPC error frames, and whether its decision governs what the caller receives |
| `vectors-observed-effect/` | `observed-effect-conformance` | the observed-effect predicate: a mutation interval recorded from a vantage the observed party does not control, with the authority tier recomputed rather than read as a claim |
| `vectors-receipt-signature/` | `receipt-signature-conformance` | signed decision receipts under draft-farley-acta-signed-receipts-03: the signing input, the key's validity window and the Section 6.6 rules, judged against an external key set with and without its windows |
| `vectors-admission/` | `adversarial-execution-evidence-admission` | the admission answer a verifier reports for an Adversarial Execution Evidence statement under a consumer's policy: every pin supplied or declined by name, the subject matched by the digest an observer bound, a fail result refused, and time bounded against an observer-signed instant |
| `vectors-scitt-cose/` | `scitt-cose-carriage-conformance` | carriage of the predicate over SCITT and COSE receipts |
| `vectors-anchored-chain/` | `anchored-record-chain/v1` | signed agent memory records whose head is anchored outside the store: the storage-level edits of draft-khandelwal-bmwg-agent-memory-integrity, including the ones that pass every signature check and fail only against the chain links or the anchor |
| `vectors-receipt-chain-end/` | `receipt-chain-end/v1` | signed agent action receipt chains in the ActionReceipt v1 wire format, judged on whether the chain held is the whole chain: tail cuts, forks, re-rooted rotations and stale heads that keep every signature and link valid, and the close or retained head that proves the end |
| `vectors-trace-anchor/` | `trace-registry-anchor/v1` | the TRACE Level 2 anchor check, Registry Anchor Format v1 with trace-spec#533: a missing or malformed registry entry, a receipt that anchors itself, and receipt fields that lie about the entry, graded against TRACE's own TR-ANC-002 at pinned commits |
| `vectors-grade-floor/` | `evidence-grade-floor/v1` | the E0-E4 evidence ladder of AAIF Observability WG issue #37, with the grade derived by the consumer: a producer-declared grade or integrity boolean never raises it, and an operationally-conformant claim needs E3 and no contradiction |
| `vectors-connector-scope/` | `connector-scope-record/v1` | A health-system connector's scope record: what it can read, what it can change and what it refused, with synthetic PHI-free fixtures, refusing a change under a read grant, an unlisted action that ran, a permitted action refused as out of scope and a refusal with no recorded reason |
| `vectors-agent-payment-mandate/` | `agent-payment-mandate/v1` | An agent-initiated payment judged from its own dispute evidence pack: the mandate the user signed, the credential presented, the charge that ran and the receipt that binds them, refused when the charge leaves the mandate in amount, currency, merchant, time or token or a single-use token is replayed or the post-checkout actions are not all recorded |
| `vectors-agent-change-admission/` | `agent-change-admission/v1` | signed decisions that admit or reject a change to an AI agent's harness, in a bare DSSE carriage and an in-toto Statement carriage: pinned keys, the predicate's required fields, the gate record against the admitted flag, and stored reports against the digests the decision names |
| `vectors-agentic-process-evidence/` | `agentic-process-evidence/v0.1` | signed in-toto Statements carrying the Agentic Process Evidence predicate proposed in in-toto/attestation#609: provider stacks, result, accountable owner, timestamps, session logs, tools and context artifacts, each field rule taken from the predicate's own specification |
| `vectors-delegation-lifecycle/` | `delegation-lifecycle/v1` | signed grants, revocations, disputes and identifier links, each case asking whether a presenter holds delegated authority when the relying party observed it: revocation across a delegation tree, a disputed revocation, re-registration of an agent under a new identifier, recovery after a lost or compromised key, and sub-agents bound to the parent's lifespan |
| `vectors-authority-at-dispatch/` | `authority-at-dispatch/v1` | delegated authority judged at the moment of dispatch: revocation, expiry, stale evidence and scope amplification across hops, including denied records that dispatch exactly the approved bytes |
| `vectors-approval-binding/` | `approval-binding/v1` | an approval presented for a use, refused when it is not bound to that use: a reused approval identifier, a consumed approval, a key that is not the approver's, another user behind the same OAuth client, a different event or phase, a payload changed after approval, a use outside the validity window, a failed policy lookup, and a policy release not served at the decision time |
| `vectors-dispatch-fence/` | `dispatch-fence/v1` | one exclusive dispatch judged from its own record: the fence bound to the sequence number the policy check read, no state change between the two, and a hold with its renewals that covers the effect and the commit with no other proposal admitted meanwhile |
| `vectors-uncertain-effect/` | `uncertain-effect/v1` | one operation whose reply may have been lost: a retry after an unknown outcome, an idempotency key reused with changed arguments, a dispatch beyond the worker's lease, an unknown released at reservation expiry and an outcome reported without the effect owner's answer, each paired with a runtime scenario a counting effect owner plays |
| `vectors-aggregate-accounting/` | `aggregate-accounting/v1` | the decisions an accounting authority took against one budget shared by a principal and its delegation subtrees: concurrent requests admitted inside the budget, racing requests that cannot both be admitted, an unknown-outcome reservation that stays charged past its expiry, a request past the latency bound refused or held, and the principal, subtree, budget, action and counts retained |
| `vectors-agent-card-receipt/` | `agent-card-receipt/v1` | a receipt for an A2A Agent Card judged from the card, the receipt statement, the issuer's signed revocation list and the time of the check: the card digest over RFC 8785 without its signatures, the validity window, a list that is absent, malformed, signed by another key, stale or naming the receipt |
| `vectors-credential-release/` | `credential-release/v1` | a broker's record of a credential released against an agent-card receipt: the receipt's digest, copied fields, subject, result and currency at release, a credential that must not outlive the receipt, a closed credential object with no field for a secret, and the revocation list consulted |
| `vectors-converted-argument-binding/` | `converted-argument-binding/v1` | an approved tool call whose shown, approved, rebuilt and executed arguments must agree under RFC 8785, with the approval naming the shown bytes and the call unchanged after approval; the rule inspect_ai adopted in UKGovernmentBEIS/inspect_ai#5652 |
| `vectors-delegator-right/` | `delegator-right/v1` | a delegated request refused when the delegating principal did not hold the right to pass the operation on: never entitled, entitlement removed at the source, an ancestor grant narrowed, or a scope wider than the delegator's, with a stated propagation limit |
| `vectors-completion-confirmation/` | `completion-confirmation/v1` | a completion claim refused when no confirmation record is bound to the task: none, another task or arguments, the acting agent's own, a reused one, one outside the authorization window, or an unresolved or absent outcome |
| `vectors-chunked-export/` | `chunked-export/v1` | an export gate's decision on each chunk of a chunked export whose every step is reversible on its own: a count or a set-of-chunks reconstruction rule committed before the first chunk, and a seal that must state the composed class rather than the maximum of the per-step labels |
| `vectors-identity-binding/` | `agent-did-identity-binding/v1` | DSSE-signed agent records whose subject is a did:web or did:wba DID, bound to the signing key through resolved DID documents, including rejected records whose signature verifies |
| `vectors-done-contract/` | `done-contract/v2` | sealed contracts for a coding agent's task, valid and invalid, each invalid one under the code of the rule it breaks |
| `vectors-done-receipt/` | `done-receipt/v2` | whole runs of a task in each corner of the receipt's two verdicts and the receipts for them, honest and forged, with a defect for every receipt and record rule |
| `vectors-spoofed-tool-output/` | `spoofed-tool-output/v2` | an agent that prints a passing run and never runs it, or claims done without one, against the observer's record, with the near misses |
| `vectors-test-tampering/` | `test-tampering/v2` | edits of the files an agent is judged by, seen by the observer or lost to it and shown only by the final tree |
| `vectors-grader-isolation/` | `grader-isolation/v2` | a result file or interpreter hook planted where the grader reads it, a mutation of the sealed execution surface or test configuration above the workspace, and a grade run on another tree or contract |
| `vectors-done-probes/` | `done-probes/v1` | the probes a grader runs beside the acceptance commands: an import probe that reads no answer, an in-process twin of the visible test whose pass hides a failure, and detectors over the visible test, each with its honest control |
| `vectors-recorded/` | `recorded-set-conformance/v1` | bytes recorded from live runs, kept byte for byte beside their publisher's `SHA256SUMS`, with synthetic sets one mutation away: a listed file missing or edited, an unlisted file, a list that is malformed, unpinned or names a path outside the set, and a timestamp proof that names other bytes |
| `vectors-a2a-jcs-v01/` | `a2a-agent-card-canonicalization-conformance` | RFC 8785 canonical bytes and the bytes an A2A Agent Card signature covers, vendored byte for byte from a2aproject/a2a-tck at a locked commit and corpus digest |
| `vectors-mcp-owasp/` | `owasp-mcp-verification-draft` | draft MCP verification requirements MCPVS-1 to MCPVS-12 and threats MCPTM-1 to MCPTM-10, minted once in one registry, with one accept and one reject observation per requirement |
| `vectors-open-weight-art53/` | `open-weight-art53/v1` | a model release record against the conditions of AI Act Article 53(2): open licence, public weights, architecture and usage information, no monetisation, no systemic risk |
| `vectors-source-coverage/` | `source-text-coverage/v1` | selected source passages against a consumer-pinned capture, report, and time window |
| `vectors-self-reported-record/` | `self-reported-record-conformance` | a self-reported agent record: turn signatures under the named key, memory-read digests over the bytes at the named path, an attesting key outside the observed runtime's reach, ledgers that name one change set, and covering signatures on declared substrate coverage |
| `vectors-w3c-intake/` | `w3c-intake-v2-conformance` | the W3C public-agent-conformance group's intake criteria for a submitted conformance result, v2 with the accepted v2.1 deltas: every rejection ground bound to its sentence, each with a record that must be refused and one that must be admitted |
| `vectors-w3c-report/` | `w3c-report-v01-conformance` | the W3C public-agent-conformance group's v0.1 per-check report: five states, the cause vocabulary, fourteen rejection rows and roll-up claims (including a declared no-void claim), as whole reports |
| `vectors-refund-connected/` | `refund-connected/v1` | retained runs of a connected refund pilot judged offline from their bytes: inputs, trust files, admission state, signed handoffs and resolutions, the executor streams and the payment simulator record, refused when any link between them breaks |

The distribution gate checks the directory and suite names against the tracked manifests. Read vector counts and digests from those manifests or [release/CORPUS-DIGESTS.txt](release/CORPUS-DIGESTS.txt). The [corpus guide](docs/guides/corpora.md) describes the formats and packaged readers.

## Adding a corpus of your own

Add a sibling `vectors-<name>/` directory using the [corpus pull-request template](.github/PULL_REQUEST_TEMPLATE/vectors-directory.md). Include a manifest, reproducible generator, specification pin and a digest routine that works without third-party packages. Register it in the count gate and release digest list. See [maintenance](docs/reference/maintenance.md) for the checks.

## Reporting a run

Use the [run form](.github/ISSUE_TEMPLATE/independent-run.yml) and retain the full report.

## Archive and identifiers

| Surface | Identifier |
| --- | --- |
| Source and Go module | `github.com/probityai/agent-evidence-vectors` |
| Go verifier | `cmd/aee-verify` |
| Python package | [agent-evidence-vectors](https://pypi.org/project/agent-evidence-vectors/) |
| Releases | [GitHub releases](https://github.com/probityai/agent-evidence-vectors/releases) |
| Signed digests | [release/CORPUS-DIGESTS.txt](release/CORPUS-DIGESTS.txt) |
| Archive | [Zenodo concept DOI](https://doi.org/10.5281/zenodo.22758687), with release-specific identifiers on the archive record |
| Dataset | [Hugging Face](https://huggingface.co/datasets/probityai/agent-evidence-vectors), one revision tag per release, built by [the publish workflow](.github/workflows/publish-hf-dataset.yml) |
