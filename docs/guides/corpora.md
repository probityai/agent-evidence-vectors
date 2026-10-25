# Choose a corpus

This suite tests two in-toto predicates:
**Adversarial Execution Evidence**, predicate version 0.7, and **AI Agent
Action**, predicate version 0.1, proposed in
[in-toto/attestation#588](https://github.com/in-toto/attestation/pull/588).
Each has its own corpus, `vectors/` and `vectors-ai-agent-action/`.

Choose the record format you need, then follow its [reader route](../reference/corpus-readers.md). `--list-corpora` shows the directories available in an installed Python release; a checkout can contain additional corpora.

| Record or task | Corpus | Contract |
| --- | --- | --- |
| Adversarial execution evidence | [vectors](../../vectors/) | AEE v0.7 statement validity, result and consumer-relative tiers |
| Agent action | [vectors-ai-agent-action](../../vectors-ai-agent-action/) | AI Agent Action v0.1 proposal and declared profiles |
| SCITT/COSE carriage | [vectors-scitt-cose](../../vectors-scitt-cose/) | [SCITT/COSE profile](../../profiles/scitt-cose.md), COSE_Sign1 and RFC 9942 receipts |
| Bind an evaluation to saved inputs | [vectors-artifact-binding](../../vectors-artifact-binding/) | [Artifact-binding v1](../../spec/artifact-binding/v1.md) |
| Record an AI-assisted dependency change | [vectors-dependency-selection](../../vectors-dependency-selection/) | [Artifact-binding v1, section 6.2](../../spec/artifact-binding/v1.md) |
| Selected source passages in a report | [vectors-source-coverage](../../vectors-source-coverage/README.md) | Consumer-pinned source capture and time window; named verifier required |
| Evidence grade derived by the consumer, E0-E4 | [vectors-grade-floor](../../vectors-grade-floor/README.md) | Ladder of AAIF Observability WG issue #37; packaged reader or named verifier |
| The admission answer for an AEE statement under a consumer policy | [vectors-admission](../../vectors-admission/README.md) | AEE consumer obligations and the statement-layer subject rule; packaged reader or named verifier through `AEE_CONSUMER_POLICY` |
| Signed admission of a change to an agent's harness | [vectors-agent-change-admission](../../vectors-agent-change-admission/README.md) | Agent change admission predicate, version 1; packaged reader or named verifier |
| Signed provenance of an agentic process | [vectors-agentic-process-evidence](../../vectors-agentic-process-evidence/README.md) | Agentic Process Evidence predicate v0.1 (in-toto/attestation#609); packaged reader or named verifier |
| SCITT-wave agent record drafts | [vectors-ietf-agent-record-drafts](../../vectors-ietf-agent-record-drafts/README.md) | the AIR hash chain of draft-emirdag-scitt-ai-agent-execution-01, checkpoint registration in draft-mih-scitt-checkpointed-local-log-02, statement identification in draft-gruszka-scitt-statement-identification-02 |
| Delegated authority after a revocation, a dispute, a re-registration, a key recovery or a parent agent's end | [vectors-delegation-lifecycle](../../vectors-delegation-lifecycle/README.md) | Revocation across a delegation tree and identifier links; `aee-verify` |
| Delegated authority at the moment of dispatch | [vectors-authority-at-dispatch](../../vectors-authority-at-dispatch/README.md) | Authority-at-dispatch contract of agent-evidence-observer: evidence age, revocation, grant window, scope across hops and the approved bytes; packaged reader or named verifier |
| An approval bound to the exact use it covers | [vectors-approval-binding](../../vectors-approval-binding/README.md) | Approval identifier, consumption, signing key, user principal, event and phase, payload, validity window and the policy release served at decision time; packaged reader or named verifier |
| A chunked export that becomes irreversible as a whole | [vectors-chunked-export](../../vectors-chunked-export/README.md) | Composition-aware export gate: count and set reconstruction rules, pre-committed, and the seal's composed class; packaged reader or named verifier |
| Agent records bound to a did:web or did:wba subject | [vectors-identity-binding](../../vectors-identity-binding/README.md) | DSSE over DID-subject records, with resolved DID documents and the did:wba `e1_` binding; packaged reader or named verifier |
| Whether a coding agent finished its task | [vectors-done-receipt](../../vectors-done-receipt/README.md) | Done Receipt predicate v2: two verdicts, the outcome of the work and the integrity of the run, derived from observation v3 records of protected paths, acceptance run by a separate verifier, probes and claimed tool runs, with [vectors-done-contract](../../vectors-done-contract/README.md); packaged reader, replayed through probity-verify in CI |
| An agent fabricating tool output | [vectors-spoofed-tool-output](../../vectors-spoofed-tool-output/README.md) | `tool_claim_match/v1` against an observer's record; packaged reader |
| An agent editing what it is judged by | [vectors-test-tampering](../../vectors-test-tampering/README.md) | `protected_paths/v1`, events and final tree; packaged reader |
| A grader's probes, in-process twin and detectors | [vectors-done-probes](../../vectors-done-probes/README.md) | `probe_observed/v1`: the import probe that reads no answer, the in-process twin of the visible test and detector findings, with honest divergences; packaged reader |
| An agent reaching its grader | [vectors-grader-isolation](../../vectors-grader-isolation/README.md) | Planted result files and interpreter hooks recorded as observation v3 mutations outside the workspace, and grades bound to the wrong tree or contract; packaged reader |
| Hash of an agent's tool-call arguments | [vectors-agent-decision](../../vectors-agent-decision/README.md) | `args_hash` and `args_state` of the agent-decision v0.1 predicate proposed in in-toto/attestation#554; `aee-verify` |
| Signed memory records anchored outside the store | [vectors-anchored-chain](../../vectors-anchored-chain/README.md) | Storage-level edits of draft-khandelwal-bmwg-agent-memory-integrity; packaged reader or named verifier |
| Whether a signed receipt chain is the whole chain | [vectors-receipt-chain-end](../../vectors-receipt-chain-end/README.md) | ActionReceipt v1 chains with session close, rotation endorsement and retained heads; packaged reader or named verifier |
| TRACE Level 2 registry anchors | [vectors-trace-anchor](../../vectors-trace-anchor/README.md) | Registry Anchor Format v1 with trace-spec#533: entry binding, self-anchored receipts, lying receipt fields; packaged reader or named verifier |
| A2A Agent Card canonicalization | [vectors-a2a-jcs-v01](../../vectors-a2a-jcs-v01/README.md) | RFC 8785 bytes and the signing input of a card, vendored from a2a-tck; packaged reader or named verifier |
| Draft MCP verification requirements and threats | [vectors-mcp-owasp](../../vectors-mcp-owasp/INDEX.md) | MCPVS-1 to MCPVS-12 and MCPTM-1 to MCPTM-10, one registry; packaged reader or `aee-verify` |
| Per-check conformance reports | [vectors-w3c-report](../../vectors-w3c-report/) | W3C public-agent-conformance v0.1 |
| Signed decision receipts | [vectors-receipt-signature](../../vectors-receipt-signature/) | `draft-farley-acta-signed-receipts-03` |

## Specification and profile scope

| Corpus | Scope to retain with the result |
| --- | --- |
| AI Agent Action | Pinned #588 text at `a5dd509`. Each reject entry cites vendored lines and a checked quotation. `aia-c-15` uses this project's proposed BMP-only canonicalization rule and also cites the proposal's contrary reading. A verifier implementing #588 alone may accept that case. Deployment-dependent `chain_break` with `priorHead: null` names its selected profile. |
| SCITT/COSE | Six accept, 17 reject and four indeterminate cases. The indeterminate entries retain questions left open by RFC 9943 and RFC 9942 and the permitted readings. Use its own checker; the Go binary has no CBOR/COSE reader. |
| Artifact binding | `verified`, `failed` or `not-established`. The last outcome means required material was not captured. Evaluation verdicts have their own contract; AEE carries execution observations. [tools/artifact-binding](../../tools/artifact-binding/) produces and checks records; [demo/four-arms.sh](../../demo/four-arms.sh) runs the examples. |
| Source coverage | Six synthetic cases at the source pin. A supplied verifier checks selected passages under the consumer's capture and time window. |
| W3C reports | Frozen rejection table, two additions of 18 September, settled thread rules, 42 delta-related pairs recut against v0.1, plus Run and discovery-snapshot subjects from `draft-arsentev-agent-run-metrics-00` and `draft-arsentev-llm-context-discovery-00`. Vendored texts and condition citations are digest-pinned. |
| Receipt signatures | Canonical signing input, an external key set, its validity windows and three further Section 6.6 rules. Every member is checked with and without key windows; the draft's SHOULD is graded as the corpus README specifies. |

The W3C Go and Python readers are checked by [w3c-rails-parity-test.py](../../scripts/w3c-rails-parity-test.py). Its Python module also emits a v0.1 report with `--emit-w3c-report`; the [conformance appendix](../W3C-V01-CONFORMANCE-APPENDIX.md) is generated from the manifest. Receipt readers are checked by [receipt-signature-rails-test.py](../../scripts/receipt-signature-rails-test.py).

## Version axes

| Identifier | Changes when |
| --- | --- |
| Predicate version | That specification changes |
| Repository release | A package or corpus release ships |
| Suite revision | That corpus's declared population or expectations change |

The predicate versions are derived from their manifest `predicateType` values and checked by [count-gate.py](../../scripts/count-gate.py). Release v0.8.0 added the second corpus while retaining AEE predicate v0.7. Consumers recompute the AEE outcome from carried bytes.

## Optional interoperability cases

These have their own inputs and policies.

| Example | Check and retained scope |
| --- | --- |
| [WS4 prior-witness candidate](../../interop/ws4-prior-witness-candidate/README.md) | Provenance fixtures for the proposed Section 7.4 integration, using an author-held key and consumer-stipulated pins. Fixture execution supplies neither outside witness custody nor WS4 conformance. |
| [Framed action tuple](../../interop/action-tuple-framed-v1/README.md) | Separate unsigned profile with explicit UTF-8 byte lengths and a versioned domain. |
| [A2A retained-field gate](../../interop/a2a-s3-retain-2026-10-01/README.md) | Thirteen source-pinned signature cases. Accepts signer-side dual signing; rejects verifier fallback that leaves an altered legacy URL unsigned. Its consumer policy is separate from A2A's canonicalization ruling. |
| [JEP Core 0.7 reader](../../interop/jep-core07-reader/README.md) | Runs the pinned JEP fixtures without importing JEP's validator, adapter or runner, under a protocol committed before execution. Reports the validation, producer and acceptance assertions separately. |
| [REMORA E7 reader](../../packaging/agent_evidence_vectors/remora_e7/README.md) | Checks the native `runtime-surface-e7-v0.1` fixtures against the producer-pinned package digest and computes each result without reading the case's expected answer. |
| [Invocation three-axis reader](../../packaging/agent_evidence_vectors/invocation_axes/README.md) | Pins one MCP `tools/call` and judges a decision capture package and an execution bundle bound to it on three separate axes: package integrity, request and decision correspondence, and observed effect. Capture authenticity, coverage and kernel-to-tool attribution stay not established. |
| [Resumed-task reader](../../packaging/agent_evidence_vectors/resume_turns/README.md) | Judges one paused and resumed agent task on turn ownership, artifact replay and repeated effects as separate claims, so a replayed artifact is never read as a second effect and a deduplicated display never hides one. |
| [Occurrence-binding reader](../../packaging/agent_evidence_vectors/occurrence_binding/README.md) | Freezes one paid request occurrence and judges the issuer budget statement, payment receipt and execution receipt each natively under frozen trust inputs, then the spend and occurrence links separately. Two controls: a mismatched occurrence and the same call content from a different execution. Also judges whether the run used the pinned input and dataset, and settles a lost call as not run only on the responder's signed statement naming that occurrence. |
| [Evaluation claim record](../../packaging/agent_evidence_vectors/claim_record/README.md) | One envelope for an evaluation claim in which applicability, population, vantage, bytes, epoch and settlement are each present as a value or as not applicable under a reason the profile pinned by the relying party's acceptance rule authorises. Refuses a case nobody ran read as a pass, a weaker profile chosen by the producer, a reference a profile requires by digest given by tag, and an unresolved action spanning an authority transition. Every negative is admitted once its repair is applied. |
| [ACS outage posture reader](../../packaging/agent_evidence_vectors/acs_outage/README.md) | Judges ACS host steps taken while the Guardian is unreachable: cached `deny` and `proceed` postures, the startup default for a session that never negotiated, and the audit record and its OTLP export. Four cases are recorded replay steps; fifteen change one thing each. Real-agent behaviour and conformance stay not established. |
| [ACS verdict evidence controls](../../packaging/agent_evidence_vectors/verdict_evidence/README.md) | Signed ACS conformance verdict and quarantine records under the draft verdict evidence predicate. A `witness_scope` above `SELF` counts only through a peer-signed [peer verification](../../spec/predicates/peer-verification.md) statement that names the vector, the requirement and the client run or retained transcript; a quarantine record binds its fields, including its expiry outcome, and reads `quarantine_overdue` after `review_by`. Whether the runner observed what it reports stays not established. |
| [Declared-constant operand provenance](../../packaging/agent_evidence_vectors/operand_provenance/README.md) | A declared constant grounds an operand only when the executed derivation read it at the declared value, from erratum E3 in zorrzai/ap1-run. Each derivation carries its declared constants and, separately, the constants its computation read; unrecorded reads stay not established. Whether the computation layer recorded its reads truthfully stays not established. |

## Specification pins

[VENDOR-PIN.json](../../spec/VENDOR-PIN.json) records the vendored specification commit. Re-vendoring moves the bytes and remaps references together.

[spec-drift-gate.py](../../scripts/spec-drift-gate.py) checks `spec:<anchor-id>@<digest>` citations; [spec-anchor-gate.py](../../scripts/spec-anchor-gate.py) checks `Lnnn` vector-table anchors. [CITATION-ANCHORS.json](../../spec/CITATION-ANCHORS.json) and [ANCHOR-PINS.json](../../spec/ANCHOR-PINS.json) bind each citation to its intended prose, using [specpins.py](../../scripts/specpins.py).

A refresh fails if a remap loses text that the upstream document still contains, including a shortened range. A deliberate move to different prose requires a named, per-citation update.
