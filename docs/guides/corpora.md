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
| Selected source passages in a report | [vectors-source-coverage](../../vectors-source-coverage/README.md) | Consumer-pinned source capture and time window; named verifier required |
| Signed memory records anchored outside the store | [vectors-anchored-chain](../../vectors-anchored-chain/README.md) | Storage-level edits of draft-khandelwal-bmwg-agent-memory-integrity; packaged reader or named verifier |
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

## Specification pins

[VENDOR-PIN.json](../../spec/VENDOR-PIN.json) records the vendored specification commit. Re-vendoring moves the bytes and remaps references together.

[spec-drift-gate.py](../../scripts/spec-drift-gate.py) checks `spec:<anchor-id>@<digest>` citations; [spec-anchor-gate.py](../../scripts/spec-anchor-gate.py) checks `Lnnn` vector-table anchors. [CITATION-ANCHORS.json](../../spec/CITATION-ANCHORS.json) and [ANCHOR-PINS.json](../../spec/ANCHOR-PINS.json) bind each citation to its intended prose, using [specpins.py](../../scripts/specpins.py).

A refresh fails if a remap loses text that the upstream document still contains, including a shortened range. A deliberate move to different prose requires a named, per-citation update.
