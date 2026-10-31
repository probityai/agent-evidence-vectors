# AIMM levels as vector runs

<!-- pins: vectors=v0.17.5 admission=53913a9007aa3d582378a924ab5fc2fe6f662fc1 -->

This page maps each pillar and level of the OWASP Agent Identity Maturity Model (AIMM) to the
conformance vector families and admission policies that test it. A level is met when the
organization's verifier returns the expected verdict on every vector in the families listed at that
level and at every level below it in the same pillar, at the pinned release:

```sh
pip install agent-evidence-vectors==0.20.0
agent-evidence-vectors --corpus vectors-anchored-chain
```

Pinned: `agent-evidence-vectors` 0.17.5 (tag `v0.17.5` of
[probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors)), and
[probityai/agent-evidence/packages/admission](https://github.com/probityai/agent-evidence/tree/main/packages/admission) at commit
`53913a9007aa3d582378a924ab5fc2fe6f662fc1`. `python3 scripts/check_aimm_levels.py` checks that every
family, case and policy named below exists at those pins.

A cell reading "assessed from records" has no vector family yet: the assessor reads the
organization's inventory and policy as the AIMM section describes.

## Pillar 1: Identity and attestation

| Level | Vector families and cases | Admission policies |
|---|---|---|
| L1 | assessed from records | none |
| L2 | assessed from records | none |
| L3 | `vectors-artifact-binding` | none |
| L4 | `vectors-scitt-cose` | none |
| L5 | `vectors`, `vectors-receipt-signature` | `kyverno/clusterpolicy-adversarial-execution-evidence.yaml` |

## Pillar 2: Authorization and scoped delegation

| Level | Vector families and cases | Admission policies |
|---|---|---|
| L1 | assessed from records | none |
| L2 | assessed from records | none |
| L3 | `vectors-acs-core`, `vectors-mcp-response-phase` | none |
| L4 | `vectors-aci` | none |
| L5 | `vectors-receipt-signature` | `kyverno/clusterpolicy-adversarial-execution-evidence.yaml` |

## Pillar 3: Traceability, intent and provenance

| Level | Vector families and cases | Admission policies |
|---|---|---|
| L1 | `vectors-self-reported-record` | none |
| L2 | `vectors-agent-audit-record`, `vectors-ai-agent-action` | none |
| L3 | `vectors-mcp-record-contract` | none |
| L4 | `vectors-observed-effect`, `vectors-source-coverage` | `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml` |
| L5 | `vectors`, `vectors-scitt-cose`, `vectors-anchor-stream`, `vectors-anchored-chain`, `vectors-anchored-chain/cases/t2-tail-removal`, `vectors-anchored-chain/cases/t7-rollback-older-record` | `kyverno/clusterpolicy-adversarial-execution-evidence-freshness.yaml` |

At Pillar 3 L1 the self-reported family shows the limit 6.1 states: a record the agent writes about
itself is refusable on its face. The two named L5 cases are the 6.1 L5 truncation of records written
before the last anchor and the restored older record. Every signature in both still verifies, so only
the anchored chain catches them.

## Pillar 4: Operational readiness

| Level | Vector families and cases | Admission policies |
|---|---|---|
| L1 | assessed from records | none |
| L2 | assessed from records | none |
| L3 | `vectors-w3c-report` | none |
| L4 | `vectors-mcp-response-phase` | `policy-controller/clusterimagepolicy-adversarial-execution-evidence.yaml` |
| L5 | `vectors` | `policy-controller/clusterimagepolicy-adversarial-execution-evidence-soundness.yaml` |

## Run it in CI

An assessor or an organization runs the same check on every push with the Action at the pinned tag:

```yaml
- uses: probityai/agent-evidence-vectors@v0.17.5
  with:
    verifier: ./your-verifier -json
    corpus: vectors
```

Set `corpus` to each family the target level lists. The job fails when the verifier answers fewer
vectors than the family holds or returns an unexpected verdict.
