# One paid request occurrence, native verdicts and cross-artifact links

This corpus freezes one request occurrence: an MCP `tools/call`, its occurrence
nonce, the payer agent and the responder. A paid call leaves three signed
artifacts about it, and each one gets its own native verdict from its own bytes
and the frozen trust inputs alone:

| Axis | ESTABLISHED means |
| --- | --- |
| `budget_statement` | The spending limit is signed by a key the trust inputs name for the issuer. An agent's own statement of its limit is not the issuer's. |
| `payment_receipt` | The payment receipt is signed by a key the trust inputs name for the payment rail. |
| `execution_receipt` | The execution receipt is signed by a key the trust inputs name for the responder. |

Two claims join artifacts. They are reported apart from the native verdicts, so
neither stands in for the other:

| Axis | ESTABLISHED means | It does not mean |
| --- | --- | --- |
| `spend_within_budget` | The payment names this budget statement, the currency matches, and the issuer's remaining limit covers the amount. Not established unless both the budget and the payment verdicts are. | That the money settled. |
| `occurrence_link` | The payment receipt and the execution receipt both commit to the frozen occurrence, and the execution names its call. Judged from the committed values only, never from the signatures. | That either receipt is genuine: read the native verdicts for that. |

Matching call content alone does not establish that two records describe the
same execution. A receipt that commits only to the call content leaves the link
`NOT_ESTABLISHED`; one that names a second run of the same call contradicts it.

Three properties are `NOT_ESTABLISHED` in every case, whatever an artifact says
about itself: `settlement_finality`, `work_acceptance` (whether the result met
criteria fixed before the call) and `observed_effect` (the
[invocation three-axis corpus](../invocation_axes/README.md) judges that one).

## The frozen inputs

| File | Holds |
| --- | --- |
| `corpus/occurrence.json` | The request occurrence, its price, the trust input file and the verifier command. |
| `corpus/trust.json` | The trust inputs: each key and the role it is trusted for. TEST keys from the published recipe `sha256("aev-occurrence-binding-test-key/<role>/v1")`. |
| `corpus/cases.json` | Each case's issuer budget statement, payment receipt and execution receipt, and its expected answer per axis. |
| `corpus/manifest.json` | The sha256 of every other member. The runner refuses a corpus whose members differ. |

The occurrence binding is `sha256` over the RFC 8785 bytes of
`{"call_binding", "occurrence_nonce", "payer_agent", "responder"}`, where
`call_binding` is the invocation three-axis corpus's binding of the call (method
and params, never the JSON-RPC id). A signature is Ed25519 over the RFC 8785
bytes of the statement.

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors-occurrence-binding --output occurrence-binding-result
```

The command checks every corpus member against `corpus/manifest.json`, judges
all cases without reading their expected answers, writes `report.json`, and
exits 1 if any case differs. From a checkout, run
`python -m agent_evidence_vectors.occurrence_binding.run` inside `packaging/` with
`--implementation-revision "$(git rev-parse HEAD)"`.

## Cases

Built by `scripts/occurrence-binding-build.py`; CI checks that the committed
files are what it writes. Every axis has `ESTABLISHED`, `CONTRADICTED` and
`NOT_ESTABLISHED` cases.

- Controls: `mismatched_occurrence` (every artifact natively valid, the
  execution receipt is for another call's occurrence) and
  `same_content_different_execution` (same call content, a second run).
- Link: `intact_occurrence`, `execution_names_call_content_only`,
  `payment_names_no_occurrence`, `payment_moved_to_other_occurrence`.
- Budget: `budget_signed_by_agent`, `budget_signature_broken`,
  `budget_signed_by_untrusted_key`.
- Spend: `payment_exceeds_issuer_limit`, `payment_names_other_budget`.
- Payment: `payment_signed_by_untrusted_key`,
  `payment_signature_broken_link_intact`.
- Execution: `execution_signature_broken_link_intact`,
  `execution_signed_by_issuer_key`, `no_execution_receipt`.

A producer can test its own records by mapping its budget, payment and execution
artifacts onto the three statement shapes and its keys onto `trust.json`. A
case where a broken signature sits beside an established link is deliberate:
the native verdict and the link are separate claims.
