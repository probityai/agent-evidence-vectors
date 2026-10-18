# One MCP invocation, three separate claims

This corpus pins one MCP `tools/call` and judges two kinds of evidence about it:
a decision capture package (what a proxy saw and decided) and an execution
bundle (what ran and what an independent reader saw afterwards). Both are bound
to the same invocation bytes. The reader keeps three claims apart, and each
claim has its own expected answer in every case. An answer is `ESTABLISHED`
(the evidence supports the claim), `CONTRADICTED` (the evidence shows the claim
is false) or `NOT_ESTABLISHED` (the evidence cannot decide it).

| Axis | ESTABLISHED means | It does not mean |
| --- | --- | --- |
| `package_integrity` | The manifest matches the digest pinned beforehand, and every retained member has the bytes the manifest names. No member is missing or unlisted. | That the bytes were captured from a real session, or that the capture was complete. |
| `request_decision_correspondence` | The captured request is the pinned invocation, and the captured decision is bound to that invocation. Member order and the JSON-RPC id are not changes. Array order, scalar kind, tool name and argument values are. | That the decision was correct, or that every path to the tool passed the decision point. |
| `observed_effect` | A bundle bound to the same invocation shows a dispatch, and a reader other than the tool observed the declared delta with strict scalar kinds. A dispatch after a bound deny is a contradiction. | That the observed object is the only effect, or that the reader is independent of the host. |

Three properties are `NOT_ESTABLISHED` in every case, whatever a package says
about itself: `capture_authenticity` (no capture attestation is checked),
`capture_coverage` and `kernel_to_tool_attribution`. The case
`package_claims_complete_coverage` carries a member that asserts both, and they
stay unestablished.

## Binding

`invocation_binding` is `sha256` over the RFC 8785 bytes of
`{"method": ..., "params": ...}` from the request. The JSON-RPC `id` and
`jsonrpc` tag are transport framing, so a proxy and an executor can see different
ids for one call. The capture's `decision.json` and the bundle's `call_binding`
must both carry this value.

The execution bundle follows the state rules of REMORA's `effect-evidence-v1`
contract: `NOT_DISPATCHED`, `DISPATCHED`, a reported success, and a verified
effect stay distinct. A reported success is never promoted without an
independent observation. `dispatch.outcome` uses that contract's values:
`DISPATCHED`, `BEGAN_OUTCOME_UNKNOWN` (dispatch began) and `REFUSED` (dispatch
never began). Any other value leaves `observed_effect` unestablished.

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors-invocation-axes --output invocation-axes-result
```

The command checks every corpus member against `corpus/manifest.json`, judges
all cases without reading their expected answers, writes `report.json`, and
exits 1 if any case differs. From a checkout, run
`python -m agent_evidence_vectors.invocation_axes.run` inside `packaging/` with
`--implementation-revision "$(git rev-parse HEAD)"`.

## Cases

The corpus is built by `scripts/invocation-axes-build.py`; CI checks that the
committed files are what it writes. Each axis has `ESTABLISHED`,
`CONTRADICTED` and `NOT_ESTABLISHED` cases:

- Package integrity: `intact_pair`, `one_byte_changed_in_member`,
  `manifest_rewritten_to_cover_change`, `member_missing`,
  `unlisted_member_added`, `unpinned_self_consistent`,
  `package_claims_complete_coverage`.
- Request and decision: `argument_members_reordered`,
  `argument_value_changed`, `array_order_changed`, `tool_name_changed`,
  `decision_bound_to_other_request`, `decision_absent`,
  `deny_and_not_dispatched`.
- Observed effect: `bundle_for_other_call`, `dispatched_after_deny`,
  `observation_contradicts_delta`, `bool_is_not_integer`,
  `success_reported_without_dispatch`, `observation_absent`,
  `observation_from_the_tool`, `vacuous_postcondition`, `no_execution_bundle`.

A producer can test its own format against these answers by mapping its capture
and execution records onto the two input shapes. A case where a broken package
still yields an established effect is deliberate: the axes are separate claims.
