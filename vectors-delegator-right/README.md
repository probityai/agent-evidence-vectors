# Delegator-right vectors

Cases for `delegator-right/v1`: does a delegated request stay inside the rights its delegators held? Each case is one record: the grant chain behind the request, the entitlements to delegate that the authoritative source holds, the scope removals that took effect at that source, and the propagation limit within which a change at the source must reach enforcement. A verifier that checks the chain's signatures, expiry and narrowing alone allows every denied case here.

The cases follow the wording proposed for OWASP AIT Pillar 2, section 5.1, level L4 (Tymofii Pidlisnyi, OWASP Slack, 2026-10-22):

> At execution, the enforcement point checks the derived grant against its ancestor grants and the delegating principal's authority to delegate the requested operation. Revocation or narrowing of an ancestor grant, or loss of the principal's authority to delegate that operation, shall prevent use of the affected scope within the defined propagation limit.

> Test each change separately. First, remove operation X from the parent grant without revoking the child. In a separate test, remove the principal's authority to delegate X. For each test, record when the change takes effect at its authoritative source. Submit the child's request for X at the propagation deadline and record the enforcement time. The request is denied in both cases. An otherwise valid request for an operation that remains in scope is authorized.

| Test in the proposal | Case |
| --- | --- |
| Remove X from the parent grant, child not revoked, request at the deadline: denied | `ancestor-scope-removed-at-deadline` (`ancestor_scope_removed`) |
| Remove the principal's authority to delegate X, request at the deadline: denied | `entitlement-removed-at-deadline` (`delegation_right_removed`) |
| An otherwise valid request for an operation that remains in scope: authorized | `allow-ancestor-narrowed-other-operation` (`entitled`) |

A removal still inside the propagation limit is allowed (`allow-ancestor-narrowed-within-limit`).

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the delegator-right contract | `contract_id_unknown` |
| the record has the fields and types the contract names, and every time parses | `malformed_record` |
| the requested operation is in the last grant's scope, and each grant's scope is inside the one before it | `delegate_exceeds_delegator` |
| every grantor that is not a trusted root held an entitlement to delegate the requested operation when it issued its grant | `delegator_not_entitled` |
| no such entitlement ended at least `propagationLimitSeconds` before the decision | `delegation_right_removed` |
| no grant on the chain had the requested operation removed at the source at least `propagationLimitSeconds` before the decision | `ancestor_scope_removed` |

A record that passes every check is `allow` with reason `entitled`. A request made before `effective + limit` may still use cached state, and a request made at or after it must be refused.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-delegator-right
```

To judge your own verifier, run it as `<verifier> <case-dir>/record.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`.

## Controls

Every denied case departs from a conformant record in one place, and each check is forced by at least one case: switching it off changes a verdict. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. `tests/test_corpus.py` holds each of these as a test, and regenerates the corpus byte for byte from `gen_vectors.py`.
