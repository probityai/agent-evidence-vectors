# Approval-binding v2 vectors

Cases for `approval-binding/v2`: is this execution bound to a quorum of authenticated approvals of exactly these bytes, from approvers who are not the proposer, consumed before dispatch, with the outcome recorded honestly? Each case is one record with four parties: the proposer whose model proposed the call, the approvers who decided on the bytes they were shown, the authority that consumes approvals and dispatches, and a witness log kept apart from the authority. A verifier that finds the approval by the call identifier and reads it as a yes allows the swapped-argument resume, the resent resume, the protocol-native argument override and the validator rewrite here. One that binds a single approval to its bytes allows every quorum, proposer and delegation case.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

`approval-binding/v1` judges one approval against one use: its identifier, issuer, key, principal, event, payload, validity and renewal. This version judges what v1 cannot express: several approvers and a quorum, the authenticated principal against the one the request body names, add-only delegation, separation of duties, vetoes, the approval window, the transforms between what the approvers saw and what ran, the model response the call came from, who consumed the approvals and when the witness saw it, and the approval status after the effect.

## What the record carries

- `proposal`: the call identifier, tool, the arguments shown to the approvers, the model response that proposed the call and its digest, the proposer and the time of the proposal.
- `policy`: the quorum, the approvers and their keys, add-only delegations, the approval window in seconds, whether a reject vetoes, conflicting pairs, and the authority's key.
- `approvals`: every decision received. Each names the principal the request body claims and, apart from it, the principal the authentication context established, which is absent when there was none.
- `execution`: the executed arguments, every transform between display and dispatch (`override_args`, `editedArgs`, `after_tool_validate`, `none`) with its before and after digests, the approvals relied on, who consumed them and when, when the call was dispatched, the outcome and the approval status.
- `ledger`: the authority's consumption ledger as read before this execution. An empty list was read and held nothing. An absent member was never read, and is refused.
- `witness`: the witness log. A consumption is witnessed by an entry of kind `approval` whose digest is the digest of `{approvalId, consumedAt, consumedBy, executionId}`.

A digest is `sha256:` and the lowercase hex SHA-256 of the object's JCS bytes. A verifier recomputes every digest it relies on: the digests in the record are claims to check.

An approval counts for a seat. An approver the policy names holds one; a principal a valid delegation adds stands in for the seat of the approver who issued the delegation. Two approvals for one seat count once, so an approver cannot reach the quorum by delegating to an alias.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the approval-binding v2 contract | `contract_id_unknown` |
| the fields and types the contract names are present, every time is a `Z` instant, every number an integer, the witness sequence gapless, and every relied approval presented | `malformed_record` |
| the consumption ledger was read | `consumption_not_checked` |
| every delegation only adds: it removes nobody, lowers no quorum and is issued by an approver | `approver_delegation_widened` |
| each relied approval names this proposal, call and tool, the execution runs them, and the model response holds the call | `approval_not_for_call` |
| each relied approval has an authenticated principal | `approver_unauthenticated` |
| the body's claimed approver is the authenticated principal | `approver_claim_mismatch` |
| the approval's key is the key the policy binds to that principal | `approver_key_not_bound` |
| the principal is an approver or was added by a valid delegation | `approver_ineligible` |
| no relied approval's seat is the proposer's | `approver_is_proposer` |
| no seat is counted twice | `approver_counted_twice` |
| no two counted seats are a conflicting pair | `approvers_conflicted` |
| every relied decision is `approve` | `approval_not_granted` |
| when rejects veto, no authenticated eligible reject was issued at or before consumption | `approval_vetoed` |
| the relied approvals reach the quorum, the larger of the policy's and any delegation's | `quorum_not_met` |
| each relied approval covers the digest of the arguments shown | `approval_not_for_bytes` |
| the executed arguments have the approved digest, whatever changed them | `args_changed_after_approval` |
| the transforms chain from the shown digest to the executed digest, and `none` changes nothing | `transforms_unaccounted` |
| the proposal, every relied approval and the execution carry the digest of the model response | `history_digest_mismatch` |
| the call was dispatched before every relied approval expired | `approval_expired` |
| no relied approval was issued after it was consumed | `approval_postdates_consumption` |
| the quorum was reached before the approval window closed | `timeout_not_fail_closed` |
| no relied approval is in the ledger | `approval_replayed` |
| the call is not in the ledger | `call_already_executed` |
| the authority consumed the approvals | `consumption_not_by_authority` |
| the witness holds each relied approval's consumption | `consumption_not_witnessed` |
| the approvals were consumed, and the witness saw it, at or before dispatch | `consumed_after_dispatch` |
| the status follows the outcome: `applied` spends, `failed` returns, `uncertain` holds | `outcome_misrecorded` |

A record that passes every check is `allow` with reason `quorum_bound`. Each limit has a case on both sides: dispatch one second before expiry and at it, the quorum one second before the window closes and at it, a reject at the instant of consumption and one second after, consumption at the dispatch instant and one second after it.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-approval-binding-v2
```

To judge your own verifier, run it as `<verifier> <case-dir>/record.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`.

## Controls

The expected decision and reason for every case are in `MANIFEST.json`. The allowed cases cover each legitimate shape: one of one, two of three, a quorum reached through a delegated approver, a recorded identity transform, a replaced-and-restored argument set, a failed effect with its approvals returned, an uncertain effect with its approvals held, a late reject, a reject under a no-veto policy, unauthenticated decisions that are neither counted nor a veto, and a raised quorum that is met. Every denied case departs from a conformant record in one place, except the attacks that change two things at once, which `tests/test_corpus.py` names with the second check each reaches. Each check is forced by at least one case. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. The tests regenerate the corpus byte for byte from `gen_vectors.py`.
