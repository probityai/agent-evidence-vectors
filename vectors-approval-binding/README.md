# Approval-binding vectors

Cases for `approval-binding/v1`: a record of one approval presented for one
use, the payload bytes of the use, and the decision a verifier must reach. The
expected decision and reason for every case are in `MANIFEST.json`.

An approval can be well formed, correctly signed and unexpired and still be the
wrong approval for the use in front of the verifier. Every denied case here
changes exactly one binding of an otherwise conformant record, so a verifier
that checks only the approval's own signature, payload digest and expiry allows
most of them. The corpus tests show which ones.

## The binding axes and where they come from

Each axis is a defect class that public projects fixed or discussed in their
own trackers in October 2026. The cases are written from the class, not copied
from any project.

| Axis | Case that refuses it | Public fix or proposal |
| --- | --- | --- |
| One identifier, one approval | `approval-id-reused-different-content` | [microsoft/agent-framework#9535](https://github.com/microsoft/agent-framework/pull/9535): filtering one approval response could expose another with the same identifier |
| Used once | `approval-already-consumed` | approval reuse, the same pull request |
| Signing key | `approval-key-not-approvers` | [MoltyCel/moltrust-api#887](https://github.com/MoltyCel/moltrust-api/pull/887): ownership and key-binding checks before signing; an authorizer key id that differs from the trusted key's id |
| Approval asserted by the model | `approval-asserted-in-tool-arguments` | [google/adk-python#7655](https://github.com/google/adk-python/issues/7655): a delete tool takes `confirm_deletion=True` from the model's own arguments as its confirmation, with no framework confirmation step |
| User, not client | `same-client-other-user` | [modelcontextprotocol/typescript-sdk#2782](https://github.com/modelcontextprotocol/typescript-sdk/pull/2782): task ownership keyed by the OAuth client identifier |
| Event and phase | `event-differs`, `phase-differs` | [modelcontextprotocol/experimental-ext-interceptors#46](https://github.com/modelcontextprotocol/experimental-ext-interceptors/pull/46): confirmation bound to event, phase, target and payload |
| Payload after mutation | `payload-mutated-after-approval`, `target-differs`, `tool-differs` | the same proposal: rechecked after a mutation |
| Validity window | `used-at-expiry`, `used-before-issued` | |
| Policy served at decision time | `release-first-served-after-decision`, `release-retired-beyond-grace` | [JanssenProject/jans#15447](https://github.com/JanssenProject/jans/pull/15447): release history and a grace period for late records |
| A failed lookup is not a match | `release-lookup-unavailable` | the same pull request |

The controls (`allow-*`) keep a verifier from denying everything: another
approval under a different identifier, the same approval presented twice with
identical content, a use one second before expiry, a release first served at
the decision instant, and a release last served exactly the grace period
before it.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is
   `https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1`
   (`contract_id_unknown`).
3. No other entry in `presentedApprovals` has the approval's `approvalId` with
   different content (`approval_id_ambiguous`). The same approval presented
   twice is not ambiguous.
4. `approvalId` is not in `consumedApprovalIds` (`approval_replayed`).
5. `trustedKeys[approver]` is the approval's `keyId` (`key_not_bound`).
6. The use's `principal` is the approval's `principal` (`principal_mismatch`).
   A matching `clientId` does not stand in for the user.
7. The use's `event` and `phase` are the approved ones
   (`event_phase_mismatch`).
8. The used `tool`, `target` and payload bytes are the approved ones
   (`payload_mismatch`).
9. `usedAt` is at or after `issuedAt` and before `expiresAt`
   (`approval_outside_validity`).
10. `policyRelease.lookup` is `ok` (`comparison_unavailable`).
11. The release's `firstServedAt` is at or before `decisionTime`, and its
    `lastServedAt` plus `graceSeconds` is at or after it
    (`release_not_served_at_decision`).

A record that passes all eleven is `allow` with reason `bound`.

`comparison_unavailable` is a deny rather than an indeterminate outcome. The
record states that the lookup failed, so the contract is not silent about the
input; what it forbids is reading "not checked" as "matched".

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-approval-binding
```

A verifier under test takes `record.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`:

```sh
agent-evidence-vectors --corpus vectors-approval-binding --verifier './verifier'
python3 vectors-approval-binding/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-approval-binding` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-approval-binding/gen_vectors.py`.

Passing these cases does not establish that a signature is valid, that the
trusted key set is current, or that the consumed set is complete; those come
from the signing, key-distribution and replay-store layers the record cites.
