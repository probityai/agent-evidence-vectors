# Approval-binding vectors

Cases for `approval-binding/v1`: a record of one approval presented for one
use, the payload bytes of the use, and the decision a verifier must reach. The
expected decision and reason for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

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
| The use cites the approval checked | `approval-use-cites-predecessor`, `approval-use-cites-no-approval` | the review of the renewal cases on [#292](https://github.com/probityai/agent-evidence-vectors/pull/292#issuecomment-6491378743) by `AAkhtanin`: a use naming another approval, or none, was judged against the one presented |
| Policy served at decision time | `release-first-served-after-decision`, `release-retired-beyond-grace` | [JanssenProject/jans#15447](https://github.com/JanssenProject/jans/pull/15447): release history and a grace period for late records |
| A failed lookup is not a match | `release-lookup-unavailable` | the same pull request |
| Renewal by replacement | `approval-renewed-same-bounds`, `approval-reused-after-renewal`, `approval-renewal-transition-not-accepted`, `approval-renewal-decision-not-distinct`, `approval-renewal-predecessor-decision-not-cited`, `approval-renewal-bounds-differ`, `approval-renewal-accepted-after-use`, `approval-renewal-predecessor-ambiguous` | the approval-renewal thread in [aaif/wg-observability-and-traceability#66](https://github.com/aaif/wg-observability-and-traceability/issues/66): the cases were asked for by `narko4u` and the sequence comes from `AAkhtanin` |
| A new grant does not reopen a closed effect | `approval-renewal-reopens-consumed-effect`, `approval-renewal-reopens-uncertain-effect` | the same thread |
| Server-held approval state | `approval-not-issued-by-server` | the client-held approval pattern: a server that accepts an approval object the client sends back, rather than reading its own register |
| One request, one completion | `approval-request-completed-twice` | a request answered twice, an approve and a deny, under two identifiers |
| Approval with corrections | `approval-corrections-not-applied` | the reviewer edits the arguments; the grant covers the corrected bytes only |
| A deny is a deny in observe mode | `approval-denied-observe-mode` | monitor and observe modes that log a deny and run the call |
| Observe mode never gates | `approval-gathered-in-observe-mode` | an approval collected while the gate only logs |
| Key rotation | `approval-issued-under-rotated-key` | an approval signed under a key after its rotation |

The controls (`allow-*`) keep a verifier from denying everything: another
approval under a different identifier, the same approval presented twice with
identical content, a use one second before expiry, a release first served at
the decision instant, a release last served exactly the grace period
before it, a replacement B that cites its predecessor's decision
(`approval-renewed-same-bounds`), and the predecessor presented before the
replacement was accepted (`allow-predecessor-before-replacement`), an
approval with corrections used with the corrected bytes
(`allow-approved-with-corrections`), and an approval issued under a key one
minute before the approver rotated it out (`allow-key-rotated-after-issue`).

## The checks, in order

A verifier names the first check that fails.

1. the record carries `contractId` (`contract_id_missing`);
2. `contractId` is the approval-binding contract (`contract_id_unknown`);
3. the use's `approvalId` is the identifier of the approval being checked; a
   use that names another approval, or none, is not judged against this one
   (`approval_not_cited`);
4. the approval is one the server issued: its identifier is in
   `issuedApprovalIds`, the register the server holds. An approval the client
   built and presented, however well formed, is not one (`approval_not_issued`);
5. no other presented approval shares the approval's identifier and differs
   from it in any member, compared as parsed JSON values over the whole object,
   including members no check reads; the same approval presented twice, with
   equal values, is not ambiguous (`approval_id_ambiguous`);
6. no other presented approval completes the same `requestId` under another
   identifier: one request is answered once
   (`approval_request_completed_twice`);
7. the approval's `outcome` is a grant, `approved` or
   `approved-with-corrections`; a denied request is not a grant, whatever
   happened to the call (`approval_not_granted`). An approval with
   corrections binds the corrected bytes in `payloadSha256`; the bytes first
   requested, in `requestedPayloadSha256`, are not approved (check 17);
8. the record's `enforcement` is `enforce`; an approval gathered in an
   observe or monitor mode never gated the call (`approval_not_enforced`);
9. the identifier is not among the consumed ones (`approval_replayed`);
10. no replacement accepted at or before the use has taken the approval's place
    (`approval_superseded`);
11. a use that claims `authorityForm: renewed` has a transition accepted at or
    before the use naming this approval as successor; a transition accepted
    later does not establish the renewal (`renewal_transition_missing`);
12. that transition binds the successor to exactly one predecessor
    (`renewal_binding_invalid`);
13. the approval's `keyId` is the trusted key of its approver, or a key listed
    for that approver in `retiredKeys` (`key_not_bound`);
14. a key listed in `retiredKeys` signed the approval before its
    `retiredAt`; an approval issued under a rotated-out key at or after the
    rotation is refused (`key_retired`);
15. the use's principal is the approval's principal; a shared `clientId` does
    not stand in for the user (`principal_mismatch`);
16. the use's event and phase are the approved ones (`event_phase_mismatch`);
17. the used tool, target and payload bytes are the approved ones
    (`payload_mismatch`);
18. `usedAt` is at or after `issuedAt` and before `expiresAt`
    (`approval_outside_validity`);
19. the effect the use names is not closed (`effect_already_closed`);
20. the policy release lookup answered (`comparison_unavailable`); an
    unanswered lookup is never read as a match;
21. the release was served at the decision time: first served at or before it,
    and last served at or after it minus the grace period
    (`release_not_served_at_decision`).

A record that passes all of them is `allow` with reason `bound`.

`comparison_unavailable` is a deny rather than an indeterminate outcome. The
record states that the lookup failed, so the contract is not silent about the
input; what it forbids is reading "not checked" as "matched".

## Renewal by replacement

Reusing an approval cites the existing approval A. Renewal by replacement cites
the new approval B and an accepted transition from A to B. Equal bounds, the same
recorded decision and the same logical effect are three different identities, so
the record carries each apart:

- `approval.decisionId` is the recorded decision that authorised that approval.
- `transitions` lists the replacements the issuer recorded. An accepted
  `exclusive-replacement` names the predecessor approval and decision, the
  successor approval and decision, and `acceptedAt`. The bounds a renewal holds
  equal are `event`, `payloadSha256`, `phase`, `principal`, `target` and `tool`;
  the validity window is B's own. A transition counts from `acceptedAt` on, for
  the predecessor it replaces and for the successor it establishes alike. Exclusive replacement is this suite's policy,
  not a claim that every renewal policy forbids overlap.
- `use.authorityForm: renewed` is a claim about a transition, and is never
  evidence that one was accepted.
- `use.effectKey` and `effectRegistry` carry the logical effect. A new grant
  does not reopen an effect that closed as `CONSUMED` or `UNCERTAIN_CLOSE`.

`approval-reused-after-renewal` presents A after the A to B replacement was
accepted and before any execution under B. A is unexpired and unconsumed and the
effect is reserved, not executed, so only supersession can refuse it. A reader
that tests A only after B has run can pass this through its consumed set and
miss a broken supersession. The control `allow-predecessor-before-replacement`
presents A before the replacement was accepted and is allowed, so the case does
not reward refusing every predecessor.

The reader grades the approval decision: deny A, then allow B. That an
executor started nothing and consumed no effect reservation on the refusal, and
that exactly one execution followed under B, are runtime observations an approval
reader cannot make; a runtime counterpart records them separately.

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
`python3 scripts/approval-binding-rails-test.py` holds the packaged reader,
`check_vectors.py` and the Go reader to one decision and reason on every member
and on mutated copies of every member.
Regenerate the cases with `python3 vectors-approval-binding/gen_vectors.py`.

Passing these cases does not establish that a signature is valid, that the
trusted key set is current, or that the consumed set is complete; those come
from the signing, key-distribution and replay-store layers the record cites.
