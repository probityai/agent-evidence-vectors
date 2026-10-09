# Authority-at-dispatch vectors

Cases for `authority-at-dispatch/v1`: a record of one attempted dispatch by an
agent acting under delegated authority, the bytes it dispatched, and the
decision a verifier must reach at dispatch time. The expected decision and
reason for every case are in `MANIFEST.json`.

An approval says someone agreed to an action once. Whether the authority behind
it still held when the action left is a separate question, and the column
headed "approved bytes" is the point of the corpus: several denied records
dispatch exactly the bytes whose digest was approved, and only the authority
evidence refuses them.

| Case | Approved bytes | Expected |
| --- | --- | --- |
| allow-direct | yes | allow, `authorized` |
| allow-two-hop-narrowing | yes | allow, `authorized` |
| allow-revoked-after-dispatch | yes | allow, `authorized` |
| allow-evidence-age-at-limit | yes | allow, `authorized` |
| revoked-before-dispatch | yes | deny, `grant_revoked` |
| dispatched-bytes-differ | no | deny, `dispatch_not_approved` |
| dispatched-object-differs | no | deny, `dispatch_not_approved` |
| dispatched-action-differs | no | deny, `dispatch_not_approved` |
| stale-authority-evidence | yes | deny, `authority_evidence_stale` |
| scope-amplified-across-hops | yes | deny, `scope_amplified` |
| grant-expired | yes | deny, `grant_expired` |
| contract-id-missing | yes | deny, `contract_id_missing` |
| contract-id-unknown | yes | deny, `contract_id_unknown` |
| evidence-age-inconsistent | yes | deny, `evidence_age_inconsistent` |

The cases follow the delegated-authority comparison in
[`interop/authority-unreachable-2026-10-03/CONTRACT.md`](https://github.com/probityai/agent-evidence-observer/blob/00e92b0a3fcf53376ebafc6cc9b4abde7e9fdc8c/interop/authority-unreachable-2026-10-03/CONTRACT.md)
of agent-evidence-observer: revocation after delegation, a changed object or
action, stale authority evidence, scope amplified across delegation hops, and an
expired grant.

## What a record holds

Every record carries `contractId` with the value
`https://probityai.github.io/agent-evidence-observer/contract/authority-at-dispatch/v1`,
and its `authorityEvidence` carries `evidenceAgeSeconds`, `observedAt` and
`maxAgeSeconds`. The other fields are `decisionTime`, `approvedAction` (tool,
target and the SHA-256 of the approved bytes), `dispatch` (tool, target and the
file holding the dispatched bytes), `delegation` (one grant per hop, with scope
and validity window) and the revocations the evidence lists.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is the authority-at-dispatch contract (`contract_id_unknown`).
3. `evidenceAgeSeconds` equals `decisionTime` minus `observedAt`
   (`evidence_age_inconsistent`). A record cannot report its evidence as
   fresher than its own timestamps say.
4. That age does not exceed `maxAgeSeconds` (`authority_evidence_stale`).
   Evidence exactly as old as the limit is fresh.
5. No grant in the chain was revoked at or before `decisionTime`
   (`grant_revoked`). A revocation that takes effect after dispatch does not
   reach back.
6. `decisionTime` is at or after each grant's `notBefore` and before its
   `expiresAt` (`grant_expired`).
7. Each hop's scope is a subset of the scope of the hop before it
   (`scope_amplified`).
8. The dispatched tool, target and bytes are the approved ones, and the tool is
   in the last hop's scope (`dispatch_not_approved`).

A record that passes all eight is `allow` with reason `authorized`.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-authority-at-dispatch
```

A verifier under test takes `record.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`:

```sh
agent-evidence-vectors --corpus vectors-authority-at-dispatch --verifier './verifier'
python3 vectors-authority-at-dispatch/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-authority-at-dispatch` judges the same cases with the Go
reader. Regenerate the cases with
`python3 vectors-authority-at-dispatch/gen_vectors.py`.

Passing these cases does not establish that the authority evidence is genuine,
that the revocation list is complete, or that the side effect committed; those
need the signed status source and the target-side observation the contract
names.
