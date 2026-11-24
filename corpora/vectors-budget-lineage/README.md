# Budget-lineage vectors

Cases for `budget-lineage/v1`: one principal's delegation tree and every charge
the accounting authority booked for the agents in it, whatever budget each charge
names. The expected decision and reason for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The shape under test is a counter kept per flow. A runtime that limits depth,
fan-out and spend per flow, keyed by an identifier the caller supplies, starts
those counters again when a sub-agent opens a new root. The parent's record then
shows a clean picture: the spend sits on a budget nobody delegated, the extra
depth is counted from zero, and the edge to the sub-agent is absent. A verifier
that reads one budget's log cannot see any of it, because the log lists only what
was booked against that budget. This corpus judges the tree instead.

| Case | Expected |
| --- | --- |
| allow-two-hop-tree-within-budget | allow, `lineage_held` |
| allow-carve-within-parent | allow, `lineage_held` |
| allow-depth-at-limit | allow, `lineage_held` |
| allow-outsider-booked-elsewhere | allow, `lineage_held` |
| allow-revoked-delegate-books-elsewhere-after-revocation | allow, `lineage_held` |
| allow-grandchild-after-parent-revoked-books-elsewhere | allow, `lineage_held` |
| allow-refused-elsewhere-not-charged | allow, `lineage_held` |
| contract-id-missing | deny, `contract_id_missing` |
| contract-id-unknown | deny, `contract_id_unknown` |
| malformed-ledger-units-negative | deny, `malformed_record` |
| malformed-delegations-not-list | deny, `malformed_record` |
| delegation-recorded-only-by-delegator | deny, `delegation_unilateral` |
| delegation-claimed-only-by-delegate | deny, `delegation_unilateral` |
| delegation-from-outside-tree | deny, `delegation_detached` |
| depth-reset-by-fresh-root | deny, `depth_limit_exceeded` |
| carve-wider-than-parent | deny, `carve_exceeds_parent` |
| subagent-rerooted-budget | deny, `charge_outside_lineage` |
| rerooted-charge-before-revocation | deny, `charge_outside_lineage` |
| rerooted-unknown-outcome | deny, `charge_outside_lineage` |
| overspend-across-subtrees | deny, `lineage_overspend` |
| overspend-inside-carve | deny, `lineage_overspend` |

Each denied case is built so the check it names is the first that fails and
every earlier check passes. The allowed cases are controls: a verifier that
refuses everything fails them, and so does one that charges the tree for an
agent that was never in it or had already been revoked.

## What a record holds

`contractId` carries
`https://probityai.github.io/agent-evidence-observer/contract/budget-lineage/v1`.
The other fields are `principal`; `budget`, with `id`, `unit` and `limit`;
`maxDepth`; `asOf`; `delegations`, each a grant with `grantId`, `delegator`,
`delegate`, `issuedAt`, an optional `revokedAt` and an optional `carve` (`id`
and `limit`); `acceptances`, each with `grantId`, `delegate` and `acceptedAt`;
and `ledger`, each charge with `requestId`, `agent`, `budget`, `units`, `at`,
`decision` (`admitted` or `refused`) and `outcome` (`committed`, `released`,
`unknown` or `none`).

An agent is a member of the tree at an instant when its grant was issued at or
before it, is not revoked at it, and its delegator is the principal or a member
at that instant, so revoking a delegate removes its subtree. Its depth is the
length of that chain. A charge counts when it was admitted and its outcome is
`committed` or `unknown`. The lineage is the principal's budget and every carve
in the tree.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is the budget-lineage contract (`contract_id_unknown`).
3. Every field has the type given above (`malformed_record`).
4. Every grant has the delegate's acceptance of the same grant, no earlier than
   the grant, and every acceptance names a grant (`delegation_unilateral`).
5. Every delegator is the principal or a member when it grants
   (`delegation_detached`).
6. No member deeper than `maxDepth` was admitted a charge
   (`depth_limit_exceeded`).
7. No carve is larger than the budget its delegator holds: its own carve, or
   the nearest carve above it, or the principal's limit (`carve_exceeds_parent`).
8. No member other than the principal is charged against a budget outside the
   lineage while it is a member (`charge_outside_lineage`).
9. The units charged against the lineage stay inside the principal's limit, and
   the units charged against each carve stay inside its limit
   (`lineage_overspend`).

A record that passes every check is `allow` with reason `lineage_held`.

## What a pass establishes

Every delegation in the record has both ends, the tree is connected to the
principal, no member past the depth limit was admitted, no sub-agent was handed
a budget wider than its parent's, and nothing a member was charged while it was
a member sits outside the budget the principal granted or past its limit.

## What a pass does not establish

- That the ledger lists every charge the authority booked. The record must come
  from the accounting authority, not from the agents it accounts for.
- That the grants and acceptances were signed by the parties they name; pair it
  with `vectors-delegation-lifecycle` for signed grants.
- That the parties' clocks agree.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-budget-lineage
```

A verifier under test takes `record.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`:

```sh
agent-evidence-vectors --corpus vectors-budget-lineage --verifier './verifier'
python3 vectors-budget-lineage/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-budget-lineage` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-budget-lineage/gen_vectors.py`.
