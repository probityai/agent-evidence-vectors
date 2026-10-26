# Converted-argument-binding vectors

Cases for `converted-argument-binding/v1`: a record of one approved tool call,
holding the arguments the model gave, the arguments as converted for the tool and
shown to the approver, the approval, the rebuild of the approved arguments, the
call as it stood after the approval chain, and the arguments the tool ran with.
The expected decision and reason for every case are in `MANIFEST.json`.

The rule is the one inspect_ai adopted in
[UKGovernmentBEIS/inspect_ai#5652](https://github.com/UKGovernmentBEIS/inspect_ai/pull/5652)
(design `design/tool-approval-arguments.md`, head
`a31b3b620254426ce7c037e8036b743a52ba6636`): the approver sees the converted
arguments, and what runs is rebuilt from the approved JSON and must serialize
back to exactly it. Comparison here is under RFC 8785, so the same members in a
different order are equal.

| Case | Expected |
| --- | --- |
| allow-unchanged | allow, `bound` |
| allow-constructor-default-shown | allow, `bound` |
| allow-modify-full-call | allow, `bound` |
| executed-key-order-only | allow, `bound` |
| contract-id-missing | deny, `contract_id_missing` |
| contract-id-unknown | deny, `contract_id_unknown` |
| approved-digest-not-shown | deny, `approval_not_bound_to_shown` |
| shown-holds-nan | deny, `shown_not_storable` |
| shown-duplicate-key | deny, `shown_not_storable` |
| invalid-enum-approved | deny, `invalid_call_approved` |
| modify-drops-defaulted-field | deny, `modify_not_full_call` |
| clock-default-rebuilds-differently | deny, `rebuild_not_identical` |
| approver-edited-in-place | deny, `call_mutated_after_approval` |
| bool-string-coerced | deny, `shown_not_executed` |
| float-truncated-to-int | deny, `shown_not_executed` |
| dict-repr-to-string | deny, `shown_not_executed` |
| constructor-default-hidden | deny, `shown_not_executed` |

Each denied case changes one thing of an allowed call, so the check it names is
the first that fails and every earlier check passes. The `shown_not_executed`
cases are the conversions that hide in plain sight: a string run as a boolean, a
float cut to an integer, an object run as its repr, and a default the approver
never saw. The `bool-string-coerced` parameter is declared a string, so the call
is valid and only the conversion is wrong. Two controls keep a verifier from
denying everything: a constructor default that was shown and then run, and an
executed file with the same members in another order.

## What a case holds

`raw.json`, `shown.json`, `rebuilt.json`, `executed.json`, an optional
`modified.json`, and `record.json`. The record carries `contractId`
(`https://probityai.github.io/agent-evidence-observer/contract/converted-argument-binding/v1`),
`parameters` (each name to `{type, enum?, default?}`, with `type` one of
`boolean`, `integer`, `number`, `string` or `object`), `approval` (`decision`,
`approve` or `modify`, and `shownSha256`), and the digests of the call's id,
function and arguments before and after the approval chain
(`callCopyBeforeSha256`, `callCopyAfterSha256`).

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is the converted-argument-binding contract
   (`contract_id_unknown`).
3. `approval.shownSha256` is the SHA-256 of the bytes of `shown.json`
   (`approval_not_bound_to_shown`).
4. `shown.json` is I-JSON: no duplicate member, no `NaN` or `Infinity`, no
   unpaired surrogate, no integer of magnitude 2^53 or more
   (`shown_not_storable`).
5. `raw.json` satisfies the declared types and enums, with no undeclared
   member (`invalid_call_approved`). A call that fails here should never have
   been shown.
6. Under `modify`, `modified.json` carries every parameter that has a default and
   no parameter that is not declared (`modify_not_full_call`).
7. The RFC 8785 form of `rebuilt.json` equals that of the approved arguments,
   which are `shown.json`, or `modified.json` under `modify`
   (`rebuild_not_identical`). A non-deterministic default fails here.
8. Under `approve`, `callCopyAfterSha256` equals `callCopyBeforeSha256`
   (`call_mutated_after_approval`).
9. The RFC 8785 form of `executed.json` equals that of the approved arguments
   (`shown_not_executed`).

A record that passes every check is `allow` with reason `bound`.

## What a pass establishes

The shown, approved, rebuilt and executed argument bytes in the record agree
under RFC 8785, the approval names the shown bytes, and the call was not changed
after approval.

## What a pass does not establish

- That `executed.json` is what the tool actually received: it is the producer's
  record.
- That validators and constructors are deterministic beyond the one recorded
  rebuild.
- That the parameter type's equality covers all state.
- That the approver understood the call.
- Calls outside the approval path, such as bridged host tools and remote MCP
  calls.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-converted-argument-binding
```

A verifier under test takes `record.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`:

```sh
agent-evidence-vectors --corpus vectors-converted-argument-binding --verifier './verifier'
python3 vectors-converted-argument-binding/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-converted-argument-binding` judges the same cases with the Go
reader. Regenerate the cases with
`python3 vectors-converted-argument-binding/gen_vectors.py`.
