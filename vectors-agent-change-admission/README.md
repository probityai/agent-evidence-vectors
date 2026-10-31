# Agent change admission vectors

Cases for `agent-change-admission/v1`: signed decisions about whether a proposed
change to an AI agent's harness was admitted, under the
[agent-change-admission predicate, version 1](https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md).
A harness change is a new system prompt, procedure, tool-call guard or tool
allowlist. The decision names the parent and candidate harness, the frozen
evaluator, the recorded-trace corpus each new guard was replayed over, the
digest of every report it rests on, the gates it checked and every exception
met on the way.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Replay from the installed package:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-agent-change-admission
```

## The rule under test

A verifier reads a DSSE v1 envelope signed with Ed25519, a consumer policy that
pins the payload type, the predicate type, the trusted keys and the required
gates, and any stored reports the consumer holds. It names the first check that
fails:

| Step | Check | Refusal |
| --- | --- | --- |
| 1 | the envelope parses as DSSE v1 | no verdict, `malformed_envelope` |
| 2 | the payload type is the pinned one | `unsupported_payload_type` |
| 3 | a signature naming a pinned keyid verifies; signatures naming other keys are ignored | `untrusted_key`, `signature_invalid` |
| 4 | the payload is a JSON object; in the in-toto carriage, a Statement v1 | `payload_not_json_object`, `unsupported_statement_type` |
| 5 | the predicate type is the pinned one | `unsupported_predicate` |
| 6 | each required field is well formed, in the predicate's field order | `payload_field_invalid:<field>` |
| 7 | in the in-toto carriage, a subject carries the candidate digest | `subject_digest_mismatch` |
| 8 | every required gate is recorded and agrees with the admitted flag | `gate_missing:<gate>`, `admitted_with_failed_gate:<gate>`, `rejected_with_all_gates_passed` |
| 9 | every supplied report is named and matches its digest; under a policy that requires reports, every named report is supplied | `report_not_named:<name>`, `report_digest_mismatch:<name>`, `report_not_supplied:<name>` |

A decision that passes all nine is `supported`: `admitted_receipt_verified` or
`rejection_receipt_verified`. A supported rejection is a verified record that a
change was refused. A check the policy does not require, such as cost, is
informational and never a gate.

Two carriages are exercised. `dsse-bare` signs the decision object itself,
which carries `predicateType`, under the payload type
`application/vnd.ratchet.decision+json`. `dsse-intoto` signs an in-toto
Statement v1 under `application/vnd.in-toto+json`, with the candidate harness as
its subject and the decision as its predicate.

Each refused member names its supported twin and differs from it by one
scripted mutation. [INDEX.md](INDEX.md) lists every member; `MANIFEST.json`
holds the expected `decision` and `reason` for each.

## Keys

Every envelope is signed with test keys whose seeds are the SHA-256 of public
labels in `gen_vectors.py`. Anyone can re-derive them. They are test keys only.

## Tools

- `gen_vectors.py` writes every case, `MANIFEST.json` and `INDEX.md`
  deterministically. The canonical JSON and the envelope encoding match the
  reference issuer, so a signer holding the same seed over the same decision
  writes the same envelope bytes.
- `check_vectors.py` runs the packaged reference reader, or a named verifier
  with `--verifier "<cmd>"`. The contract: `<cmd> <case-dir>/case.json --json`
  prints one JSON object with `decision` and `reason` on its last line, and
  exits 0 for `supported`, 1 for `contradicted` or `not_established`, and 2 when
  no verdict was reached.
- `mutation_check.py` switches off each rule in turn and fails unless some
  member changes its answer.
