# Durable-history vectors

Cases for `durable-history/v1`: does a durable engine's exported workflow history agree with the records witnessed at execution time? Each case is one record: what the operator exported of a run (`exports`), and what was witnessed outside the operator's worker while the run executed (`witnessed`): for each gated tool call a permit naming the exact arguments, the tool, the tool code that ran and what the model asked for, and an effect naming what the system of record observed.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

A durable engine's history is the operator's record. The operator can edit the store, rewrite an export, delete a run or reset it into a new one. Replaying the history against the workflow code still passes, because replay compares each activity's id and type with the commands the code issues and never an input or a result. An encrypting payload codec refuses an editor without the key and accepts the key holder. The cases reproduce what a run of an agent on a durable engine showed: an edited model request, an edited tool result, changed tool code, a consistent rewrite of every payload, an edit of the server's own store, a deleted run and a reset, each passing replay; and the edits a codec does and does not stop.

## The record

| Member | What it holds |
| --- | --- |
| `exports[]` | each export as the engine writes it: `{"source": "workflow-show", "events": [...]}` for one run, or `{"source": "cloud-export", "items": [{"history": {"events": [...]}}]}` for one or more runs, where at-least-once delivery may repeat a run |
| `events[]` | `{eventId, eventType, attributes}`; the types read are `WorkflowExecutionStarted {workflowId, runId, resetFrom?}`, `ActivityTaskScheduled {activityId, activityType, input}`, `ActivityTaskCompleted {scheduledEventId, attempt, result}`, `ActivityTaskTimedOut {scheduledEventId, attempt}`, `WorkflowExecutionUpdateAccepted {updateId}` and `WorkflowExecutionReset {newRunId, resetEventId}`; other types pass through |
| payloads | `{"encoding": "json/plain", "data": <value>}`, or `{"encoding": "binary/encrypted", "keyId", "data": <base64 ciphertext>}` |
| activities | `model_request`, whose result carries `toolCalls [{callId, tool, args}]`, and `tool:<name>`, whose input carries `{callId, args}` |
| `witnessed` | `workflowId`, `runId`, `gatedTools`, `expectedToolCodeDigest` (from the measured launch), `permits[]` and `effects[]` |
| permit | `permitId, grantDigest, workflowId, runId, callId, activityId, attempt, tool, argsDigest, modelActivityId, modelArgsDigest, toolCodeDigest, issuedAt, expiresAt, authorityKeyId`, with `inputCiphertextDigest` and `modelResponseCiphertextDigest` under a codec, `approvalIds` and `srl` |
| effect | `effectId, permitId, grantDigest, workflowId, runId, callId, argsDigest, observedAt, observerKeyId, outcome` (`applied`, `not-applied` or `uncertain`), `resultDigest` or `resultCiphertextDigest`, and for an uncertain outcome an optional `settlement {source, outcome, settledAt, observerKeyId, resultDigest}` |

One permit is issued per attempt, so a retried activity carries one permit for each attempt. A digest is `sha256:` and lowercase hex, of the canonical JSON bytes of a value (sorted keys, no whitespace) or of a ciphertext's decoded bytes. The reader recomputes every digest it compares.

## The checks, in the order a verifier applies them

The verifier names the first check that fails. Every exported copy of the witnessed run is checked.

| Check | Reason on failure |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the durable-history contract | `contract_id_unknown` |
| the record has the fields and types the contract names, every time parses, every digest is well formed, every ciphertext decodes, and each effect belongs to a permit of the same call | `malformed_record` |
| the witnessed run was not reset to a point before a witnessed event, and no fork of it is offered in its place | `history_reset` |
| the export holds the witnessed run | `witnessed_run_missing_from_history` |
| every run's event ids run 1, 2, 3 ... in order, the run opens with its one start event, and each activity is scheduled once and closed at most once, after its schedule | `event_sequence_broken` |
| every encrypted payload of a witnessed activity is the ciphertext witnessed at execution, and none was replaced by plaintext | `encrypted_payload_differs_from_witnessed` |
| each permitted activity is scheduled as the permitted tool with the permitted call id and arguments | `history_args_differ_from_permitted` |
| the model's recorded request for each permitted call names the permitted tool and the arguments the model was witnessed asking for | `model_request_differs_from_witnessed` |
| each recorded result of a witnessed attempt is the result witnessed for it | `history_result_differs_from_witnessed` |
| every permit names the tool code of the measured launch | `tool_code_changed` |
| every completed attempt of a gated tool has a permit for that attempt | `activity_unwitnessed` |
| every permitted activity is in the history, and every applied effect has a completion for its attempt | `witnessed_effect_missing` |
| no Update id is accepted twice | `update_applied_twice` |
| no attempt whose witnessed outcome is uncertain is recorded as completed unless the system of record settled it as applied | `lost_reply_settled_without_evidence` |

A record that passes every check is `allow` with reason `consistent`. A reset to the last witnessed event or later leaves every witnessed event in force and is allowed; a reset one event earlier discards a witnessed event and is denied. Under a codec the reader cannot read the payload, so it compares ciphertext: a keyless edit, a valid ciphertext moved from another event, a payload stored back as plaintext and an edit the key holder re-encrypted are all denied by the same check.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-durable-history
```

To judge your own verifier, run it as `<verifier> <case-dir>/record.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`. The expected verdicts live in `MANIFEST.json`, one `expected` object per case, and `gen_vectors.py` writes every record.

## Controls

The allowed cases cover each legitimate shape: a clean run, a retry whose every attempt was permitted, a run under an encrypting codec, a cloud export, a cloud export that repeats the run beside another workflow's run, a lost reply settled by the system of record, a lost reply left honestly as a timeout, a reset after the last witnessed event, an approved argument override, a declined call recorded as declined, distinct Update ids, and an ungated tool that ran with no permit.

Each check is forced by at least one case: switching it off changes a verdict. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. Two verifiers the field ships today are modelled and refused: a replay of the history against the workflow code, which passes the model-request edit, the result edit, the changed tool code, the consistent rewrite, the store edit and the reset fork; and the one check an outsider can run on an export with no key (the call the model asked for against the call scheduled), which catches only the model-request edit and refuses an approved override the witnessed record explains. `tests/test_corpus.py` holds each of these as a test, and regenerates the corpus byte for byte from `gen_vectors.py`.
