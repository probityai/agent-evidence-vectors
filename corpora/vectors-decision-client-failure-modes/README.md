# Decision-client failure-mode vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Cases for `decision-client-failure-modes/v1`. A decision client sits in front of an
action and asks a decision point whether the action may run. The answer can fail to
arrive, or fail to mean anything. None of those failures is an allow. A client that
reads one as an allow lets an action run that nobody decided to run, and a client
that records one as a policy decision writes a record that says it was decided.

The corpus is the failure-mode matrix: seven conditions of the decision point, each
under two client modes, plus four controls, eighteen scenarios in all.

| Condition | The decision point |
| --- | --- |
| `unreachable` | nothing listens at its address |
| `http-500` | answers HTTP 500 |
| `http-503` | answers HTTP 503 with an empty body |
| `unparseable-body` | answers HTTP 200 with a body that is not JSON |
| `timeout` | answers `block` 2.5 seconds after the client's 1 second timeout |
| `unknown-verdict` | answers HTTP 200 with a verdict outside `allow`, `block`, `halt` |
| `missing-verdict` | answers HTTP 200 with no `verdict` member |

Each runs under mode `default`, the client as it ships with no error-handling option
set, and mode `strict`, the client's own strictest fail-closed setting. A conforming
client withholds the action in all fourteen and records a `fallback` decision. The
controls run under `default`: `control-block` and `control-halt` withhold the action
on a `policy` basis (the halt also stops the run), `control-allow` performs it once,
and `control-401` withholds it as a `fallback`.

## Run it in CI

A client adds one step and an adapter that builds the client and asks it once:

```yaml
- uses: probityai/agent-evidence-vectors@<tag>
  with:
    corpus: vectors-decision-client-failure-modes
    runtime: .venv/bin/python tests/decision_client_adapter.py
```

`tests/client_adapter.py` is a reference adapter with two policies. `closed` passes
every scenario. `open` allows on a transport fault under `default` and reads an
unknown or missing verdict as an allow, the way a client that fails open does, and
fails nine scenarios.

## The client contract

- The adapter is run as `<client> <scenario.json>` with `AEV_DECISION_POINT` set to
  the decision point's base URL, `AEV_EFFECT_SINK` set to the sink's base URL and
  `AEV_DECISION_RECORD` set to a path it may write its record to. It must finish
  within a minute.
- It builds the client in the scenario's `mode` with the scenario's `timeoutMillis`
  and asks about the scenario's `request` with one POST. The decision point answers
  every POST, on any path, with the scenario's response.
- Only when the client allows the action, it performs it once with
  `POST {sink}/effects`, a JSON body of `action` and `args`.
- It prints, as its last line, `{"outcome": "allow" | "deny", "basis": "policy" |
  "fallback", "halted": bool}` and exits 0.

A scenario passes when the sink received the accepted number of effects, the printed
decision is the accepted one, and any record written passes the checks below and
agrees with the printed decision.

## What a record holds

`contractId` carries
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/decision-client-failure-modes`.
The other members: `request` (`action`, `argsDigest`, `consequential`), `client`
(`mode`, `timeoutMillis`), `exchange` (`reached`, `timedOut`, `httpStatus`,
`bodyIsJsonObject` and, when the body carried one, `verdict`), `decision`
(`outcome`, `basis`, `condition`, `halted`) and `effect.performed`.

The condition the exchange gives: `unreachable` when the point was not reached,
`timeout` when no reply came inside the timeout, `unauthorized` on 401 or 403,
`http-error` on any other status outside 200-299, `unparseable-body` when the body
is not a JSON object, `missing-verdict` and `unknown-verdict` as named, and `ok`
otherwise. Every condition but `ok` is a fault.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is this contract (`contract_id_unknown`).
3. Every required member is present with a value from its vocabulary, and a reply
   that arrived carries a status (`record_malformed`).
4. The recorded condition is the one the exchange gives (`condition_misclassified`).
5. A fault is recorded on a `fallback` basis (`fault_recorded_as_policy`).
6. A fault never allows the action (`fault_allowed`).
7. A readable verdict is followed on a `policy` basis (`verdict_not_followed`).
8. A `halt` verdict is recorded as halted, and nothing else is (`halt_not_honoured`).
9. An action the client denied was not performed (`effect_on_deny`).

A record that passes every check is `allow` with reason `decision_sound`.

## What a pass establishes

Under each tested condition and mode the client withheld a consequential action it
had no usable verdict for, said so in its decision, and acted on a readable verdict
as the verdict said.

## What a pass does not establish

- Anything about conditions or modes the matrix does not list.
- That a hosted decision point ever sends these responses.
- That the client's record is truthful about the exchange; the sink count is the
  independent observation.

## Running it

```sh
agent-evidence-vectors --corpus vectors-decision-client-failure-modes
agent-evidence-vectors --corpus vectors-decision-client-failure-modes --verifier './verifier'
agent-evidence-vectors runtime --corpus vectors-decision-client-failure-modes --runtime './adapter'
```

`aee-verify vectors-decision-client-failure-modes` judges the same cases with the Go reader.
Regenerate the cases with `python3 corpora/vectors-decision-client-failure-modes/gen_vectors.py`.
