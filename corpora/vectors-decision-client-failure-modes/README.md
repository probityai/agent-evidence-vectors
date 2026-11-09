# Decision-client failure-mode vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Cases for `decision-client-failure-modes/v1`. A decision client sits in front of an
action and asks a decision point whether the action may run. The answer can fail to
arrive, or fail to mean anything, or the client may not ask at all because its circuit
breaker opened. None of those is an allow. A client that reads one as an allow lets an
action run that nobody decided to run, and a client that records one as a policy
decision writes a record that says it was decided.

A correct decision says nothing when the client was not enforcing. A monitor (audit,
dry-run) mode logs a block and runs the action anyway. A client configured to fail
open allows whenever the decision point is down. A client whose fail-closed flag was
never set is governed by whatever its shipped default is that release. The corpus
judges that configuration, the posture, beside the exchange.

The question it answers: did this client withhold the action it had no usable verdict
for, follow the verdict it had, and do so under a posture that enforces?

## The scenarios

The runtime matrix is nine conditions of the decision point, each under two client
modes, plus five controls. Every scenario sets the client's timeout and its response
limit (`maxResponseBytes`).

| Condition | The decision point |
| --- | --- |
| `unreachable` | nothing listens at its address |
| `http-500` | answers HTTP 500 |
| `http-503` | answers HTTP 503 with an empty body |
| `unparseable-body` | answers HTTP 200 with a body that is not JSON |
| `timeout` | answers `block` 2.5 seconds after the client's 1 second timeout |
| `unknown-verdict` | answers HTTP 200 with a verdict outside `allow`, `block`, `halt` |
| `missing-verdict` | answers HTTP 200 with no `verdict` member |
| `oversize` | answers HTTP 200 with an `allow` body one byte over the client's limit |
| `outage` | nothing listens for several asks in a row, past any breaker threshold |

Each runs under mode `default`, the client as it ships with no error-handling option
set, and mode `strict`, the client's own strictest fail-closed setting. A conforming
client withholds the action in every one and records a `fallback` decision. The
oversize body puts its verdict first, so a client that truncates at its limit and
reads the prefix with a lenient parser allows, and fails. The outage scenario asks
with one client instance, so a breaker opens; a breaker that lets the action through
while open fails. The controls run under `default`: `control-block` and
`control-halt` withhold the action on a `policy` basis (the halt also stops the
run), `control-allow` performs it once, `control-401` withholds it as a `fallback`,
and `control-at-limit` performs an allow whose body is exactly at the limit.

## Run it in CI

A client adds one step and an adapter that builds the client and drives it:

```yaml
- uses: probityai/agent-evidence-vectors@<tag>
  with:
    corpus: vectors-decision-client-failure-modes
    runtime: .venv/bin/python tests/decision_client_adapter.py
```

`tests/client_adapter.py` is a reference adapter. `--policy closed` passes every
scenario. `--policy open` fails open the way shipped clients do: it allows on a
transport fault or an open breaker under `default`, reads a reply of any size, and
reads an unknown or missing verdict as an allow. Stating its fail-open posture, it
fails every scenario on the posture; claiming a closed one, it fails on what it did.
`--enforcement monitor`, `--no-posture` and `--fail-mode-source default` show the
posture rule alone.

## The client contract

- The adapter is run as `<client> <scenario.json>` with `AEV_DECISION_POINT` set to
  the decision point's base URL, `AEV_EFFECT_SINK` set to the sink's base URL and
  `AEV_DECISION_RECORD` set to a path it may write its record to. It must finish
  within a minute.
- It builds the client in the scenario's `mode` with the scenario's `timeoutMillis`
  and `maxResponseBytes`, and asks about the scenario's `request` `attempts` times
  with one client instance. Each ask is one POST; the decision point answers every
  POST, on any path, with the scenario's response.
- Only when the client allows the action, it performs it once with
  `POST {sink}/effects`, a JSON body of `action` and `args`.
- It prints, as its last line, its last decision: `{"outcome": "allow" | "deny",
  "basis": "policy" | "fallback", "halted": bool, "posture": {"enforcement":
  "enforce" | "monitor", "failMode": "closed" | "open", "failModeSource": "explicit"
  | "default"}}` and exits 0. `failModeSource` is `explicit` when the adapter's
  configuration, or client code with no option to change it, fixes the fail mode,
  and `default` when an option left unset decided.

A scenario passes when the sink received the accepted number of effects, the printed
decision is the accepted one, the posture enforces, and any record written passes the
checks below, states the printed posture and agrees with the printed decision.

The posture enforces when it is `enforce` and `closed`, and, under `strict`,
`explicit`. A missing posture fails the scenario: unstated is not evidence. Under
`default`, a `default` source is what the mode measures and passes; the record such a
client writes is held to every check but `fail_mode_defaulted`. The Action reads every
row's posture and fails the job with an error naming the scenario and the posture.

## What a record holds

`contractId` carries
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/decision-client-failure-modes`.
The required members: `request` (`action`, `argsDigest`, `consequential`), `client`
(`mode`, `timeoutMillis`), `exchange` (`reached`, `timedOut`, `httpStatus`,
`bodyIsJsonObject` and, when the body carried one, `verdict`), `decision`
(`outcome`, `basis`, `condition`, `halted`) and `effect.performed`.

The optional members: `posture` (`enforcement`, `failMode`, `failModeSource`, all
three), `client.maxResponseBytes`, `exchange.bodyBytes` (the size of a reply that
arrived; a client that stops reading at its limit records the bytes it read) and
`exchange.circuitOpen` (the client did not ask, so nothing was reached). A record
that states a limit gives the size of every reply that arrived.

A record without `posture` is judged on its exchange alone: its `decision_sound`
says the client decided this exchange correctly, and nothing about its configuration.
The records the corpus shipped before the optional members are unchanged, byte for
byte, with the same verdicts; `tests/v1-baseline.json` holds them.

The condition the exchange gives: `circuit-open` when the breaker was open,
`unreachable` when the point was not reached, `timeout` when no reply came inside the
timeout, `unauthorized` on 401 or 403, `http-error` on any other status outside
200-299, `oversize` when the body's size is over the stated limit (exactly at it is
not), `unparseable-body` when the body is not a JSON object, `missing-verdict` and
`unknown-verdict` as named, and `ok` otherwise. Every condition but `ok` is a fault.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is this contract (`contract_id_unknown`).
3. Every required member is present with a value from its vocabulary, a reply that
   arrived carries a status, and the optional members are typed and consistent with
   the exchange (`record_malformed`).
4. A stated posture is not `monitor` (`monitor_mode`).
5. A stated posture does not fail `open` (`fail_open_posture`).
6. A stated posture's fail mode was set, not defaulted (`fail_mode_defaulted`).
7. The recorded condition is the one the exchange gives (`condition_misclassified`).
8. A fault is recorded on a `fallback` basis (`fault_recorded_as_policy`).
9. A fault never allows the action (`fault_allowed`).
10. A readable verdict is followed on a `policy` basis (`verdict_not_followed`).
11. A `halt` verdict is recorded as halted, and nothing else is (`halt_not_honoured`).
12. An action the client denied was not performed (`effect_on_deny`).

The posture checks come first because they judge the configuration the exchange ran
under: under `monitor` no decision gated anything, under `open` a correct deny says
nothing about the next fault, and under a defaulted fail mode the next release's
default decides. They run broadest first. A record that passes every check is `allow`
with reason `decision_sound`. The expectations live in `MANIFEST.json`, one row per
case, with the runtime scenario each case pairs with.

## What a pass establishes

Under each tested condition and mode the client withheld a consequential action it
had no usable verdict for, bounded what it read, kept the action withheld while its
breaker was open, said so in its decision, acted on a readable verdict as the verdict
said, and stated an enforcing, fail-closed posture it set itself.

## What a pass does not establish

- Anything about conditions or modes the matrix does not list.
- That a hosted decision point ever sends these responses.
- That the client's record or its stated posture is truthful; the sink count is the
  independent observation, and a monitored client shows in it.

## Running it

```sh
agent-evidence-vectors --corpus vectors-decision-client-failure-modes
agent-evidence-vectors --corpus vectors-decision-client-failure-modes --verifier './verifier'
agent-evidence-vectors runtime --corpus vectors-decision-client-failure-modes --runtime './adapter'
```

`aee-verify vectors-decision-client-failure-modes` judges the same cases with the Go reader.
Regenerate the cases with `python3 corpora/vectors-decision-client-failure-modes/gen_vectors.py`.
