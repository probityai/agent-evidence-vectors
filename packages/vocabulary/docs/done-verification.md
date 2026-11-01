# Done verification terms

Name the parts of a done decision so that a verdict and the evidence behind it can be told apart. The [README](../README.md) is the short version of the repository; this page covers the `done_verification` section added in 0.6.0.

A coding agent says its task is done. A verifier outside the agent's container decides whether that is true, and a receipt carries the records so a third party can repeat the decision. These eight terms name the parts, and each carries a `check`: the rule a verifier applies to decide it. All eight are `proposed`, none lists an issuer, and each has a `review_by` date.

## One question, answered in terms

Did the agent leave the tests alone? The term is `protected_path`, and its check is `protected_paths/v1`. Did the tests pass? That is `acceptance_observed`, checked by `acceptance_observed/v1` against a grade written by a verifier that rebuilt the tree. Did the agent run what it says it ran? A `claimed_tool_output` is matched against an `observed_tool_output` by `tool_claim_match/v1`. When a record is missing, the answer is an `inconclusive_verdict`, never a pass.

## The terms

| term | what it names | check |
|---|---|---|
| `done_contract` | the definition of done, sealed before the agent's first turn | the grade and the receipt name the contract's digest |
| `done_receipt` | the replay bundle of one done decision | a verifier recomputes every verdict from the bundle |
| `acceptance_observed` | the acceptance commands pass in a separate verifier | `acceptance_observed/v1` |
| `protected_path` | a path the contract forbids the agent to touch | `protected_paths/v1` |
| `claimed_tool_output` | a command the agent says it ran | `tool_claim_match/v1` |
| `observed_tool_output` | the exec events an independent observer recorded | `tool_claim_match/v1` |
| `stop_decision` | the action a published table returns for the verdict history | the action is recomputed from the table the receipt names |
| `inconclusive_verdict` | `not_established`: the records show neither side | never `supported` without the records |

`acceptance_observed` takes the values `supported`, `contradicted` and `not_established`. `stop_decision` takes `continue`, `replan`, `escalate` and `stop`.

The records the checks read, and the reason codes each check returns, are specified in the [done-receipt guide](https://github.com/probityai/probity-verify/blob/main/docs/done-receipt.md) of `probity-verify`. Source paths beginning `predicate.` name fields of the done-receipt predicate, whose specification fixes them at its release.

## Crosswalks

Three filings from outside map neighbouring work onto these terms. None promotes a term.

| filing | maps | read for |
|---|---|---|
| [`crosswalk/claude-code-goal.yaml`](../crosswalk/claude-code-goal.yaml) | Claude Code `/goal` verdicts: not yet met, met, impossible | the evaluator judges only what the agent surfaced, which is the claimed side |
| [`crosswalk/codex-goals.yaml`](../crosswalk/codex-goals.yaml) | Codex goal states: active, paused, complete, budget-limited | completion is checked by the agent that worked the goal |
| [`crosswalk/in-toto-604.yaml`](../crosswalk/in-toto-604.yaml) | in-toto/attestation#604, a proposed generation predicate | the claimed-versus-observed split of an acceptance result is the nearest neighbour of `acceptance_observed` |

## Check it

```bash
python3 scripts/test_done_verification.py
python3 scripts/validate_crosswalks.py
```

The first holds the registry, the validator and this page to each other: every term has a check, every check the registry names is on this page, and a mapping filed under the wrong section is refused by name.
