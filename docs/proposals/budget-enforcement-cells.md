# Budget enforcement: the measured cells the reject vectors are built from

Source: Elankumaran Srinivasan's S2 budget-exhaustion runs in
[elang2/agent-budget-semantics](https://github.com/elang2/agent-budget-semantics), handed over on
[issue #1](https://github.com/elang2/agent-budget-semantics/issues/1). Every value below is copied from a
committed driver output at the commit named in its section, and each cell has a per-request ledger beside
it in that repository. Credit for the runs is his; the vector design on this page is ours.

Scenario: `scenarios/S2-budget-exhaustion.yaml`, nine tool turns then one text turn, against
`mock-llm/server.py`. The counterparty arm is `--tool-choice-policy`: `ignore` never honours a stop
request, `honour` honours `tool_choice: none` or an absent `tools` list on a tool turn.

## The four frameworks run on 2026-10-13 and 2026-10-14

At [`b30ca39`](https://github.com/elang2/agent-budget-semantics/tree/b30ca39a57b70d3b6fed602edfb980546d036c1a):
`results/S2-toolchoice-four-frameworks-2026-10-13.json` (first declared budget) and
`results/second-budget-2026-10-14/` (second declared budget, langchain at its pinned versions).
Write-up: `MEASUREMENT-S2-tool-choice-four-frameworks-2026-10-13.md`.

| Framework | Version | Budget | Arm | Model calls | Tool calls | `tool_choice: none` sent | Toolless requests | Honoured | `stopped_by` | Mechanism |
|---|---|---|---|---|---|---|---|---|---|---|
| autogen | 0.7.5 | 3 | ignore | 2 | 2 | 0 | 0 | 0 | budget | local_stop |
| autogen | 0.7.5 | 3 | honour | 2 | 2 | 0 | 0 | 0 | budget | local_stop |
| langgraph | 1.2.11 | 6 | ignore | 3 | 3 | 0 | 0 | 0 | natural | withheld |
| langgraph | 1.2.11 | 6 | honour | 3 | 3 | 0 | 0 | 0 | natural | withheld |
| llamaindex | 0.14.24 | 3 | ignore | 3 | 3 | 0 | 0 | 0 | budget_exceeded | withheld |
| llamaindex | 0.14.24 | 3 | honour | 3 | 3 | 0 | 0 | 0 | budget_exceeded | withheld |
| langchain (at pin) | 0.3.14 | 3 | ignore | 3 | 3 | 0 | 0 | 0 | budget | local_stop |
| langchain (at pin) | 0.3.14 | 3 | honour | 3 | 3 | 0 | 0 | 0 | budget | local_stop |
| autogen | 0.7.5 | 5 | both | 4 | 4 | 0 | 0 | 0 | budget | local_stop |
| langgraph | 1.2.11 | 10 | both | 5 | 5 | 0 | 0 | 0 | natural | withheld |
| langchain (at pin) | 0.3.14 | 5 | both | 5 | 5 | 0 | 0 | 0 | budget | local_stop |

langchain 1.3.16 in the main environment returns `0`, `0` and `error` in those three columns, because 1.x removed `AgentExecutor`;
those two cells are void and are not used. The `mechanism` label for langgraph and llamaindex is withheld
at the source: the classifier would read their one-call gap between ledger and framework counts as a
client-side refusal, while both stop before tool dispatch.

## Why this is not eight cells of information

The arm never reaches these four frameworks. All four stop at the budget and never issue the final
summarising request, so no request ever omits `tools` or sends `tool_choice: none`, and the mock has
nothing to honour or ignore. Every counter is 0 in both arms at both budgets, and the arms agree
cell for cell. Reaching the scenario's text turn would need a budget above nine, at which point the
budget is no longer what is measured.

So the family takes these four one-armed: one cell per framework and budget, recorded with the arm
marked as not reached. The arm is load-bearing only where a framework runs past its limit or takes a
free final turn, which the 2026-10-04 run shows.

## The arm where it matters (2026-10-04 run, for comparison)

At [`53cd8e6`](https://github.com/elang2/agent-budget-semantics/tree/53cd8e6): `results/S2-toolchoice-2026-10-04.json`,
budget 3.

| Framework | Version | Arm | Model calls | Tool calls | `tool_choice: none` sent | Toolless requests | Honoured | `stopped_by` |
|---|---|---|---|---|---|---|---|---|
| agno | 1.2.5 | ignore | 10 | 9 | 7 | 0 | 0 | completed |
| agno | 1.2.5 | honour | 4 | 3 | 1 | 0 | 1 | completed |
| openai_agents | 0.22.0 | ignore | 3 | 3 | 0 | 0 | 0 | budget |
| openai_agents | 0.22.0 | honour | 3 | 3 | 0 | 0 | 0 | budget |
| semantic_kernel | 1.44.1 | ignore | 4 | 4 | 0 | 1 | 0 | completed |
| semantic_kernel | 1.44.1 | honour | 4 | 3 | 0 | 1 | 1 | completed |
| crewai | 1.15.16 | ignore | 4 | 4 | 0 | 1 | 0 | error |
| crewai | 1.15.16 | honour | 4 | 3 | 0 | 1 | 1 | natural |

agno under a budget of 3 makes 10 model calls against a counterparty that ignores the stop request, and 4
against one that honours it. A record claiming the budget held is false in the first arm and true-looking
in the second, which is the reject vector this family exists for.

## What the vectors will assert

- **Reject:** a record that declares a model-call budget beside a request ledger exceeding it (agno,
  `ignore` arm: budget 3, ledger 10).
- **Reject:** a record that credits the stop to the agent's own enforcement while its ledger shows the
  counterparty honoured a stop request (agno, crewai and semantic_kernel, `honour` arm, honoured 1).
- **Accept:** the hard-stop frameworks above, one arm each, where the ledger count is at or under the
  declared budget.
- **No vector** asserts a stop mechanism for langgraph or llamaindex until a run records whether any
  request followed the unexecuted tool call.

Open at the source and useful here: a longer script that separates "stopped at the budget" from "ran out
of script" without raising the budget past the thing being measured (section 7 of the write-up).
