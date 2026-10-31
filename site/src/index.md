---
title: "Agent Evidence Conformance Board"
subtitle: "Check claims about agent actions."
description: "Open-source tools, conformance tests and retained runs for checking claims about agent actions."
---

Probity builds evidence tools for agent harnesses, reviewers and platform teams. Use them to define claims, test verifiers, inspect action records and apply workload policy.

[Choose a project](start.html) for your task, or [find a retained run](runs.html) by its claims, roles and limits.

## The public code

| Task | Start with |
| --- | --- |
| Define an evidence claim | [Vocabulary](start.html#vocabulary) |
| Test a verifier | [Vectors](start.html#vectors) · [Recorded Action controls](automation.html#check-a-verifier-in-ci) |
| Record file actions or check delegation runs | [Observer](start.html#observer) |
| Check a supplied claim | [Verify](start.html#verify) |
| Apply workload admission policy | [Admission](start.html#admission) |
| Work with canonical JSON or signature envelopes | [jcs-admit](start.html#jcs-admit) and [dsse](start.html#dsse) |

The task page links a pinned quickstart for each project. For scripts and agents, use the [automation guide](automation.html), [llms.txt](llms.txt) or [project catalog](catalog.json).

![Choose by task: Vocabulary defines evidence terms; Vectors tests verifier cases; Observer records actions; Verify checks supplied claims; Admission applies workload policy; jcs-admit handles canonical JSON; dsse handles signature envelopes; Atlas publishes mechanisms and retained runs. These are entry points, not a required sequence.](assets/component-tasks.svg)

[Replay an evidence decision](replay-an-evidence-decision.html) to inspect a retained signed packet, admit it once and reproduce the replay, authority and signature refusals. The walkthrough checks the decision from recorded bytes; it does not execute the original agent action. The essay [*Independent AI evaluators need evidence they can verify*](https://thepragmaticquant.com/independent-evaluators-need-something-to-verify/) (October 14, 2026) explains which records a buyer should require before an agent action counts as approved, and ends with this replay.

Inspect accepted our [bounded native result reader listing](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c9f2d1cadb5e46cd8b89d217c7a2a1f816bce057/docs/extensions/extensions.json) on October 3, 2026, and the [live extensions catalog](https://inspect.aisi.org.uk/extensions/) lists it (checked October 14). [Read the pinned consumer guide](https://github.com/probityai/agent-evidence-observer/blob/71ac0b2126473316655184235000647a6dd0f5cf/docs/NATIVE-CONSUMER-CI.md).

Read [why a green test suite can contain negative conclusions](evidence-test-meaning.html). The worked example separates a correct test, a valid record and the result of an action, with retained files and a checking procedure.

## Agent action assurance

The [assurance atlas](atlas.html) maps the mechanisms teams use to control agents and check their actions. The [Open Evidence Lab](lab.html) publishes run artifacts, replay commands and review state. [Experiments](experiments.html) document the procedure behind each recorded check.

Sources and re-derive commands live in the [claim ledger](claims.html). The [version ledger](versions.html) records each artifact and its release state.

## Research {#peer-reviewed-work}

*Three Jobs, Not One* explains why deciding, containing and witnessing agent execution need separate mechanisms ([Zenodo](https://doi.org/10.5281/zenodo.21935891)).

Sankalp Gilda and Shlok Gilda, *Position: Evaluation Scores Are Perishable Knowledge Claims*, GEM ([paper](https://doi.org/10.18653/v1/2026.gem-main.80)).

[Working in the repository](repository.html) covers the sources and checks; [maintaining the catalog](catalog.html) covers new project entries.
