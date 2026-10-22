# One resumed agent task, three separate claims

When an agent run pauses (a tool asks for confirmation, a delegated sub-agent waits
for the user) and resumes, three different faults can occur. This corpus judges each
one on its own axis, so a record cannot report one fault as another.

| Axis | ESTABLISHED means |
| --- | --- |
| `turn_owner` | The turn after a paused sub-agent in a delegated mode (`task`, `single_turn`) belongs to the agent that delegated to it. The sub-agent may return its result to the delegator; it may not answer the user. A chat sub-agent keeps its own turn. |
| `artifact_replay` | The resumed response's artifacts are emitted as exactly their new parts. A part is new unless it equals, at the same position, the part last emitted under the same id. An artifact replaced under the same id is new whole, even when its first parts equal the old ones. |
| `repeated_effect` | Each logical action had at most one effect, as an independent observer recorded it. |

A replayed artifact is not a repeated effect, and a display that suppresses replayed
artifacts must not hide a real second effect: `earlier_turn_artifacts_replayed` and
`second_effect_hidden_by_deduplicated_display` are the two halves.
`effect_correctness` and `observation_coverage` stay `NOT_ESTABLISHED` in every case.

The cases follow the resume paths that google/adk-python#7605 (paused `single_turn`
routing) and #7604 (resumed-task artifacts) change, and sit beside the delegation
lifecycle recovery cases in `corpora/delegationlifecycle.go`. Artifact parts are
`sha256` digests of their content, so a producer maps its own parts onto them.

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors-resume-turns --output resume-turns-result
```

The command checks the corpus against `corpus/manifest.json`, judges every case without
reading its expected answer, writes `report.json`, and exits 1 if any case differs.

## Cases

Built by `scripts/resume-turns-build.py`; CI checks that the committed files are what
it writes. Every axis has `ESTABLISHED`, `CONTRADICTED` and `NOT_ESTABLISHED` cases.

- Turn owner: `intact_resume`, `paused_single_turn_agent_answers_user`,
  `task_mode_worker_returns_to_delegator`, `chat_sub_agent_keeps_its_turn`,
  `delegation_mode_unrecorded`.
- Artifact replay: `earlier_turn_artifacts_replayed`,
  `replaced_artifact_shares_leading_part`, `replaced_artifact_emitted_whole`,
  `appended_part_equal_to_an_earlier_one`, `no_earlier_snapshot`.
- Repeated effect: `second_effect_hidden_by_deduplicated_display`,
  `replayed_artifacts_and_a_second_effect`, `effect_reported_only_by_the_tool`.
