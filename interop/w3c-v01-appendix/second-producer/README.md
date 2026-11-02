# Second producer for the v0.1 reporting format

`from_log.py` turns a generic agent run log into a v0.1 report of the W3C
Agent Conformance CG, then runs the package's reference reader on it.

```sh
uv run --no-project --with agent-evidence-vectors==0.31.1 python \
  interop/w3c-v01-appendix/second-producer/from_log.py \
  interop/w3c-v01-appendix/second-producer/sample-run.jsonl -o report.json
```

It prints `conforms`. Exit 0 conforms, 1 the reader lists rejected rows, 2 the
log could not be mapped and no report was written.

## Log format

JSONL. The first line is `{"run": {"checker", "constraint_set", "domain"}}`.
Each later line is one check: `check`, `outcome`, optional `reason`, `detail`
and `control` (the outcome of a control run under that same checker and
configuration). An Inspect eval log converted to JSON is read directly
(`sample-inspect-log.json` is hand-written in that shape, not a recorded run).

## Mapping (v0.1 sections 1.1, 1.2, 5.4)

| outcome | state | cause (`reason`) |
|---|---|---|
| pass, fail | pass, fail | none; a reason is refused |
| inconclusive, error, timeout | inconclusive | failed, unavailable, resource_exhausted, unsupported_input, availability-failure; timeout defaults to resource_exhausted |
| skipped | not-exercised | not_applicable, disabled_by_policy, unsupported_input, out_of_scope, withheld, unavailable, precondition-unsatisfiable |
| void | void | evidence-does-not-hold (default), integrity-failure, confinement-failed-during-check |

Inspect: `C` is pass, `I` is fail, a sample error is inconclusive/failed, a
sample limit is inconclusive/resource_exhausted. Partial credit (`P`, `N`) has
no state and is refused.

`negative-capable` is `control-failed` when a control's outcome is `fail`,
else `shown-by-run` when a declared check failed, else `nothing`. A control
that did not fail shows nothing and is not reported.

## Refused, not guessed

An outcome outside the table, a reason outside the list for its state, free
text as a reason, an unknown field, a repeated check id, a missing header.
`python -m pytest second-producer` holds each case.
