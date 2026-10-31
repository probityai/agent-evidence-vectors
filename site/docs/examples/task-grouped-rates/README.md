# Task-grouped rates with a matched benign control

A small worked example for reporting a failure rate when each task has repeated
episodes. Both arms of a task travel together through the calculation. The
episode labels are invented; a robot run can supply the same fields with its
own retained inputs and provenance.

Run from the repository root with Python 3.11 or later. The reader has no extra
dependencies:

```sh
python3 tools/check_grouped_rates.py \
  --input examples/task-grouped-rates/input.json \
  --expect examples/task-grouped-rates/report.json \
  --output grouped-rate-report.json
```

`input.json` retains every episode ID, label and task assignment, plus the
declared matching conditions, rubric and population. `contract.json` states the
calculation and its limits. `report.json` binds the exact input and reader
SHA-256 values and keeps every resampling draw.

## Counts and two different questions

Both arms use the same declared agent, environment, budget and outcome rubric;
the declared attack intervention differs. Matching these declarations does not
verify the actual conditions of a producer run.

| Task | Attack failures / resolved episodes | Benign failures / resolved episodes | Unresolved in each arm |
|---|---|---|---|
| T01 | 8/10 | 2/10 | 0 |
| T02 | 3/4 | 1/4 | 0 |
| T03 | 0/2 | 1/2 | 0 |
| T04 | 1/2 | 0/2 | 1 |

There are 19 attempts and 18 resolved episodes in each arm. Pooling resolved
episodes gives attack 12/18 and benign 4/18, a difference of 4/9. Giving each
task equal weight gives attack 41/80 and benign 19/80, a difference of 11/40.
The first answers a question about the retained episode mix; the second answers
a question about an equally weighted task mix. Declare the target before
choosing an aggregation rule.

Unresolved labels stay visible. They are excluded only from those named
resolved-rate denominators. Over all attempted episodes, the attack failure
rate lies between 12/19 and 13/19, and benign between 4/19 and 5/19, depending on
how the unresolved labels turn out. These are worst-case missing-label bounds,
not sampling intervals. An empty or unresolved-only task arm has a null rate.
It stays in the population and blocks the equal-task estimand; the reader never
silently removes it.

## Resample tasks, retaining repeats and controls

The sampling unit is a paired task cluster. Each draw selects four tasks with
replacement, keeping both arms and every episode of each selected task. It
recomputes both estimands and their contrasts jointly.

The toy enumerates all 4^4 = 256 ordered draws. For nominal level 0.95 it uses
the left inverse empirical CDF: rank `max(1, ceil(p * B))`, without interpolation.
The endpoint ranks are 7 and 250. The episode-weighted contrast interval is
[-1/10, 10/17]; the equal-task contrast interval is [-1/4, 23/40]. Every exact
rational value and a convenience decimal appear in the report.

Those are exact summaries of this empirical resampling distribution. Four
invented tasks do not establish 95% population coverage. Generalization would
require independent exchangeable task clusters and an appropriate sampling
design. Shared scenes, sessions, agents or robots can leave dependence across
tasks; the input must state it. A degenerate distribution is labelled
`degenerate`. A missing draw statistic blocks its interval, with all missing
draws retained.

Repeating each episode within its original task preserves these estimands and
the entire task-bootstrap distribution. It adds no independent tasks. The
tests also show how an episode-iid variance calculation would incorrectly
shrink after that cloning. Selectively adding repeats can change the pooled
episode target, while equal-task weighting keeps each task's weight fixed.

For larger inputs, an explicit `monte-carlo` configuration requires a seed and
replicate count. `sha256-counter-rejection-v1` generates paired task indices
reproducibly; all draws are retained. It approximates the empirical bootstrap
distribution and adds Monte Carlo error. The byte, population and draw caps are
in the contract.

## Sources and a producer-owned next run

[Cameron and Miller's published article](https://doi.org/10.3368/jhr.50.2.317)
describes whole-cluster resampling and warns about few clusters and missing
bootstrap values. [SciPy 1.16.2's bootstrap documentation](https://docs.scipy.org/doc/scipy-1.16.2/reference/generated/scipy.stats.bootstrap.html)
describes paired index resampling and percentile intervals. This reader uses
its own explicit nearest-rank convention; neither source establishes coverage
for this example. The source record, `source-record.json`, keeps the originally
checked July 2014 author manuscript, its version and hashes. The current
citation uses the publisher's DOI; this route update does not replace that
checked manuscript or change the reader's methods and results.

A producer can replace the labels with a task-grouped attack/benign run, pin
its source, retain raw episodes and disclose missing labels, sampling design
and residual dependence. A Lab submission still needs its own evidence and
review. This example does not change the measured register.
