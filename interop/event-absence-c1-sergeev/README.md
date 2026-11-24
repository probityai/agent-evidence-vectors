# Bounded event absence, three C1 cases

Source: Mikhail Sergeev, who prepared the three cases and the mapping note on 2026-10-28 to compare a standalone finite checker with `event_absence/v2` in `probity-verify`. His inputs are kept byte for byte under [source/](source/), pinned by length and SHA-256 in [MANIFEST.json](MANIFEST.json). His note is [source/witnessability-probity-c1.md](source/witnessability-probity-c1.md).

| Case | Decision under the default PEER requirement | Under EXTERNAL |
| --- | --- | --- |
| `C1-01-covered-empty` | `supported`, `absence_within_covered_scope` | `not_established`, `witness_scope_below_required` |
| `C1-02-event-with-gap` | `contradicted`, `event_observed` | unchanged |
| `C1-03-empty-with-gap` | `not_established`, `observation_coverage_unestablished` | unchanged |

These are the decisions `probity-verify` 0.2.2 returned when the cases were run, and they match his source-derived expectations. [EXPECTED.json](EXPECTED.json) keeps them outside the reader's input. The checker-side files under `source/checker/` are his; compare.py runs them.

```sh
uv run --no-project --with probity-verify==0.2.2 python interop/event-absence-c1-sergeev/run.py
```

## Both checkers on the same inputs

[compare.py](compare.py) runs the standalone checker Mikhail Sergeev published in [Witnessability/witnessability-research](https://github.com/Witnessability/witnessability-research) and `event_absence/v2` on the one set of pinned bytes under [source/](source/), and fails the build when either side flips or the two stop agreeing. The checker engine is a checkout at the commit in [CHECKER-PIN.json](CHECKER-PIN.json), each module checked against the hash listed there. [PAIRING.json](PAIRING.json) maps `TRUE`, `FALSE` and `UNRESOLVED` to `supported`, `contradicted` and `not_established`. [compare_test.py](compare_test.py) shows that a flip on either side fails. A new checker release is a change to CHECKER-PIN.json alone.

```sh
git clone https://github.com/Witnessability/witnessability-research checker
git -C checker checkout --detach "$(python3 -c "import json;print(json.load(open('interop/event-absence-c1-sergeev/CHECKER-PIN.json'))['commit'])")"
uv run --no-project --python 3.13 --with probity-verify==0.2.2 python interop/event-absence-c1-sergeev/compare.py --checker-root checker
```

The synthetic records establish neither authenticated identity or custody nor that an event occurred or capture was complete; the note states these limits.
