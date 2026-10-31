# Bounded event absence, three C1 cases

Source: Mikhail Sergeev, who prepared the three cases and the mapping note on 2026-10-28 to compare a standalone finite checker with `event_absence/v2` in `probity-verify`. His inputs are kept byte for byte under [source/](source/), pinned by length and SHA-256 in [MANIFEST.json](MANIFEST.json). His note is [source/witnessability-probity-c1.md](source/witnessability-probity-c1.md).

| Case | Decision under the default PEER requirement | Under EXTERNAL |
| --- | --- | --- |
| `C1-01-covered-empty` | `supported`, `absence_within_covered_scope` | `not_established`, `witness_scope_below_required` |
| `C1-02-event-with-gap` | `contradicted`, `event_observed` | unchanged |
| `C1-03-empty-with-gap` | `not_established`, `observation_coverage_unestablished` | unchanged |

These are the decisions `probity-verify` 0.2.2 returned when the cases were run, and they match his source-derived expectations. [EXPECTED.json](EXPECTED.json) keeps them outside the reader's input. The checker-side files under `source/checker/` are his and are carried unrun here; a result from his checker on the same three cases gives the pairing.

```sh
uv run --no-project --with probity-verify==0.2.2 python interop/event-absence-c1-sergeev/run.py
```

The synthetic records establish neither authenticated identity or custody nor that an event occurred or capture was complete; the note states these limits.
