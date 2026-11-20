# Adjudication disagreement cases D1 and L1

Cases where `event_absence/v2` in agent-evidence-verify and the standalone finite checker in [Witnessability/witnessability-research](https://github.com/Witnessability/witnessability-research/tree/719b243b6c8b1bcd4429cab6347bb3e77ead6a5e) read the same records under declared binding and failure-domain assumptions. The exact checker, the C1 cases and the lost-binding candidate are Mikhail Sergeev's. The case table, with each assumption and the reason for each difference, is [docs/proposals/joint-case-table-wexp.md](../../docs/proposals/joint-case-table-wexp.md).

Every file under `inputs/`, and `MANIFEST.json`, `EXPECTED.json` and `CHECKER-PIN.json`, is written by `gen.py`; never edit them by hand.

```sh
python3 interop/adjudication-disagreement-d1/gen.py --check
uv run --no-project --python 3.13 --with agent-evidence-verify==0.5.1 python interop/adjudication-disagreement-d1/run.py
python3 interop/adjudication-disagreement-d1/run_checker.py --checker-root ../witnessability-research
```

The records are synthetic. They establish neither authenticated identity or custody nor that an event occurred or capture was complete.
