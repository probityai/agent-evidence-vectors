# Request and effect join fixture

A reader-neutral contract for the request/effect cases: ten synthetic records, one expected classification each,
and nothing that requires either implementation's internals. It is for anyone writing a third reader against
[the shared case table](CASE-TABLE.md) and wanting the same three seams tested the same way.

```sh
python3 run_contract.py          # one line per case, then the comparison
python3 -m unittest discover -s tests -v
```

The output ends with `10/10 cases match expected.json`. Each line is a `case_id`, a classification
(`established`, `refused`, `not_established`, `invalid_input`) and the findings behind it.

The three seams the corpus freezes:

| Seam | Case pair | What a reader must not do |
|---|---|---|
| Missing evidence versus absent key | `S-05` (null) and `S-06` (key absent) | Treat an absent key as an empty read. `S-05` is `established`; `S-06` is `invalid_input`. |
| A refusal versus an untouched store | `S-09` | Report `later_state_unchanged` because a decision denied. A denial is observable; an unwritten file is not. |
| Semantic comparability versus provenance equivalence | `S-00`, `S-04` | Treat a row that is comparable to another project's case as the same evidence. Every case here is `provenance_equivalent: false`. |

Version 0.1. The vectors are synthetic and were written for this contract; no producer verifier is run here,
no execution produced these bytes, and no file was read. `run_contract.py` was written by the same author as the
contract and the expected results, so it is answer-exposed: it shows the contract is implementable, not that an
independent reader agrees.

| Read next | Content |
|---|---|
| [Input contract](docs/INPUT-CONTRACT.md) | Record shape, order of checks, classification, findings, what counts as not established |
| [Cases](fixtures/cases.json) | The ten records, with every ref derived from its preimage |
| [Expected results](expected.json) | One classification and finding set per case, plus the equivalence mapping |
| [Case table](CASE-TABLE.md) | The experiment these cases belong to, and the producer runs beside it |
| [Join the case](https://github.com/probityai/agent-evidence-vectors/issues/352) | Bring a reader, a run, or a case that splits these seams differently |
