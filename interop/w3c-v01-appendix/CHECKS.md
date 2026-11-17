# What the weekly rerun checks, row by row

Every row below reruns from its pins with `python rerun.py <row>` on Linux x86_64, Linux arm64 and macOS arm64, on each
change to this directory and weekly. The check compares the value the row's producer posted with the value the rerun
writes. Nothing is adjusted to make a value match. A row that differs is a red job, with both values in its result file.
The older input and checker pins in each row stay as posted; the check does not repeat history, it tells us when a
newer release or a moved pin changes what the row says.

| Row | Kind | What is compared (posted value against the rerun) | Excluded from the comparison, and why |
|---|---|---|---|
| R1 | rerun | conformance-report.json; report.json | none |
| R2 | rerun | SHA256SUMS | summary.json: records the Python version (0063); SHA256SUMS: lists the file above |
| R3 | rerun | SHA256SUMS | none |
| R3-v01 | rerun | run-report-v01.json | none |
| R4 | rerun | SHA256SUMS (as committed) | run.json: carries the runner and the environment (0099); SHA256SUMS: lists run.json |
| R4-nonascii | rerun | checks with a non-ASCII tool name, per report | none |
| R4-driver | rerun | report equals recorded-run.json | none |
| R5 | rerun | finality-threshold-report.level1.json | none |
| R6 | rerun | exit; stdout; tests | none |
| R6-v01 | rerun | run-report-v01.json | none |
| R7 | rerun | outcomes; packet MANIFEST.json; portable helper; tests | none |
| R8 | rerun | not-selected.tsv; verdicts.tsv | none |
| R8-compare | comparison | agree; differs; judged; numbered; outside_selection_families; selected; unnumbered; verdicts.tsv | none |
| R8-compare-169 | comparison | agree; judged; numbered; unnumbered; verdicts.tsv | none |
| R9 | comparison | v0.17.4; v0.18.0; v0.18.1 | none |
| R10 | comparison | v0.17.4; v0.18.1 | none |
| Item-7.3-10 | rerun | members raising TypeError; rejected; accepted; rejection row | none |
| R11 | rerun | reader output | none |
| R12 | rerun | per-member verdicts | none |
| R13 | rerun | files; tests | none |
| R14 | comparison | R1; R2; R3; R4; R5 | none |
| R15 | no-command | tally | none |

Who maintains it: the appendix's author (Sankalp Gilda) keeps rerun.py, rows.json and the workflow; each row's
producer owns the row's content and its posted values. Roel owns the results table in the paper; this list only
says which of its rows have a check behind them, and which fields that check compares.

Rows with no compared output: R6 compares exit status, printed lines and the four Rust approval tests (no output
digest was posted); R15 has no posted command, so the check only tallies the census file's own state fields.
