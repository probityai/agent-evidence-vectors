# Reader conformance matrix for the v0.1 paper's reports

Row R14 of the [results table](../README.md) summarises reader verdicts people
posted on the list. This directory replaces that summary with a run: every v0.1
report the appendix rows write, read by every reader that can read one, with
single-field negative controls beside each report.

```sh
python matrix.py run --work .build/m --observed observed.json   # rerun, mutate, read
python matrix.py check observed.json                            # fails when a cell moved
python render.py                                                # matrix.json -> tables
```

[`matrix.md`](matrix.md) has every cell and the controls table, and
[`verification.tex`](verification.tex) the same two tables for the paper. Both
are generated from [`matrix.json`](matrix.json), and `tests/test_matrix.py`
fails when they disagree with it.
[`../../../.github/workflows/w3c-v01-matrix.yml`](../../../.github/workflows/w3c-v01-matrix.yml)
runs the whole matrix on ubuntu-24.04, ubuntu-24.04-arm and macos-15 on each
change here and weekly, and fails when a cell or an input digest differs from
the committed table.

## Inputs

`matrix.py` imports [`../rerun.py`](../rerun.py) and reruns R1, R2, R3, R3-v01,
R4 and R5 from their pins, then keeps every file those reruns write that
declares the v0.1 format. A scan of the rerun trees of R1 to R5, R7 and R13 on
2026-11-01 found exactly the nine reports `REPORTS` lists. Which rows yield a
report, and why the others do not, is the first table of `matrix.md`, from
`ROW_META` in `matrix.py`:

- R1, R2, R3-v01, R4 and R5 yield v0.1 reports.
- R3 writes records in the producer's own encoding; R3-v01 re-encodes them.
- R4-driver writes this repository's comparison report, not a v0.1 report.
- R6 prints a check line and test results and writes no report.
- R7 is a native (state, reason) packet, not a v0.1 report: a footnote, no cell.
- R8 and R11 are readers' verdicts over corpus members; R8-compare, R9, R10,
  R12 and R14 compare verdicts or bytes; R13 writes case files, none in the
  v0.1 format; R15 is a census file.

## Readers

- The Python reference reader, `agent_evidence_vectors.w3creport`,
  `shape_errors` then `rejections`, at 0.12.0, 0.13.0, 0.17.4 and 0.18.1 (the
  releases the table names) and at 0.31.0 (the newest on PyPI on 2026-11-01),
  each installed by uv at that exact version ([`drivers/py_reader.py`](drivers/py_reader.py)).
- The Go reader in `corpora/w3creport.go` at v0.18.1 and at the checked-out
  commit. Its command line reads a whole corpus; its own path for one emitted
  report is `w3cEmittedReportFindings`, which calls `decodeJSONNumbers`,
  `w3cShapeErrors` and `w3cRejections`. The driver
  [`drivers/w3c_matrix_driver_test.go.txt`](drivers/w3c_matrix_driver_test.go.txt)
  is copied into `corpora/` for the run, calls those three, and is removed.
- The Rust reader in `readers/w3c-report-rs` at v0.18.1 and at the checked-out
  commit, `--report <file>`. The matrix reads its `rows:` line; the
  layout and leaf-count lines it also prints are kept in the cell's note.
- Rouiada Abbas's reader, from the tarball of 2026Oct/0039 (sha256
  `396dbac8...`, the R8 pin), and Lars Kroehl's reader at
  `MoltyCel/reporting-format-v01-reader` `6d8ee54b` (the R11 pin). Both were
  written from the spec text and both read corpus members, so the matrix wraps
  each report as a member: the `members()` adapter in `matrix.py` writes
  `{"id": <input id>, "subject": <report>}` and nothing else. With no
  `resolves` store, a referenced observation reads as unresolved, which both
  readers report as such. Their `cannot tell` verdict is kept as it is.

## Negative controls

[`mutants.py`](mutants.py) writes, for each report, one mutant per target it
can aim at: rows 1 to 14 of the rejection table, W3C-R-019 (a state outside the
enumeration), W3C-R-016 and W3C-R-021 (moved against compared, and declared
moved against recomputed), W3C-R-020 (a root altered, and a state flipped with
the root kept), W3C-R-015 (the leaf count), W3C-R-017 (a roll-up count, and the
roll-up dropped), W3C-R-018, W3C-R-023, W3C-R-013, and two dropped required
members (`format`, a check's `state`) that make the report not v0.1-shaped.
Each changes one JSON member and names the row it should hit; a target the
report gives no member to aim at is listed with the reason. R5's report, with
150,006 checks, gets only the flipped state under an unchanged root.

A non-ASCII check identity needs the root recomputed, so that pair changes two
members: with the root over the RFC 8785 form (UTF-8) it is a positive control,
and over the ASCII-escaped form it is aimed at W3C-R-020.

Changing a check also changes its leaf, and changing a state the roll-up
counts, so readers that recompute those name W3C-R-020 or W3C-R-017 beside the
target. Only the target is scored. A reader that accepts a mutant is recorded
as accepting it; nothing is adjusted.

## Verify commands

`matrix.json` carries one command per report in the form
`uvx agent-evidence-vectors==<release> --read-w3c-report <file>`, for the flag
the next release adds. Until that release is published the commands carry
`{release}` and the LaTeX the macro `\aevreadrelease`.
