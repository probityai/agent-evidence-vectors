# PR 572 lane status (temporary; delete in the next commit on this branch)

The matrix run of CI run 43634214291 recorded the R3 input as missing: the path
R3/out/records/run-report.json does not exist, because the R3 emitter writes its records
straight into out/ when it writes no records/ directory (rerun.row_r3). matrix.py run also
exits 0 with a missing input. Fix: resolve the path with the same rule as rerun.row_r3, and
make cmd_run return 1 when any listed report is missing. Then regenerate matrix.json,
matrix.md and verification.tex with `matrix.py adopt` from the ubuntu observed.json.
Full steps: probity-lanes/catchup-1114/act-w3c-ietf/STATUS.md.
