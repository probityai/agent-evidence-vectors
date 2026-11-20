# What the weekly rerun checks, row by row

Every row below is checked from its pins with `python rerun.py <row>` on Linux x86_64, Linux arm64 and macOS arm64, on
each change to this directory and weekly. Most rows rerun a posted program or compare what pinned programs print. Two
rerun nothing: R4-nonascii only reads the reports committed at its pinned commit, and R15, for which no command was
posted, only reads the file served at its pinned URL, so its result file says recorded rather than reproduced. Nothing
is adjusted to make a value match. A row whose check does not hold is a red job, with the posted and observed values
in its result file.

A green row means that every condition in its "Decides green" cell held on that run, and nothing more. It is not a
statement that the run reproduced every output byte for byte. Where a row lets whole files differ, decides on counts,
exit statuses, printed lines or verdicts, or records a value without deciding on it, its line says so. A green row is
also not a reading of whether a historical run happened as reported: the check compares what the pins produce today
with what was posted.

Each row runs the pins it posted and no others, and the older pins stay as posted. A green weekly rerun therefore says
nothing about a release newer than a row's pins: a newer release is checked only once rows.json names it as a pin of
its own, as R9, R10 and R14 name each release they cover. What a rerun of fixed pins can show is a change underneath
them, such as a toolchain, a platform or a served file that no longer gives the posted value. Every commit pin is a
full SHA and a checkout whose HEAD differs from it is refused, so a moved tag cannot change what a row runs.

| Row | Kind | Decides green | Recorded, not deciding | Allowed to differ, and why |
|---|---|---|---|---|
| R1 | rerun | report.json and conformance-report.json written by the pinned emitter have the posted SHA-256 | none | none |
| R2 | rerun | every file in the posted zip comes out byte-identical, except the two whole files in the last column; no file is missing and none is extra | the SHA-256 of the rerun's SHA256SUMS against the posted one (it differs whenever summary.json does) | summary.json as a whole file: it records the Python version (0063); SHA256SUMS as a whole file: it lists summary.json |
| R3 | rerun | every file in the posted zip, SHA256SUMS included, comes out byte-identical; no file is missing and none is extra outside evaluation/ | the SHA-256 of SHA256SUMS against the posted value; the count of files under evaluation/ | evaluation/: raw per-check traces the run leaves beside the records, which SHA256SUMS does not list (0062) |
| R3-v01 | rerun | the posted converter, run over R3's rerun records, writes run-report-v01.json with the posted SHA-256; the file in the posted zip has that SHA-256 too; the recount of Nov/0023 prints the three posted lines | none | none |
| R4 | rerun | every committed record file comes out byte-identical, except the two whole files in the last column; the committed SHA256SUMS has the posted SHA-256 | none | run.json as a whole file: it carries the runner and the environment (0099); SHA256SUMS as a whole file: it lists run.json |
| R4-driver | rerun | the fixture has the posted SHA-256, and the fresh report equals recorded-run.json as parsed JSON | the SHA-256 of both files; the number of matching cases | none |
| R4-nonascii | read of committed files | each of the three committed reports has the posted number of checks whose tool name holds a non-ASCII character; no program is rerun | each report's check count and the matching check ids | none |
| R5 | rerun | the emitter, run with --verify, writes finality-threshold-report.level1.json with the posted SHA-256 | the file's size | none |
| R6 | rerun | at each pinned commit: check.py --controls exits 0 and its output contains the posted line "limited checks: ok"; the unittest suite exits 0 with the posted 6 tests and none skipped; the four named Rust approval tests pass and no other test runs | the SHA-256 and last line of check.py's output | no output file is compared: no output digest was posted, and the producer's original report is kept as retained input (R6-v01 reads it) |
| R6-v01 | rerun | the posted converter, run over the report R6 fetches, writes run-report-v01.json with the posted SHA-256; the posted file has that SHA-256 too | none | none |
| R7 | rerun | the packet MANIFEST.json and the portable helper have the posted SHA-256; the packet tests exit 0 with the posted count and none skipped; the helper exits 0, reports criteria_passed, and its state recount equals the posted outcomes | none | none |
| R8 | rerun | the posted reader, run over the corpus at its tag, writes verdicts.tsv and not-selected.tsv with the posted SHA-256 | the number of corpus members | none |
| R8-compare | comparison | the posted verdicts.tsv has its posted SHA-256; the families outside the selection equal the posted list; judged, selected, numbered, agree, differs and unnumbered equal the posted figures | a second run with only w3c-f-29 excluded, as in 0188 | none |
| R8-compare-169 | comparison | the posted verdicts.tsv has its posted SHA-256; with no family excluded, judged, numbered, agree and the unnumbered split equal the posted figures | the other figures r8_compare.py prints | none |
| R9 | comparison | at each release: corpusDigest recomputes to the posted value and equals the manifest's; the selection counts equal the posted ones; the reference reader exits 0 on the corpus; the readers present at the tag are exactly the readers rows.json names for it (Python and Go at v0.17.4; Python, Go and Rust at v0.18.0 and v0.18.1), every one built and ran, each passes the corpus and fails the probe, its verdict on every W3C-R-016 member equals the manifest's (the result file lists each member where it does not, and any one fails the row), and all give the same verdicts on those members | each reader's version, its verdict digest, and its counts of members that agree with the manifest and that reject under W3C-R-016 | none; a reader absent at a tag is recorded as absent, and a failed build fails the row |
| R10 | comparison | at each release, the Python and Go readers exit 0 and print the posted bytes for -0; at v0.17.4, the count of -0 number tokens in the corpus equals the posted one | the files the tokens are in | none |
| Item-7.3-10 | rerun | at the pinned commit, json.load raises TypeError on the posted number of members; the reader's own loader rejects and accepts the posted numbers, under the posted rows, and every member gets its manifest verdict | each member's printed lines | none |
| R11 | rerun | the posted reader, run over the posted selection, prints output with the posted SHA-256 | the number of members | none |
| R12 | rerun | the scorer's verdict on each of the raw, signing and verify paths equals the posted per-member verdict for every posted member, and every posted member is scored | the SHA-256 of the scorer output; per-path agreement with the expected verdict | none |
| R13 | rerun | experiment.py and the unittest suite exit 0, with the posted test count and none skipped; every file SHA256SUMS lists matches, and that is the posted number of files | the SHA-256 of results.json | none |
| R14 | comparison | each listed reader release gives the posted verdict on every report the R1 to R5 reruns wrote, and exits 0 | the rejection rows each reader names | none |
| R15 | no command | the census file served at the pinned URL has the posted row count and number of DEMONSTRATED rows | its SHA-256 and whether it equals the captured bytes; its as_of date and full state tally | no command was posted, so nothing is rerun; byte equality with the capture is recorded and does not decide |

Who maintains it: the appendix's author (Sankalp Gilda) keeps rerun.py, rows.json and the workflow; each row's
producer owns the row's content and its posted values. Roel owns the results table in the paper; this list only
says which of its rows have a check behind them, and what that check decides.

`tests/test_checks_md.py` holds this table to rows.json: every row has exactly one line, in the same order.
