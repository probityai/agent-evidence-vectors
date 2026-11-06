# Every number in the 5 November arXiv draft, rerun against its pin

The draft is `arxiv-v01-draft-2026-11-05.md`, sha256
`f2881f9c038969300d3de52e61ab4ce813069431edb1b2177fd61b4931495b23`, posted by
Evgenii Arsentev in
[2026Nov/0017](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Nov/0017.html),
which asked the authors to check it by Sunday 8 November.

## How it ran

From the repository root, `python3 interop/w3c-v01-appendix/rerun.py --all`
ran on Linux x86_64 on 5 November at 21:31 UTC. R1, R2, R3, R3-v01, R4,
R4-driver, R5, R6, R6-v01, R7, R8, R8-compare and R9 to R14 reproduced (18 of
18); R15 is recorded, because no command was posted for it. The counts below
were taken from the run's output files (the state counts of each report,
`fixtures.json`, the control roll-ups, the reader outputs against
`MANIFEST.json`), not from `rows.json`.

The appendix workflow runs every row on Linux x86_64, Linux arm64 and macOS
arm64. It was green on all three at `0629bc2f`
([run 41766757899](https://github.com/probityai/agent-evidence-vectors/actions/runs/41766757899),
54 of 54 jobs) and at `b733f45e86`, the merge of PR 438
([run 42112040509](https://github.com/probityai/agent-evidence-vectors/actions/runs/42112040509),
54 of 54 jobs).

## Table

"Same" means the rerun value equals the draft value. "Partial" means the
figure the draft states is not itemised by the harness, so only part of it was
rerun.

| Draft section | Draft value | Rerun value | Pin | Row |
|---|---|---|---|---|
| Abstract, 3, 8 R1 | 272 records, 239 fail, 31 pass, 2 inconclusive; shown-by-run | same | agent-evidence-vectors 0.12.0, `2f3aee40` | R1 |
| 3 R1 | `report.json` `37288d8d`, `conformance-report.json` `ee349e66` | both identical | same | R1 |
| 3 R1, 7.4 | `uvx agent-evidence-vectors==0.32.1 --read-w3c-report report.json` prints conforms | conforms, exit 0, run by hand on 5 November; `33d5451` (v0.18.1) also accepts R1 | 0.32.1; v0.18.1 | R14 |
| 4.1, 8 R4 | 76, 67 and 16 checks, all pass; controls 3, 3, 2 | same | AgentAvow `fbbbd4ac` | R4 |
| 4.1 | `SHA256SUMS` `c720c68a`; 11 of 13 files identical | same; the other two are `run.json` and `SHA256SUMS` | `fbbbd4ac` | R4 |
| 4.1 | five checks per report carry a non-ASCII tool name | readers 0.12.0, 0.13.0 and 0.17.4 reject R4 as stated; the harness does not itemise the five | matrix | partial |
| 4.1 | after PR 236 the driver accepts the current vector file | fresh report equals `recorded-run.json` (`82ff51ee`) | `82b8bb67` | R4-driver |
| 4.2, 8 R5 | 150,006 checks, 93,731 pass, 56,269 fail, 6 not-exercised; shown-by-run; report `7eb4e434` | same (13,550,212 bytes) | payhelm `c221b478` | R5 |
| 8 R5 | unit "generated draws against thresholds" | wrong unit: correction 2 | payhelm `c221b478` | R5 |
| 4.3, 8 R3 | 48 checks, three accepting seeds, all pass; 44 of 192 mutants | 48 of 48 pass; 44 fixtures; `mutants_total` 192 | eatf `c421dadc` | R3, R3-v01 |
| 4.3 | `run-report-v01.json` `0e608637` conforms | identical | converter `7878f24e` | R3-v01 |
| 4.3 | the 34 checks behind the 44 controls are not pinned or rerun | they are: correction 3 | `7878f24e` | R3-v01 |
| 4.3 | reruns 51 of 52 (Roel), 52 of 52 (Nicolas) | 53 of 53 records identical (`SHA256SUMS` `8e52d99a`), 8 trace files outside the record set; a different file set, not a contradiction | `c421dadc` | R3 |
| 5.2, 8 R2 | 72, 168 and 750 checks, all pass | same | disensor `dbdb6518` | R2 |
| 5.2 | 61 fixtures; controls 24 of 72, 140 of 168, 650 of 750 | same | `dbdb6518` | R2 |
| 5.2 | `SHA256SUMS` `3714de64`; reports, fixtures and isolation identical | 12 of 12 identical | `dbdb6518` | R2 |
| 5.2 | 37 rule and 24 schema controls; 12 of 12 rules flip; 10 of 24 with a second ground | 61 and the per-rule flips reproduce; the 37/24 split and the 10 are not itemised | `dbdb6518` | partial |
| 5.4, 8 R13 | 5 of 5 cases, 23 tests, 15 hashes | same, 0 skipped | prior-run-evidence-v01 `98366047` | R13 |
| 5.5, 8 R6 | 4 checks pass; 5.4 nothing; v01 report `699a52b3` | identical; Rust approval tests 4 passed at `0e59b404` and `8a385471` | assay | R6, R6-v01 |
| 5.5 | 28 controls rejected as stated | `check.py --controls` exits 0; the 28 are not itemised in its output | `0e59b404` | partial |
| 8 R7 | 21 outcomes: 7 pass, 13 fail, 1 inconclusive | same, 18 tests | councilof-ai `d0cbe773` | R7 |
| 7.1, 8 R8 | 92 of 96; 165 selected; 23, 2, 44 of 69; 43 under W3C-R-016; `verdicts.tsv` `de987220`, `not-selected.tsv` `cd6962f3` | same; the same four differ; both digests identical | corpus `99b47c56`, `r8_compare` `44691cf4` | R8, R8-compare |
| 7.1 | all 169 in: 94 of 98; 25, 2, 44 of 71 | no appendix row; not rerun | | none |
| Abstract, 7.3, 8 R9 | corpusDigest `f00d4443` then `f9e58e62`; 83/82 to 41/124; 165 members | same (235 and 269 members in the two corpora; 42 W3C-R-016 rejections moved to accept) | | R9 |
| 7.3 item 1, 8 R10 | -0 | Python `7b2276223a307d`, Go `7b2276223a2d307d` at v0.17.4; both 0 at v0.18.1 | | R10 |
| 7.3 item 10 | 8 members raise TypeError; 6 rejected, 2 accepted at `4cb988e8` | no appendix row; not rerun | | none |
| 7.2, 8 R11 | 102 agree (77 accept, 25 reject), 55 cannot-tell, 8 differ; output `505dfb71` | same | reader `6d8ee54b` | R11 |
| 7.2, 8 R12 | 33 members; each path agrees on 28 | 28, 28 and 28, but the scorer reads 34 members (`members_posted` 33, `members_scored` 34) | moltrust-api `fbc5e288` | R12 |
| 7.4 | 11 report inputs, 11 readers; 168 negative and 7 positive controls; 161 of 168 for Python 0.12.0 to 0.17.4; 168 of 168 for the rest; 58 of 59 for the two readers written from the text | as in `matrix.json` | matrix | matrix |
| 7.4, 8 R14 | the posted reader verdicts | all 18 posted pairs equal what the readers print | releases 0.12.0 to 0.18.1 | R14 |
| 8 R15 | 3 of 592 | census bytes `ff04a12f`: 592 rows, 3 DEMONSTRATED, 586 NOT_RECORDED, 3 UNCHECKABLE; a tally of the file's own state fields, its classifier not rerun | | R15 |

## Corrections, with text to paste

1. **Header and 7.4.** "PR 438 in agent-evidence-vectors (head commit 4acd6549 as shown by GitHub on 5 November), which is open and not merged" becomes "PR 438 in agent-evidence-vectors, merged on 5 November as b733f45e86". In 7.4, "(agent-evidence-vectors, head 4acd6549, open; ...)" becomes "(agent-evidence-vectors PR 438, merged as b733f45e86; the full appendix reruns green on three platforms at 0629bc2f and at b733f45e86)".
2. **8 R5, unit.** Roel Schuurkes is right ([Nov/0020](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Nov/0020.html)). The report holds 150,006 check records, 30 groups of 5,000 plus 6, and each fixture is 5,000 draws, so 150,006 counts checks, not draws. Unit: "checks (six thresholds per generated draw, plus six exclusions)", Roel's wording.
3. **4.3, last sentence.** The 34 checks are pinned: row R3-v01 reruns the converted report, and its control roll-up lists 34 checks. Replace with: "The 44 controls go by the control-failed route over 34 checks; row R3-v01 reruns the converted report, and the 34 reproduce." The same sentence is in the note to Anton in Nov/0017.
4. **9.1, dated update.** Nicolas Rocchia is right ([Nov/0019](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Nov/0019.html)): `matrix.json` has 11 inputs (R1; R2 v0.2, v0.3 and v0.4; R3-v01; the three R4 reports; R5; R6; R6-v01) and no original R3. Roel's replacement text in Nov/0020 is correct as written; add Nov/0004 beside Oct/0188 and Nov/0002.
5. **7.4, matrix wording.** Replace "at the current commit" with "at 1bcac53e84d391cca8e414debd3cb59543e71bed". After the 168 of 168, add: "Rejection counts do not necessarily mean the targeted row was cited; for the two Rust readers it was cited on 159 of 168." After "both miss the same one", add "(Rouiada Abbas's reader answers conforms on it, Lars Kersten Kroehl's cannot-tell)".
6. **Abstract, R15.** Replace "Every row with a posted command reruns from its pins on three platforms" with Roel's sentence from Nov/0020 point 5, and replace "pins each result to its inputs, checker, configuration and archive message" with "pins each result to its inputs and archive message, and to its checker and configuration where they were posted (R15's were not)".
7. **3, the [OWNER] note.** Nicolas confirmed in Nov/0019 that these are two runs; the note can go.
8. **7.2, R12.** The scorer scores 34 members where the row says 33. Agreement is 28 on each path either way; the row's owner decides which count it carries.
9. **7.4, reader pin.** 0.32.1 is verified as written. The newest release is 0.35.0 (4 November): `uvx agent-evidence-vectors==0.35.0 --read-w3c-report <file>` prints conforms, exit 0, on R1, the three R2 reports, R3-v01, the three R4 reports and R5, and the original R3 report still stops at the shape check. Either pin works; 0.35.0 makes the line name the newest release, as it says.

Three figures have no appendix row yet: the 169-member R8 variant, the eight
members of 7.3 item 10, and the five non-ASCII checks per report in 4.1. Rows
for all three are being added so the next draft can cite them as rerun.

The related-work and threats text for the paper is in
[`../sections/related.tex`](../sections/related.tex) and
[`../sections/threats.tex`](../sections/threats.tex), with plain-text and PDF
builds beside them in `../sections/txt/` and `../sections/pdf/`.
