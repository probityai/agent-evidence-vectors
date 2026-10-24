# Provenance appendix: rerun commands for the v0.1 paper's results table

The W3C Agent Conformance and Benchmarking Community Group is writing a short
paper on its v0.1 reporting format. Roel Schuurkes posted the paper's
results-to-inputs table to public-agent-conformance in
[2026Oct/0162](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0162.html),
corrected in [0163](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0163.html).
This directory gives each row one pinned rerun: the command, the commits,
package versions and list attachments it runs on, and the digest that was
posted for it. [`rows.json`](rows.json) holds all of it, and
[`rerun.py`](rerun.py) runs it.

```sh
python rerun.py R8            # one row
python rerun.py --all         # every row; R14 runs last
```

Needs git, [uv](https://docs.astral.sh/uv/), Node for R3 and R4, and Go for R10.
Each row writes `<work>/results/<row>.json` with the posted and observed
digests side by side. The exit status is 0 only when every row run reproduced.
A row that does not reproduce is reported with what came out, and nothing is
adjusted to make it match.
[`.github/workflows/w3c-v01-appendix.yml`](../../.github/workflows/w3c-v01-appendix.yml)
runs every row on each change here and weekly, so a pin that stops resolving
upstream shows up as a red run.

## What the harness checks

- A commit is fetched by its full SHA and the checkout's `HEAD` is compared
  with the pin before anything runs.
- A list attachment is fetched from the archive and its sha256 is compared with
  the digest posted in the message. The archive appends one newline to a text
  attachment; the posted bytes are the served bytes without it, and the harness
  checks exactly that.
- Interpreters and packages come from uv at the versions the producer named.
- Where a producer posted a whole record set (R2, R3, R4), every file must come
  out byte-identical, except files the producer said carry the runner or the
  environment. Those are listed with the reason, and the comparison still
  reports both digests.

## Rows

The posted digests are those in the cited messages. `rows.json` has full
values.

| Row | Rerun | Pins | Posted |
|---|---|---|---|
| R1 | `uvx agent-evidence-vectors==0.12.0 --emit-w3c-report report.json` | release 0.12.0, commit `2f3aee40` | `report.json` `37288d8d`, `conformance-report.json` `ee349e66` (Sep/0089) |
| R2 | `python3 -P tools/emitir-55.py --runner "<runner>" <out>` | `NicolasRocchia/disensor` `dbdb6518`, CPython 3.14.2, jsonschema 4.26.0, zip from 0063 | every file of the zip; `SHA256SUMS` `3714de64` (0063) |
| R3 | `python3 emit_w3c_v01.py --artifact papers/dependable-multiroot-agent-evidence/artifact --out <out> --runner "<runner>"` | `tyche-institute/eatf-multiroot-softwarex` `c421dadc`, script from the 0060 zip | every file of `records/`; `SHA256SUMS` `8e52d99a` (0060, 0062) |
| R4 | `python emit.py --runner "<name>" --runner-wrote none --out <out>` | `AgentAvow/AgentAvow` `fbbbd4ac`, cryptography 50.0.2, rfc8785 0.1.4 | every committed record except `run.json`; committed `SHA256SUMS` `c720c68a` (0099) |
| R4-driver | `python fetch_fixture.py --output vectors.json` then `python run_agentavow.py --fixture vectors.json` | this repository at `82b8bb67`, producer `b7c5cd2f` | report equal to `recorded-run.json` (lock moved in #236) |
| R5 | `python3 -m paybench.w3c_report.emit --out <file> --verify` | `agentic-paybench/payhelm` `c221b478` | `7eb4e434` (0080, 0083, 0084) |
| R6 | `python3 check.py --controls` and `python3 -m unittest test_claim_boundary` | `Rul1an/assay` `0e59b404` and `8a385471` | exit 0 and "limited checks: ok" (0016, 0018); no output digest posted |
| R7 | `PYTHONHASHSEED=0 python3 -B packages/evidence-fabric/tests/test_w3c_control2_packet.py -v` | `CSOAI-ORG/councilof-ai` `d0cbe773`, cryptography 50.0.2 | `MANIFEST.json` `7094c4a9`, helper `752d29eb` (0081, 0088) |
| R8 | `python3 -B reader/v01reader.py <vectors> out/rerun` | reader tarball from 0039 (`396dbac8`), corpus at v0.17.4 | `verdicts.tsv` `de987220`, `not-selected.tsv` `cd6962f3` (0103, 0104, 0105) |
| R9 | `python rows/r9_corpus_history.py` | this repository at v0.17.4, v0.18.0, v0.18.1 | corpusDigest `f00d4443` then `f9e58e62`; selection counts as in 0079 |
| R10 | `python rows/r10_minus_zero.py` | Python and Go readers at v0.17.4 and v0.18.1 | `{"v":-0}` written as `7b2276223a307d` or `7b2276223a2d307d` (0038, 0046, 0079) |
| R11 | `PYTHONHASHSEED=0 python3 -I reader.py <members>` | `MoltyCel/reporting-format-v01-reader` `6d8ee54b`, members listed in the 0139 attachment at v0.18.1 | output `505dfb71` (0139) |
| R12 | `python -I score_w3c_jcs.py <api> <corpus> <manifest>` | `MoltyCel/moltrust-api` `fbc5e288`, jcs 0.2.1, corpus v0.18.1 | per-member verdicts of the 0140 TSV (`a7cefa02`) |
| R13 | `python3 experiment.py`, `python3 -m unittest -v test_experiment.py`, `sha256sum -c SHA256SUMS` | `LaToucheai/prior-run-evidence-v01` `98366047` | every listed file OK (0154) |
| R14 | the reference reader of each release over the R1, R2, R4 and R5 reports | releases 0.12.0, 0.13.0, 0.17.4, 0.18.1 | accept or reject as posted in Sep/0089, 0084, 0101, 0145, 0150 |
| R15 | no command was posted | the census URL in Sep/0080 | tally of the file's own `state` fields; the classifier is not rerun |

Limits that belong to the rows rather than to the harness are in each row's
`limits` field in `rows.json`, and in the limitations text of 0163. A rerun
here is a reproduction in O8's sense: the producer's own implementation, run
by another operator, with the posted outputs visible.
