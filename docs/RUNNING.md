# Running the suite

How to replay a corpus against your verifier, in CI or from a shell, and what a conformance claim must show. Part of the [agent-evidence-vectors](../README.md) documentation; the [index](README.md) lists every page.

## Run the suite against your verifier

Add one step to the workflow that builds your verifier:

```yaml
- uses: probityai/agent-evidence-vectors@v0.16.0
  with:
    verifier: ./path/to/your-verifier --json
```

Or replay the corpus from a shell, with nothing cloned:

```bash
uvx agent-evidence-vectors --verifier './path/to/your-verifier --json'
```

Both run the harness described in [the verification pipeline](ARCHITECTURE.md#the-verification-pipeline) against your
verifier through the external-implementation contract: the harness invokes
`<cmd> <vector-file>`, reads the verdict from the exit status and the condition
codes from the last line of stdout, and hands the key policy to the process in
`AEE_SUBSTRATE_KEYS`. Your verifier has to speak that contract and nothing
else. The reference rail replays the same vectors beside it, and the report
records where the two agree, where they disagree, and where your verifier
reached the corpus's verdict under a different condition code.

The action pins the corpus to the release you name in `uses:`, installs the
suite from that checkout, and then:

- Writes the job summary: a totals row, one row per vector that disagreed
  with the corpus, and the suite notes.
- Uploads the report JSON as the artifact `agent-evidence-vectors-results`.
  The report is the same `conformance-report.json` the harness writes locally,
  and a scoreboard in another repository pulls it by that name. It
  records the corpus release and digest the run read.
- Fails the job when any vector disagreed, the suite raised a refusal, or the
  named verifier did not run on every vector.

Inputs, all optional except the first:

| Input | What it does |
| --- | --- |
| `verifier` | Command line of the verifier under test. The first token must be on `PATH` or a path relative to the workspace. This verifier is always the program that runs: the job fails when it cannot be started or when it answered fewer vectors than the corpus holds. |
| `corpus` | Corpus to replay (default: `vectors`). `agent-evidence-vectors --list-corpora` lists the shipped corpora. `vectors-w3c-report` and `vectors-observed-effect` refuse a named verifier; `vectors-receipt-signature` and `vectors-source-coverage` define external verifier contracts. |
| `tag` | A release to replay other than the one the action itself is pinned to, such as `v0.16.0`. The default is the action's own ref. |
| `artifact-name` | The results artifact's name. Change it only when the action runs more than once in one workflow. |
| `report-path` | Where the report is written, relative to the workspace. |
| `retention-days` | Days GitHub keeps the uploaded report (default: `30`). The repository's own retention setting caps it. |

Outputs: `report` (the report's path), `vectors` and `conform` (the totals),
`executed` (how many vectors the named verifier ran on), and `result` (`pass`
or `fail`), so a later step can act on the count rather than re-read the file.

The package is stdlib-only and carries every corpus, so `pip install
agent-evidence-vectors` needs no network access to this repository. Without
`--verifier` it judges `vectors`, `vectors-w3c-report`,
`vectors-observed-effect`, `vectors-receipt-signature`, and
`vectors-agent-audit-record` with their packaged readers.
The source-coverage corpus requires a named verifier. Every other corpus
without a packaged reader is refused by name with exit 2 and judged by
`aee-verify <corpus-dir>`.
`agent-evidence-vectors --self-test` runs the reference rail against its own
oracle, which is the first thing to run when a result looks wrong.

### What a conformance claim must show

A claim that an implementation passes a corpus here is a claim about one
report, and that report has to show that the implementation answered every
vector, not this package's reference rail. The report settles it in its own
fields: `rail` reads `external`, `verifier.vectorsExecuted` equals
`totals.vectors`, and `totals.conform` equals `totals.vectors` with
`totals.suiteRefusals` at zero. A specification that makes passing this suite
a requirement should require all of those in the same sentence. A pass printed
without them is the defect `SECURITY.md` records under "A named verifier could
be replaced by the reference rail", which releases before 0.12.1 carry.

## One harness judges every corpus here

`aee-verify` takes a corpus directory as well as a statement. The directory's
`MANIFEST.json` publishes a `suite`, the suite selects a reader, and the reader
judges every member: an intact corpus exits 0 and prints the member counts by
verdict, a member whose bytes moved exits 1 and is named, and a suite this
binary does not know is refused by name rather than skipped, because a skipped
corpus and a clean one otherwise print the same zero.

```
go build -o aee-verify ./cmd/aee-verify
for corpus in vectors*/; do ./aee-verify "${corpus%/}"; done
```

Every corpus used to carry a Python self-check beside its vectors, so the
command a reader was told to run differed per corpus and three of the six were
wired into no workflow at all. Two Python files remain and answer different
questions: `vectors-anchor-stream/run_verifier.py` runs this corpus against a
third party's `anchors_verify.py`, which is a measurement of that build rather
than of the corpus, and `vectors-mcp-record-contract/check_run_record.py` is the
interoperability criterion as a standalone tool for a record of your own. The
SCITT/COSE corpus keeps its own checker until a reader for it lands; the binary
refuses that suite by name and says what judging it would need.
