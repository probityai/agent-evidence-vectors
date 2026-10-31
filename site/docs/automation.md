# Use Probity from an automated job

Use the [worked report example](evidence-test-meaning.md) to interpret test results separately from evidence conclusions. Its [retained accounting procedure](experiments/w3c-report-replay-2026-10-06/README.md) checks original files through the maintained Lab consumer.

<a id="find-a-project"></a>

## Find a project

Read [llms.txt](llms.txt) for the navigation index or [catalog.json](catalog.json) for structured records. Components name the tools; repository records hold their pinned README sources. Integration profiles belong to a component.

Use the stable `id` for lookups. Follow `docs_url` for the quickstart and `source.commit` to reproduce the captured source.

<a id="check-discovery"></a>

## Check discovery

Use the [fixed discovery prompts and receipt checker](discovery-evaluation.md) to retain a reader or agent session and review its answers against pinned public sources. Keep actual discovery attempts separate from author-operated packet checks.

<a id="check-a-verifier-in-ci"></a>

## Check a verifier in CI

Use the [pinned Vectors Action guide](https://github.com/probityai/agent-evidence-vectors/blob/9e596fbff7bb29809d38319aebb56f2141923eb2/docs/guides/runner.md#run-the-suite-in-ci) from the [verifier task](start.md#vectors). Its example selects release `v0.18.0`; keep the release and source required by the result you reproduce.

The [recorded `action` job](https://github.com/probityai/agent-evidence-vectors/actions/runs/38480809538/job/115582642213) succeeded on October 13, 2026 at source `9e596fbff7bb29809d38319aebb56f2141923eb2`. The [workflow at that source](https://github.com/probityai/agent-evidence-vectors/blob/9e596fbff7bb29809d38319aebb56f2141923eb2/.github/workflows/ci.yml#L1139) builds the verifier and calls the actual Action. It requires a nonempty corpus, complete execution and the declared conformance result. The same job requires failure when the verifier is unavailable, the canonicalizer emits the wrong number bytes, or the selected corpus directory is changed. It also checks the custom-directory digest against its source lock.

The workflow declares `contents: read`. Its checkout dependency is the historical floating `actions/checkout@v4`; the recorded checkout head fixes the Action, verifier and corpus source. This author-operated control result does not establish an outside run or agreement on Windows. A successful control job can contain a required refusal. Read the [test-result explanation](evidence-test-meaning.md) and [claim ledger](claims.md) for the result's scope.

<a id="run-a-local-replay"></a>

## Run a local replay

To produce a new local APS/PriorSeal capture, use the [replay tools guide](replay-tools.md). Declare the caller and keep the source hashes, actual process logs and result together. The guide links one complete pinned procedure, including the copied-file route.

<a id="read-a-retained-run"></a>

## Read a retained run

From a pinned Atlas checkout:

``` sh
python3 tools/check_lab.py --list
python3 tools/check_lab.py --record E6-observer-admission --json
```

The checker validates artifact hashes and measured fields before returning a record. The JSON includes results, operator roles and review state.

<a id="share-a-result"></a>

## Share a result

Keep the source pins, command, raw output and retained artifact together. Submit them through the [run form](https://github.com/probityai/agent-evidence-vectors/issues/new?template=evidence-run.yml), or use the [correction form](https://github.com/probityai/agent-evidence-vectors/issues/new?template=evidence-correction.yml) when a recorded claim needs fixing.

[HTML view](automation.html) | [Agent guide](llms.txt)
