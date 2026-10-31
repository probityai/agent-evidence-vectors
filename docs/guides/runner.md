# Run the suite in CI

Build a verifier, then pass its command to the harness. After the signed release tag is available, this example uses the repository's Go CLI; replace the command with your implementation when comparing it.

```yaml
- run: GOWORK=off go build -o aee-verify ./cmd/aee-verify
- uses: probityai/agent-evidence-vectors@v0.31.0
  with:
    verifier: ./aee-verify -validity-only --json
```

For a shell run before publication, use the [source-wheel recipe](../../README.md#try-it) from a reviewed checkout. After the tag and PyPI wheel are published, install the matching release:

```sh
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.31.0
uvx agent-evidence-vectors==0.31.0 --verifier "aee-verify -validity-only -json"
```

The command invokes your verifier for each vector using the [external-verifier contract](../reference/verifier-contract.md). Reports keep normative conformance and reason-code agreement separate. Both still affect row status and the command's exit status.

## Action inputs

| Input | Meaning |
| --- | --- |
| `verifier` | Required command. Its first token must be on PATH or relative to the workspace. An unavailable verifier or incomplete run fails the job. |
| `corpus` | Corpus directory; default `vectors`. Use `--list-corpora` to see the installed set and check its [reader route](../reference/corpus-readers.md). |
| `vectors` | Path of a corpus directory in the workspace, replayed instead of `corpus`. Use it to replay a corpus your workflow checks out and pins itself, such as a2a-tck's `conformance-vectors/a2a-jcs-v01` at a commit; the report carries the digest its MANIFEST recomputes to. |
| `tag` | Release override. By default the corpus follows the action's own ref. |
| `artifact-name` | Uploaded report name; default `agent-evidence-vectors-results`. Give separate runs distinct names. |
| `report-path` | Report path relative to the workspace. |
| `retention-days` | Days GitHub keeps the uploaded report (default: `30`). Repository retention settings can cap it. |

The action writes a summary, uploads the report, and fails on a scored disagreement, suite refusal or incomplete verifier run. The report names the corpus release and digest.

| Output | Meaning |
| --- | --- |
| `report` | Report path |
| `vectors`, `conform` | Population and normative conformance totals |
| `executed` | Vectors answered by the named verifier |
| `result` | `pass` or `fail` |

## Read a result

For an external result, check these fields in the same report:

| Field | Required for a complete conforming run |
| --- | --- |
| `rail` | `external` |
| `verifier.vectorsExecuted` | Equals `totals.vectors` |
| `totals.conform` | Equals `totals.vectors` |
| `totals.suiteRefusals` | `0` |
| `totals.notExercised` | Review every declared exclusion before describing the whole population as tested |
| `totals.reasonParityMismatch` | Reason-code agreement, reported separately from conformance |

A zero exit also requires reason parity under the current scoring policy. Use the [comparison reference](../reference/verifier-contract.md#comparison-rules) to interpret that difference.

Run `agent-evidence-vectors --self-test` to check the packaged reference rail. Run `agent-evidence-vectors --jcs-byte-vectors` for the absolute path of the shipped RFC 8785 byte cases (`corpora/jcs-byte-vectors/cases.json`), which an SDK's CI can read after pinning the package. Set `corpus: vectors-a2a-jcs-v01` to score an A2A Agent Card canonicalizer against a2a-tck's corpus under [its contract](../reference/corpus-readers.md#the-a2a-jcs-v01-contract). To test a canonicalizer in process instead, parametrize a pytest test with `agent_evidence_vectors.a2ajcs.params()` ([the Python API](../reference/corpus-readers.md#test-a-canonicalizer-from-python)). Released wheels expose their corpus set through `--list-corpora`; additional source corpora need a checkout and matching reader. The [historical substitution defect](../../SECURITY.md) affected releases before 0.12.1.

## Reference stage

After your verifier runs, the action always runs a second stage that no input switches off. It installs a pinned release of the reference verifier (`probity-verify` 0.2.4) by version and hash into a venv of its own, replays the corpus's members through it with the same comparison [the done-corpus cross-check](../reference/corpus-readers.md) uses, and prints one line:

```text
reference-checked conformance N of M
```

N is the number of members whose every declared verdict the reference verifier reached too. M is every member of the corpus. Every member kind of the default `vectors` corpus has a route through the reference verifier's `adversarial_execution_evidence/v1` claim type, judged under the corpus's published substrate test key and under no key, so a conformant run reports N equal to M for the whole corpus. A corpus the reference verifier has no route into reads `0 of M`. `FULL-RELEASE` is printed only when M is above zero and N equals M.

The stage records `reference.verifier.id`, `reference.checked`, `reference.total` and `reference.fullRelease` in the uploaded report, and exposes them as outputs. It does not change `result`: your verifier's verdict and the reference count are reported separately. The pin and its hashes are in `action-reference-requirements.txt`. The `agent-evidence-vectors` package takes no dependency on the reference verifier; only the action installs it.

| Output | Meaning |
| --- | --- |
| `reference-checked`, `reference-total` | N and M of the line above |
| `full-release` | `true` or `false` |
| `reference-verifier-id` | The identifier recorded as `reference.verifier.id` |
