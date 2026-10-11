# Run the suite in CI

Build a verifier, then pass its command to the harness. After the signed release tag is available, this example uses the repository's Go CLI; replace the command with your implementation when comparing it.

```yaml
- run: GOWORK=off go build -o aee-verify ./cmd/aee-verify
- uses: probityai/agent-evidence-vectors@v0.17.6
  with:
    verifier: ./aee-verify --json
```

For a shell run before publication, use the [source-wheel recipe](../../README.md#try-it) from a reviewed checkout. After the tag and PyPI wheel are published, install the matching release:

```sh
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.17.6
uvx agent-evidence-vectors==0.17.6 --verifier "aee-verify --json"
```

The command invokes your verifier for each vector using the [external-verifier contract](../reference/verifier-contract.md). Reports keep normative conformance and reason-code agreement separate. Both still affect row status and the command's exit status.

## Action inputs

| Input | Meaning |
| --- | --- |
| `verifier` | Required command. Its first token must be on PATH or relative to the workspace. An unavailable verifier or incomplete run fails the job. |
| `corpus` | Corpus directory; default `vectors`. Use `--list-corpora` to see the installed set and check its [reader route](../reference/corpus-readers.md). |
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

Run `agent-evidence-vectors --self-test` to check the packaged reference rail. Run `agent-evidence-vectors --jcs-byte-vectors` for the absolute path of the shipped RFC 8785 byte cases (`corpora/jcs-byte-vectors/cases.json`), which an SDK's CI can read after pinning the package. Set `corpus: vectors-a2a-jcs-v01` to score an A2A Agent Card canonicalizer against a2a-tck's corpus under [its contract](../reference/corpus-readers.md#the-a2a-jcs-v01-contract). Released wheels expose their corpus set through `--list-corpora`; additional source corpora need a checkout and matching reader. The [historical substitution defect](../../SECURITY.md) affected releases before 0.12.1.
