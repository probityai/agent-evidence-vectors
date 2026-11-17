# Run the suite in CI

Build a verifier, then pass its command to the harness. After the signed release tag is available, this example uses the repository's Go CLI; replace the command with your implementation when comparing it.

```yaml
- run: GOWORK=off go build -o aee-verify ./cmd/aee-verify
- uses: probityai/agent-evidence-vectors@v0.37.0
  with:
    verifier: ./aee-verify -validity-only --json
```

For a shell run before publication, use the [source-wheel recipe](../../README.md#try-it) from a reviewed checkout. After the tag and PyPI wheel are published, install the matching release:

```sh
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.37.0
uvx agent-evidence-vectors==0.37.0 --verifier "aee-verify -validity-only -json"
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
| `profile` | The profile your verifier declares: `integer-only`, `safe-integer`, `ascii-only` (comma-joined), or a JSON file `{"excludes": [features], "outOfProfile": [ids]}`. Members outside it are scored on their own line and their failures do not fail the job; a failure inside it still does. |
| `fail-on-no-vectors` | `true` (default) fails a run that found no case on the runner's own disk; `false` reports `no-verdict`, never a pass. |
| `fail-on-missing-case` | `true` (default) fails a run in which a listed case is not on disk or was not scored, naming each; `false` reports them. |
| `mutate` | `none` (default), `structural` or `bytes`: mutate every accept member and require your verifier and the reference verifier both to reject each mutant ([Mutation stage](#mutation-stage)). |
| `mutate-limit` | Most mutants judged per run (default `2000`); a larger set is sampled at even, deterministic spacing. |
| `expected-verdicts`, `cases` | [Conformance mode](#conformance-mode): your own cases held to your own expected-verdicts file. |

The action writes a summary, uploads the report, and fails on a scored disagreement, suite refusal or incomplete verifier run. The report names the corpus release and digest.

| Output | Meaning |
| --- | --- |
| `report` | Report path |
| `vectors`, `conform` | Population and normative conformance totals |
| `executed` | Vectors answered by the named verifier |
| `result` | `pass`, `fail`, or `no-verdict` when no case was found and `fail-on-no-vectors` is `false` |
| `vectors-found`, `missing-cases` | Listed cases on this runner's disk, and listed cases missing from disk or the replay |
| `in-profile`, `in-profile-pass`, `out-of-profile`, `out-of-profile-pass` | With `profile`: the two populations and their passes |
| `control-always-accept`, `control-always-reject`, `discriminates` | The null controls ([below](#null-controls)) |
| `mutation-checked`, `mutation-total`, `mutation-agreement`, `mutation-survivors` | With `mutate`: N, M, agreeing verdicts and mutants both verifiers accepted |

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

## Null controls

Every summary prints what two constant verifiers score on the same corpus: one that accepts every member and one that rejects every member, replayed through the same harness as your verifier (`scripts/action-control-verifier.py`). A corpus where either control passes more members than must be accepted (or rejected), or passes all of them, cannot tell a verifier from a constant answer, and the summary says so in bold. The counts are in the report as `controls` and in the outputs above; they never change `result`.

## Declared profile

A verifier that declares a profile, for example a canonicalizer that handles integers only, sets `profile: integer-only`. Each member's features (`non-integer-number`, `unsafe-integer`, `negative-zero`, `non-ascii`, `surrogate-escape`) are read from its input tokens as written, or from a `features` list its MANIFEST entry declares. Members with an excluded feature are counted as out of profile, and the job passes when every in-profile member passes and the suite raised no refusal. On the a2a-jcs-v01 corpus, `integer-only` puts the 11 members with a fraction or an exponent out of profile; a canonicalizer that refuses those passes with the profile and fails without it.

## Case counts

The summary counts the cases the corpus MANIFEST lists on the runner's own disk with `os.walk`, comparing POSIX paths, so a Windows runner counts the same files a Linux one does; a pattern that matched nothing on Windows once let a project's CI pass on zero vectors. A run that found no case fails (`fail-on-no-vectors`). A listed case that is not on disk, or that the replay did not score, is named and fails the job (`fail-on-missing-case`).

## Conformance mode

Naming `expected-verdicts` holds your verifier to your own cases instead of a corpus of ours. The file lists each case and the verdict it must get, one `<path> <valid|invalid>` per line (the layout of a `verify-expected.txt`), or a JSON object of the same; paths are relative to `cases`. The verifier runs as `<verifier> <case>`: exit 0 is valid, exit 1 invalid, and a last stdout line that is a JSON object with a `verdict` must agree. The job fails on a mismatch, a case the verifier did not answer, a listed case not on disk and an empty run, and the summary prints both null controls.

The mode installs nothing and runs no setup step: `scripts/action-conformance.py` uses the standard library only and runs under `python -S`. The reference stage runs the same way and reads `reference-checked conformance 0 of M` with `reference-verifier-id` `unavailable`, because your cases are your own and no route of the reference verifier reaches them.

```yaml
- uses: probityai/agent-evidence-vectors@<tag>
  with:
    expected-verdicts: test-vectors/verify-expected.txt
    cases: test-vectors
    verifier: python -m my_verifier --json
```

`sh scripts/run-conformance-demo.sh` runs the mode on bundled cases in one command, once with a verifier that gets every case right and once with one that accepts everything.

## Mutation stage

With `mutate`, every member the corpus says must be accepted is mutated and each mutant is judged by your verifier (`<verifier> <file>`, exit 0 valid) and by the reference verifier. `bytes` flips every bit of every DSSE payload after decoding and does not re-sign, so the signature no longer covers the bytes. `structural` drops each member of the signed payload or of the statement's predicate, moves each scalar by one unit and to 2^53 and 2^64 - 1, and swaps each digest, then re-signs each changed envelope with the corpus's published test key and recomputes the batch root, so the refusal is the semantic one. A corpus that publishes no key recipe has its envelope members refused by name.

The stage prints `mutation-checked N of M`: M mutants judged, N rejected by both verifiers. A mutant both accept is a survivor and a mutant they judge differently is a disagreement; each is named and fails the job. A corpus with no reference route reads `0 of M` and fails. The report gains `mutation` and keeps `reference.verifier.id`.

