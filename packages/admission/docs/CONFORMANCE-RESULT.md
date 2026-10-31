# Conformance result records

How do you publish "implementation X passed N of M cases of corpus revision R" so that a stranger can check who signed it, what it covers, and that the figure was not edited afterward? Sign a conformance result record, and put it in a run registry.

A record is a DSSE envelope around an in-toto Statement v1. It states one run of one corpus revision by one implementation, how independent that run was, and what it scored. Nothing in it asserts that the corpus is right; it records a measurement.

## Worked example

Replay the runs the vectors repository already posts, then check the registry:

```bash
git clone --depth 1 https://github.com/probityai/agent-evidence-vectors.git vectors
agent-evidence-admission conformance keygen --seed-file run-key.hex
agent-evidence-admission conformance replay vectors/docs/INDEPENDENT-RUNS.json \
  --seed-file run-key.hex --registry registry
agent-evidence-admission conformance verify registry \
  --trusted-key "$(agent-evidence-admission conformance public-key --seed-file run-key.hex)"
```

The last command prints `8 records checked, 0 failing` and exits 0. It exits 1 when a record fails to verify, an index entry disagrees with its file, or a file is missing from the index or from disk, and 2 when something could not be read.

To run an implementation yourself, write a manifest and give the runner a command. The runner calls `<command> <input>` once per case:

```bash
agent-evidence-admission conformance run manifest.json \
  --implementation my-checker --run-label author-produced --evidence measured \
  --seed-file run-key.hex --registry registry --results-out results.json \
  -- ./my-checker verify
```

## The manifest

```json
{"suite": {"revision": 28, "commit": null},
 "cases": [{"id": "v0001", "input": "cases/v0001.json", "expect": "accept"}]}
```

`input` is relative to the manifest. `expect` is `accept` or `refuse`. The command's exit code is the verdict: 0 is accept, 1 is refuse, anything else is `errored`. An errored case counts against the score and is never read as a refusal, so an implementation that cannot start does not pass the cases that expect a refusal.

## The record

| field | meaning |
|---|---|
| `_type` | `https://in-toto.io/Statement/v1` |
| `predicateType` | `https://github.com/probityai/agent-evidence/blob/main/packages/admission/docs/CONFORMANCE-RESULT.md` |
| `subject[0].name` | `run:<implementation>@suite-revision-<N>` for a replayed row, `results:<implementation>@suite-revision-<N>` for a local run |
| `subject[0].digest.sha256` | SHA-256 of the canonical JSON of the evidence: the posted row, or the list of `{id, expect, verdict}` the runner produced |
| `predicate.implementation` | who was measured |
| `predicate.suite` | `{revision, commit}`; `commit` is null where the posting did not record one |
| `predicate.runLabel` | `author-produced`, `second-party-same-code` or `independent` |
| `predicate.evidence` | `blind`, `directed`, `first-run-unchanged-build` or `measured` |
| `predicate.scores` | one or more `{role, passed, total}`; `passed` never exceeds `total` |
| `predicate.posting`, `predicate.date` | where and when the run was posted, or null |
| `predicate.runner` | `{kind, name, version}`; `kind` is `replayed-row` or `local-run` |

The label and the evidence are the two axes the posted-runs file already uses. The label says who produced the run. The evidence says whether the implementer read the answers first. The runner cannot know either, so the caller states both, and the record is signed under the key of whoever stated them.

Canonical JSON means keys sorted, no whitespace, UTF-8 without escaping non-ASCII. For the strings, integers, booleans and nulls used here this equals RFC 8785.

## What a verifier checks

1. The envelope has `payloadType` `application/vnd.in-toto+json`, canonical base64, and at least one signature whose keyid is the SHA-256 of a pinned raw Ed25519 public key and which verifies over the DSSE pre-authentication encoding.
2. The statement is in-toto Statement v1 with this predicate type and exactly one subject with a SHA-256 digest.
3. The predicate passes the table above.
4. When you hold the evidence (`--source`), its canonical digest equals the subject digest.

A record that passes says that the pinned key signed this measurement. It does not say the run happened as described, that the corpus was the one named, or that a score of `N/N` means more than the cases say. The label and evidence fields are claims by the signer.

## The run registry

A registry is a directory:

```text
registry/index.json
registry/records/<sha256 of the envelope's canonical JSON>.dsse.json
```

`conformance verify <dir>` reads every record, not the index, and fails on a record that does not verify, a file whose name is not its digest, a record the index omits, an index entry that disagrees with its record, and an entry whose file is missing. Records are only added, never edited. A correction is a new record with its own digest.

## Limits of this first slice

- Signing uses a pure-Python Ed25519 that is not constant time. It fits a key held by a job runner. A key that must resist a local timing attacker signs the statement with another tool, and this command line verifies the result unchanged.
- The runner calls one command per case and has no sandbox. Run an implementation you do not trust in a container.
- No registry key is published yet. A registry becomes citable when its public key and its location are pinned in a release.
