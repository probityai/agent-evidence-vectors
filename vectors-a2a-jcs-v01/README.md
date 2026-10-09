# a2a-jcs-v01: A2A Agent Card canonicalization

This directory is [`a2aproject/a2a-tck`](https://github.com/a2aproject/a2a-tck)
`conformance-vectors/a2a-jcs-v01` at commit
`97b007237ee4c3b802ed563829e3937a5529244e`, copied byte for byte: MANIFEST.json
and every vector it lists. [source-lock.json](source-lock.json) pins the
commit, the corpus digest
`29b3f2c5a9c2e6b07dc7e925b13c81563e2efd407a62ce05df513fca04e9361c` and every
file's SHA-256. The corpus documentation, generators and oracles stay upstream.

Score a canonicalizer through the harness or the GitHub Action:

```sh
agent-evidence-vectors --corpus vectors-a2a-jcs-v01 --verifier "./my-canonicalizer"
A2A_JCS_TARGET=rfc8785 agent-evidence-vectors --corpus vectors-a2a-jcs-v01 --verifier "./my-canonicalizer"
```

```yaml
- uses: probityai/agent-evidence-vectors@<tag>
  with:
    corpus: vectors-a2a-jcs-v01
    verifier: ./my-canonicalizer
```

The verifier is run as `<verifier> <target> <input.json>`; the
[contract](../docs/reference/corpus-readers.md#the-a2a-jcs-v01-contract) gives
the targets, exits and outcomes. With no verifier, the packaged reader answers
every vector for both targets itself, and `aee-verify vectors-a2a-jcs-v01`
does the same in Go.

| File | Role |
| --- | --- |
| `upstream.py check` | refuses any byte that differs from the lock, any unlocked file, and a lock that disagrees with [RUNS.md](../RUNS.md) |
| `upstream.py check --upstream <clone>` | also compares every file with `git show` of the locked commit |
| `upstream.py vendor --upstream <clone> --commit <sha>` | re-vendors a new upstream commit and rewrites the lock |
| `digest.py` | the corpus digest for `scripts/release-digests.py` |
| `tests/` | the lock checks and the replay with a conformant and a non-conformant verifier |
