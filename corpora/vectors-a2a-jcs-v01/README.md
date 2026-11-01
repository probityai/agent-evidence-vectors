# a2a-jcs-v01: A2A Agent Card canonicalization

This directory is [`a2aproject/a2a-tck`](https://github.com/a2aproject/a2a-tck)
`conformance-vectors/a2a-jcs-v01` at commit
`97b007237ee4c3b802ed563829e3937a5529244e`, copied byte for byte: MANIFEST.json
and every vector it lists. [source-lock.json](source-lock.json) pins the
commit, the corpus digest
`29b3f2c5a9c2e6b07dc7e925b13c81563e2efd407a62ce05df513fca04e9361c` and every
file's SHA-256. The corpus documentation, generators and oracles stay upstream.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

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
