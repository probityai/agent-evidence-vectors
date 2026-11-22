# Reproduction request: the issue opened for every release

Every release gets one public issue asking people outside this repository to reproduce it on their own machine. A
reproduction is not a conformance run of someone's verifier (that is the
[independent-run form](../.github/ISSUE_TEMPLATE/independent-run.yml)); it is a check that the tagged release
installs and replays as stated, on an operating system and toolchain we did not use. Replies arrive through the
[reproduction report form](../.github/ISSUE_TEMPLATE/reproduction-report.yml) and stay in the issue as posted,
failures included.

## When

Step 12 of [RELEASING.md](../RELEASING.md): after the publish pull request merges and PyPI serves the version. One
issue per release; a patch release gets its own.

## The issue

Title: `Reproduction request: vX.Y.Z`. Label: `reproduction-request`. Body, with every placeholder filled from the
release itself and nothing from memory:

````markdown
We invite anyone to reproduce agent-evidence-vectors vX.Y.Z on their own machine and report the result, whatever it is.

## Target

- Release: https://github.com/probityai/agent-evidence-vectors/releases/tag/vX.Y.Z
- Commit: `<the tagged commit, 40 hex>`
- PyPI: https://pypi.org/project/agent-evidence-vectors/X.Y.Z/
- Environment we expect to work: Python 3.11 or later with uv

## Commands

From PyPI, no clone:

```sh
uvx --from agent-evidence-vectors==X.Y.Z agent-evidence-vectors --corpus vectors-agent-audit-record
```

From the tagged source:

```sh
git clone --branch vX.Y.Z https://github.com/probityai/agent-evidence-vectors
cd agent-evidence-vectors
python3 corpora/vectors-restart-records/check_vectors.py
```

## What a clean run prints last

```text
<the final lines of each command from the release run, pasted verbatim>
```

## Please report

Use the reproduction report form: operating system and version, tool versions, the outcome, the last lines of
output, elapsed time if convenient, and any instruction you had to guess at. A clean report is as useful as a
failure. For a defect, open a focused issue and link it here. Do not post private keys, credentials, unpublished
records or personal data.
````

## Rules for the maintainer

- The expected lines are pasted from the release run, never typed. If a command's output changed in this release,
  the request says so in one line under the block.
- Every reply stays in the issue as posted. A failure is answered in the issue with what changed, and the fix ships
  as a new patch release, never as an edit to the reported release.
- The issue is closed when the next release's request opens, with a link to it.
