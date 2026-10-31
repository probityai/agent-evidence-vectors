# REMORA E7 rerun from the published package alone, 2026-10-09

The reader was installed from PyPI with no clone of any repository, then run against the frozen REMORA package that ships inside the wheel:

```sh
python3.13 -m venv v && v/bin/python -m pip install agent-evidence-vectors==0.17.6
v/bin/agent-evidence-vectors-remora-e7 --output e7 --operator EXTERNAL \
  --run-ref https://github.com/darklordVirtual/REMORA-research/issues/707
```

- Package: agent-evidence-vectors 0.17.6, wheel sha256 `7031adfb1b30b66754190599cfdfddd855bdb66e79e3d7bbc2ab4c0581a5d57d`, tag v0.17.6
- Contract runtime-surface-e7-v0.1, REMORA revision e4fe474f488c3047b346abb01cbfd77ab447ad69, package digest sha256:01dfdb7885bdbb18c025bc013edc28b482b0631ae282aca877bd0953b865e4bf, all five members verified before evaluation
- Python 3.13.15. Five cases, no failures; runtime_capability_surface_completeness stays NOT_ESTABLISHED
- report.json sha256 `3fe44a74b4c15cdb6eea1c4b5d930e3108569117c7bc8ff7edd55b4f49e2ef68`
- external-run-record-v1.json sha256 `6ae82485ea5e8f19a21429b8db4f9c677ed0bc65fa3a87a59017dc59b3725d97`

The reader is author-produced: written and run by this repository's maintainer, a second implementation run by an external operator, not an independent one.

The recorded `command` names the Python environment as `<env>` and gives paths relative to the working directory. The files first published carried the runner's absolute paths; they were replaced on 2026-10-23, and the digests above are of the files as they stand.
