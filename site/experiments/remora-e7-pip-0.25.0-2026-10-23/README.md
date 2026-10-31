# REMORA E7 rerun from agent-evidence-vectors 0.25.0, 2026-10-23

The same run as `../remora-e7-pip-2026-10-09`, from the current release instead of 0.17.6. The reader was taken from PyPI with no clone of any repository and run against the frozen REMORA package inside the wheel:

```sh
uvx --python 3.13 --from agent-evidence-vectors==0.25.0 agent-evidence-vectors-remora-e7 \
  --output e7-025 --operator EXTERNAL \
  --run-ref https://github.com/darklordVirtual/REMORA-research/issues/707
```

- Package: agent-evidence-vectors 0.25.0, wheel sha256 `0bc14207b0832193bb0e7490a2ce29dd3b46d37c2830f23bb981c76512dc9c9e`. 0.19.0 is the first release carrying the Windows path fix (agent-evidence-vectors#128, merge 1881949b).
- Contract runtime-surface-e7-v0.1, REMORA revision e4fe474f488c3047b346abb01cbfd77ab447ad69, package digest sha256:01dfdb7885bdbb18c025bc013edc28b482b0631ae282aca877bd0953b865e4bf, all five members verified before evaluation.
- Python 3.13.15. Five cases, no failures; runtime_capability_surface_completeness stays NOT_ESTABLISHED.
- Against the 0.17.6 run made the same day the same way, the results, package digest, consumed revision and input digests are identical. The only differences are the command line and the digest of `reader.py`, which carries the PurePosixPath change.
- report.json sha256 `5723959d2d8645ad0ce274575da8fbc58ae52abe0447d99ec06014ea50b9f356`
- external-run-record-v1.json sha256 `9a04f0a678f96da3970cd17ebe2ad297552e6dcef1f0375003400b4c8c41063d`
- The recorded `command` names the Python environment as `<env>` (`<uv-env>` for a uv archive) and gives paths relative to the working directory. The files first published carried the runner's absolute paths; they were replaced on 2026-10-23, and the digests above are of the files as they stand.
