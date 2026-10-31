# REMORA E7 self-service rerun, 2026-10-08

A rerun of `runtime-surface-e7-v0.1` done with no help from the REMORA maintainers, as asked in [REMORA #707](https://github.com/darklordVirtual/REMORA-research/issues/707#issuecomment-6007865547).

Steps, all from public pins:

```sh
git init rem && cd rem
git fetch --depth 1 https://github.com/darklordVirtual/REMORA-research e4fe474f488c3047b346abb01cbfd77ab447ad69
git checkout FETCH_HEAD
cd ..
git clone https://github.com/probityai/agent-evidence-vectors aev
git -C aev checkout v0.17.5   # 8e9cc6c3edc915a9248426a0b5a33612f6e11319
# lay the six package files out under up/artifacts/interop/runtime-surface-e7-v0.1/,
# storing reference_verifier.py as reference_verifier.py.source (never imported or run)
python aev/interop/remora-e7-reader/run.py --upstream up --output out \
  --reader-revision 8e9cc6c3edc915a9248426a0b5a33612f6e11319 --operator EXTERNAL \
  --run-ref https://github.com/darklordVirtual/REMORA-research/issues/707
```

The reader verified all five manifest members against `sha256:01dfdb7885bdbb18c025bc013edc28b482b0631ae282aca877bd0953b865e4bf` before evaluating. The freshly fetched package bytes are identical to the copy vendored in the reader repository.

| Case | Result |
|---|---|
| valid_reference_surface | ESTABLISHED |
| undeclared_tool_invocation_surface | CONTRADICTED |
| runtime_identity_changed | NOT_ESTABLISHED |
| observation_coverage_incomplete | NOT_ESTABLISHED |
| alternative_effect_path_observed | CONTRADICTED |

All five match the 2026-10-02 run in `../remora-e7-2026-10-02/`. `runtime_capability_surface_completeness` stays `NOT_ESTABLISHED`. Environment: Python 3.13.15 on Linux x86_64. The reader is author-produced (Probity maintains it), so this is a second implementation run by an external operator, not an independent one.

| File | sha256 |
|---|---|
| external-run-record-v1.json | 60c3488b1901f75cd4190bee5256ed06ffa671413513e6a86bcfa3c90a4a6819 |
| report.json | 894b4ba56f2c55eccbece39a8d2b870ef898483da919915272dc178d75f4b39e |

The recorded `command` names the Python environment as `<env>` and gives paths relative to the working directory. The files first published carried the runner's absolute paths; they were replaced on 2026-10-23, and the digests above are of the files as they stand.
