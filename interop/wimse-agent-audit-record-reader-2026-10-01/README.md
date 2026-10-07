# WIMSE audit record: second-reader rerun

Mayur021 reported a conforming run across the corpus in [WIMSE #144](https://github.com/ietf-wg-wimse/draft-ietf-wimse-aims/issues/144#issuecomment-5934905211). His [reader](https://github.com/Mayur021/agent-audit-record-reader/tree/0ad911a39d7942d5fabd9a4ea0b9093bb04f88a7) contains the implementation and findings, but no committed per-member output. This is our rerun of that source, dated 2026-10-01. It is not a copy of his original run.

The reader commit is `0ad911a39d7942d5fabd9a4ea0b9093bb04f88a7`. The corpus is `probityai/agent-evidence-vectors` release v0.16.0 at `8d6295fb5db3e57c52df09f2fbeeb758b09f5c7d`, with manifest digest `9617291fd6c1721dfd9430d3f15987da716ee5c722094f74431a95a2d4b3c3c6`. `INPUTS.json` pins every reader source file, the manifest and every statement file by SHA-256. No reader source or corpus statement is copied into this record.

| Corpus row | Observed | Conforming |
|---|---:|---:|
| Accept | valid | all accept rows |
| Reject | malformed | all reject rows |
| Indeterminate | N1 and N2 valid | valid is a listed reading for each |

`RESULTS.json` carries every individual verdict, stage outcome and refusal finding. The rerun used Python 3.12.14 and `cryptography==46.0.0`. From this directory:

```sh
python -m pip install cryptography==46.0.0
python fetch_inputs.py
python run_reproduction.py
```

The fetch checks every downloaded byte against `INPUTS.json`. The runner checks the reader source again, executes its three published modules, and compares every result with `RESULTS.json`. The CI workflow retains the three raw stage outputs. The upstream `fetch_corpus.sh` defaults to mutable `main`; this reproduction instead uses the exact release commit.

This is evidence of agreement on the frozen corpus. It does not establish how the reader was developed, an independent replay in Mayur's environment, completeness of observed activity, or production deployment. His `FINDINGS.md` records that T2 and T3 caught earlier reader mistakes; this result is for the pinned corrected revision.
