# Read published MintID trace records

This installed reader checks three published MintID JSONL/Markdown/manifest-v2 bundles. It admits each original JSON document through the existing installed Go JCS and raw-admission commands before parsing. Original Markdown stays hash-bound bytes with separate disclosure checks.

From the repository root, with Python 3.11 or later, uv, Rust and Go installed:

```sh
git clone https://github.com/cyberphone/json-canonicalization /absolute/path/go-source
git -C /absolute/path/go-source checkout 19d51d7fe467d4706a3ff08adf8a748f29fc21e0
python3 interop/mintid-trace-records-v2/qualify.py \
  --upstream /absolute/path/go-source \
  --output /absolute/new/directory/outside-checkout
```

The command builds a wheel, checks installed source bytes, runs the original Go corpus and tests 89 named controls. It retains original members, native input/output, exits and refusal records before analysis. Resource-aborted output is marked incomplete.

The reader separates stale-root refusals from a revoked agent's failed witness refresh. Missing source, build, policy or refresh observations stay unknown. Older revision assertions stay under `stated`. A transport failure during an authored outage control does not become a verifier denial.

[Source selection](SOURCE-SELECTION.json) pins the later published `public-v2026-10-06` source. It does not recover the unavailable October 4 tag or authenticate the historical deployment. [Profile and limits](PROFILE.md) explain the installed entry point, captured facts and refusal rules. The reader does not authenticate an operator, verify ICS23/BBS proofs, establish independent custody or prove an external action.
