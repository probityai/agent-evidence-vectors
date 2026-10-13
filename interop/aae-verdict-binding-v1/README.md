# AAE verdict binding (v1.4.0)

This package recomputes AAE verdict records from draft-kroehl-agentic-trust-aae-02 and binds one to an [observed-effect](../../spec/predicates/observed-effect.md) evidence record. It reports authorization, binding, execution and completeness as separate results. It pins AAE vector set v1.4.0 and does not import MolTrust's verifier.

## Run

From the repository root, with an output directory that does not exist yet:

```bash
uv sync --locked --extra dev
uv run python -m pytest interop/aae-verdict-binding-v1 -q
uv run python interop/aae-verdict-binding-v1/run_binding.py --output-dir /tmp/aae-binding-attempt
uv run python interop/aae-verdict-binding-v1/check_report.py /tmp/aae-binding-attempt/report.json
```

The run prints:

```text
aae-verdict-binding: 26/26 vectors reproduced, 7/7 cases as declared, report /tmp/aae-binding-attempt/report.json
```

Exit 0 means every pin held, every vector reproduced and every case produced its declared outcome. Exit 1 means a fresh report records a difference. Exit 2 means malformed input, a failed file or key pin, or an output failure, and no report was written. [OUTPUT-CONTRACT.md](OUTPUT-CONTRACT.md) lists every field, enum and pin, and [PROFILE.md](PROFILE.md) defines the binding. CI runs the same steps in [aae-verdict-binding.yml](../../.github/workflows/aae-verdict-binding.yml) and keeps the report as an artifact.

## What is checked

- **All 26 enforce vectors**, from input alone: verdict or status, core digest, grant index, the named trace predicates, kernel version, domain tags and the two caller errors. Each one is evaluated again with every object's keys reversed.
- **Three cases.** `B1-valid-binding`: the vector 01 PERMIT record with an evidence record whose `authorityDigest` cites it. `B2-mismatched-digest`: the citation differs in one hex digit. `B3-missing-receipt`: there is no evidence record, so execution stays `UNKNOWN`.
- **Four controls that must fail.** A mutated core whose digest no longer recomputes. A PERMIT citation offered for a DENY record. A ratification whose `prev_core_digest` names another record (vector 25). An evidence record with a flipped signature bit.

## What it establishes and what it does not

In Lars Kroehl's words ([#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5932411922)): "a verdict record establishes what the issuer asserted at issuance time, and it establishes nothing about execution, outcome, or whether every decision in a set was written down." So a valid authorization never sets execution, and a missing evidence record never fails authorization. Execution is at most `CLAIMED_BY_BOUND_RECORD`, because an evidence record is a claim. Completeness is always `NOT_ESTABLISHED`. Keys are upstream test keys pinned in [INPUTS.json](INPUTS.json). They prove nothing about production identity, revocation or custody.

## Attribution

The 26 files under [fixtures/aae-v1.4.0/](fixtures/aae-v1.4.0/) are MolTrust's AAE conformance vectors by Lars Kroehl (MoltyCel), [MoltyCel/aae-conformance-vectors](https://github.com/MoltyCel/aae-conformance-vectors) at tag `v1.4.0`, commit `531f880155ea1ce993a7ca74137b12c255d5b2ee`. They are kept byte for byte under Apache-2.0, with the upstream [LICENSE](fixtures/aae-v1.4.0/LICENSE.upstream) and [NOTICE](fixtures/aae-v1.4.0/NOTICE.upstream) ("Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust)"). [INPUTS.json](INPUTS.json) pins each file's SHA-256 and upstream path. The kernel, adapter, cases and tests are this repository's, under its Apache-2.0 license.

## Provenance

This is not a clean-room implementation. The kernel was written from the draft text. MolTrust's `examples/enforce-verify.py` was then read to resolve the digested structural trace members the draft leaves unnamed (PROFILE.md lists them), and lines 55 to 70 of `tools/build_enforce_vectors.py` were read to identify the key that signs vector 23. No producer code is imported or copied. Canonicalization uses the pinned `rfc8785` 0.1.4, and signatures use `cryptography`. Evidence records come from this repository's observed-effect generator under its fixed test observer key. They are checked by its reference verifier.
