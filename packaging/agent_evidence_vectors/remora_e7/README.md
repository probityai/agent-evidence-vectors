# Separate REMORA E7 reader

Probity evaluates the five native `runtime-surface-e7-v0.1` fixtures at REMORA
revision `e4fe474f488c3047b346abb01cbfd77ab447ad69`, with selected package digest
`sha256:01dfdb7885bdbb18c025bc013edc28b482b0631ae282aca877bd0953b865e4bf`.
The producer formally handed this pin to Probity in
[REMORA #707](https://github.com/darklordVirtual/REMORA-research/issues/707#issuecomment-5954893715).

The reader imports neither REMORA runtime code nor the producer's verifier.
It checks every manifest member against the selected digest before evaluation,
then calculates actual results without reading each case's expected answer.
The global property `runtime_capability_surface_completeness` stays
`NOT_ESTABLISHED`. Native claim ceilings, assumptions and every explicit
non-claim are repeated in the retained report.

The reader and the frozen producer package ship in the wheel, so one pinned
install reproduces a run with no clone:

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors-remora-e7 \
  --output remora-e7-result \
  --operator EXTERNAL \
  --run-ref https://probityai.github.io/agent-evidence-atlas/lab.html
```

An installed run records `agent-evidence-vectors==VERSION` as its implementation
revision. From a checkout, run `python -m agent_evidence_vectors.remora_e7.run`
inside `packaging/` and pass `--reader-revision "$(git rev-parse HEAD)"`.

Select `EXTERNAL` only for an operator outside REMORA; a producer-owned CI
reproduction uses `AUTHOR`. The reader records implementation diversity,
operator and independence separately under REMORA's native definition. This
fixture-only result establishes no independent effect custody or production
enforcement. The command refuses an existing output directory, retains actual
source hashes and writes both `report.json` and `external-run-record-v1.json`.

The report must be shared for seven days of producer review before final
publication. An unresolved objection is retained as a disagreement. No review
window starts merely because this reader is published. REMORA lifecycle and CI
adoption stay producer-owned; the reader grants no execution authority.

For controls outside the five pinned examples, this reader treats offered or
dispatch-callable tools as reachable, and registry presence alone as insufficient.
These are explicit local readings, not additional producer conformance claims.
Published expected answers were read before implementation. A lint diagnostic
exposed portions of the retained author verifier after this reader was written;
the author verifier was never imported or executed. This is not a blind study.

Original producer bytes, BUSL-1.1 license and NOTICE are retained under
`upstream/`. The author verifier is stored as `reference_verifier.py.source`,
with unchanged bytes and its original manifest path preserved for hashing,
so it cannot be accidentally imported or formatted as our implementation.

```sh
python -m pip install pytest==8.4.2 hypothesis==6.168.3
python -m pytest -q scripts/remora-e7-reader-test.py
```
