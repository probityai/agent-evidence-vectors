# Corpus measurements

Use the mutation baseline to inspect what the corpus forces, and the condition registry to connect each case to its specification rule.

## Replay checks

[aee/vectors_test.go](../../aee/vectors_test.go) replays the suite at `../../vectors`, or `AEE_VECTORS_DIR` when set. Accepts require validity, matching results and both tier columns. Rejects require an expected primary code, invalidity and no result or tiers. An absent suite is reported as an explicit skip.

Pinned test keys are derived from `seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`. They are test material, not private production keys.

## What the corpus forces

A vector count alone does not measure rule coverage. Removing the `result-vocabulary` emission makes two gate-0 displays fail while the suite still reports 285 of 285, exit 0. A rail with no result-vocabulary check clears that corpus.

[forcing-gate.py](../../scripts/forcing-gate.py) disables one reference-rail rule, rebuilds and replays the population. It measures what the corpus notices -- 808 single-site weakenings of `aee/`, one rebuild and one full replay per site.

The quantifier operator stops a collection loop after one member. That tests whether the corpus forces a rule for every member, including when the defective member is not the first one.

[FORCING-BASELINE.json](../FORCING-BASELINE.json) is the tighten-only ratchet: **466 rules forced, 36 seen-but-tolerated, 301 unforced, 5
unmeasurable.** The four outcomes retain their own meanings:

| Outcome | Meaning |
| --- | --- |
| Forced | A weakened rule causes a scored failure |
| Seen but tolerated | The run observes a change without a scored failure |
| Unforced | The weakening survives the tested population |
| Unmeasurable | This campaign cannot produce a usable measurement |

The baseline annotates four sites as equivalent behavior (three) or masked by an earlier check (one). An annotated site that is ever killed fails the gate.

CI checks the previously forced sites on every push and sweeps all 808 sites nightly. The measurement describes this corpus against this reference implementation. Because the answer key is public, an external verifier can look up expected answers; a complete sweep records correct outputs, rather than proving how they were computed.

## Specification-level projection

[FORCING-HONESTY.md](../FORCING-HONESTY.md) projects the site baseline onto normative condition IDs: forced rules, redundant coverage and optional reason-code emissions. [condition-forcing-gate.py](../../scripts/condition-forcing-gate.py) derives and checks those figures.

[PRIOR-FORCING.json](../PRIOR-FORCING.json) pins the historical baseline and manifest Git objects. `--verify-prior` reconstructs that projection from a full clone; it runs in the nightly job because a shallow checkout may omit the objects.

The reconstruction finds three more killed weakenings than the earlier published note. All three belong to the no-key-policy branch, which that earlier run never exercised. The verifier checks the named set and the subtraction back to the released figure.

## Detector liveness

A planted stimulus, the manifest's expected wire form, the substrate commitment, the row's comparability assertion and the run-end attribution seal establish liveness for that attack class. Fixtures exercise each channel. [liveness-probe.py](../../scripts/liveness-probe.py) derives this from existing statement fields; [DETECTOR-LIVENESS.md](../DETECTOR-LIVENESS.md) records the construction and its class-specific scope.

## Accept anchors

Every rejection has a declared accepting parent. [accept-anchor-gate.py](../../scripts/accept-anchor-gate.py) checks that the parent ships, maintains a ratchet for conditions cited only by refusals, and validates the figures it owns.

It also checks that the child is one mutation from its parent. The semantic comparison normalizes a signature, batch root, run binding, carried result or digest only when each side matches its own derivation. Other changed paths are reported.

[MULTI-MUTATION-VECTORS.json](../MULTI-MUTATION-VECTORS.json) records exceptions with a reason. Missing reasons, absent vectors and exceptions that no longer need multiple mutations fail the gate.

## Condition registry

The [condition table in vectors/reject/INDEX.md](../../vectors/reject/INDEX.md) resolves every `aee-c-NN` cited by a vector to its specification lines.

The earlier registry covered reject-used IDs only, so 17 ids cited by accept vectors had no resolution. It now covers both directions. [condition-registry-gate.py](../../scripts/condition-registry-gate.py) rejects missing rows and rows unused by every vector.
