# Monitor-coverage vectors

Cases for `monitor-coverage/v1`: one monitor's verdict over one window, judged against
what the monitor could see. A detector, a defence or a log reader reports clean; the
word hides two gaps. The collector behind it may have dropped or never received part of
the window, and its vantage may not include the channel an effect used. A missing
observation then reads as a clean one. Evaluations of defences carry a third gap: a
defence that never acted is credited with the harm it is said to have prevented.

For anyone who writes or reads monitor verdicts, detector reports or defence evaluation
results, and wants a reader that refuses those three readings.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-monitor-coverage
python3 corpora/vectors-monitor-coverage/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and
exits 0 for `allow`, 1 for `deny`.

## What the cases force

The reader applies nine checks in order and names the first that fails:
`contract_id_missing`, `contract_id_unknown`, `window_invalid`,
`coverage_counts_invalid`, `coverage_self_reported` (a clean verdict on a count the
watched producer made about itself), `clean_with_incomplete_coverage`,
`clean_outside_vantage`, `clean_contradicts_observed_effect`, and
`defence_effect_without_effective_actions`. Each denied case fails exactly its named
check; the controls show that `not_established` and `flagged` stand on partial coverage,
and that a defence with no effective action is fine as long as nobody credits it with an
effect. Counts are in `MANIFEST.json`.

The case `reject-defence-effect-with-zero-effective-actions` is the shape of a defence
evaluated over 2,000 decisions in which it took no action: an evaluation has to count
the control's effective actions before it credits the control with an outcome.

## Synthetic, and labelled so

Every member is synthetic. Monitors, collectors and channels are fixed labels, and no
member records a real system or incident. The manifest says so in `synthetic`.

## What it does not test

Whether a monitor is any good. A conforming verdict says what the monitor saw and how
much of the window it saw; it is not evidence that the monitor would have caught the
effect. Regenerate with `python3 corpora/vectors-monitor-coverage/gen_vectors.py`.
