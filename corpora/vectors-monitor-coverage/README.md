# Monitor-coverage vectors

Cases for `monitor-coverage/v1`: one monitor's verdict over one window, judged against
what the monitor could see. A detector, a defence or a log reader reports clean; the
word hides two gaps. The collector behind it may have dropped or never received part of
the window, and its vantage may not include the channel an effect used. A missing
observation then reads as a clean one. Evaluations of defences carry a third gap: a
defence that never acted is credited with the harm it is said to have prevented.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-4c6278?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

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
