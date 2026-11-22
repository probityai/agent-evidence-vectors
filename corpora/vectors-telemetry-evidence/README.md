# vectors-telemetry-evidence

Suite `telemetry-evidence/v1`: 36 synthetic records that check two things a telemetry pipeline claims and rarely
proves. A digest must bind the copy the consumer actually reads, and an event log must be the whole log.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-telemetry-evidence
python3 corpora/vectors-telemetry-evidence/check_vectors.py --verifier "<your verifier>"
```

Your verifier is called as `<verifier> <case-dir>/record.json --json`, prints `{"decision", "reason"}` and exits 0
for `agrees`, 1 for `contradicted`, 2 for `cannot-tell`.

## What the cases hold

| Requirement | Cases | What a digest-only check misses |
|---|---|---|
| OBS-5a, a digest over declared canonical bytes | 12 | default-separator and `\u`-escaped serializations, ECMAScript number spelling, astral characters, an empty body, deterministic and non-deterministic CBOR, raw bytes under SHA-512, an undeclared form (`cannot-tell`) |
| OBS-5b, the digest binds the consumed copy, with a denominator | 5 | a repeated member in a consumed body, a consumed copy edited while the hashed copy is not, every reference removed (`0 of 4`), `0 of 0` (`cannot-tell`), two references to one item |
| OBS-5c, a signed digest set under a pinned key | 6 | a manifest signed by the key it carries for itself (`contradicted`, `signer_pinned`) beside the same manifest signed by the pinned key (`agrees`), no pin, a required signature absent, a digest changed after signing, a `null` signature member (`contradicted`, `record_shape`: neither a signature nor its absence) |
| OBS-7, an event log against a retained signed head | 13 | each of six edits (drop, swap, status flip, link rewrite, body edit, tail cut) with its own reason, a relinked rewrite, a rewrite re-signed by another key, no head, no events, an event outside the coverage boundary, a log that starts at a declared seq |

Each record is self-contained: the manifest as the exact text the producer wrote (so a repeated member survives),
each consumed copy as text or hex, and the SHA-256 of every key the consumer pinned. The head is in the
`probity-witness-ledger-head-v0` format. Keys come from seeds under `agent-evidence-vectors/telemetry-evidence/v1/`
and every body was written for this corpus; `gen_vectors.py` regenerates it byte for byte.

The reference verifier `agent-evidence-verify` reads the same rules as `evidence_digest/v1` and
`event_log_completeness/v1`, with the same reasons, and agrees with all 36 cases. The cases say nothing about
whether the recorded content is true or whether the producer recorded every event that happened.
