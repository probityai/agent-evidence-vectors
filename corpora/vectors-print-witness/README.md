# Print witness vectors

Cases for `print-witness/v1`: one machine job seen by a witness, a device that
sits between the agent controlling a machine and the machine itself. The
witness signs the job file it received before forwarding it, signs log records
while the job runs, and signs a closing record when the job ends. Each case is
the job file (G-code for a five-layer test part on a Bambu Lab H2D), the signed
log, and the consumer's trust inputs: the witness keys it trusts and the digest
of the job file it ordered. The expected decision and reason for every case are
in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

A signature tells a verifier that a trusted witness signed a record. It does
not say the log is whole, that the job file beside it is the one the witness
saw, or that the witness that saw the job file is the one that watched the
print. The column headed "every signature verifies" is the point of the
corpus: eight of the ten rejected logs carry only records that verify under a
key the consumer trusts.

| Case | Every signature verifies | Expected | Pairs with |
| --- | --- | --- | --- |
| intact | yes | verified, `print_witnessed` | |
| intact-other-witness | yes | verified, `print_witnessed` | |
| log-stops-early | yes | rejected, `log_truncated` | intact |
| log-closes-early | yes | rejected, `print_not_finished` | intact |
| gcode-changed-after-signing | yes | rejected, `gcode_altered` | intact |
| gcode-not-ordered | yes | rejected, `gcode_not_ordered` | intact |
| witness-changed-mid-print | yes | rejected, `witness_changed` | intact-other-witness |
| untrusted-witness | no | rejected, `signature_invalid` | intact-other-witness |
| log-record-edited | no | rejected, `signature_invalid` | intact |
| log-from-other-print | yes | rejected, `job_mismatch` | intact |
| log-reordered | yes | rejected, `chain_link_broken` | intact |
| log-without-intake | yes | rejected, `intake_missing` | intact |

Each rejected case differs from the accepted case it pairs with in one thing,
so a verifier that passes the pair has shown it reads that one thing. Three
pairs answer the questions a scorer of a witnessed job has to answer:

- **The log stops early.** `log-stops-early` is the intact log cut after layer
  3. Every record left verifies and links, and nothing in it says a record is
  missing; only the absent closing record does. `log-closes-early` is the
  honest version of the same stop: the witness signed a closing record saying
  the print ended at layer 3, so the log is whole and the print is not.
- **The job file changed after the witness signed it.** In
  `gcode-changed-after-signing` the log is byte for byte the intact log and the
  file beside it prints 10% infill, not 15%. Only the digest in the intake
  record catches it. `gcode-not-ordered` is the other side: the witness took in
  and faithfully logged a job the consumer never ordered.
- **The log is signed by a different witness.** In `witness-changed-mid-print`
  witness a took in the job file and witness b signed every later record. Both
  keys are trusted and every signature verifies. `intact-other-witness`, the
  whole job witnessed by b, is accepted: what is refused is the change, not
  the witness.

## The record layout

Each line of `log.jsonl` is `{"kid", "record", "sig"}`: `sig` is an Ed25519
signature over the RFC 8785 form of `record` by the trusted key `kid` names in
`case.json`, and `record.witness` names the same witness. Every record carries
`job`, `seq` (its position) and `prev` (the SHA-256 of the line before it, or
64 zeros). The first record has `type` `intake` and names the job file by
`gcode_sha256`, `gcode_bytes` and `layers`; `progress` records follow, one per
layer; the last has `type` `close`, a `status` and `layers_printed`. The layout
is this corpus's own. A witness that writes another layout carries the same
cases once its fields are mapped onto these.

## Running it

The package judges the corpus with its own reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-print-witness
```

A verifier under test takes `case.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `verified` and 1 for
`rejected`:

```sh
agent-evidence-vectors --corpus vectors-print-witness --verifier './verifier'
python3 vectors-print-witness/check_vectors.py --verifier './verifier'
```

The reader checks in this order and names the first check that fails: record
signature under a trusted witness key, intake record first, one witness
throughout, one job throughout, sequence and chain link, job file digest,
ordered job file, closing record present, closing record finished. The order
is part of the contract, so a log that fails two checks has one expected
reason.

Regenerate the cases with `python3 vectors-print-witness/gen_vectors.py`. The
keys are Ed25519 seeds derived from published labels in the generator, so
anyone can rebuild every signature; they protect nothing.

Passing these cases does not establish that the witness observed the machine
rather than a replay of its output, that the printed part matches the job file,
or that the witness key was held only by the device that signed.
