# Decision records: OCSF API Activity

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

A verifier of OCSF API Activity decision records of the AID-EMIT-1 `record_integrity` kind (the
Praxis Policy Engine `ocsf-audit` sink) must report each check as its own dimension, never one merged
pass, and must refuse what the format's own verifier rule accepts but a relying party should not: a
member named twice riding a valid seal, a key chosen by a key id that sits outside the signed bytes,
and a stream whose tail was cut.

## What is here

| Path | What it is |
|---|---|
| `source/` | the format's three published sample outputs, unchanged, pinned by SHA-256 in `SOURCE.json` |
| `gen_vectors.py` | writes every member, `MANIFEST.json` and `INDEX.md` from `source/`, with its own emitter |
| `check_vectors.py` | judges every member with `agent-evidence-verify` and recomputes the corpus digest |
| `members/` | one JSON object per member: `records` (the exact text, one record per line), `trust_policy`, `relying_party`, `profile` |
| [`INDEX.md`](INDEX.md) | every member, its profile, verdict and code |

## Two groups of members

- **`baseline-*`**: the published signed pair under the published demo key, the nine published
  unchained decision records, a chain emitted here over the published decisions, and one member per
  way a stream breaks: a duplicate member (plain and escaped) under the published seal, a swapped or
  unknown key id, a record re-signed under a retired key, a key of another authority, a policy listing
  one key twice, a dropped tail with an independent head, a deleted record, changed content, a
  fingerprint recomputed without a signature, a fork, a substituted uid, a stream gap, `emission_seq`
  disorder, a verdict that reads two ways and a suppressed deny no flag reports. One member drops the
  tail with no head: the records alone cannot show it, so `tail` reads `not_checked`, never `verified`.
- **`strict-*`**: a complete signed chain with an independent head, and refusals for two live keys of
  one authority, no head, an unsigned chain rewritten end to end, an epoch a double cannot hold and a
  chain whose opening is not supplied.

The member's `code` is the first dimension that refused and its status, such as `key_binding:failed`
or `tail_anchored:not_checked`.

## Run it

```sh
uv run --extra generators python corpora/vectors-ocsf-decision/gen_vectors.py
uv run --with agent-evidence-verify python corpora/vectors-ocsf-decision/check_vectors.py
agent-evidence-verify corpus corpora/vectors-ocsf-decision
```

The corpus suite is `ocsf-decision/v1`. Without `agent-evidence-verify` the check exits 2 and says it
did not run.
