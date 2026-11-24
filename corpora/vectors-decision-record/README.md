# Decision records: action binding

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

A verifier of decision-record action-binding attachments (documents carrying
`"profile": "dps-action-binding"` and `"profile_version": "0.3.0"`) must report each check as its
own dimension, never one merged pass, and must refuse what the format's own text accepts but a
relying party should not.

## What is here

| Path | What it is |
|---|---|
| `source/` | the format's published test cases and vectors, unchanged, pinned by SHA-256 in `SOURCE.json` |
| `gen_vectors.py` | writes every member, `MANIFEST.json` and `INDEX.md` from `source/` |
| `check_vectors.py` | judges every member with `agent-evidence-verify` and recomputes the corpus digest |
| `members/` | one JSON object per member: `attachment` (the exact text), `record`, `trust_policy`, `relying_party`, `profile` |
| [`INDEX.md`](INDEX.md) | every member, its profile, verdict and code |

## Three groups of members

- **`baseline-*`**: one member per published binding case of the format, with the case's own
  expected value for every binding dimension. Read under the `baseline` profile: a dimension that
  failed refuses; `not_checked` and `unavailable` stay as reported.
- **`baseline-sig-*`**: the format's published signed attachments under its published trust policy,
  and the ways a seal or a document fails: a result changed after signing, a key the policy does
  not list, a policy that lists one key twice, a member named twice.
- **`strict-*`**: attachments signed with this corpus's published test key and read with every
  source a relying party holds, where exactly one check refuses. Each is a case the format's text
  accepts: an approval by the drafting role or by the executor, one request observed to succeed
  twice, a retry after an indeterminate attempt with nothing observed at the target, a person no
  identity source confirms, a change no authority source grants, stages backdated consistently, an
  older attachment of the decision, and a removed signature.
  Further members cover the shapes of a missing or mismatched observation: the requesting service
  approving, a grant under another charter, an identity source that fails or does not know the
  approver, an approval the independent clock places after the action ran, a relying party that
  holds no identity source, authority source, clock, latest-attachment record or trust policy, and a
  key later revoked as compromised that signs a time before the revocation. The `baseline-sig-*`
  group adds a key superseded, expired or listed in another role than the one that sealed.

The member's `code` is the first dimension that refused and its status, such as
`action_binding:failed` or `single_effect_per_request:not_checked`.

## Run it

```sh
uv run --extra generators python corpora/vectors-decision-record/gen_vectors.py
uv run --with agent-evidence-verify python corpora/vectors-decision-record/check_vectors.py
agent-evidence-verify corpus corpora/vectors-decision-record
```

The corpus suite is `decision-record/v1`. Without `agent-evidence-verify` the check exits 2 and
says it did not run.
