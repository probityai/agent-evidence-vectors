# Decision records: action binding

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

## Four groups of members

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
  key later revoked as compromised or superseded that signs a time before the retirement, and an
  identity source that reads the approver as verified without naming the source it rests on (so
  neither the identity nor the approver's grant is confirmed). The `baseline-sig-*` group adds a key
  superseded, expired, revoked as compromised or listed in another role before the stated sealing
  time; a key superseded after it, which is `unavailable` without an independent timestamp and
  `verified` with one earlier than the retirement; and the seal's signature in a second base64 text
  of the same bytes, which is not read.
- **`baseline-time-*`**: the published signed attachment beside a relying party's reading of a
  timestamp token over its seal. A timestamp bounds the issuer's times from above only: an issuer
  time after it fails, one within a day before it is verified, one seven months before it stays
  `not_checked`, and a timestamp over other bytes is `unavailable`.

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
