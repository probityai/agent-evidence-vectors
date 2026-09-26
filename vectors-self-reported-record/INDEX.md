# Self-reported agent record vectors

Emitted by `gen_vectors.py`. Do not edit: an edit here is overwritten on the
next build and `scripts/regenerability-gate.py` refuses the push that makes
one.

Contract: `spec/self-reported-record/v1.md`, pinned at `bab82338ffc6`.
Predicate type: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/self-reported-record`.

The `parent` column names the accepted member a refusal is one mutation from.

| vector | verdict | code | conditions | what it carries | parent |
| --- | --- | --- | --- | --- | --- |
| `v27d7d1f2907c93b7` | invalid | `memory-digest-not-over-named-path` | `srr-c-2` | the digest of the stored copy reported against an inverted file | `v308c9f77bd7e1006` |
| `v308c9f77bd7e1006` | valid |  | `srr-c-2` `srr-c-4` `srr-c-6` | an empty turn set, two empty ledgers and one memory read that agrees |  |
| `v4c2b7e742b70b493` | invalid | `attesting-key-in-self-signers` | `srr-c-3` | an attesting key the record's own declaration puts inside the runtime | `v9e808d2647227acf` |
| `v6ba13900c29be2ca` | invalid | `ledger-members-disagree` | `srr-c-4` | a change the session ledger still names and the change log does not | `vac020bc4f647790d` |
| `v730be9199668cf6d` | valid |  | `srr-c-1` `srr-c-3` | an attesting key outside the declared set the runtime holds |  |
| `v95b74832c6cc3173` | valid |  | `srr-c-1` `srr-c-2` `srr-c-3` `srr-c-4` `srr-c-5` `srr-c-6` | a record whose turns, memory read and covered fields all hold |  |
| `v9e808d2647227acf` | valid |  | `srr-c-1` `srr-c-5` `srr-c-6` | twelve caller-supplied values, each declared the producer's own assertion |  |
| `vaab489ae4d909406` | invalid | `field-claims-coverage-uncovered` | `srr-c-5` | the same twelve values, each declaring a coverage nothing carries | `v9e808d2647227acf` |
| `vac020bc4f647790d` | valid |  | `srr-c-1` `srr-c-4` | a removal applied to both ledgers, so the two still agree |  |
| `vb3ad83a8e48d43d1` | malformed | `record-malformed` | `srr-c-6` | an unregistered origin_kind value, and every other rule holding | `v308c9f77bd7e1006` |
| `vcfa46b7eb3d08f55` | invalid | `turn-unsigned-by-attesting-key` | `srr-c-1` | a third turn declaring the attesting key and signed by another | `v95b74832c6cc3173` |

## Conditions

| id | what it requires | code on refusal |
| --- | --- | --- |
| `srr-c-1` | every turn carries a signature that verifies under the attesting key | `turn-unsigned-by-attesting-key` |
| `srr-c-2` | a memory read's asserted digest is the digest of the bytes at its path | `memory-digest-not-over-named-path` |
| `srr-c-3` | the attesting key is not one the record says the runtime can mint | `attesting-key-in-self-signers` |
| `srr-c-4` | every ledger the record carries names the same change set | `ledger-members-disagree` |
| `srr-c-5` | a field declaring substrate coverage carries the covering signature | `field-claims-coverage-uncovered` |
| `srr-c-6` | the record is well formed and every closed vocabulary value is registered | `record-malformed` |
