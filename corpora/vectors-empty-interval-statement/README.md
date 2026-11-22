# Empty-interval statement vectors

Cases for `empty-interval-statement/v1`: a revocation ledger kept as a hash-linked chain of
signed events, a signed statement from the ledger that a credential has no revocation
between two positions of it, and the value a verifier must reach. The five values are the
`revocation_establishment` term of the
[vocabulary](https://w3id.org/agent-evidence/vocab/v1/revocation_establishment):
`recorded`, `not_recorded`, `query_failed`, `cross_federation_unsynchronised` and
`undetermined`. `undetermined` is the fallback for every statement that fails a check, so
a statement that does not verify is never read as an empty interval. The expected value
and reason of every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

An empty interval is the answer a relying party most often needs and the one that is
easiest to fake: a ledger that deleted a revocation, edited it into another event or rolled
back to an abandoned branch can still sign "nothing recorded". The corpus pairs each of
those with the honest empty interval and with a negative control, a signed statement that
lists nothing while the ledger holds a revocation inside the interval. The ledger decides,
never the statement.

| Case | Value | Reason | What it shows |
| --- | --- | --- | --- |
| `interval-empty-not-recorded` | not_recorded | `no_revocation_in_covered_interval` | the chain is unbroken, a signed and timestamped checkpoint covers the interval and the ledger holds no revocation of the credential inside it |
| `interval-holds-revocation` | recorded | `revocation_recorded` | the credential is revoked at position 4, inside the interval, and the statement lists it |
| `statement-omits-recorded-event` | recorded | `statement_omits_recorded_event` | the negative control: a signed statement that lists nothing while the ledger holds a revocation inside the interval; the ledger decides, not the statement |
| `other-credential-revoked-in-interval` | not_recorded | `no_revocation_in_covered_interval` | another credential is revoked inside the interval, which says nothing about this one |
| `revocation-outside-interval` | not_recorded | `no_revocation_in_covered_interval` | the credential is revoked at position 1 and at position 6, one before the interval and one after it, and the interval is empty |
| `query-failed` | query_failed | `ledger_query_failed` | the ledger returned no answer, which is never read as an empty interval |
| `cross-federation-unsynchronised` | cross_federation_unsynchronised | `federation_not_synchronised` | the ledger is in a federation the verifier has no synchronisation record with, so a missing event may only be one not yet exchanged |
| `cross-federation-synchronised` | not_recorded | `no_revocation_in_covered_interval` | the control: the same ledger in another federation, with a synchronisation record bridging to it, is read as an interval of the verifier's own |
| `forged-statement-signature` | undetermined | `statement_signature_invalid` | the statement is signed by a key that is not the ledger's |
| `statement-for-other-credential` | undetermined | `statement_for_other_interval` | a genuine statement about another credential, replayed for this one |
| `forged-checkpoint-signature` | undetermined | `checkpoint_signature_invalid` | the statement verifies and the checkpoint inside it is signed by another key |
| `checkpoint-without-time` | undetermined | `checkpoint_not_timestamped` | a correctly signed checkpoint that carries no signing time |
| `checkpoint-stops-short` | undetermined | `checkpoint_does_not_cover_range` | the checkpoint is signed over position 4 and the interval ends at 5 |
| `event-edited-in-place` | undetermined | `ledger_event_invalid` | a revocation edited into a rotation after signing, which an empty list then appears to confirm |
| `event-deleted-from-interval` | undetermined | `chain_link_broken` | the revocation is removed from the ledger and every remaining signature verifies; only the chain shows the hole |
| `ledger-rolled-back-to-abandoned-branch` | undetermined | `checkpoint_head_mismatch` | every event verifies and links, and the checkpoint names a head the ledger no longer holds |

`not_recorded` says that the checked ledger holds no revocation in the interval. A
revocation decided and never logged cannot show here, so the value is not evidence that
the credential was never revoked, and no case in this corpus can make it so. The same
word is a value of a different term in `vectors-agent-decision`, where a producer writes
it for a tool-call argument it chose not to record; the two are unrelated.

## Running it

The package judges the corpus with its own reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-empty-interval-statement
```

A verifier under test takes `case.json --json`, prints one JSON object carrying `decision`
and `reason`, and exits 0 for `recorded`, 1 for `not_recorded`, 2 for `query_failed`, 3 for
`cross_federation_unsynchronised` and 4 for `undetermined`:

```sh
agent-evidence-vectors --corpus vectors-empty-interval-statement --verifier './verifier'
python3 vectors-empty-interval-statement/check_vectors.py --verifier './verifier'
```

The reader checks in this order and names the first check that fails: the query returned an
answer, the ledger's federation is the verifier's or bridged, the statement verifies, the
statement is about the credential and interval asked, the checkpoint verifies, the
checkpoint carries a signing time, the checkpoint covers the end of the interval, every
event verifies, every event links to the one before at its own position, and the checkpoint
names the head the ledger holds. The order is part of the contract.

Regenerate the cases with `python3 vectors-empty-interval-statement/gen_vectors.py`. The
keys are Ed25519 seeds derived from published labels in the generator, so anyone can
rebuild every signature; they protect nothing. Every ledger and statement is synthetic.
