# Key-revocation list vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Cases for `key-revocation-list/v1`: a signed list of the keys an issuer has revoked, each
with the time the revocation takes effect, the keys the list covers, its issue time and the
time its next update is due. A verifier holds the thumbprints of the list-signing keys it
trusts, the issue time of the last list it accepted and the revocations it has already
seen, and is asked whether one key is revoked at one time. The five decisions are
`revoked`, `not_revoked`, `no_statement`, `rejected` and `stale`. The expected decision
and reason of every case are in `MANIFEST.json`.

A revocation list is easy to weaken without breaking a signature: replay an older genuine
list that predates a revocation, drop a revocation from a list a later one replaces, name a
trusted thumbprint beside a key of your own, or let a list that covers other keys stand for
the key asked about. The corpus pairs each of these with the honest case and with a control
that sits exactly on the boundary.

| Case | Decision | Reason | What it shows |
| --- | --- | --- | --- |
| `revoked-in-list` | revoked | `revoked_in_list` | the list carries the key with an effective time before the time asked |
| `covered-no-entry` | not_revoked | `covered_no_entry` | the list covers the key and has no entry for it: not revoked in the record live when the list was served |
| `key-not-covered` | no_statement | `key_not_covered` | the list does not cover the key, so it says nothing about it; silence is not a statement |
| `revocation-not-yet-effective` | not_revoked | `revocation_not_yet_effective` | the entry takes effect after the time asked |
| `revocation-kept-after-later-list-omits-it` | revoked | `revoked_kept_from_earlier_list` | a revocation already seen is kept when a newer list covers the key and omits it |
| `revocation-kept-for-key-the-later-list-no-longer-covers` | revoked | `revoked_kept_from_earlier_list` | a revocation already seen is kept when a newer list no longer covers the key |
| `signer-not-trusted` | rejected | `signer_not_trusted` | the list verifies under the key it carries and the verifier does not trust that key |
| `signer-claims-a-trusted-thumbprint` | rejected | `signer_not_trusted` | the list names a trusted thumbprint beside a key of its own; the verifier recomputes the thumbprint from the key |
| `list-signature-invalid` | rejected | `list_signature_invalid` | a revocation removed from a trusted signer's list after it was signed |
| `list-older-than-accepted` | rejected | `list_older_than_accepted` | an older genuine list replayed over a newer one, which omits a later revocation |
| `list-issued-at-the-last-accepted-time` | not_revoked | `covered_no_entry` | the control: a list issued at the same time as the last accepted one is not older |
| `list-past-next-update` | stale | `list_stale` | the verifier's clock is one second past the list's next update |
| `list-at-next-update` | not_revoked | `covered_no_entry` | the control: at the next update instant the list is still current |

`not_revoked` over a covered key with no entry says only that the list, current when it was
served, holds no revocation for the key. A revocation the issuer decided and never published
cannot show here. A key the list does not cover is `no_statement`, never `not_revoked`.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-key-revocation-list
```

A verifier under test takes `case.json --json`, prints one JSON object carrying `decision`
and `reason`, and exits 0 for `revoked`, 1 for `not_revoked`, 2 for `no_statement`, 3 for
`rejected` and 4 for `stale`:

```sh
agent-evidence-vectors --corpus vectors-key-revocation-list --verifier './verifier'
python3 vectors-key-revocation-list/check_vectors.py --verifier './verifier'
```

The reader checks in this order and names the first check that fails: the signing key is
trusted by thumbprint computed from the key, the list verifies, the list is not older than
the last one accepted, and the verifier's clock is not past the next update. A list that
passes is read with the revocations already seen, which a later list cannot remove. The
order is part of the contract.

Regenerate the cases with `python3 vectors-key-revocation-list/gen_vectors.py`. The keys are
Ed25519 seeds derived from published labels in the generator, so anyone can rebuild every
signature; they protect nothing. Every list is synthetic.
