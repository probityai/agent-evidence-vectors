# Authority epoch fence vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Type URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/authority-epoch-fence`

Signing domains: the type URI with the fragment `#event` for a log event, `#head` for the
head that closes the log, and `#request` for a request.

Cases for `authority-epoch-fence/v1`. An authority epoch is a numbered period of an
authority log. Every request names the epoch of the log it was made in, and a request of
a closed epoch is refused whatever its time: an epoch, not a clock, decides whether it may
still act. The log is signed, chained by digest and closed by a signed head, so a log that
was cut short, or a head that is missing, reads `unknown` rather than clean.

Every case answers three things: a `decision` (`admit`, `refuse` or `no_verdict`), a
`reason`, and a `revocation_status`, which says whether a revocation that applies to the
request's subject has taken effect: `live`, `suspended`, `partial`, `closed` or `unknown`.
The expected answers of every case are in `MANIFEST.json`, with the counts by decision and
by status.

## The rule this corpus exists for

An open, unresolved or unreadable state never reads `closed`. A revocation whose dispute is
open reads `unknown`. A revocation that stops only new admissions reads `partial`, because
work admitted before it may still run. A log or head that cannot be read whole reads
`unknown`. A suspension can be lifted, so it reads `suspended`. A reader that reports any
of these as `closed` tells an operator the authority is gone when it may not be, and the
corpus refuses it: the cases `status-open-dispute-reads-unknown`,
`status-new-admissions-scope-reads-partial` and `status-truncated-log-reads-unknown` fail
such a reader.

A revocation is never undone. A restoration is a new grant, and the revoked grant stays
revoked (`status-restored-dispute-still-revoked`, `status-restoration-is-a-new-grant`). A
resume lifts only a suspension (`suspend-resume-after-revoke-does-nothing`). A revocation
of every grant of a subject, a kill, survives an owner change and a re-registration
(`owner-kill-survives-owner-change`, `rereg-does-not-lift-a-kill`). This follows the
[UCAN revocation specification](https://github.com/ucan-wg/revocation), where a revocation
is irreversible and reaches every grant below the revoked one.

## Records

Every record is a JSON object with exactly two members, `{"claims": {...}, "sig": "..."}`.
`claims` has exactly the members its type declares. `sig` is the standard base64, with
padding, of an Ed25519 signature over

    DOMAIN || 0x00 || JCS(claims)

where DOMAIN is the record's signing domain as UTF-8 and JCS is the
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical form. `sig` must be the
canonical spelling of the bytes it decodes to. `kid` is the lowercase hex SHA-256 of the
raw 32-byte public key; it only selects among keys the verifier already pins, and a key is
never taken from a record. Times (`*_ns`) are nanoseconds as decimal strings with no
leading zero, because RFC 8785 numbers are IEEE 754 doubles and lose integer precision at this size. `v`, `seq` and `epoch`
are JSON integers, never booleans and never `1.0`. Unused members are the empty string.

| Record | Members, exactly | Domain |
| --- | --- | --- |
| event | `v`, `log_id`, `seq`, `epoch`, `kind`, `subject`, `ref`, `parent`, `cause`, `scope`, `at_ns`, `previous`, `kid` | `#event` |
| head | `v`, `log_id`, `seq`, `epoch`, `digest`, `at_ns`, `kid` | `#head` |
| request | `v`, `request_id`, `subject`, `grant_id`, `approval_id`, `epoch`, `at_ns`, `kid` | `#request` |

An event's `previous` is the hex SHA-256 of the RFC 8785 form of the previous event's whole
record (claims and signature), and the empty string at `seq` 0. The head's `digest` is the
same digest of the last event. This is the hash-chain idea of
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) in its simplest form: the signed head
commits to the whole log, so dropping, editing or reordering an event breaks it.

`case.json` carries `v`, `log_id`, `keys` (`genesis`, the base64 log key at epoch 0, and
`holders`, one base64 key per subject), `events` (the event files in order), `head` (a file
or `null`), `request` and `now_ns`, the verifier's clock. No check reads `now_ns`: the
cases set it so that a reader deciding by time instead of by epoch gives the wrong answer.

## Event kinds

| Kind | Members used | Meaning |
| --- | --- | --- |
| `genesis` | none | `seq` 0, `epoch` 0, signed by the genesis key |
| `epoch_open` | `cause`, and `subject` or `ref` | opens the next epoch: `epoch` is the previous plus one. `cause` is `clock_acknowledged`, `restart`, `root_change` (`ref` is the new log key, used from the next event on), `re_registration` or `owner_change` (`subject` names who) |
| `grant` | `ref`, `parent`, `subject` | issues grant `ref` to `subject`, below grant `parent` or at the top when `parent` is empty |
| `revoke` | `ref`, `subject`, `scope` | revokes grant `ref`, or every grant of `subject` when `ref` is empty; `scope` is `all` or `new_admissions` |
| `suspend`, `resume` | `subject` | a resume lifts a suspension and nothing else |
| `approval_consumed` | `ref`, `subject` | approval `ref` has been used and counts once |
| `fork` | `subject` | a second signer for `subject` was recorded (a proposal, below) |
| `dispute_open`, `dispute_closed` | `ref`, `cause` | `ref` is the revoke event's `seq` as a decimal string; a close has `cause` `confirmed` or `restored`, and a restoration never revives the grant |

Any other event has the epoch of the one before it.

## Check order

The reader stops at the first check that fails.

| Step | Check | Decision and reason | Status |
| --- | --- | --- | --- |
| 1 | every file is a record of its type: shape, members, types | `no_verdict` `malformed` | `unknown` |
| 2 | a head is present | `refuse` `epoch_unavailable` | `unknown` |
| 3 | the log walks: `seq` contiguous from a genesis, one `log_id`, `previous` links, epoch rules, kind rules, every event signed under the current log key | `refuse` `log_invalid` | `unknown` |
| 4 | the head is signed under the current key and its `log_id`, `seq`, `epoch` and `digest` bind the last event | `refuse` `history_incomplete` | `unknown` |
| 5 | the subject's holder key is pinned and named by `kid`; it signs the request | `refuse` `unknown_holder`, `request_signature_invalid` | from the log |
| 6 | the request's epoch is the current epoch | `refuse` `epoch_closed`, `epoch_ahead` | from the log |
| 7 | the approval was not consumed | `refuse` `approval_consumed` | from the log |
| 8 | the grant was issued to the subject, and no re-registration of the subject came after it | `refuse` `no_grant`, `grant_superseded` | from the log |
| 9 | the subject's standing: a fork, then revocations on the grant chain or of the subject, then a suspension | `refuse` `fork`, `parent_revoked`, `revoked`, `revoked_dispute_open`, `suspended`; else `admit` `authority_valid` | see below |

The status from the log, computed for the request's subject whenever steps 1 to 4 pass:
`closed` for a fork; for applying revocations, `unknown` when any has an open dispute,
`partial` when every one has scope `new_admissions`, and `closed` otherwise; `suspended`
for a suspension; `live` otherwise. A revocation applies when it names the subject with an
empty `ref`, or names a grant on the request's chain through `parent` links. It reads
`parent_revoked` when an ancestor was revoked before the request's grant was issued.

## Families

Case ids start with their family: `epoch-` (closed, ahead, restart, acknowledged clock),
`approval-`, `suspend-`, `delegation-` (parent, child, sibling, grandchild), `root-`
(log key change, unpinned holder, altered request), `rereg-`, `owner-`, `fork-` and
`status-` (disputes, scopes, truncated or unreadable logs, malformed records).

Each entry in `MANIFEST.json` has `"status": "normative"` or `"status": "proposed"`. The
proposed cases state rules offered for adoption: `epoch-dead-request-presented-two-epochs-later`
(a request on a grant revoked in a closed epoch stays dead in every later epoch) and
`fork-second-signer-recorded` (a second signer for one subject ends in a recorded fork,
which closes it).

## Running

    python3 corpora/vectors-authority-epoch-fence/check_vectors.py
    python3 corpora/vectors-authority-epoch-fence/check_vectors.py --verifier "<your verifier>"
    go run ./cmd/aee-verify corpora/vectors-authority-epoch-fence

An external verifier is run as `<verifier> <case-dir>/case.json --json`. It prints one
JSON object with `decision`, `reason` and `revocation_status`, and exits 0 for `admit`, 1
for `refuse` and 2 for `no_verdict`. The Python reader is
`packaging/agent_evidence_vectors/authorityepoch.py`; the Go reader
`corpusreaders/authorityepoch.go`, which `aee-verify` runs, applies the same checks in the
same order. `gen_vectors.py` rebuilds every file byte for byte;
the keys come from published labels and protect nothing.
