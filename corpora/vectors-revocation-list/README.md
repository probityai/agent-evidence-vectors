# Revocation list

One signed, cumulative revocation list format, and what a verifier must refuse.
A list is `{"body": BODY, "sig": base64(Ed25519 over "probity-revocation-v1\0" || JCS(BODY))}`;
lists are chained by sequence number and digest, and an entry, once published,
stays in every later list byte for byte. A verifier pins its root key ids out of
band and never reads one from a list.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Each case under `cases/` is what one verifier sees: `roots.json` (the pinned root
key ids) and the signed lists it is handed, in order. `MANIFEST.json` states, per
case, the decision, the full refusal (code, or code:detail) and the index of the
refused list, the list in force when the verdict was reached, and the ListDigest
of every list file.

The cases whose `source` is `shared:RLnn` are the shared vectors every reader of
this format answers, pinned at `aee/testdata/revocation-list.json`. The `minted`
cases add one refusal for each check the shared set does not reach alone.

Judge the corpus with the reference verifier:

```sh
go run ./cmd/aee-verify corpora/vectors-revocation-list
```

Rebuild it with `python3 corpora/vectors-revocation-list/gen_vectors.py`; never
edit a case file by hand.

## The verdict and its reasons

A verifier applies each list in order and answers, for the list it refused or accepted, one reason.

An accepted list is `in_force`: it is now the list in force, and the roots, the held entries and the chain head it
leaves are the state the next list is judged against.

A refusal names the first check that failed, in this order. A code that takes a detail is written `code:detail`.

| Check | Reason | Refused when |
| --- | --- | --- |
| 1 | `revocation_list_shape:<why>` | The list is not the format. The details are in the next table. |
| 2 | `revocation_list_signer_not_a_root` | The SHA-256 of the raw `issuerKey` bytes, in lowercase hex, is not a pinned root key id. A key revoked by an earlier list is no longer a root. |
| 3 | `revocation_list_signature_unverified` | `sig` is not canonical padded base64 of 64 bytes, or it is not an Ed25519 signature by `issuerKey` over `"probity-revocation-v1\0"` followed by the JCS bytes of the body. |
| 4 | `revocation_list_other_chain` | `listId` differs from the `listId` of the list in force. |
| 5 | `revocation_list_rollback:<seq><=<held>` | `seq` is not greater than the sequence number of the list in force, as in `revocation_list_rollback:1<=2` and `revocation_list_rollback:2<=2`. |
| 6 | `revocation_list_gap:<seq>><expected>` | `seq` is more than one above the list in force, so a list between them was never seen, as in `revocation_list_gap:3>2` and `revocation_list_gap:2>1`. A verifier that holds no list expects `seq` 1. |
| 7 | `revocation_list_previous_mismatch` | `previous` is not the ListDigest of the list in force, or it is present when none is held, or missing when one is. |
| 8 | `revocation_list_time_reversed` | `issuedAt` is earlier than the `issuedAt` of the list in force. |
| 9 | `revocation_entry_from_future` | An entry's `revokedAt` is later than the list's own `issuedAt`. |
| 10 | `revocation_list_drops_entry:<kind>:<id>` | A held entry is missing from the list or differs from its earlier JCS bytes. The detail names the kind and the first 12 characters of the id of the first such entry in kind-then-id order, as in `revocation_list_drops_entry:agent:agent:alpha`. |

### Shape details

The shape check reads the list in this order and stops at the first detail that applies.

| Detail | Refused when |
| --- | --- |
| `revocation_list_shape:signed_list_unreadable` | The bytes are not one JSON value, or a number is not an exact I-JSON number, or a member name repeats. |
| `revocation_list_shape:signed_list_members` | The value is not an object with exactly `body` and `sig`. |
| `revocation_list_shape:body_members` | The body is not an object with exactly `type`, `listId`, `seq`, `previous`, `issuedAt`, `issuerKey` and `entries`. |
| `revocation_list_shape:type` | `type` is not the type URI of this predicate. |
| `revocation_list_shape:list_id_form` | `listId` is not 1 to 512 printable ASCII characters (0x21 to 0x7e). |
| `revocation_list_shape:seq_not_a_positive_exact_integer` | `seq` is not a JSON integer from 1 to 2^53 - 1. |
| `revocation_list_shape:previous_form` | `previous` is not null for `seq` 1, or for any later list is not `sha256:` and 64 lowercase hex characters. |
| `revocation_list_shape:issuedAt_not_a_utc_second` | `issuedAt` is not exactly `YYYY-MM-DDTHH:MM:SSZ`. |
| `revocation_list_shape:issuedAt_not_a_calendar_instant` | `issuedAt` has that shape but names no real instant, such as 31 February or year 0000. |
| `revocation_list_shape:issuerKey_not_base64` | `issuerKey` is not a string of valid padded base64. |
| `revocation_list_shape:issuerKey_not_an_ed25519_key` | `issuerKey` decodes to other than 32 bytes. |
| `revocation_list_shape:issuerKey_not_canonical_base64` | `issuerKey` decodes but is not the canonical spelling, for example because it holds a line break. |
| `revocation_list_shape:entries_not_a_list` | `entries` is not an array. |
| `revocation_list_shape:entry_not_an_object` | An entry is not an object. |
| `revocation_list_shape:entry_members` | An entry has a member other than `kind`, `id`, `revokedAt`, `reason` and `successor`, or lacks `kind`, `id` or `revokedAt`. |
| `revocation_list_shape:entry_kind_unknown` | `kind` is not one of `agent`, `build`, `grant`, `key`, `permit`, `sponsor`, `stream`. |
| `revocation_list_shape:entry_id_form:grant`, `:key`, `:permit` | The id of a `grant`, `key` or `permit` entry is not 64 lowercase hex characters. |
| `revocation_list_shape:entry_id_form:agent` | The id of an `agent` entry is not 1 to 512 printable ASCII characters. The same check applies to `build`, `sponsor` and `stream`, as in `revocation_list_shape:entry_id_form:build`. |
| `revocation_list_shape:revokedAt_not_a_utc_second` | `revokedAt` is not exactly `YYYY-MM-DDTHH:MM:SSZ`. |
| `revocation_list_shape:entry_reason_not_text` | `reason` is present and is not a string. |
| `revocation_list_shape:successor_on_non_key_entry` | `successor` is present on an entry whose `kind` is not `key`. |
| `revocation_list_shape:successor_not_base64` | `successor` is not a string of valid padded base64. A successor that decodes to other than 32 bytes is `successor_not_an_ed25519_key`, and a non-canonical spelling is `successor_not_canonical_base64`. |
| `revocation_list_shape:entries_not_strictly_ascending` | The entries are not in strictly ascending order by `kind`, then `id`, so a repeated entry is refused here too. |

A root key a list revokes leaves the pinned roots. A `successor` named on a revoked key entry joins the roots only when
the revoked key was a root, and a successor the same list revokes does not stay.
