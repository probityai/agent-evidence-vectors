# Status-receipt-binding vectors

Cases for `status-receipt-binding/v1`: an agent credential that lists the capabilities it
grants and every public key it may act with, and an authority's signed receipt that says
the credential is active. The expected decision and reason for every case are in
`MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)



A relying party that holds a status receipt decides offline, without asking the authority
again. The receipt is only worth that if it names the credential by the digest of its bytes.
A receipt that names the credential by identifier, or signs the status and nothing else,
vouches for every credential carrying that identifier: the holder changes the capabilities,
swaps or adds a key, signs the result with a key the credential itself now lists, and
presents it beside the authority's genuine receipt. Both signatures verify. A verifier that
checks the two signatures, the identifier, the window and the status accepts it.

The two signature columns are the point of the corpus, and so is the third: the rows marked
in it carry the accepted control's receipt file byte for byte (`sharedReceipt` in the
manifest), beside a credential that grants more or acts with another key.

| Case | Receipt signature verifies | Credential signature verifies | Control's receipt | Expected |
| --- | --- | --- | --- | --- |
| accept-bound | yes | yes | control | accept, `credential_bound` |
| accept-two-keys-second-signs | yes | yes |  | accept, `credential_bound` |
| accept-at-issued-at | yes | yes | yes | accept, `credential_bound` |
| capabilities-escalated | yes | yes | yes | reject, `credential_digest_mismatch` |
| key-swapped | yes | yes | yes | reject, `credential_digest_mismatch` |
| key-added | yes | yes | yes | reject, `credential_digest_mismatch` |
| capabilities-and-key-swapped | yes | yes | yes | reject, `credential_digest_mismatch` |
| receipt-status-only | yes | yes |  | reject, `receipt_unbound` |
| receipt-status-only-forged-credential | yes | yes |  | reject, `receipt_unbound` |
| receipt-for-earlier-version | yes | yes |  | reject, `credential_digest_mismatch` |
| receipt-for-other-credential | yes | yes |  | reject, `credential_id_mismatch` |
| receipt-signed-by-other-key | no | yes |  | reject, `receipt_signature_invalid` |
| receipt-altered-after-signing | no | yes |  | reject, `receipt_signature_invalid` |
| receipt-window-inverted | yes | yes |  | reject, `receipt_malformed` |
| receipt-member-unexpected | yes | yes |  | reject, `receipt_malformed` |
| credential-signed-by-unlisted-key | yes | no | yes | reject, `credential_signature_invalid` |
| credential-altered-after-signing | yes | no | yes | reject, `credential_signature_invalid` |
| credential-capabilities-unsorted | yes | yes |  | reject, `credential_malformed` |
| credential-kid-repeated | yes | no |  | reject, `credential_malformed` |
| receipt-not-yet-valid | yes | yes | yes | reject, `receipt_not_yet_valid` |
| receipt-expired | yes | yes | yes | reject, `receipt_expired` |
| receipt-expired-at-valid-until | yes | yes | yes | reject, `receipt_expired` |
| credential-suspended | yes | yes |  | reject, `credential_not_active` |
| credential-revoked | yes | yes |  | reject, `credential_not_active` |

## What a case holds

- `credential.json`: a DSSE envelope with payload type
  `application/vnd.agent-evidence.agent-credential+json`. The payload is the RFC 8785 form
  of `{"capabilities", "id", "keys", "name"}`; `capabilities` is a sorted, duplicate-free
  list of strings and `keys` a list of Ed25519 JWKs, each with its own `kid`. Each signature's
  `keyid` names a `kid` in that list.
- `receipt.json`: a DSSE envelope with payload type
  `application/vnd.agent-evidence.credential-status-receipt+json`, signed by the authority.
  The payload is `{"credential": {"digest": {"sha256"}, "id"}, "issuedAt", "status",
  "validUntil"}`. The digest is the SHA-256 of the credential's payload bytes, so it covers
  the capabilities and every key. `status` is `active`, `suspended` or `revoked`; the window
  runs from `issuedAt` inclusive to `validUntil` exclusive.
- `case.json`: the check time `now`, the authority's base64 Ed25519 public key
  `authorityKey`, and the names of the two envelopes.

## The checks, in order

A verifier names the first check that fails.

1. The receipt has its payload type, one signature, exactly its four members, a known status
   and a window whose start is before its end (`receipt_malformed`).
2. The receipt's signature verifies under the authority key (`receipt_signature_invalid`).
3. The receipt names the credential by digest, not by identifier alone (`receipt_unbound`).
4. The credential has its payload type, exactly its four members, a sorted duplicate-free
   capability list and Ed25519 keys with distinct `kid` values (`credential_malformed`).
5. Every credential signature verifies under the key its `keyid` names in the credential's
   own list (`credential_signature_invalid`).
6. The receipt names the credential's `id` (`credential_id_mismatch`).
7. The receipt's digest is the SHA-256 of the credential payload bytes
   (`credential_digest_mismatch`).
8. The check time is not before `issuedAt` (`receipt_not_yet_valid`) and is before
   `validUntil` (`receipt_expired`).
9. The status is `active` (`credential_not_active`).

A case that passes every check is `accept` with reason `credential_bound`.

Check 5 alone proves little: whoever writes the key list also holds a key that verifies. It
is there so a credential presented by someone who holds none of its keys is refused. Check 7
is what ties the capabilities and the keys to the authority.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-status-receipt-binding
```

A verifier under test takes `case.json --json`, prints one JSON object carrying `decision`
and `reason`, and exits 0 for `accept` and 1 for `reject`:

```sh
agent-evidence-vectors --corpus vectors-status-receipt-binding --verifier './verifier'
python3 vectors-status-receipt-binding/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-status-receipt-binding` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-status-receipt-binding/gen_vectors.py`. The keys
are Ed25519 seeds derived from published labels in the generator, so anyone can rebuild
every signature; they protect nothing.

## What a pass does not establish

That the authority is who it claims to be: the verifier is handed its key. That the
capabilities are the right ones for the agent, or that the agent uses only them at run time.
That a credential is still active after `validUntil`: a status receipt says nothing past its
window, and a relying party that needs revocation sooner asks the authority again.
