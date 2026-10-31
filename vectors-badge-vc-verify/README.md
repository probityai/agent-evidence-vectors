# Badge credential vectors

Cases for `badge-vc-verify/v1`: does your verifier accept an agent badge issued as a W3C Verifiable Credential in a compact JWS (EdDSA) only when the issuer is trusted, the signing key belongs to that issuer, the signature covers the exact bytes sent, the credential is inside its validity window, and the issuer's own status store does not list it as revoked? Each case is one `case.json`: the token, the verification time, the key material resolved for each issuer DID, the trusted issuers, and the issuer's revocation store.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Each denied case departs from a conformant case in one place and is allowed by a verifier that skips the check it names. The revocation case, for example, is allowed by a verifier that reads only the token, because the issuer's status store is the authority and the token carries no sign of revocation.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| `case.json` carries `contractId` | `contract_id_missing` |
| `contractId` is the badge contract | `contract_id_unknown` |
| the case has the fields and types the contract names | `malformed_case` |
| the token is three unpadded base64url parts; the header is a JSON object with `alg` `EdDSA` and a `kid` of the form `<did>#<fragment>` | `jws_malformed` |
| the payload is a credential with `id`, `issuer`, `issuanceDate`, `credentialSubject.id` and `VerifiableCredential` among its `type`, and every time is RFC 3339 | `credential_malformed` |
| the credential's issuer is in `trustedIssuers` | `issuer_not_trusted` |
| the `kid`'s DID is the credential's issuer and its fragment names a key of that issuer | `issuer_key_binding` |
| the Ed25519 signature verifies over the ASCII bytes `header.payload` | `signature_invalid` |
| `issuanceDate` is not after `verificationTime` | `not_yet_valid` |
| `expirationDate`, when present, is after `verificationTime` | `expired` |
| the credential's `id` is not in `status.revoked` | `revoked` |

A case that passes every check is `allow` with reason `verified`. Resolving a DID to its keys is outside this corpus: the case carries the keys the verifier resolved.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-badge-vc-verify
```

To judge your own verifier, run it as `<verifier> <case-dir>/case.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`.

## Controls

Every denied case departs from a conformant case in one place, and each check is forced by at least one case: switching it off changes a verdict. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. `tests/test_corpus.py` holds each of these as a test, and regenerates the corpus byte for byte from `gen_vectors.py`.
