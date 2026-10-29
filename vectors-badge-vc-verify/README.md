# Badge credential vectors

Cases for `badge-vc-verify/v1`: does your verifier accept an agent badge issued as a W3C Verifiable Credential in a compact JWS (EdDSA) only when the issuer is trusted, the signing key belongs to that issuer, the signature covers the exact bytes sent, the credential is inside its validity window, and the issuer's own status store does not list it as revoked? Each case is one `case.json`: the token, the verification time, the key material resolved for each issuer DID, the trusted issuers, and the issuer's revocation store.

A verifier that checks the signature and the key identifier but not the rest accepts an expired badge, a badge not yet valid, and a badge its issuer has revoked, because the token carries no sign of the revocation: the issuer's store is the authority, not the copy the holder presents. A verifier that checks the signature against the key the token names, without asking whether that key belongs to the issuer the credential claims, accepts a credential signed by its own subject. Every denied case here is allowed by one of those two verifiers.

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
