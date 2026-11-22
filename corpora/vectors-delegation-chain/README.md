# Delegation-chain vectors

Cases for `delegation-chain/v1`: is a signed chain of grants handed from agent to agent still inside what the root granted? Each case is one record: four signed grants a to d (three delegation hops below the root grant), the trusted root key ids, the instant the chain is judged at, the receiving agent and the revoked grant digests. A verifier that checks signatures alone allows every denied case here except the one with a bad signature.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the delegation-chain contract | `contract_id_unknown` |
| the record has the fields and types the contract names, and every time carries a UTC offset | `malformed_record` |
| every signature verifies under the grant's own `issuerKey` | `signature_invalid` |
| the first issuer is a trusted root; each later issuer is the holder of the grant above | `issuer_not_authorised` |
| the first grant has no parent; each later `parent` is the digest of the grant above | `parent_mismatch` |
| the judging instant is inside every grant's window | `grant_not_in_window` |
| `maxDepth` falls by at least one per hop | `depth_exceeded` |
| each grant's tools are inside its parent's | `widens_tools` |
| each tool's arguments are inside the parent's, name by name and value by value | `widens_arguments` |
| each audience is inside its parent's | `widens_audience` |
| each grant expires no later than its parent | `widens_expiry` |
| each budget is no larger than its parent's | `widens_budget` |
| no grant in the chain is revoked | `ancestor_revoked` |
| the receiving agent is in the last grant's audience | `receiver_outside_audience` |

A record that passes every check is `allow` with reason `chain_valid`. A signature is Ed25519 over `probity-grant-v1` followed by a zero byte and the RFC 8785 form of the grant body; a key id is the SHA-256 of the raw public key; a grant digest is the SHA-256 of the RFC 8785 form of the body. The widening cases depart at different hops (the middle one, the last one) so a verifier that checks only the final hop is refused.

## Running

```sh
pip install agent-evidence-vectors
python corpora/vectors-delegation-chain/check_vectors.py
python corpora/vectors-delegation-chain/check_vectors.py --verifier "my-verifier"
```

The external contract: `<verifier> <case-dir>/record.json --json` prints one JSON object with `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. The cases regenerate byte for byte with `gen_vectors.py`; keys come from fixed seeds and Ed25519 signatures are deterministic.
