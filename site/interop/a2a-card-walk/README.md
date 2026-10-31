# Signed A2A card-signature walk

A walk fetches a public A2A agent card and the JWKS at the `jku` its signatures name, on the same host. It keeps both byte for byte and checks every signature with the retained-field ES256 gate from agent-evidence-vectors. That gate is copied unchanged here as `retain_gate.py`, pinned by SHA-256 to the [source at 9e596fbf](https://github.com/probityai/agent-evidence-vectors/blob/9e596fbff7bb29809d38319aebb56f2141923eb2/interop/a2a-s3-retain-2026-10-01/retain_gate.py). The result is signed with the Ed25519 walk key in `walk-key.json`.

## Re-check a retained walk

Python 3.14, offline:

```sh
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python walk.py verify retained/2026-10-15-gate-horizonshield
```

It prints the per-signature result and exits 0 only when every check holds. The record signature verifies under the pinned key. The card and JWKS bytes match the signed digests. The signed JWKS URL is the card's `jku`, and the gate gives the signed result again.

## 2026-10-15: gate.horizonshield.dev

| Signature | Key | Result |
| --- | --- | --- |
| 0 | `hs-2026-09`, ES256 | verifies |
| 1 | `hs-2026-09`, ES256 | does not verify over the retained-field payload |

The card is admitted: one signature verifies. Record SHA-256 `8e930b166685ac6d938c539aed12a2f30bf9454330d30553ed4a0ef8e8c3742c`.

The payload is RFC 8785 over the served card with only the top-level `signatures` member removed. The gate tries no other canonical form, so signature 1 may verify under a form that prunes or reshapes fields. This walk does not test that.

## Record shape

`record.json` carries `record.record_canonical`, `record.signature_ed25519_b64`, `record.public_key_ed25519_b64` and `record.sha`, the same envelope a NENRIN witness record uses. `record_canonical` is sorted-key, no-space ASCII JSON with integer numbers only, and the signature covers its exact bytes.

## What a walk does not show

Who operates the host or controls the key, or whether the key was the host's at any other time. Nothing about the agent's behaviour. Whether a refused signature is valid under another canonical form.
