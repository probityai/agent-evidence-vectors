# Tamper Description

**Original value**: `verdict = "allow"`
**Tampered value**: `verdict = "block"`
**Signature**: NOT re-signed after tampering

The signature was computed over the JCS canonical form of the original receipt
(with `verdict: "allow"`). After changing `verdict` to `"block"`, the canonical
bytes differ, so the Ed25519 signature verification fails.

The independent checker must detect this and return:
```json
{"verdict": "invalid", "reason": "signature mismatch"}
```
