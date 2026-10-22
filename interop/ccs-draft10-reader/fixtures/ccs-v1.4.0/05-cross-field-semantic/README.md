# Case 05 — Cross-Field Semantic Negative Vectors

These vectors test semantic validation **beyond** structural and signature checks.
They were specifically requested by Henri Sirkkavaara (Vaara) in SCITT
interoperability discussions to catch implementation bugs that pure signature verification misses.

| Sub-case | Issue | Signature | Expected |
|---|---|---|---|
| 05a | Timestamp denotes impossible date (month=13) | Valid | invalid |
| 05b | Sandbox flag not bound to principal | Valid | invalid |
| 05c | response_hash doesn't match response body | Valid | invalid |
| 05d | verdict=block but response is not block envelope | Valid | invalid |

Note: In 05c and 05d the signature is cryptographically valid — the signer
signed a receipt that contains semantically incorrect data. This tests that
checkers perform semantic validation independently of signature verification.
