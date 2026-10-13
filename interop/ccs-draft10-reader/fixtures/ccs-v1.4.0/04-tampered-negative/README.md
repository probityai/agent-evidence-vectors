# Case 04 — Tampered Negative Vector

A valid receipt is modified after signing without re-signing.

- **Original verdict**: `allow`
- **Tampered verdict**: `block`
- **Signature**: Unchanged from original (now invalid)
- **Expected checker result**: `invalid` — `signature mismatch`

This tests that the checker cryptographically verifies the signature rather
than trusting the receipt's self-declared fields.
