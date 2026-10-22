# Case 02 — Deny Pre-Admission (Positive Block Vector)

A tool call that CCS blocks **before** the tool body executes.

- **Tool**: `process_refund`
- **Args**: `{"account_id": "ACC-99999", "amount": 99999, "currency": "USD"}`
- **Response**: `{"blocked": true, "reason": "Refund amount 99999 exceeds threshold; pre-admission policy denied."}`
- **Verdict**: `block`
- **Rule summary**: Refund amount exceeds per-transaction threshold (max 10000)
- **Signature**: Valid

When verdict is `block`, the response body must be a block envelope containing
`{"blocked": true, "reason": "..."}`. The checker verifies this cross-field
consistency.
