# Case 01 — Allow (Positive Vector)

A normal, fully-compliant tool call that CCS allows.

- **Tool**: `lookup_customer`
- **Args**: `{"customer_id": "CUST-10042", "include_history": true}`
- **Response**: Customer record for Alice Zhang (premium tier)
- **Verdict**: `allow`
- **Signature**: Valid Ed25519 over JCS-canonicalized receipt
- **All hashes**: Consistent with their respective payloads

The independent checker must return `valid` with all checks passing.
