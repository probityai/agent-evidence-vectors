# Case 07a — Missing field: `runtime_context_hash`

The field `runtime_context_hash` is removed from an otherwise-valid L1 receipt.
Strict mode requires exactly the 30 defined fields; the checker must reject.
