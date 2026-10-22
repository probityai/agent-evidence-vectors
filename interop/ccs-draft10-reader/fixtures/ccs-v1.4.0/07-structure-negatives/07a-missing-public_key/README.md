# Case 07a — Missing field: `public_key`

The field `public_key` is removed from an otherwise-valid L1 receipt.
Strict mode requires exactly the 30 defined fields; the checker must reject.
