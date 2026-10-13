# Case 07a — Missing field: `signing_algorithm`

The field `signing_algorithm` is removed from an otherwise-valid L1 receipt.
Strict mode requires exactly the 30 defined fields; the checker must reject.
