# Case 07a — Missing field: `latency_us`

The field `latency_us` is removed from an otherwise-valid L1 receipt.
Strict mode requires exactly the 30 defined fields; the checker must reject.
