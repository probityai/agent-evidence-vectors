# Case 08e — Verified after window close (Negative)

Contributed by Certisyn, Inc. (Joel Hillier). The declared window is well
formed (`expires_at` = `issued_at` + 86400) and `|timestamp - verified_at|` = 0,
but `verified_at` is 2,505,600s (29.00 days) after `expires_at` — exceeding
`expires_at + max_clock_skew` by 2,505,570s. No skew-tolerant reading admits it.

A receipt whose verification instant falls after its declared window MUST be
rejected. Note `verified_at` is an issuer stamp (inside the signed input); this
gate checks the internal temporal-claim coherence of the receipt — wall-clock
freshness against the relying party's own clock is a separate policy decision.
