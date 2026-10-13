# Case 08 — Temporal Negatives

Tests time semantics: expiry, clock-skew tolerance, issuance ordering, and
verification relative to the declared validity window.

| Case | Scenario | Expected |
|------|----------|----------|
| 08a-expired | expires_at before issued_at — window never opened | invalid |
| 08b-future-timestamp | timestamp skews beyond max_clock_skew from verified_at | invalid |
| 08c-issued-after-timestamp | issued_at after the event timestamp | invalid |
| 08d-clock-skew-boundary | skew just over the max_clock_skew boundary | invalid |
| 08e-verified-after-expiry | verified_at after the declared window closed | invalid |

**Issuer-stamp semantics.** The temporal gates validate the receipt's *internal*
temporal claims (the issuer's stamps): issued_at, expires_at, timestamp,
verified_at must be mutually coherent. The new `cross-field:verified-within-window`
gate (08e) checks that a verification is not stamped after `expires_at +
max_clock_skew` for a window that was open. It is only evaluated when the window
was ever open (`expires_at >= issued_at`); a window that never opened is already
reported by the expires-after-issued gate (08a). Wall-clock freshness against a
relying party's own clock is a separate policy decision and is outside the scope
of this conformance checker.

08e was contributed by Certisyn, Inc. (Joel Hillier) during independent
interoperability testing.
