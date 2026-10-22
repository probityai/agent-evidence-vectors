# Case 10e — Prev-hash declaration unanchored (Negative)

Two valid, signed receipts in a contiguous chain (sequences 0, 1), same trace.
Both prev-hash declarations — runtime-context-2.json::prev_receipt_digest and
chain.json::expected_prev_digests[1] — agree with each other, but on a digest
that does NOT match receipt-1's actual computed L1 digest. A checker that only
compares the two declarations against each other cannot detect this; the anchor
must be the computed digest of the predecessor receipt bytes.

Regression vector for the chain:prev-hash-matches anchoring defect found by
Joel Hillier (Certisyn) during independent interoperability review (2026-08-30).
