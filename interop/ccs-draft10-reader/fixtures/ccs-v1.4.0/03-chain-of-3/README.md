# Case 03 — Chain of 3 (Positive Chain Vector)

Three consecutive L1 receipts from the same agent session, forming a chain.

- **Trace ID**: `conformance-v1.4.0-trace` (shared)
- **Run ID**: `run-conformance-v1.4.0-trace` (in runtime_context_hash)
- **Sequences**: 0 → 1 → 2
- **Tools**: `search_inventory` → `get_product_details` → `create_order`
- **All verdicts**: `allow`
- **All signatures**: Valid Ed25519

The checker verifies:
1. Each receipt has a valid signature
2. All receipts share the same `trace_id`
3. Sequence numbers are monotonically increasing
4. The `runtime_context_hash` in each receipt encodes the same `run_id`,
   linking them into one agent session
