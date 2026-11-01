# MCPVS-9 (draft)

**Requirement.** The record stream MUST be tamper-evident: each record commits to its predecessor, and the head MUST be published to a party that is not the client.

**Acceptance test.** Delete one record from the middle of the stream. Verification fails and names the break. Verification against the published head still fails after the stream is re-signed by the client alone.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP08 |
| threats it tests | MCPTM-10 |
| accept vector | [`v8f46708e1d7c1425`](../records/v8f46708e1d7c1425.json) |
| reject vector | [`vc29b5143f9111082`](../records/vc29b5143f9111082.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
