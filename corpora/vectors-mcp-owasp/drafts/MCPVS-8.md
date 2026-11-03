# MCPVS-8 (draft)

**Requirement.** For every tool call the client MUST emit one record naming the server identifier, the tool digest, the calling principal, the approval state, a digest of the arguments, and the outcome. A call that proceeded with no approval decision MUST be distinguishable in that record from an approved one.

**Acceptance test.** Run one call a user approved and one that ran with no approval decision at all. The approval-state field differs between the two records.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP08 |
| threats it tests | MCPTM-10 |
| accept vector | [`v419a6804dbbe1516`](../records/v419a6804dbbe1516.json) |
| reject vector | [`vfd42ff5ffbca5a6a`](../records/vfd42ff5ffbca5a6a.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
