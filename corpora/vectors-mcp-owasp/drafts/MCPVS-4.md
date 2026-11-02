# MCPVS-4 (draft)

**Requirement.** A tool call MUST be authorized against the scope in force for the session that carries it, never against the union of scopes granted across sessions.

**Acceptance test.** Grant scope `S1`, then grant `S2` in a later session. Replay a call requiring `S2` inside an `S1` session. The call is refused.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP02 |
| threats it tests | MCPTM-3 |
| accept vector | [`vcd379fd2f74f1fa0`](../records/vcd379fd2f74f1fa0.json) |
| reject vector | [`vef59b78d5a811466`](../records/vef59b78d5a811466.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
