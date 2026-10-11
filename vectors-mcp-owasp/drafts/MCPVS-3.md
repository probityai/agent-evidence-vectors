# MCPVS-3 (draft)

**Requirement.** The client MUST NOT send a credential issued for one server to another server, and MUST NOT place a credential in a tool argument.

**Acceptance test.** Configure servers `A` and `B` with distinct tokens. Invoke a tool on `B` that echoes every header and argument it receives. `A`'s token appears in neither, and no argument carries any token.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP01 |
| threats it tests | MCPTM-2 |
| accept vector | [`v8b1275f9de9f3277`](../records/v8b1275f9de9f3277.json) |
| reject vector | [`v3011201523b79420`](../records/v3011201523b79420.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
