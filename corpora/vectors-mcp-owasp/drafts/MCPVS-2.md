# MCPVS-2 (draft)

**Requirement.** The pin MUST survive client restart and transport reconnection.

**Acceptance test.** Restart the client, reconnect, serve the altered `description` again. The refusal fires on the second connection as it did on the first.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP03 |
| threats it tests | MCPTM-1 |
| accept vector | [`vd0ad172254fcddd8`](../records/vd0ad172254fcddd8.json) |
| reject vector | [`v1ec276d80064b4c1`](../records/v1ec276d80064b4c1.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
