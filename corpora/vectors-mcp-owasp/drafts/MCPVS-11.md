# MCPVS-11 (draft)

**Requirement.** A server MUST attribute every tool call to an authenticated end user as well as to the client, and MUST refuse a call it cannot attribute.

**Acceptance test.** Send one call twice through the same authenticated client, once with a user identity bound to the session and once without. The server refuses the second call and records why.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP07 |
| threats it tests | MCPTM-8 |
| accept vector | [`vc3b1d076622b1896`](../records/vc3b1d076622b1896.json) |
| reject vector | [`vc579e08ed0c177c7`](../records/vc579e08ed0c177c7.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
