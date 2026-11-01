# MCPVS-10 (draft)

**Requirement.** The client MUST NOT load a server configuration from an untrusted workspace, and MUST report every server it did load.

**Acceptance test.** Place a server configuration in an untrusted workspace and open it. No server from that file starts, the refusal is reported, and the report lists the servers that did start.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP09 |
| threats it tests | MCPTM-7 |
| accept vector | [`v15437a45ff8f20a0`](../records/v15437a45ff8f20a0.json) |
| reject vector | [`v61dfbac4f433a42f`](../records/v61dfbac4f433a42f.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
