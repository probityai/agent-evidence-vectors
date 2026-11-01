# MCPVS-1 (draft)

**Requirement.** The client MUST pin each tool by a digest over its canonical definition (name, description, `inputSchema`, annotations) and MUST refuse a tool whose digest differs from the approved one.

**Acceptance test.** Approve tool `T`. Serve `T` again with one word changed in `description`. The client refuses `T` and reports both digests. Silent acceptance is a fail.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP03 |
| threats it tests | MCPTM-1 |
| accept vector | [`vae1302b80de94a36`](../records/vae1302b80de94a36.json) |
| reject vector | [`v0485d4e3a7045da5`](../records/v0485d4e3a7045da5.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
