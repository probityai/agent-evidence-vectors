# MCPVS-5 (draft)

**Requirement.** A server MUST NOT build a shell command by interpolating a tool argument.

**Acceptance test.** Send `; id`, `$(id)` and a backtick-wrapped `id` to every string parameter. No process runs with the injected token, in the process table or the audit record.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP05 |
| threats it tests | MCPTM-4 |
| accept vector | [`vd6e9e91c00bb2d3f`](../records/vd6e9e91c00bb2d3f.json) |
| reject vector | [`v0750d702c6997c76`](../records/v0750d702c6997c76.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
