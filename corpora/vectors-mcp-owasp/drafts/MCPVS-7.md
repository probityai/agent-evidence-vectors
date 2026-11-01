# MCPVS-7 (draft)

**Requirement.** The client MUST record, per connected server, an identifier bound to the artifact it launched (a package digest, an image digest, or a host with a pinned certificate), and MUST refuse a server whose identifier is absent from the configured set.

**Acceptance test.** Replace the server binary at the same path with one of a different digest. The client refuses to start it and names the digest it expected.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP04, MCP09 |
| threats it tests | MCPTM-6 |
| accept vector | [`vb9f53652f0a483a5`](../records/vb9f53652f0a483a5.json) |
| reject vector | [`v0b97895d220dbdff`](../records/v0b97895d220dbdff.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
