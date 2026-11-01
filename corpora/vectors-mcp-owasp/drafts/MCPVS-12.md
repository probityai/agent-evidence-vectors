# MCPVS-12 (draft)

**Requirement.** The client MUST send a server only the arguments the tool's `inputSchema` declares, and MUST NOT attach conversation history or workspace content the schema does not ask for.

**Acceptance test.** Invoke a tool whose schema declares one string parameter, in a session holding earlier messages and open files. The server's request log shows that parameter and nothing else.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP10 |
| threats it tests | MCPTM-9 |
| accept vector | [`v59ca88c60d352d00`](../records/v59ca88c60d352d00.json) |
| reject vector | [`v953b5b4255073fce`](../records/v953b5b4255073fce.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered. Judge both vectors with `pip install agent-evidence-vectors` and
`agent-evidence-vectors --corpus vectors-mcp-owasp`, or from a checkout with
`go run ./cmd/aee-verify vectors-mcp-owasp`.
