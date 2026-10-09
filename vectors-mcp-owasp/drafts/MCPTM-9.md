# MCPTM-9 (draft)

**Boundary crossed.** conversation to server, context

**Threat.** The client sends a server more of the conversation or the workspace than the call's schema needs.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP10 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-12](./MCPVS-12.md) | [`v59ca88c60d352d00`](../records/v59ca88c60d352d00.json) | [`v953b5b4255073fce`](../records/v953b5b4255073fce.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
