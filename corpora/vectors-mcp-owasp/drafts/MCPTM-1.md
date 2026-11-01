# MCPTM-1 (draft)

**Boundary crossed.** server to client, tool definitions

**Threat.** A server changes a tool's description after approval, and the model follows instructions the user never approved.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP03 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-1](./MCPVS-1.md) | [`vae1302b80de94a36`](../records/vae1302b80de94a36.json) | [`v0485d4e3a7045da5`](../records/v0485d4e3a7045da5.json) |
| [MCPVS-2](./MCPVS-2.md) | [`vd0ad172254fcddd8`](../records/vd0ad172254fcddd8.json) | [`v1ec276d80064b4c1`](../records/v1ec276d80064b4c1.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
