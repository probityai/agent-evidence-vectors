# MCPTM-5 (draft)

**Boundary crossed.** tool output to model

**Threat.** Returned content steers the model into a tool call, a scope change or an approval nobody made.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP06 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-6](./MCPVS-6.md) | [`vf00978eedfd523dd`](../records/vf00978eedfd523dd.json) | [`v7ca58f31d62f0078`](../records/v7ca58f31d62f0078.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
