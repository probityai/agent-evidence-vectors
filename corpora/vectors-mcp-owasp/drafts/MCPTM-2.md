# MCPTM-2 (draft)

**Boundary crossed.** client to server, credentials

**Threat.** A token issued for one server reaches another through a forwarded header, a tool argument or a log line.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP01 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-3](./MCPVS-3.md) | [`v8b1275f9de9f3277`](../records/v8b1275f9de9f3277.json) | [`v3011201523b79420`](../records/v3011201523b79420.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
