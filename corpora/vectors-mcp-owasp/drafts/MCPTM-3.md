# MCPTM-3 (draft)

**Boundary crossed.** session to session, scope

**Threat.** A call is authorized against every scope granted across sessions, including scopes no longer in force.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP02 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-4](./MCPVS-4.md) | [`vcd379fd2f74f1fa0`](../records/vcd379fd2f74f1fa0.json) | [`vef59b78d5a811466`](../records/vef59b78d5a811466.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
