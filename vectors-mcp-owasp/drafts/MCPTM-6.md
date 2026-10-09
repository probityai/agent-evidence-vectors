# MCPTM-6 (draft)

**Boundary crossed.** registry to host, server artifact

**Threat.** The binary at a configured path is replaced, and the client launches it under the old name.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP04 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-7](./MCPVS-7.md) | [`vb9f53652f0a483a5`](../records/vb9f53652f0a483a5.json) | [`v0b97895d220dbdff`](../records/v0b97895d220dbdff.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
