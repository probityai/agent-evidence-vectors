# MCPTM-10 (draft)

**Boundary crossed.** client to auditor, the record

**Threat.** The client that made a call also writes, holds and can rewrite the only record of it.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP08 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-8](./MCPVS-8.md) | [`v419a6804dbbe1516`](../records/v419a6804dbbe1516.json) | [`vfd42ff5ffbca5a6a`](../records/vfd42ff5ffbca5a6a.json) |
| [MCPVS-9](./MCPVS-9.md) | [`v8f46708e1d7c1425`](../records/v8f46708e1d7c1425.json) | [`vc29b5143f9111082`](../records/vc29b5143f9111082.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
