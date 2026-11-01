# MCPTM-8 (draft)

**Boundary crossed.** user to server, caller identity

**Threat.** A server accepts a call it cannot attribute to a user, having authenticated only the client.

| field | value |
|---|---|
| status | draft |
| OWASP Top 10 for MCP | MCP07 |

## Tested by

| requirement | accept vector | reject vector |
|---|---|---|
| [MCPVS-11](./MCPVS-11.md) | [`vc3b1d076622b1896`](../records/vc3b1d076622b1896.json) | [`vc579e08ed0c177c7`](../records/vc579e08ed0c177c7.json) |

The identifier is minted in [`REGISTRY.json`](../REGISTRY.json) and is never
renumbered.
