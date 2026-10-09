# Conformance vectors (OWASP MCP verification, draft)

This corpus is 24 vectors, of which 12 a conformant verifier must
not fail closed on and 12 it must reject.

Each member is the observation one acceptance test produced against a draft
requirement. Every requirement has one accept and one reject member, and the
reject member differs from its accepting twin in exactly one observation field.
Every threat reaches both through the requirements that test it.

Regenerate byte-identically: `python3 gen_vectors.py`.
Judge: `agent-evidence-vectors --corpus vectors-mcp-owasp` (installed package) or
`go run ./cmd/aee-verify vectors-mcp-owasp` from the repository root.

## Requirements

| id | Top 10 | accept | reject |
|---|---|---|---|
| [MCPVS-1](drafts/MCPVS-1.md) | MCP03 | `vae1302b80de94a36` | `v0485d4e3a7045da5` |
| [MCPVS-2](drafts/MCPVS-2.md) | MCP03 | `vd0ad172254fcddd8` | `v1ec276d80064b4c1` |
| [MCPVS-3](drafts/MCPVS-3.md) | MCP01 | `v8b1275f9de9f3277` | `v3011201523b79420` |
| [MCPVS-4](drafts/MCPVS-4.md) | MCP02 | `vcd379fd2f74f1fa0` | `vef59b78d5a811466` |
| [MCPVS-5](drafts/MCPVS-5.md) | MCP05 | `vd6e9e91c00bb2d3f` | `v0750d702c6997c76` |
| [MCPVS-6](drafts/MCPVS-6.md) | MCP06 | `vf00978eedfd523dd` | `v7ca58f31d62f0078` |
| [MCPVS-7](drafts/MCPVS-7.md) | MCP04, MCP09 | `vb9f53652f0a483a5` | `v0b97895d220dbdff` |
| [MCPVS-8](drafts/MCPVS-8.md) | MCP08 | `v419a6804dbbe1516` | `vfd42ff5ffbca5a6a` |
| [MCPVS-9](drafts/MCPVS-9.md) | MCP08 | `v8f46708e1d7c1425` | `vc29b5143f9111082` |
| [MCPVS-10](drafts/MCPVS-10.md) | MCP09 | `v15437a45ff8f20a0` | `v61dfbac4f433a42f` |
| [MCPVS-11](drafts/MCPVS-11.md) | MCP07 | `vc3b1d076622b1896` | `vc579e08ed0c177c7` |
| [MCPVS-12](drafts/MCPVS-12.md) | MCP10 | `v59ca88c60d352d00` | `v953b5b4255073fce` |

## Threats

| id | boundary | Top 10 | tested by |
|---|---|---|---|
| [MCPTM-1](drafts/MCPTM-1.md) | server to client, tool definitions | MCP03 | MCPVS-1, MCPVS-2 |
| [MCPTM-2](drafts/MCPTM-2.md) | client to server, credentials | MCP01 | MCPVS-3 |
| [MCPTM-3](drafts/MCPTM-3.md) | session to session, scope | MCP02 | MCPVS-4 |
| [MCPTM-4](drafts/MCPTM-4.md) | tool argument to server host | MCP05 | MCPVS-5 |
| [MCPTM-5](drafts/MCPTM-5.md) | tool output to model | MCP06 | MCPVS-6 |
| [MCPTM-6](drafts/MCPTM-6.md) | registry to host, server artifact | MCP04 | MCPVS-7 |
| [MCPTM-7](drafts/MCPTM-7.md) | workspace to client, configuration | MCP09 | MCPVS-10 |
| [MCPTM-8](drafts/MCPTM-8.md) | user to server, caller identity | MCP07 | MCPVS-11 |
| [MCPTM-9](drafts/MCPTM-9.md) | conversation to server, context | MCP10 | MCPVS-12 |
| [MCPTM-10](drafts/MCPTM-10.md) | client to auditor, the record | MCP08 | MCPVS-8, MCPVS-9 |
