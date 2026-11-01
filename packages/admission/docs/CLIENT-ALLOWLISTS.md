# Client MCP allowlists from one admit list

`agent-evidence-admission generate` turns one list of admitted MCP servers into the allowlist each
client enforces natively. Write the list once, then deploy the files it generates for each client.

## The admit list

```json
{
  "admitted": [
    {
      "name": "io.github.example/files",
      "version": "1.4.2",
      "description": "Read and write files under one directory.",
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "package": {"registryType": "npm", "identifier": "@example/files"},
      "stdio": {"command": "npx", "args": ["-y", "@example/files@1.4.2", "/srv/data"]}
    },
    {
      "name": "com.example/search",
      "version": "2.0.0",
      "description": "Search the example index.",
      "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "remote": {"url": "https://mcp.example.com/v2/mcp", "type": "streamable-http"}
    }
  ]
}
```

Each entry has these fields:

- `name`: the server's registry name.
- `version`: one release. `latest` is refused.
- `description`: a short description of the server.
- `digest`: the sha256 of the bytes that were admitted.
- `stdio` or `remote`, exactly one. `stdio` gives the exact command and arguments. `remote` gives
  the exact https URL and the transport type.
- `key` (optional): the name users give the server in their own configuration. The default is the
  part of `name` after the slash.
- `package` (optional): the registry package. Only the registry output uses it.

The generator refuses the whole list, exits 2 and writes nothing for any of these:

- an invalid digest;
- a plain http URL;
- a wildcard or `${...}` in a command, argument or URL (`${...}` expands on the user's machine, so
  the match would not be exact);
- an entry that gives both transports;
- one name and version admitted twice;
- one key that names two servers.

## Run it

```sh
agent-evidence-admission generate admit-list.json --out generated
```

Pass `--client` once for each client you want (`claude-code`, `cursor`, `windsurf`, `registry`).
Without it, the generator writes for all four. `--json` prints the report as JSON.

| Client | File | Where it goes | What the client then matches |
|---|---|---|---|
| Claude Code | `claude-code/managed-settings.json` | Merge both keys into the managed settings source you deploy (server-managed settings, MDM, or the system `managed-settings.json`) | The exact command and arguments (`serverCommand`) or the exact URL (`serverUrl`). It writes no `serverName` entry: the Claude Code documentation says a name is a label the user chooses and is not a security control. `allowManagedMcpServersOnly` keeps users from widening the list |
| Cursor | `cursor/mcp-allowlist.json` | Add each `entry` as a command or URL entry under MCP Configuration in the team dashboard | The full command string and the URL. A relative command such as `npx` is written as `*/npx`, because Cursor matches the resolved path, so the command matches by name in any directory |
| Windsurf | `windsurf/allowlist.json` | Add each pair as Server ID and Server Config (JSON) in the team MCP allowlist | The server ID, plus the command and every argument (or the URL) as anchored patterns that match only the literal value; `env` stays free |
| GitHub Copilot, Windsurf registries | `registry/v0.1/...` | Serve each file at its route, with the CORS headers GitHub documents, and point the registry-only policy at that URL | Membership by registry name |

Under `registry/`, `v0.1/servers.json` is the body for `GET /v0.1/servers`. Each
`v0.1/servers/<name>/versions/<version>.json` is the body for that route, with the name
percent-encoded, and `latest.json` holds the last version listed in the admit list. Each entry
carries the admitted digest under the `_meta` key `io.github.probityai/agent-evidence-admission`.

## What no client checks

All four clients match a server by its arguments, its URL or its registry name. None of them hashes
the bytes it is about to start. An `npx` package republished under the same version, or a URL that
serves different code tomorrow, still matches. The report says this for every server:

```text
BINDS claude-code io.github.example/files@1.4.2: command and every argument, exactly
UNBOUND io.github.example/files@1.4.2 sha256:2222...: no client hashes the bytes it starts
```

The digest is carried into the registry output and the report, so a launcher that hashes before it
starts the server, or a gateway that admits by digest, can check it.

## Refusals

If a client cannot express a server exactly, the generator refuses that server for that client.
It does not widen the entry. It still writes the other clients' files, names the refusal and exits
1:

- Cursor joins arguments with spaces and reads `*` as a wildcard, so an argument that holds either
  one cannot match exactly.
- A stdio server without `package.registryType` and `package.identifier` cannot appear in an MCP
  registry.

The positive and negative cases are in
[`python/vectors/generate/manifest.json`](../python/vectors/generate/manifest.json). The exact files
for the first case are under [`python/vectors/generate/expected/`](../python/vectors/generate/expected/).

## Sources

The client formats were read on 26 October 2026 from these pages:

- Claude Code: <https://code.claude.com/docs/en/managed-mcp.md>, the sections on allowlists and denylists and on how `serverCommand` and `serverUrl` entries match.
- Cursor: <https://cursor.com/docs/enterprise/model-and-integration-management.md>, the "MCP Allowlist" section.
- Windsurf: <https://docs.windsurf.com/windsurf/cascade/mcp>, "MCP Allowlist" and "How Server Matching Works".
- GitHub Copilot: <https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-registry>, the endpoint and CORS requirements.
