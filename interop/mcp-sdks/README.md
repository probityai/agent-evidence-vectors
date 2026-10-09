# JCS byte corpus through the official MCP SDKs

One harness per official Model Context Protocol SDK. Each harness decodes a
JSON-RPC message with the SDK's own message decoder and re-encodes it with the
SDK's own wire encoder. The driver wraps every corpus input as `result.v` of a
response, cuts the re-encoded value out of the SDK's bytes, and compares it with
the RFC 8785 bytes the corpus pins. The results and the method are in
[docs/mcp-sdk-jcs-divergence.md](../../docs/mcp-sdk-jcs-divergence.md).

Run every SDK in its pinned container (needs docker and python3):

```sh
interop/mcp-sdks/run-all.sh            # all ten SDKs
interop/mcp-sdks/run-all.sh python go  # a subset
```

Each `<sdk>/run.sh` builds against the pinned SDK release inside its image and
then serves the line protocol: one JSON-RPC message per stdin line in, one
`OK <base64 of the encoded message>` or `ERR <reason>` line out. Any program
that speaks it can be compared with `driver.py run <name> -- <command>`.

| Harness | SDK release | Image | Codec the harness calls |
| --- | --- | --- | --- |
| `typescript` | `@modelcontextprotocol/sdk` 1.32.1 | `node:22-bookworm` | `deserializeMessage` / `serializeMessage` (shared/stdio) |
| `python` | `mcp` 2.3.0 | `python:3.13-slim-bookworm` | `types.jsonrpc_message_adapter.validate_json` / `model_dump_json(by_alias=True, exclude_unset=True)` |
| `go` | `github.com/modelcontextprotocol/go-sdk` v1.8.0 | `golang:1.25-bookworm` | `jsonrpc.DecodeMessage` / `jsonrpc.EncodeMessage` |
| `java` | `io.modelcontextprotocol.sdk:mcp-core` 2.0.1, `mcp-json-jackson2` 2.0.1 | `maven:3.9-eclipse-temurin-21` | `McpSchema.deserializeJsonRpcMessage` / `writeValueAsString`, default Jackson 2 mapper |
| `kotlin` | `io.modelcontextprotocol:kotlin-sdk-core-jvm` 0.15.0 | `gradle:8.14-jdk21` | `McpJson.decodeFromString<JSONRPCMessage>` / `serializeMessage` |
| `csharp` | `ModelContextProtocol.Core` 2.2.0 | `mcr.microsoft.com/dotnet/sdk:10.0` | `JsonSerializer` with `McpJsonUtilities.DefaultOptions` |
| `swift` | `swift-sdk` 0.12.1 | `swift:6.1-bookworm` | `JSONDecoder` into `Response<M>` with `Value` results / the `Server.send` encoder (`.sortedKeys, .withoutEscapingSlashes`) |
| `rust` | `rmcp` 3.5.1 | `rust:1.90-bookworm` | `serde_json::from_slice::<ServerJsonRpcMessage>` / `serde_json::to_vec` |
| `ruby` | `mcp` gem 1.7.0 | `ruby:3.3-bookworm` | `JSON.parse(symbolize_names: true)` / `JSON.generate` (stdio transport) |
| `php` | `mcp/sdk` 0.8.1 | `composer:2` | `MessageFactory::create` / `json_encode(JSON_THROW_ON_ERROR)` (server protocol) |

`jcs-admit/` is the admission reference: the `jcs-admit` 0.1.1 crate run on
the raw input under RFC 8785 and under its I-JSON profile.

The corpus is `corpora/jcs-byte-vectors/cases.json` at the `v0.17.5` tag,
fetched by URL and checked against a pinned SHA-256 (set `JCS_CORPUS_PATH` to
use a local copy), plus `extra-cases.json`. `gen_extra.mjs` builds that file
from `extra-inputs.json`; every pinned value there agrees between the
ECMAScript oracle of `check.mjs` and `jcs-admit`.
