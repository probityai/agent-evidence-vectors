# JCS bytes through the official MCP SDKs

Every official Model Context Protocol SDK was given the same JSON-RPC
messages and asked to decode and re-encode them with its own codec. None of
the ten emits RFC 8785 bytes for the whole corpus, and every one of them admits
at least one input that RFC 8785 refuses. A signature or hash computed over
what an SDK re-serializes is therefore not reproducible across SDKs; a
verifier has to hash the bytes it received, or canonicalize with a JCS
implementation before it signs.

Run on 2026-10-09 by the `mcp-sdk-jcs` workflow (run 37944695894, head
`16d6c5e`). Reproduce with `interop/mcp-sdks/run-all.sh`.

## Method

Each harness under [`interop/mcp-sdks/`](../interop/mcp-sdks/) decodes a
JSON-RPC message with the SDK's message decoder and encodes the decoded message
with the SDK's wire encoder, the same calls its stdio or stream transport
makes. The input is wrapped as the structured content of a tool result:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"v":INPUT}}}
```

The driver cuts `structuredContent.v` out of the SDK's output and compares it
byte for byte with the pinned RFC 8785 bytes. The wrapper adds three levels of
nesting, so `depth-64` reaches an SDK parser at depth 67.

Inputs: the eight cases of `corpora/jcs-byte-vectors/cases.json` at `v0.17.5`
(SHA-256 `b07c54bc...a29f`, fetched by tag) and nineteen supplementary cases in
`interop/mcp-sdks/extra-cases.json`, whose pinned bytes agree between the
ECMAScript oracle of `check.mjs` and `jcs-admit`. The admission column is the
`jcs-admit` 0.1.1 crate run on the raw input, under RFC 8785 and under its
I-JSON profile.

| SDK | Release | Codec | Image digest source |
| --- | --- | --- | --- |
| TypeScript | `@modelcontextprotocol/sdk` 1.32.1 | `JSON.parse` + zod / `JSON.stringify` | `node:22-bookworm` |
| Python | `mcp` 2.3.0 | pydantic `validate_json` / `model_dump_json` | `python:3.13-slim-bookworm` |
| Go | `go-sdk` v1.8.0 | `jsonrpc.DecodeMessage` / `EncodeMessage` (result kept as `json.RawMessage`) | `golang:1.25-bookworm` |
| Java | `mcp-core` + `mcp-json-jackson2` 2.0.1 | default Jackson 2 `ObjectMapper` | `maven:3.9-eclipse-temurin-21` |
| Kotlin | `kotlin-sdk-core-jvm` 0.15.0 | `McpJson` (kotlinx.serialization, lenient) | `gradle:8.14-jdk21` |
| C# | `ModelContextProtocol.Core` 2.2.0 | `System.Text.Json` with `McpJsonUtilities.DefaultOptions` | `mcr.microsoft.com/dotnet/sdk:10.0` |
| Swift | `swift-sdk` 0.12.1 | `JSONDecoder` / `JSONEncoder` with `.sortedKeys, .withoutEscapingSlashes` (`Server.send`) | `swift:6.1-bookworm` |
| Rust | `rmcp` 3.5.1 | `serde_json` (`BTreeMap` objects) | `rust:1.90-bookworm` |
| Ruby | `mcp` gem 1.7.0 | `JSON.parse` / `JSON.generate` | `ruby:3.3-bookworm` |
| PHP | `mcp/sdk` 0.8.1 | `json_decode` / `json_encode(JSON_THROW_ON_ERROR)` | `composer:2` |

Exact image digests are recorded in each `results/<sdk>.json` artifact of the
run.

## Results

`= JCS` means the SDK re-emitted the RFC 8785 bytes. A quoted value is what it
emitted instead (truncated). **refused** means its decoder rejected the
message. **accepted** on an admission row means it re-emitted an input that
RFC 8785 refuses. `rounded-unsafe-integer` is refused only by the bounded
safe-integer profile, so its row shows bytes, not a verdict.

| Class | Vector | jcs-admit (RFC 8785 / I-JSON) | csharp | go | java | kotlin | php | python | ruby | rust | swift | typescript |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| number | `exponent-switch` | admit / admit | `[{"data":{"small":1e-7,"switch"...` | `[{"data":{"small":1e-7,"switch"...` | `[{"data":{"small":1.0E-7,"switc...` | `[{"data":{"small":1.0E-7,"switc...` | `[{"data":{"small":1.0e-7,"switc...` | `[{"data":{"small":1e-7,"switch"...` | `[{"data":{"small":1.0e-07,"swit...` | `[{"data":{"small":1e-7,"switch"...` | `[{"data":{"small":1e-07,"switch...` | = JCS |
| number | `largest-safe-integer` | admit / admit | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| number | `first-unsafe-integer` | admit / refuse (UnsafeInteger) | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| number | `negative-zero` | admit / admit | `[-0]` | `[-0]` | = JCS | = JCS | = JCS | = JCS | = JCS | `[-0.0]` | = JCS | = JCS |
| number | `one-point-zero` | admit / admit | `[1.0]` | `[1.0]` | `[1.0]` | `[1.0]` | = JCS | `[1.0]` | `[1.0]` | `[1.0]` | = JCS | = JCS |
| number | `integer-valued-1e20` | admit / refuse (UnsafeInteger) | `[1e20]` | `[1e20]` | `[1.0E20]` | `[1.0E20]` | `[1.0e+20]` | `[1e+20]` | `[1.0e+20]` | `[1e+20]` | `[1e+20]` | = JCS |
| number | `exponent-1e21` | admit / refuse (UnsafeInteger) | `[1e21]` | `[1e21]` | `[1.0E21]` | `[1.0E21]` | `[1.0e+21]` | = JCS | `[1.0e+21]` | = JCS | = JCS | = JCS |
| number | `point-three-ulp` | admit / admit | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| number | `min-subnormal` | admit / admit | = JCS | = JCS | `[4.9E-324]` | `[4.9E-324]` | `[5.0e-324]` | = JCS | `[5.0e-324]` | = JCS | = JCS | = JCS |
| number | `max-double` | admit / refuse (UnsafeInteger) | `[1.7976931348623157e308]` | `[1.7976931348623157e308]` | `[1.7976931348623157E308]` | `[1.7976931348623157E308]` | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `ordinary-unicode` | admit / admit | `[{"data":{"label":"caf\u00E9"}}]` | `[{"data":{"label":"caf\u00e9"}}]` | = JCS | = JCS | `[{"data":{"label":"caf\u00e9"}}]` | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `control-char-escape` | admit / admit | `["\u001F"]` | = JCS | `["\u001F"]` | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `short-escapes` | admit / admit | `["\b\f\n\r\t\u0022\\"]` | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `escaped-solidus` | admit / admit | = JCS | `["a\/b"]` | = JCS | = JCS | `["a\/b"]` | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `html-characters` | admit / admit | `["\u003C\u0026\u003E\u0027"]` | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `nfd-combining-mark` | admit / admit | `["cafe\u0301"]` | `["cafe\u0301"]` | = JCS | = JCS | `["cafe\u0301"]` | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `nbsp-and-line-separator` | admit / admit | `["\u00A0\u2028"]` | `["\u00a0\u2028"]` | = JCS | = JCS | `["\u00a0\u2028"]` | = JCS | = JCS | = JCS | = JCS | = JCS |
| string | `astral-value` | admit / admit | `["\uD83D\uDE00"]` | `["\ud83d\ude00"]` | = JCS | = JCS | `["\ud83d\ude00"]` | = JCS | = JCS | = JCS | = JCS | = JCS |
| key order | `utf16-nested-key-order` | admit / admit | `[{"data":{"\uE000":"bmp","\uD83...` | `[{"data":{"\ue000":"bmp","\ud83...` | `[{"data":{"":"bmp","😀":"astral...` | `[{"data":{"":"bmp","😀":"astral...` | `[{"data":{"\ue000":"bmp","\ud83...` | `[{"data":{"":"bmp","😀":"astral...` | `[{"data":{"":"bmp","😀":"astral...` | `[{"data":{"":"bmp","😀":"astral...` | `[{"data":{"":"bmp","😀":"astral...` | `[{"data":{"":"bmp","😀":"astral...` |
| key order | `ascii-key-order` | admit / admit | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | `{"b":1,"a":2,"aa":3,"B":4,"":5}` | = JCS | = JCS | `{"b":1,"a":2,"aa":3,"B":4,"":5}` |
| structure | `insignificant-whitespace` | admit / admit | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| structure | `depth-64` | admit / admit | **refused** | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS | = JCS |
| admission | `duplicate-member` | refuse (DuplicateMember) / refuse (DuplicateMember) | **accepted** `[{"data":{"decision":"allow","d...` | **accepted** `[{"data":{"decision":"allow","d...` | **accepted** `[{"data":{"decision":"deny"}}]` | **accepted** `[{"data":{"decision":"deny"}}]` | **accepted** `[{"data":{"decision":"deny"}}]` | **accepted** `[{"data":{"decision":"deny"}}]` | **accepted** `[{"data":{"decision":"deny"}}]` | **accepted** `[{"data":{"decision":"deny"}}]` | **accepted** `[{"data":{"decision":"allow"}}]` | **accepted** `[{"data":{"decision":"deny"}}]` |
| admission | `lone-surrogate` | refuse (StringNotScalar) / refuse (StringNotScalar) | **refused** | **accepted** `[{"data":{"label":"\ud800"}}]` | **accepted** `[{"data":{"label":"?"}}]` | **accepted** `[{"data":{"label":"?"}}]` | **refused** | **refused** | **refused** | **refused** | **refused** | **accepted** `[{"data":{"label":"\ud800"}}]` |
| admission | `rounded-unsafe-integer` | admit / refuse (UnsafeInteger) | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` | `[{"data":{"count":9007199254740...` |
| admission | `non-finite-1e400` | refuse (NonFiniteNumber) / refuse (UnsafeInteger) | **accepted** `[1e400]` | **accepted** `[1e400]` | **accepted** `["Infinity"]` | **refused** | **refused** | **accepted** `[null]` | **refused** | **refused** | **refused** | **accepted** `[null]` |
| admission | `depth-129` | refuse (TooDeep) / refuse (TooDeep) | **refused** | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` | **refused** | **refused** | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` | **accepted** `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...` |

| SDK | canonical | differs | refused | dropped | reject accepted |
|---|---|---|---|---|---|
| csharp | 6 | 15 | 3 | 0 | 2 |
| go | 9 | 13 | 0 | 0 | 4 |
| java | 13 | 9 | 0 | 0 | 4 |
| kotlin | 14 | 8 | 1 | 0 | 3 |
| php | 11 | 11 | 2 | 0 | 2 |
| python | 17 | 5 | 1 | 0 | 3 |
| ruby | 15 | 7 | 3 | 0 | 1 |
| rust | 17 | 5 | 3 | 0 | 1 |
| swift | 19 | 3 | 2 | 0 | 2 |
| typescript | 20 | 2 | 0 | 0 | 4 |

## What this means for a record signed over MCP traffic

- No SDK sorts keys by UTF-16 code units. Swift and Rust sort by UTF-8 bytes,
  which agrees with RFC 8785 only while every key is ASCII.
- Duplicate members are accepted by all ten SDKs, and they do not agree on
  which value survives: Go and C# keep both, Swift keeps the first, the rest
  keep the last. Two parties reading the same bytes see different decisions.
- An out-of-range number (`1e400`) becomes `null` in TypeScript and Python,
  the string `"Infinity"` in Java, and passes through untouched in Go and C#.
- Ten SDKs print the same double `1e20` five different ways: `100000000000000000000` (the RFC 8785 form, TypeScript only), `1e+20`, `1e20`, `1.0E20` and `1.0e+20`.

To make an SDK's CI report the same table for its own release, call the
reusable workflow:

```yaml
jobs:
  jcs:
    uses: probityai/agent-evidence-vectors/.github/workflows/mcp-sdk-jcs.yml@<sha>
    with:
      sdks: '["python"]'
      fail-on-divergence: true
```

For canonical bytes, run the corpus against a JCS implementation such as the
`jcs-admit` crate, or install `agent-evidence-vectors` from PyPI and run its
rail.
