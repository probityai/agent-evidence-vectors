# Named-tool definition pin for live MCP

This optional case reads the live MCP tool-definition digest profile introduced in [AgentAvow commit `9a65bd9`](https://github.com/AgentAvow/AgentAvow/commit/9a65bd96b02ab3e81359a7e1f4a909abf32e837c). An earlier, separately trusted `toolDigest` is pinned to an endpoint and tool name. The reader computes the digest of one later `tools/list` definition and reports `match`, `changed`, or `not_established`.

The preimage is RFC 8785 JSON for `{profile, tool}`. The profile is `agentavow.mcp-tool-definition.v1`; `tool` keeps non-null `name`, `title`, `description`, `inputSchema`, `outputSchema`, and `annotations`. Other fields do not affect the digest. The source commit, relevant blobs, license, and fixture hashes are pinned in [MANIFEST.json](MANIFEST.json). The upstream repository reserves software rights. This directory contains original Probity code and synthetic definitions, with no upstream source or fixture copied into it.

| Capture | Result | Reason |
| --- | --- | --- |
| Original, reordered list, changed `_meta` | `match` | The named definition is unchanged. |
| Changed named description or schema | `changed` | The named digest differs. |
| Changed other tool | `match` | This pin concerns one name. |
| Duplicate name, missing name, wrong endpoint | `not_established` | The intended definition cannot be selected. |
| Fractional number | `not_established` | This small reader does not implement the full numeric domain. |

Run from the repository root:

```sh
PYTHONPATH=packaging python interop/agentavow-live-mcp/build_cases.py --check
PYTHONPATH=packaging python interop/agentavow-live-mcp/run.py
PYTHONPATH=packaging python -m unittest discover -s interop/agentavow-live-mcp -p 'test_definition_pin.py'
```

The cases and expected answers are separate files, both pinned by SHA-256. The generator builds fixture inputs without calling the reader. The test pins the canonical preimage bytes for the authored example and checks changes to visible fields, metadata, ambiguity, absence, and unsupported values.

The pin in this case was authored here. A deployment must obtain a prior authenticated AgentAvow scan, verify its JWS against a trusted key and issuer, check the signed subject and freshness, retain its `scan.toolDigests` entry, and separately capture the same endpoint's later `tools/list` response. This reader does none of that transport, signature, custody, or time work; its `match` is only digest agreement given those inputs. It also does not check `toolManifestDigest` or AgentAvow's duplicate-name fold. Duplicate names fail closed under this consumer's stricter rule because the gate cannot select one definition by name. No tool call is authorized by this test, and no AgentAvow approval or shared pilot is implied.
