# AgentID action_ref v2 recompute

This optional consumer profile recomputes the AgentID `action_ref` vectors published at
`haroldmalikfrimpong-ops/agentid-aps-interop` tag `interop-freeze-2026-10-06`
(`bd1f2e7c0d3b8bf55fe5a70479be504cb5533455`) without the producer's tool, and then tests the v2
construction on tuples the four vectors do not cover. It is separate from the released vector
corpus and does not change its scoring or reference rail.

The two constructions, over the same four fields:

| Version | Bytes hashed with SHA-256 |
|---|---|
| v1 | `UTF8(agent_id) ‖ UTF8(action_type) ‖ UTF8(scope) ‖ int64_be(timestamp_ms)` |
| v2 | RFC 8785 JCS of `{agent_id, action_type, scope, timestamp_ms}` |

v1 has no field framing, which is the ambiguity the [AgentID offline reader](../agentid-offline/README.md)
reported on 2026-10-01. v2 is the producer's answer to it.

## Run

From the repository root:

```bash
uv sync --locked --extra dev
uv run python -m pytest interop/agentid-action-ref-v2/test_reader.py -q
uv run python interop/agentid-action-ref-v2/reader.py --output-dir /tmp/action-ref-v2-attempt
```

The last command prints `upstream checks 30/30, domain cases 15/15` and writes `report.json` in the
new directory. Exit 0 means every check and case has its declared outcome; 1 means a report was
written and something differs; 2 means a pinned input changed, an input is malformed or the output
directory already exists, and no report is written.

## What is measured

1. **The 30 upstream checks.** The four vector files are copied unmodified and pinned by size and
   SHA-256 in [INPUTS.json](INPUTS.json). For every tuple the reader recomputes v1 with `struct.pack`
   and v2 with the pinned `rfc8785` package, and reproduces each check the producer's
   `tools/action_ref_v2.py` states: per-tuple v1, v2 and version labels, the pinned literal, and for
   each pair whether v1 and v2 collide and whether the v1 preimages are identical. Both collision
   pairs collide under v1 and separate under v2; the control pair separates under both.
2. **Fifteen domain cases** in [DOMAIN-CASES.json](DOMAIN-CASES.json). Each gives the tuple as raw
   JSON text. Where a value is defined, the expected canonical bytes and timestamp octets are written
   out by hand, so the reader does not grade itself.

What the domain cases show about v2 as published:

- **v2 is defined only for `|timestamp_ms| <= 2^53 - 1`.** RFC 8785 serializes numbers as IEEE
  doubles, so 2^53 and above have no canonical form; a strict canonicalizer refuses them, and one that
  parses through a double maps 9007199254740993 onto 9007199254740992, giving two tuples one value.
  v1 covers all of int64. The producer's stdlib path (`json.dumps` with sorted keys, used when the
  optional `jcs` package is absent) returns a value for these inputs that no RFC 8785
  implementation produces. A v2 definition needs the bound stated, and a verifier refuses
  outside it (D02 to D05).
- **`timestamp_ms` has to be an integer token.** `1790882271509.0` canonicalizes to `1790882271509`
  under RFC 8785 but to `1790882271509.0` under `json.dumps`, and an `int()` coercion turns both that
  and `true` into integers silently (D06 to D08).
- **No Unicode normalization.** Composed and decomposed `cafe` with an acute accent are different
  tuples under both constructions (D09, D10).
- Exactly four members: a missing field or an extra one such as `action_ref_version` inside the
  hashed object is refused (D12, D13); so are lone surrogates and duplicate members (D14, D15).

## Provenance and what is not established

Probity wrote and ran this reader. The producer's `tools/action_ref_v2.py` and README were read
first; none of that code is imported. The vectors are by haroldmalikfrimpong-ops; the source commit
carries no license file. The result is a digest-consistency recompute. It does not establish that any
emitter produces v2, that any signature covers these values, or the authorization, execution or
completeness of any action, and it is not a formal Pack #3 result or host acceptance.
