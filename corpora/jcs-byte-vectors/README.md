# Canonical JSON bytes at the audit transcript boundary

`cases.json` pins raw JSON, canonical UTF-8 hex, and SHA-256 for five small
inputs, then 18 drift and 10 depth cases (below). `check.mjs` checks those bytes with ECMAScript string and number
serialization and UTF-16 member sorting. The Go test checks the separate
safe-integer record profile, including three malformed inputs.

Run the byte oracle:

```sh
node corpora/jcs-byte-vectors/check.mjs
```

The wheel ships `cases.json` and this README, so an SDK's CI can pin the
package and read the cases offline instead of fetching them by tag:

```sh
pip install agent-evidence-vectors==VERSION
agent-evidence-vectors --jcs-byte-vectors
python -c "from agent_evidence_vectors.run_vectors import jcs_byte_vectors_path; print(jcs_byte_vectors_path())"
```

Both print the absolute path of the installed `cases.json`. Releases from 0.17.7 on carry it.

To run a candidate canonicalizer, pass a command that reads one JSON value
from stdin and writes canonical bytes to stdout, with no trailing newline.
It exits nonzero on rejected input:

```sh
node corpora/jcs-byte-vectors/check.mjs --verifier ./canonicalizer
node corpora/jcs-byte-vectors/check.mjs --profile bounded --verifier ./record-canonicalizer
```

| Input | Boundary |
| --- | --- |
| Escaped `caf\u00e9` | JCS emits the UTF-8 character. Python's default `json.dumps` escapes it. |
| `\ud83d\ude00` and `\ue000` as nested keys | UTF-16 puts the supplementary key first; Python's `sort_keys` puts it second. |
| `1e-7` and `1e-6` | JCS emits `1e-7` and `0.000001`. Both are rejected by the integer-only record profile. |
| 2^53 - 1 and 2^53 | JCS can serialize both exact values. The bounded profile admits only the first. |
| Duplicate key, lone surrogate, 2^53 + 1 | The first two are invalid JCS input. The last is rejected by the bounded profile before a parser can round it. |

The [`TRACEAuditSink`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/src/agentmesh/governance/trace_sink.py)
uses `json.dumps` with default ASCII escaping for its transcript hash.
[`trace_model`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/src/agentmesh/governance/trace_model.py)
sets `ensure_ascii=False`; both paths use Python key and number formatting.
The fixture is a byte contract for the entry array. A TRACE record's signature,
schema, and call count require their own checks.

## Drift and depth families

`cases.json` also carries two generated families, written by
`scripts/gen-jcs-drift-vectors.py` (`--check` fails when the file differs).

`driftCases` (18 members) are bytes a producer printed and presented as the
canonical form of a value, which RFC 8785 does not print that way. Each pins
`input` (the value as JSON text), `presented` (the drifted bytes) and
`canonicalHex` (the correct bytes, with their SHA-256). The expected answer is
the same for every member: a check that `presented` is canonical says no, and
canonicalizing either `input` or `presented` gives `canonicalHex`.

| Family | Members | What drifts |
| --- | --- | --- |
| `html-escape` | 5 | `<`, `>` and `&` printed as `\u003c`, `\u003e` and `\u0026`, in values and in member names. This is Go `encoding/json`'s default. |
| `non-ascii-escape` | 5 | Non-ASCII text left as `\u` escapes (BMP, surrogate pairs, member names), and U+2028 and U+2029, which Go escapes and JCS prints as UTF-8. |
| `number-format` | 8 | `-0`, `1.0`, `1e-07`, `1E2`, `1e30`, `1000000000000000000000`, `0.0000001` and an integer past 2^53 printed verbatim. |

`source` names the printer. A `go-encoding-json` member is held to a real run of
`encoding/json` by the `jcsvectors` Go test: it must print exactly `presented`.

`depthCases` (10 members) nest arrays and objects 129, 256, 512 and 1024
levels deep, which a gate with the normative cap of 128 containers refuses
(`expect: "reject"`, `error: "too-deep"`), and the same two shapes at exactly 128
levels, which it admits (`expect: "accept"`, with `canonicalHex`). RFC 8785 has
no depth rule, so `check.mjs --profile bounded` holds a verifier to these, and
the default profile does not.

Run `check.mjs --verifier CMD` and the verifier receives each `presented` text
and must print `canonicalHex`; under `--profile bounded` it must also exit
nonzero on every too-deep input and accept the two 128-deep ones. A verifier
that passed before can fail now, so the families arrived in a minor release.

RFC 8785 [sections 3.2.2 and 3.2.3](https://www.rfc-editor.org/rfc/rfc8785#section-3.2)
define the byte rules. The safe-integer rejection is an application profile,
not a blanket JCS rejection.
