# Choose a corpus reader

The manifest's `suite` selects the reader. Use the packaged Python route for a supported suite or build the Go CLI to judge a corpus directory.

From the repository root:

```sh
GOWORK=off go build -o aee-verify ./cmd/aee-verify
./aee-verify vectors
./aee-verify vectors-ai-agent-action
./aee-verify vectors-artifact-binding
```

| Result | Exit |
| --- | --- |
| Every member matches its manifest | `0`, with counts by verdict |
| A member or corpus-level check fails | `1`, with findings |
| Missing, unreadable or unsupported suite | `2`, with the suite or read error |

The Go binary supports its [registered readers](../../corpora/registry.go), rather than every directory named `vectors-*`. In particular, the SCITT/COSE corpus retains its own checker; the binary refuses that suite and describes the missing reader.

The following Python routes describe the current source. A released wheel exposes its own set with `--list-corpora`.

| Current source Python route | Supported corpora |
| --- | --- |
| Packaged reference readers | `vectors`, `vectors-w3c-report`, `vectors-observed-effect`, `vectors-receipt-signature`, `vectors-agent-audit-record`, `vectors-anchored-chain`, `vectors-mcp-owasp`, `vectors-a2a-jcs-v01` |
| Named verifier required | `vectors-source-coverage` |
| Own external contract supported | `vectors`, `vectors-receipt-signature`, `vectors-anchored-chain` and `vectors-a2a-jcs-v01`; source coverage uses its consumer contract |

`vectors-w3c-report`, `vectors-observed-effect`, `vectors-agent-audit-record` and `vectors-mcp-owasp` refuse a named verifier. Other suites with no packaged reader exit `2` unless a named verifier supplies their external route. Check each [corpus README](../guides/corpora.md) for its contract.

Two standalone tools have separate jobs: [vectors-anchor-stream/run_verifier.py](../../vectors-anchor-stream/run_verifier.py) measures a supplied `anchors_verify.py` implementation; [vectors-mcp-record-contract/check_run_record.py](../../vectors-mcp-record-contract/check_run_record.py) checks a run record you supply.

## The a2a-jcs-v01 contract

`vectors-a2a-jcs-v01` is a2aproject/a2a-tck's Agent Card canonicalization corpus, kept byte for byte and locked by commit and corpus digest in its [source-lock.json](../../vectors-a2a-jcs-v01/source-lock.json). Its MANIFEST names two targets, with the vector count of each under `targets`, and the harness scores one per run:

| Target | Function | Vectors |
| --- | --- | --- |
| `card-signing-input` (default) | the card without its top-level `signatures` member, canonicalized | every vector |
| `rfc8785` (`A2A_JCS_TARGET=rfc8785`) | one JSON value to RFC 8785 bytes | groups A3 to A6 |

The harness runs `<verifier> <target> <input.json>` once per vector. The input file holds the vector's JSON text: `input_raw` verbatim for a reject, `input` serialized for an accept. The verifier answers on its last nonempty stdout line:

| Exit | Answer | Meaning |
| --- | --- | --- |
| `0` | `{"canonical_utf8_hex": "<hex>"}` | produced canonical bytes |
| `1` | anything | refused: the input has no canonical form |
| other, timeout, malformed | none | errored |

A MUST-ACCEPT vector passes on the expected bytes; other bytes are `diverged` and a refusal is `refused`. A MUST-REJECT vector passes on a refusal; bytes are `accepted`. The four rule-3 rejects present a card that still carries `signatures` as its own signing bytes, and pass when the recomputed bytes differ from them. The report has `rail: external`, the `target`, and `verifier.vectorsExecuted`, so the Action's summary applies unchanged. `python -m agent_evidence_vectors.a2ajcs` is the packaged reference implementation of the contract.
