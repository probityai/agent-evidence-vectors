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
| Packaged reference readers | `vectors`, `vectors-w3c-report`, `vectors-observed-effect`, `vectors-receipt-signature`, `vectors-agent-audit-record`, `vectors-anchored-chain`, `vectors-grade-floor` |
| Named verifier required | `vectors-source-coverage` |
| Own external contract supported | `vectors`, `vectors-receipt-signature`, `vectors-anchored-chain` and `vectors-grade-floor`; source coverage uses its consumer contract |

`vectors-w3c-report`, `vectors-observed-effect` and `vectors-agent-audit-record` refuse a named verifier. Other suites with no packaged reader exit `2` unless a named verifier supplies their external route. Check each [corpus README](../guides/corpora.md) for its contract.

Two standalone tools have separate jobs: [vectors-anchor-stream/run_verifier.py](../../vectors-anchor-stream/run_verifier.py) measures a supplied `anchors_verify.py` implementation; [vectors-mcp-record-contract/check_run_record.py](../../vectors-mcp-record-contract/check_run_record.py) checks a run record you supply.
