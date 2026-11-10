# Producer mode: check the records your project emits

The corpus modes of the Action test a reader: each member is a record your verifier must accept or reject. If your project writes records instead (an emitter, an exporter, a harness that saves a run record), producer mode reads what you wrote with the reader this release pins for the record class, holds it to your pins, and writes a receipt.

## Inputs

| input | meaning |
| --- | --- |
| `records` | Paths or globs, one per line, of the records you emit. Setting it selects producer mode. |
| `record-class` | `w3c-report` (default), `run-record`, `agent-run-metrics` or `llm-context-discovery`. |
| `producer` | Optional command that writes the records, run with bash before they are read. |
| `pins` | Optional JSON file: `{"records": {"<path>": {"sha256": "...", "size": 0, "count": 0, "checkSetRoot": "..."}}}`. Every field is optional; `count` and `checkSetRoot` apply to `w3c-report`. |
| `receipt-path` | Where the receipt is written (default `agent-evidence-vectors-receipt.json`). |

A `w3c-report` is read through the v0.1 reading table and the rejection rows; your own report reaches the reader with no observation store, so referenced observations read as unchecked. A `run-record` is read by the interoperability-evidence criterion of `vectors-mcp-record-contract`.

With a pins file, a pinned record that was not produced and a produced record that was not pinned are both mismatches.

## What it writes and how it exits

The receipt (`agent-evidence-vectors/producer-receipt/v1`) lists each record with its SHA-256, size, verdict, findings and pin mismatches, and carries `reference.verifier.id`, the package URL of the reader that judged, for example `pkg:pypi/agent-evidence-vectors@0.37.0#reader/w3c-report`. It is uploaded as the job artifact.

| exit | result | when |
| --- | --- | --- |
| 0 | `pass` | at least one record was read, every record conforms, every pin holds |
| 1 | `fail` | a record does not conform, or a pin does not hold |
| 2 | `no-verdict` | no file matched, an unknown class, an unreadable record or pins file, a reader crash |

The same check runs locally: `agent-evidence-vectors produced w3c-report 'out/*.json' --pins pins.json`.

## Example workflow

```yaml
# .github/workflows/records.yml
name: records
on: [push, pull_request]
permissions:
  contents: read
jobs:
  produced:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: probityai/agent-evidence-vectors@v0.37.0
        with:
          producer: python3 -m mypkg.emit --out out/report.json
          records: out/*.json
          record-class: w3c-report
          pins: EXPECTED.pins.json
```

Keep the pin exact and let a bot open the bump, so a new reader release reaches your CI as a pull request your tests run:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```
