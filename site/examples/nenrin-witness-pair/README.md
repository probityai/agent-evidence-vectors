# Read a signed witness pair

These two records fetched the same agent card and walked different endpoints.
This second reader verifies each record under a separately pinned key and checks
the signed URL exactly. It is written from the record format, without the producer reader.

| Requested target | Record A: `/a2a` | Record B: `/mcp` |
| --- | --- | --- |
| `https://gate.horizonshield.dev/a2a` | matches | refuses |
| `https://gate.horizonshield.dev/a2a/` | refuses | refuses |

A reports seven true assertions and one unevaluated assertion. B reports four true
and four unevaluated assertions. Both records contain eight assertions. The reader
keeps each true, false and null value; it does not turn `7/7` or `4/4` into eight passes.

Install the pinned environment, then run the complete retained check:

```sh
uv sync --locked --group dev
bash scripts/run-gate.sh
```

`gate-results` contains the actual exits, signature/target reads, tests and coverage.
The CLI recipe for one record is in the [input contract](docs/INPUT-CONTRACT.md).

Credit to Pavlo (`pipavlo82`) and `kuangmi-bit` for the witness records, and Horizon
Shield for supplying the pair. Probity owns this reader. Current key verification
and reported assertion values stay separate from card signatures, response correctness,
historical key control and timestamp proofs. Those details are in the [source map](docs/SOURCE-MAP.md).

## Runs by other operators

- `ogasurfproject-jpg` ran the gate at `2bff38d8` on Ubuntu 22.04 aarch64 with CPython 3.14.7: all 10 steps
  matched their expected exits, and a direct read with their own operator string gave the same four outcomes
  ([report](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529870053)).
  Their machine checked the two key documents against the SHA-256 in `pins.json`, not a live fetch.
- Horizon Shield keeps the same gate as a weekly check in
  [`probity-witness-reader.yml`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/.github/workflows/probity-witness-reader.yml)
  ([first run](https://github.com/ogasurfproject-jpg/horizon-shield/actions/runs/37931782273)). It also checks
  that `a.api.json` and `b.api.json` hold the record bytes its ledger serves.
