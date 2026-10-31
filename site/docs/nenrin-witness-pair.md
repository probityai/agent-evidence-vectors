# Same card, different endpoint

Check the signed record, the key and the exact target

Horizon Shield brought us two signed witness records: one for `/a2a`, one for `/mcp`, both carrying the same agent-card hash. We wrote a second reader so you can check the record bytes, keys and endpoint yourself.

| Check             | A: `/a2a`       | B: `/mcp`       |
|-------------------|-----------------|-----------------|
| Requested `/a2a`  | matches         | target mismatch |
| Requested `/a2a/` | target mismatch | target mismatch |

Both signatures verify under the separately pinned keys. A reports seven true assertions and one null; B reports four true and four nulls. The reader keeps all eight entries visible. You can reproduce the four reads and 62 tests with the [source and run instructions](examples/nenrin-witness-pair/README.md).

Thanks to Pavlo (`pipavlo82`) and `kuangmi-bit` for the records, and Horizon Shield for the pair. Probity maintains this reader. The [input contract](examples/nenrin-witness-pair/docs/INPUT-CONTRACT.md) explains the key, card and time boundaries; the [retained check](examples/nenrin-witness-pair/qualification/RESULT.json) has the actual results.

Want to try it? Run the reader and share your output, or bring another pair that should match in one context and refuse in another. We can keep the case together, with credit for the records and the run.

<details>

<summary>

Source, trust choices and retained checks
</summary>

The [source map](examples/nenrin-witness-pair/docs/SOURCE-MAP.md) pins each supplied API record and current key. The reader checks the signed target as an exact URL. It keeps a mismatch separate from a signature refusal.

The keys were fetched and pinned for this reader. The signed records report their assertion results and observation vantages. Card-signature verification is null in both records. This check does not rewalk the endpoints, validate their card or response claims, prove historical key control, or validate the retained timestamp proof.

The [preparation check](examples/nenrin-witness-pair/docs/QUALIFICATION.md) and [integration record](examples/nenrin-witness-pair/INTEGRATION.json) retain the source and roles. The [original failed check](examples/nenrin-witness-pair/qualification/original-r1/diagnosis.json) and [test output](examples/nenrin-witness-pair/qualification/original-r1/tests.xml) stay alongside the corrected result. The new reader's retained run is author-operated.

</details>

[HTML view](nenrin-witness-pair.html) | [Agent guide](llms.txt)
