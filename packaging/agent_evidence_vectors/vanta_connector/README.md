# Vanta connector: verifier pass/fail as compliance evidence

This pushes the result of a pinned agent-evidence verifier run into Vanta as a custom resource, so a Vanta Custom Test can mark "the verifier passes its conformance corpus" as passing or failing evidence. It is for teams that already track controls in Vanta and want agent-evidence verification to show up there.

```
pip install agent-evidence-vectors==X.Y.Z
agent-evidence-vectors-vanta schema
agent-evidence-vectors-vanta push --corpus vectors
```

`push` runs the reference rail over the shipped corpus (or `--vectors DIR` for a bundle directory, or `--report FILE` for a `conformance-report.json` you already have), builds one record per corpus, and prints the exact HTTP requests. By default it sends nothing. The first run prints:

```
aev-vectors: allPass=True pass=<n>/<n>
PUT https://api.vanta.com/v1/resources/custom_resource
```

## One-time setup in Vanta

Vanta has no API for resource definitions or Custom Tests, so `schema` prints what to enter in the Dashboard: the JSON Type Definition for the custom resource, and the test rule `allPass equals true`. The setup follows Vanta's "Build a custom integration for compliance data" quickstart: create a Private integration under Developer Console, define the resource, then author the test.

## Sending

Export `VANTA_CLIENT_ID`, `VANTA_CLIENT_SECRET` and `VANTA_RESOURCE_ID`, then add `--send`. The connector requests a token with the `connectors.self:write-resource` scope, PUTs the records, and exits 1 if Vanta rejects any. Plain http is refused except on loopback, redirects are not followed, and secrets are never printed.

Each PUT is the full state Vanta holds for the resource, so one push carries every corpus you want to keep. A corpus left out of a later push is marked as no longer existing. `--fail-on-fail` makes the exit status 1 when any corpus fails, for a CI step that should also go red.

Details, the record fields and the tests: [docs/guides/vanta.md](../../../docs/guides/vanta.md).
