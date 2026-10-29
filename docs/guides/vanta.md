# Push verifier results into Vanta

`agent-evidence-vectors-vanta` turns a verifier run into a Vanta custom resource. A Vanta Custom Test then reads one boolean per corpus and reports pass or fail against your controls. The module is stdlib-only and ships in the same wheel as the rail it runs, so the pin on `agent-evidence-vectors` also pins the verifier whose result you push.

## What is pushed

One record per corpus, with `uniqueId` `aev-<suite>`:

| Field | Meaning |
| --- | --- |
| `corpus`, `suiteVersion`, `corpusDigest` | which corpus, which revision, and its digest |
| `vectors`, `pass`, `fail`, `notExercised`, `suiteRefusals` | the run's counts, copied from the report |
| `allPass` | true only when every vector passed, none was skipped and the suite refused nothing |
| `failingVectors` | the first twenty failing vector ids, comma separated |
| `verifier`, `packageVersion`, `lastRun` | which rail ran, which package version, and when |

A report missing a count is refused rather than read as zero, and an empty corpus does not pass. Two report shapes are read: the AEE harness report and the report the corpora with their own reader write.

## Steps

1. In Vanta, open Settings, Developer Console, and create a Private integration. Note the client id and secret.
2. Run `agent-evidence-vectors-vanta schema`, add the custom resource with the printed schema, and copy its Resource ID.
3. On the Tests page, create the custom test with the printed rule. Vanta tests cannot be created by API and cannot be edited after creation.
4. Check the payloads with `agent-evidence-vectors-vanta push --corpus vectors`, then send them by adding `--send` with `VANTA_CLIENT_ID`, `VANTA_CLIENT_SECRET` and `VANTA_RESOURCE_ID` exported.

## Tests

`scripts/vanta-connector-test.py` runs the connector against a local fake HTTP server and asserts the exact token request, bearer header, PUT body, the retry on a 503, the refusal to follow a redirect and that a dry run sends nothing. No test calls the live API. The first live push is yours to run in your own tenant.
