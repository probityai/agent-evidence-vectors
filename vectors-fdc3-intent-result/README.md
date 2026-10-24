# FDC3 intent-result error vectors

Cases for [finos/FDC3#2271](https://github.com/finos/FDC3/issues/2271): how a
Desktop Agent Communication Protocol (DACP) message sequence reports an intent
handler that throws or returns a rejected promise, so that the raising app's
`IntentResolution.getResult()` rejects with `IntentHandlerRejected`.

Each case is a message sequence (`cases/<id>/case.json`): the
`intentResultRequest` the resolving app's proxy sends to the Desktop Agent and,
where the case has one, the `raiseIntentResultResponse` the Desktop Agent sends
to the raising app. Every message is validated with JSON Schema draft-07 against
three schema sets under `schema-sets/`, and `MANIFEST.json` records the expected
decision and the rejected steps for every case against every set.

| Set | Whose bytes | What it is |
| --- | --- | --- |
| `fdc3-39505b1` | upstream, vendored by `vendor.py` from commit `39505b1` | the schemas the issue cites |
| `proposed-oneof` | a proposal | `intentResultRequest`'s payload is `intentResult` or `error` (a `ResultError`), never both, as the maintainers asked in [this comment](https://github.com/finos/FDC3/issues/2271#issuecomment-6194982724); `agentResponse`'s open success branch no longer also matches an error payload |
| `optional-error` | derived here | `proposed-oneof` with `error` merely optional beside a required `intentResult`, the first option the issue lists, kept to show why the alternative shape is needed |

| Case | `fdc3-39505b1` | `optional-error` | `proposed-oneof` |
| --- | --- | --- | --- |
| handler-resolves-context | accepted | accepted | accepted |
| handler-resolves-void | accepted | accepted | accepted |
| handler-throws | rejected | rejected | accepted |
| handler-returns-rejected-promise | rejected | rejected | accepted |
| proxy-reports-handler-error | rejected | rejected | accepted |
| agent-forwards-result-error | rejected | accepted | accepted |
| both-result-and-error | rejected | accepted | rejected |
| neither-result-nor-error | rejected | rejected | rejected |
| error-with-app-metadata | rejected | rejected | rejected |
| error-is-not-a-result-error | rejected | rejected | rejected |
| agent-sends-result-and-error | rejected | rejected | rejected |

`agent-forwards-result-error` is rejected at `39505b1` for a reason outside
`intentResultRequest`: `agentResponse.schema.json` gives every response payload
a `oneOf` whose first branch is an open object, so any `{"error": ...}` payload
matches both branches and draft-07 `oneOf` refuses it. That affects every
Desktop Agent error response, not only this one.

## Run it

```sh
python3 vectors-fdc3-intent-result/check_vectors.py
python3 -m pytest vectors-fdc3-intent-result/tests -q
```

`gen_vectors.py` writes the cases, the derived set and the manifest;
`vendor.py --check` refetches the upstream set and compares it byte for byte.

## What it does not test

The behaviour of any Desktop Agent or proxy implementation. The cases test the
schemas, so an implementation that skips validation can pass or fail them
without changing any verdict here.
