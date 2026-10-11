# ACS-Core wire probes

One reproduction per Guardian obligation that a host adapter can see on the
wire, for any ACS v0.1.0 Guardian reachable over HTTP. The corpus in `../vectors`
states expectations; these probes send the requests and score the answers.

The probe ids follow the defect table of
[agent-control-standard issue 184](https://github.com/GenAI-Security-Project/agent-control-standard/issues/184):

| id | obligation | spec |
|---|---|---|
| D1a-c | unsigned, inverted and subset-coverage signatures are refused with `-32004` | section 10, 17.1 |
| D2a | a repeated `request_id` is refused with `-32005` | 10.3 MUST |
| D2b | a repeated `nonce` is refused with `-32005` | 10.3 SHOULD |
| D2c | the same request bytes are refused after a Guardian restart | 10.3 MUST |
| D3a-c | `skew_window_ms` in the ServerHello; +/-3600 s refused with `-32006` | 10.3 |
| D4a-b | allow and deny carry an advancing `chain_hash` under a response signature that verifies with the session key | 8.6, 10 |
| D4c | a client `chain_hash` that cannot match is denied `chain_mismatch` or `-32007` | 8.6 MAY |
| D5 | `system/ping` answers `allow` with no ACS error | 13 |
| D6a-b | an unsupported version is refused with `-32001`; `profiles_accepted` is sent | 4, conformance.md |
| D6c | a method outside the negotiated `methods_implemented` is refused with `-32003` | 4, 17.1 |
| D6d | a step in a session that never sent `handshake/hello` gets an error, not a decision | 4 |
| D7 | `sessionStart`, `userMessage`, `agentResponse`, `sessionEnd` are answered | conformance.md |
| D8 | `protocols/MCP/tools/call` reaches policy | conformance.md |
| D10 | a tool the deployment does not govern is denied `tool_unregistered` | issue 184 |

## Run it

Against the AGT reference Guardian in a checkout of the specification's
repository (needs `bun` and `python3`, nothing else):

```sh
bash run_against_agt.sh path/to/agent-control-standard out
```

Against any other Guardian, start it with an HMAC key and point the probes at it:

```sh
python3 acs_wire_probes.py --guardian http://127.0.0.1:8787/acs \
    --ikm-b64 "$ACS_HMAC_SECRET" --out out
```

Every request and response is written to `out/wire/`, and `out/results.json`
holds the scored rows.

## Key derivation is a reading, and it is a flag

Section 10 says the per-session key is HKDF-derived from the deployment's
keying material "together with the `session_id`" and fixes neither the salt nor
the info string. The default here (empty salt, info = `session_id`,
`key_id` = `session_id`) matches the AGT Guardian. `--hkdf-salt` and
`--key-id-mode` cover other readings, and two conformant Guardians that read it
differently will not verify each other's signatures.

## Recorded runs

`expected/` holds the status of every probe at two refs of the AGT Guardian,
and `.github/workflows/acs-wire-probes.yml` re-runs both on every change here:

| ref | what it is | expectation |
|---|---|---|
| `770f1e0` | `integration` before pull request 229 | every probe fails |
| `beee5b5` | head of pull request 229 | `expected/agt-pr229.json` |

At `beee5b5` the open MUST rows are D2c (replay memory does not survive a
restart), D6c (a method outside `methods_implemented` is answered) and D6d (a
step with no handshake is answered); the pull request lists the first two as
follow-up work. D2b (SHOULD) and D4c (MAY) are also open. A run passes when it
matches its recorded statuses exactly, so a probe that changes in either
direction turns the workflow red until the expectation is updated with it.
