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
| D2c | the same handshake and request bytes, resent after a Guardian restart, are refused with `-32005` | 10.3 MUST |
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
| D11a-b | a `session_id` over 1024 bytes, and a payload nested past the parser's stack, each get a JSON-RPC answer rather than an HTTP 500 | pull request 229 review |

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

## Key derivation follows section 10

Section 10 at `integration` fixes the derivation: HKDF-SHA256 with no salt,
`info` set to the request's `session_id` exactly as sent, and a 32-byte key,
applied to the secret that `key_id` names. `key_id` is an opaque label chosen by
the deployment, and a verifier must refuse an unknown one. The probes follow
that text by default (`--key-id-mode label --key-id conformance-k1`), and
`run_against_agt.sh` starts the Guardian with `ACS_HMAC_KEY_ID` set to the same
label. `--key-id-mode session_id` reproduces the earlier AGT reading, where
`key_id` carried the `session_id`; set `ACS_PROBE_KEY_ID_MODE=session_id` to run
the script that way.

## Recorded runs

`expected/` holds the status of every probe at each ref of the AGT Guardian
below, and `.github/workflows/acs-wire-probes.yml` re-runs each of them on every
change here:

| ref | what it is | expectation |
|---|---|---|
| `770f1e0` | `integration` before pull request 229 | every D1 to D10 probe fails (`expected/agt-integration-770f1e0.json`) |
| `beee5b5` | head of pull request 229 when these probes were written | `expected/agt-pr229.json` |
| `6e6942d` | head of pull request 229 after its handshake, replay-capacity and signing-block fixes | `expected/agt-pr229-6e6942d.json` |
| `f94d393` | head of pull request 229 on 2026-10-23, whose Guardian requires `ACS_HMAC_KEY_ID` | `expected/agt-pr229-f94d393.json` |

At `beee5b5` the open MUST rows are D2c (replay memory does not survive a
restart), D6c (a method outside `methods_implemented` is answered) and D6d (a
step with no handshake is answered); the pull request lists the first two as
follow-up work. D2b (SHOULD) and D4c (MAY) are also open. A run passes when it
matches its recorded statuses exactly, so a probe that changes in either
direction turns the workflow red until the expectation is updated with it.

At `6e6942d` the handshake is enforced, and D2c shows why the probe resends the
recorded `handshake/hello` before the request: the step alone is now refused
with `-32003`, because the restart forgot the session, but the hello and the
step resent together are allowed. The Guardian still does not remember
requests across a restart. D11b's answer there is `-32020`, a code outside the
section 17.1 registry. The pull request's own `a4efc16` answers a full replay
cache with the registry's `-32000` for this reason: a client that does not know a
code outside the registry can fail open on it.
