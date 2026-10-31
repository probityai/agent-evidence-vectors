# ACS-Core hook probes

One reproduction per obligation a host can see at its own hook, for the Claude
Code shim in the specification repository's reference implementation
(`reference-implementations/agt/hosts/claude-code/acs-hook.ts`). The wire probes
beside this directory drive a Guardian over HTTP; these drive the process a host
runs at each hook, and read four things: the exit code and stdout, which the host
reads; the audit entry the specification requires when a step goes on without a
decision, under either posture (section 6.4) or with no session at all (section
4.1); and, with the Guardian up, its envelope log, which says whether the step
reached it at all.

They were written from one run. On 2026-09-12 the shim, driven by hand on
Windows 11 under Bun 1.4.2 at `7d2dd3c`, exited 0 with nothing on either stream:
with the Guardian running it sent nothing to it, and with the Guardian stopped it
wrote no audit entry
([agent-control-standard issue 111](https://github.com/GenAI-Security-Project/agent-control-standard/issues/111),
corpus member `v564ff5d8d344bea2`). A host reads exit 0 with no output as a hook
with no decision to report and lets the step continue, so that run looks like a
clean one to anything that does not read the output. H6 reads it; every other
probe that reads an answer fails on it too, which `--selftest` proves.

| id | obligation | where |
|---|---|---|
| C0 | an allowed step gets exit 0 and an `allow` in the JSON body, writes no audit entry, and the Guardian's log shows the request arriving and the allow leaving | host README, exit codes |
| H1 | a denied step gets exit 0 and a `deny` in the JSON body, the deny travels in the body, never the exit code, and the Guardian's log shows the request and the deny | 6.4, host README |
| H2 | the result gate renders a `PostToolUse` answer and the Guardian's log shows the result arriving | host README, the result gate |
| H3a-f | input or configuration the shim cannot trust gets exit 2 with stderr only, and no audit entry: stdin that is not JSON, no `session_id`, an unsafe `session_id`, a hook the hookmap does not map, a hookmap path that does not exist, a hookmap declaring a `permissionDecision` Claude Code does not accept | host README, exit codes; `govern-step.ts` for the unmapped hook, which is refused after the handshake |
| H4a-b | with the Guardian unreachable and no session negotiated, the handshake fails and the step proceeds under the startup posture, default `proceed`; one audit entry records it: `outcome` proceeded, `posture_source` default, a transport failure and a failed handshake | 4.1 (a session started unguarded is recorded in the deployment's own audit log), 6.4 |
| H5a-b | with `on_decision_failure` deny negotiated (the Guardian's log shows the step that negotiated it) and the Guardian then stopped, the step is blocked and one audit entry records it: `outcome` blocked, `posture_source` negotiated, no session failure | 6.4 (every decision failure, under either posture) |
| H6 | no run exits 0 with nothing on stdout, counted over every run of each phase | issue 111 |
| H7 | with the Guardian unreachable and ten shims started at once in one session, every one answers `allow` and every one has its own audit entry, none lost, with distinct `rpc_id`s | 6.4, ten steps at once |

The specification requires the entry and leaves its shape to the deployment. The
fields the probes read (`outcome`, `posture_source`, `failure.kind`,
`session_failure.kind`, `rpc_id`, `seq`) are the reference implementation's, from
`packages/host-adapter/src/audit-sink.ts`.

H7 reports how many distinct `seq` values the ten entries carry and does not
score it. [Issue 250](https://github.com/GenAI-Security-Project/agent-control-standard/issues/250)
measured, at `27799c2` under Bun 1.3.11 on Windows 11, 44 to 56% of entries
carrying a `seq` another entry already had once five or more shims ran at once,
with no entry lost and every `rpc_id` distinct. The Linux runs behind these
expectations saw both ten distinct values and a duplicated one. A race is not a
stable verdict, so the number is written into every run's record and left out of
the comparison.

## Run it

Against the shim and Guardian in a checkout of the specification's repository
(needs `bun` and `python3`, nothing else), into an out directory that holds no
earlier run's captures, state, results or Guardian logs:

```sh
bash run_against_agt.sh path/to/agent-control-standard out [expected/some.json]
```

The runner starts the Guardian under the default posture with an envelope log,
runs the `up` phase against both, stops it, runs `down`, starts it under
`on_decision_failure` deny for `deny-up`, stops it again for `deny-down`, and
with an expectation checks that every probe the expectation names was produced.
Its exit status is the worst any step returned: 2 when the shim or the Guardian
could not run, 1 on a failed or drifted probe or a missing one. One phase at a
time, against a shim and Guardian you manage yourself (`up` and `deny-up` take
the Guardian's `ACS_ENVELOPE_LOG` as `--guardian-log`):

```sh
python3 acs_hook_probes.py --acs path/to/agent-control-standard --out out \
    --phase down --guardian http://127.0.0.1:1/acs
```

`--shim` names a different hook command, run from
`reference-implementations/agt`. Every invocation's stdin, exit code, both
streams, audit entries and the envelope-log lines it produced are written to
`out/hook/`, and `out/results-<phase>.json` holds the scored rows.

```sh
python3 acs_hook_probes.py --acs path/to/agent-control-standard --out out --selftest
```

runs all four phases against a shim that reads stdin and exits 0 with nothing,
and succeeds only when every probe fails.

## Recorded runs

`expected/` holds the status of every probe at each ref and runtime below, and
`.github/workflows/acs-hook-probes.yml` re-runs each of them on every change
here:

| ref | runtime | what it is | expectation |
|---|---|---|---|
| `d1ad294` | Bun 1.3.11 | `integration` on 2026-10-23, under the Bun version the repository's `reference-implementation.yml` pins | `expected/agt-integration-d1ad294-bun-1.3.11.json` |
| `d1ad294` | Bun 1.4.2 | the same head under the Bun version issue 111 named | `expected/agt-integration-d1ad294-bun-1.4.2.json` |
| `27799c2` | Bun 1.3.11 | the `integration` commit and Bun version issue 250 measured at | `expected/agt-integration-27799c2-bun-1.3.11.json` |
| `27799c2` | Bun 1.4.2 | the same commit under Bun 1.4.2, the second pairing `../README.md` records silent on Windows 11 | `expected/agt-integration-27799c2-bun-1.4.2.json` |
| `7d2dd3c` | Bun 1.4.2 | the `integration` commit and Bun version of the run issue 111 reports, the first pairing | `expected/agt-integration-7d2dd3c-bun-1.4.2.json` |

Every probe passes in all five, on Linux. The last two rows are the pairings
`../README.md` records silent on Windows 11, and both answer here, so what
remains of that report is the Windows run. A run passes when it matches its
recorded statuses exactly and produces every probe the expectation names, so a
probe that changes in either direction, or disappears, turns the workflow red
until the expectation is updated with it.

An expectation's statuses are written from a run, never typed. Its header (`ref`,
`runtime`, `note`) is the author's; then, with the four phases in `out`:

```sh
python3 acs_hook_probes.py --acs path/to/agent-control-standard --out out \
    --expect expected/some.json --write-expect
```
