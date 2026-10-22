# ACS host steps taken while the Guardian is unreachable

This corpus judges what an ACS host does on a step when no decision arrives from
its Guardian. The rules come from the ACS instrument specification at
GenAI-Security-Project/agent-control-standard commit `8a459524530b`:

- Section 6.4: the host applies the session's negotiated `on_decision_failure`
  posture, the default is `proceed`, and every step that proceeds without a
  decision is audited.
- Section 4.1: a session whose handshake never succeeded has no negotiated
  posture. The default applies, and the unguarded start is audited. A setting
  the host read from its own environment is not a negotiated posture.

## Where the cases come from

The four supported cases are the four outage steps of a replay of the outage
bundle posted on ACS issue #92 (bundle sha256 `eec4b2d3...b737`), run at ACS
commit `8a459524530b` with Bun 1.3.11. The replay printed `PASS: 8 scenarios`.
Its records are kept byte for byte under `corpus/source/`: the audit log, its
OTLP export and the negotiated session for each posture, plus the hook decision
and marker change of each step. The executor was the bundle's synthetic host,
and the Guardian was shut down cleanly before the outage steps.

Every other case changes one thing in one of those steps and names the supported
twin it came from. `scripts/acs-outage-build.py` writes the corpus and states
each expected answer by hand.

| Supported step | Refused by one change |
| --- | --- |
| warm session, cached `proceed` | a block, a marker that did not move, a missing audit record, a step taken with the Guardian reachable |
| warm session, cached `deny` | an allow, a marker that moved, an edited audit posture or outcome, no OTLP event, an edited failure class or posture |
| fresh session, default `proceed` | an audit record that says `negotiated`, no `handshake_failed` record, an event that names the Guardian as reporter |
| fresh session, environment says `deny`, default still applies | a host that applies the environment's `deny` |

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors-acs-outage --output acs-outage-result
agent-evidence-vectors-acs-outage --output acs-outage-result --verifier "my-verifier"
```

The command checks every source record and case against `corpus/MANIFEST.json`,
judges every case without reading its expected answer, writes `report.json`, and
exits 1 if any case differs. A verifier under test is called as
`<verifier> <case.json> --json`, prints one JSON object with `decision` and
`reason`, and exits 0 for `supported`, 1 for `contradicted` or
`not_established`, 2 for no verdict.

What a passing run does not establish: that a real coding agent behaves as the
synthetic host did, that the behaviour holds beyond a cleanly refused
connection, or that a deployment is conformant.
