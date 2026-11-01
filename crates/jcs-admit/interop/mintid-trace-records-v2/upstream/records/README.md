# Revocation trace records

Records written by `test-harness/trace/revocation_trace.py`, kept so that every
revocation timing quoted in the documentation has a record behind it. Each run
is three files: the raw events (`.jsonl`, one event per line), the summary the
tool wrote from them (`.md`) and the machine-readable manifest
(`.manifest.json`, below). The JSONL and the summary are the tool's output as
written, unedited.

| Record | Target | When (UTC) | Source revision | Who ran it | Paths |
|---|---|---|---|---|---|
| `revocation-trace-testnet-20261005T022948Z` | the public testnet, chain `mintid-testnet-2` | 2026-10-05 02:29–02:36 | services `2bd3b23c761c` (MINT-453..459: signed challenges, holder signature check, decision records with `condition` and `vocabulary`, ADR-0024); the trace ran from `4a01bf1` | the operator, with the testnet's operator credentials | issuer, kill switch, cascade, emergency; decision-log lines read (the Rule section derived from them) |
| `revocation-trace-testnet-20261004T153434Z` | the public testnet, chain `mintid-testnet-2` | 2026-10-04 15:34–15:40 | `08ca3d829665` (the image tag of every testnet service; the trace ran from the same revision) | the operator, with the testnet's operator credentials | issuer, kill switch, cascade, emergency |
| `revocation-trace-local-20261004T122943Z` | the local stack, chain `mintid-anchor-local`, production parameters | 2026-10-04 12:29–12:33 | `3210806` | the operator | issuer, kill switch, cascade, emergency |

The two records of 2026-10-04 were written by the tool as it stood before
ADR-0024 (MINT-459) and the holder's challenge-signature check (MINT-458);
the record of 2026-10-05 was written after both. All three were written
before the attribution of MINT-469 (the summary's "Attribution" section and
the follow-up of a refused agent's witness refresh; see "Reading them").

## The manifest

`<record>.manifest.json` (schema `mintid-trace-manifest/2`, written by
`test-harness/trace/manifest.py`) is built from the JSONL alone; rebuild it
with `uv run python test-harness/trace/manifest.py <record>.jsonl` and
compare. It holds:

- `source`: the commit the trace ran from, the `public-v…` release tags on
  it, whether tracked files were changed, and the services revision when
  the operator states it (`MINTID_SERVICES_REVISION`);
- `deployment`: target, chain id, issuer and verifier ids, endpoints, the
  verifier's build pins (engine, SDK, specification revision, state-vector
  version and digest, conformance suite), the parameters (A, H, K, G,
  cascade spread), the maximum root age, heartbeat and height lag; and,
  in records written since MINT-466, `services`: per service (verifier,
  issuer) the `source_revision` and `release` its build-info served
  (`basis: "build-info"`), or the operator's stated revision when it served
  none (`basis: "stated"`). The issuer's signing-key id is in `build`, in its
  own field, never as a revision;
- `policy`: the claim and issuer policy the trace asked for and the SHA-256
  of their canonical JSON (stable across challenges; the binding digest of a
  proof covers the whole request and differs per decision);
- `paths`: per path (per agent on the cascade), t0 and its definition, the
  bound, the last accepted and the first refused decision (time, seconds
  after t0, session id, reason code, node head, and the decision-log line's
  deciding condition and root epoch, height and age), the root at the
  denial, the root carrying the revocation, when the witness refresh was
  refused, and on the issuer path the never-revoked control;
- `paths[*].attribution` (schema `/2`, MINT-469): what tells the revocation
  apart from a root rollover. `revoked`: the agent and its witness refresh
  (`observation`: `refused`, `not_refused_within_budget` or `not_recorded`;
  the `outcome`, such as `credential_revoked`; time and seconds after t0).
  `control` (issuer path only, else `null`): the never-revoked sibling's
  first refusal (with its decision-log condition and root), its own refresh,
  and the decision after the refresh;
- `decisions`: every decision of the run with its reason code, condition
  and root fields;
- `files`: the SHA-256 of the JSONL and the summary.

It carries nothing the events do not: ids, roots, heights, codes, digests;
no presentation content, credential material or KYC data. **The three
records below predate the manifest**: their manifests are derived from
their JSONL (`"derived": true`), fields those runs did not record are
`null` (source, build pins, policy), and the revisions in the table above
are kept under `"stated"`, as the operator states them, never as recorded
values. A record written now has `"derived": false` and its own `source`,
`build` and `policy`.

The derived manifests were regenerated on 2026-10-06 for schema `/2`
(MINT-469), from the same JSONL and with the same `"stated"` values; they
stay `"derived": true`. The JSONL and the summaries were not touched. In
these records a refresh the trace did not record is `not_recorded`: the
control's refresh (those runs logged only refused refreshes), and the
refresh of a cascade agent after its first refusal (see "Reading them").

SHA-256 of the files as written:

| File | SHA-256 |
|---|---|
| `revocation-trace-testnet-20261005T022948Z.jsonl` | `95b8c1dd2493d779d2d4b6ec98f22d1abee5c17fca4c2ba3430c5e9f592b7a63` |
| `revocation-trace-testnet-20261005T022948Z.md` | `f9abc4e9dd0292d730458269ddfdf8546f2694117154d1d244104459d85a6c7e` |
| `revocation-trace-testnet-20261004T153434Z.jsonl` | `66e1a9016db956fafc31c91fa00e27bd55762ccabcefa4fb0e3a8656584ee90b` |
| `revocation-trace-testnet-20261004T153434Z.md` | `41e1318b426a0b6e699490412c32775751755e16773eceaea39bc7fc294ec5c8` |
| `revocation-trace-local-20261004T122943Z.jsonl` | `1dbe4db8f996fa4784d6f6a8ce8d0fa58d9c4c9a136f60b9b5914e995e03daff` |
| `revocation-trace-local-20261004T122943Z.md` | `26d6405a6ddf729485fe37b3ff5d6100b23666770dc879bba007cf0fe5f6ceb8` |
| `revocation-trace-testnet-20261005T022948Z.manifest.json` (derived) | `b9207de62f3ff0dd0deeedef9082d34983fc2bc3a215cd91e0feabd5bab544dd` |
| `revocation-trace-testnet-20261004T153434Z.manifest.json` (derived) | `5724af97dbb3f410a23151263bbdefee75d7e6bfaef3a8e0c113cb2fc40a5d96` |
| `revocation-trace-local-20261004T122943Z.manifest.json` (derived) | `bbac3adaaca4326940a8a45b1b2f6376573ac6461d39a96ba3d72a4bc74b6d4e` |

## Reading them

- **The bound is the guarantee; these are observations.** Each record is one
  verifier in one run. The first refusals move from run to run; the bounds
  (185 s, 245 s, 395 s, one block) are what every conforming verifier keeps.
- **What a first refusal measures.** This verifier checks every agent proof
  against the issuer definition that the newest provable root anchors, and the
  agent accumulator changes at every root. A proof over an older witness
  therefore stops verifying as soon as the next root can be proven, whether or
  not the agent was revoked. Every record holds a control on the issuer path:
  a sibling agent that was never revoked, forcing proofs over the witness it
  held at the trigger, is refused at a root rollover just as the revoked agent
  is (testnet, 4 October: last accepted +5.5 s, refused +21.9 s, the revoked
  agent refused at +10.5 s in between; testnet, 5 October: refused +7.6 s, the
  revoked agent +14.2 s, both decision-log lines naming the root of epoch
  1309; local: +30.5 s against +31.3 s), and is accepted again once it
  refreshes (+34.6 s, +41.8 s, +34.5 s). The first refusal is when the next
  root became provable. The verifier's record shows the root a decision
  rested on; it does not show whether the agent was revoked.
- **What singles out the revoked agent.** Its witness refresh fails with
  `CredentialRevoked` (`kind: holder_refresh`, `outcome: credential_revoked`):
  a revoked agent cannot obtain a newer witness, a live one can. The manifests
  carry it per path under `paths[*].attribution`. Every record shows it on the
  issuer, kill-switch and emergency paths. On the cascade path the records
  show it for one agent of two at most: the testnet records for
  `cascade_agent_1` (4 October, +45.8 s after the trigger root) and
  `cascade_agent_2` (5 October, +61.0 s), the local record for neither. The
  cause is the trace, not the issuer: the tool that wrote these records
  stopped asking for an agent's witness at that agent's first refusal. A
  cascaded agent leaves at its own root, up to seven heartbeats after the
  trigger root, and an agent refused earlier at a root rollover was never
  asked again, so these records do not say when its refresh would have
  failed. In both testnet records the agent shown is the one refused
  second. The tool
  now keeps asking until the refresh is refused, or records
  `not_refused_within_budget` (MINT-469); in these manifests the missing
  refreshes are `not_recorded`.
- **The "Revision" row** of a summary is what the issuer's build-info serves as
  its identifier (revision, else version, else the start of its signing key
  id), not a source commit; the source revision is in the table above.
- **The "Rule" paragraph** of these two summaries is fixed text: they were
  written before ADR-0024, by a tool version that did not derive it. For
  these runs the evidence for the rule is the decision-log lines (root fields
  `null` on a refusal decided at proof verification, as records then were)
  and the control. A run recorded now derives the rule from each refusal's
  `condition` and evidence.
- **The emergency path** needs the issuer's operator side. On the testnet it
  was run by the operator; a third party can run it only on the local stack.
  Its refusal can come from either of two rules, proof verification against
  the newest provable root or the emergency clause of the root check,
  depending on whether the verifier's anchoring read has already moved past
  the presented root; both refuse within one block. In the testnet record the
  first refusal came at proof verification (`null` root fields), at the head
  after the emergency root's block (root in block 308, refused at head 309).
