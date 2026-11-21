# Predicate type: Credential Reachability

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/credential-reachability

Version: 1.0.0

Predicate Name: Credential Reachability

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer. The
> URI will not move once a signed statement carries it. The conformance corpus in
> this repository, `corpora/vectors-credential-reachability/`, carries it in
> signed statements under published test keys.

## Purpose

An AI agent acts with whatever credentials its environment lets it reach. A
credential broker can keep a named secret out of the agent's hands, but the agent
may still find an SSH agent socket, a cloud metadata endpoint, a token in an
environment variable, a cookie store in a mounted home directory or a cluster
service-account token. Any of those lets the agent act under an identity that
does not name the agent, so a downstream service cannot tell the agent from the
person or workload whose credential it used.

This predicate records the result of a probe that ran inside the agent's
environment, with the agent's own identity and view, and tried every ambient
credential class in a closed list. Each class gets one of three verdicts:
`reachable`, `not_reachable` or `could_not_test`. A probe that did not run is never
`not_reachable`. The record carries no credential value: for a credential it found
it carries a locator and a 12-hex-digit prefix of the SHA-256 of the credential's
bytes, enough to tell two findings apart and to match a known key fingerprint,
and too short to work as the credential.

The statement is signed by a key outside the agent's reach (the host or control
plane that runs the environment), bound to the environment's contract by digest,
to a verifier's challenge and to an audience. A verifier recomputes every class
verdict and the overall result from the attempts the record carries and refuses a
record whose declared verdicts are better than its attempts support.

## Use cases

- A buyer or auditor who is told "the agent cannot use any credential that does
  not name it" asks the operator of the agent's environment for a fresh record
  under the buyer's own challenge, and checks it with the buyer's own copy of the
  operator's public key.
- An operator runs the same probe in a plain container with a developer's home
  directory mounted, as a positive control, and gets `exposed`: the probe finds
  what is there.
- A continuous-integration job refuses to start an agent run whose environment's
  latest record is not `contained`.

## Related public guidance

The classes follow credential-access techniques that public guidance already
names. The mapping is informative; the closed list below is normative.

| Class | Related guidance |
| --- | --- |
| `ssh-agent` | MITRE ATT&CK T1563.001 (SSH Hijacking) |
| `ssh-key-file` | MITRE ATT&CK T1552.004 (Private Keys) |
| `cloud-metadata` | MITRE ATT&CK T1552.005 (Cloud Instance Metadata API) |
| `cloud-config-file` | MITRE ATT&CK T1552.001 (Credentials In Files) |
| `registry-config-file` | MITRE ATT&CK T1552.001 (Credentials In Files) |
| `browser-cookie-store` | MITRE ATT&CK T1539 (Steal Web Session Cookie), T1555.003 (Credentials from Web Browsers) |
| `environment-token` | CWE-526 (Cleartext Storage of Sensitive Information in an Environment Variable) |
| `cluster-service-account` | MITRE ATT&CK T1528 (Steal Application Access Token), T1552.007 (Container API) |
| `git-credential` | MITRE ATT&CK T1552.001 (Credentials In Files) |
| `host-keyring` | MITRE ATT&CK T1555 (Credentials from Password Stores) |

## Model

The producer is the party that runs the agent's environment and holds a signing
key the agent cannot reach. The probe runs inside the environment, as the agent's
user, and returns its attempts to the producer, which binds them and signs.

The **subject** is the environment: exactly one member whose `name` identifies the
environment and whose `digest` holds only `sha256`, the digest of the environment's
contract (the configuration that defines what the environment can reach, as the
producer published it). A verifier pins both, so a record for one environment
cannot be presented for another.

The **predicate** is a closed object with exactly these members:

- `classSet`: `credential-reachability/v1`, the name of the closed class list
  below. Any other value is refused, so a record cannot claim coverage of a
  shorter, older or private list.
- `audience`: printable ASCII text, 1 to 200 bytes: the verifier the record is for.
- `challenge`: 64 lowercase hex characters, issued by the verifier before the probe
  ran.
- `probedAt`: an RFC 3339 UTC time to whole seconds (`YYYY-MM-DDTHH:MM:SSZ`).
- `vantage`: `agent-process`. The probe ran in the agent's environment with the
  agent's own user and view. A probe run from outside, or with more privilege,
  does not measure what the agent can reach.
- `probe`: exactly `name` and `version` (printable ASCII text, 1 to 200 bytes) and
  `digest` (exactly `sha256`, 64 lowercase hex): the program that ran.
- `placeholders`: a list of objects, each exactly `prefix` (printable ASCII, 1 to
  200 bytes). Each is a prefix of a stand-in value a credential broker hands the
  agent in place of a secret it holds back. May be empty.
- `markedCredentials`: a list of objects, each exactly `id` (printable ASCII, 1 to
  200 bytes) and `digestPrefix` (12 lowercase hex): credentials the environment
  issues to the agent that carry an agent marker (they name the agent). May be
  empty.
- `classes`: a list of class results, one per class of the class set, each exactly
  `class`, `verdict` and `attempts`:
  - `class`: one term of the class list.
  - `verdict`: `reachable`, `not_reachable` or `could_not_test`.
  - `attempts`: a non-empty list of attempts, each with `locator` (printable ASCII,
    1 to 512 bytes: a path, socket, URL, environment variable name or command the
    probe tried) and `outcome`, and only these optional members: `digestPrefix` (12
    lowercase hex) and `detail` (printable ASCII, at most 200 bytes).
- `result`: `contained`, `exposed` or `incomplete`.

### The class list `credential-reachability/v1`

| Class | What the probe tries, read only |
| --- | --- |
| `ssh-agent` | The socket named by `SSH_AUTH_SOCK` and agent sockets in the temporary directory; asks each for its identity list |
| `ssh-key-file` | Private key files under every home directory the agent can read |
| `cloud-metadata` | The instance metadata endpoints of the major clouds and the container credential endpoint named in the environment |
| `cloud-config-file` | Cloud command-line credential and configuration files |
| `registry-config-file` | Package and container registry credential files |
| `browser-cookie-store` | Browser cookie and login databases |
| `environment-token` | Environment variables of the agent's process, and of every process whose environment it can read, whose name or value has the shape of a credential |
| `cluster-service-account` | Mounted cluster service-account and projected tokens, and cluster configuration files |
| `git-credential` | Configured git credential helpers, stored git credentials, `.netrc` and forge command-line host files |
| `host-keyring` | Desktop keyring, secret-service, password-manager and agent sockets of the host |

### Attempt outcomes

| Outcome | Meaning | `digestPrefix` |
| --- | --- | --- |
| `found` | A credential that carries no agent marker was read or answered | required |
| `marked` | A credential was found and it is one of `markedCredentials` | required, equal to that entry's |
| `placeholder` | A value was found and it is a broker stand-in (it starts with a declared `placeholders` prefix) | absent |
| `absent` | The locator does not exist or did not answer | absent |
| `denied` | The locator exists and the agent's access was refused | absent |
| `error` | The attempt ran and failed in a way that leaves the answer unknown | absent |
| `not_run` | The attempt did not run | absent |

### Derivations

A verifier recomputes, and never copies:

- A class verdict is `reachable` when any attempt is `found`; otherwise
  `could_not_test` when any attempt is `error` or `not_run`; otherwise
  `not_reachable`.
- The result is `exposed` when any class is `reachable`; otherwise `incomplete`
  when any class is `could_not_test`; otherwise `contained`.

Only `contained` supports the claim that no credential without an agent marker is
reachable from the agent's environment, and only for the classes of the class set,
at `probedAt`, from the agent's vantage.

## Carriage

A DSSE envelope with payload type `application/vnd.in-toto+json` whose payload is
an in-toto Statement v1 in strict JSON (no repeated member). Signatures are Ed25519
over the DSSE pre-authentication encoding. A `keyid` is the lowercase hex SHA-256 of
the raw 32-byte public key.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "environment/run-0042", "digest": { "sha256": "<64-hex of the environment contract>" } }
  ],
  "predicateType": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/credential-reachability",
  "predicate": {
    "classSet": "credential-reachability/v1",
    "audience": "https://auditor.example.org",
    "challenge": "<64-hex issued by the verifier>",
    "probedAt": "2026-11-21T18:00:00Z",
    "vantage": "agent-process",
    "probe": { "name": "credential-probe", "version": "1.0.0", "digest": { "sha256": "<64-hex>" } },
    "placeholders": [ { "prefix": "BROKER_PLACEHOLDER_" } ],
    "markedCredentials": [],
    "classes": [
      { "class": "ssh-agent", "verdict": "not_reachable",
        "attempts": [ { "locator": "env:SSH_AUTH_SOCK", "outcome": "absent" } ] },
      { "class": "environment-token", "verdict": "not_reachable",
        "attempts": [ { "locator": "env:API_TOKEN", "outcome": "placeholder" } ] }
    ],
    "result": "contained"
  }
}
```

The example shows two of the ten classes; a conforming record carries all ten.

## Rules

A verifier holds a policy: the pinned payload type, the trusted signer keys, the
keys the agent holds, the environment name and contract digest, the audience, the
challenge it issued, the time it judges at, the oldest result it accepts in
seconds, and optionally the probe digests it accepts. It applies these in order and
reports the first that fails, as a decision and a reason.

| # | Rule | Decision | Reason |
| --- | --- | --- | --- |
| 1 | The envelope is DSSE v1 JSON with a payload type, a base64 payload and at least one signature, each with a `keyid` and a base64 `sig` | no verdict | `malformed_envelope` |
| 2 | The payload type is the pinned one | not established | `unsupported_payload_type` |
| 3 | No signature verifies under a key the agent holds, whatever `keyid` it names | contradicted | `signed_by_agent_key` |
| 4 | A signature whose `keyid` names a trusted signer verifies under that signer's key; a signature naming any other key is ignored | contradicted | `signature_invalid` when one names a trusted key and none verifies, `untrusted_key` when none names one |
| 5 | The payload is a strict JSON object | not established | `payload_not_json_object` |
| 6 | `_type` is `https://in-toto.io/Statement/v1` | not established | `unsupported_statement_type` |
| 7 | `predicateType` is this document's Type URI | not established | `unsupported_predicate` |
| 8 | `subject` has exactly one member, exactly `name` (text) and `digest` holding only a lowercase hex `sha256` | not established | `subject_malformed` |
| 9 | The subject's name and digest are the pinned environment's | contradicted | `environment_mismatch` |
| 10 | The predicate is an object | not established | `predicate_field_invalid:predicate` |
| 11 | The predicate has exactly the members of its list | not established | `predicate_field_invalid:members` |
| 12 | `classSet` is `credential-reachability/v1` | not established | `class_set_unsupported` |
| 13 | Each member is well formed, in the order `audience`, `challenge`, `probedAt`, `vantage` (a text), `probe`, `placeholders`, `markedCredentials`, `classes` (a list of objects, each exactly `class`, `verdict` and `attempts`, with a known class term, a known verdict and a non-empty list of attempts, each an object with a well-formed `locator`, a known `outcome`, and a well-formed `detail` when present), `result` | not established | `predicate_field_invalid:<member>` |
| 14 | No attempt has a member outside `locator`, `outcome`, `digestPrefix` and `detail`; `digestPrefix` is present exactly when the outcome is `found` or `marked`, and is then 12 lowercase hex characters. A record that can hold more than a short prefix will eventually be handed a secret | contradicted | `attempt_fields` |
| 15 | `vantage` is `agent-process` | not established | `vantage_not_agent` |
| 16 | `audience` is the pinned audience | contradicted | `audience_mismatch` |
| 17 | `challenge` is the challenge the verifier issued | contradicted | `challenge_mismatch` |
| 18 | `probedAt` is not after the time the verifier judges at | contradicted | `probed_in_future` |
| 19 | `probedAt` is no older than the oldest result the verifier accepts | not established | `result_stale` |
| 20 | When the policy pins probe digests, the probe's digest is one of them | not established | `probe_not_pinned` |
| 21 | No class appears twice | contradicted | `class_duplicate:<class>` |
| 22 | Every class of the class set appears | contradicted | `class_missing:<class>`, the first missing class in list order |
| 23 | Every `marked` attempt's prefix is a declared marked credential's | contradicted | `marked_undeclared` |
| 24 | A `placeholder` attempt appears only when `placeholders` is not empty | contradicted | `placeholder_undeclared` |
| 25 | Each class's verdict is the derived one, checked in list order | contradicted | `reachable_reported_clean:<class>` when declared `not_reachable` and derived `reachable`; `untested_reported_clean:<class>` when declared `not_reachable` and derived `could_not_test`; `class_verdict_mismatch:<class>` otherwise |
| 26 | The result is the derived one | contradicted | `result_overstates` when the declared result is better than the derived one (`contained` is better than `incomplete`, which is better than `exposed`), `result_mismatch` otherwise |

A record that passes every rule is supported, with the reason `contained_verified`,
`exposed_verified` or `incomplete_verified` after its result. A supported `exposed`
record is a verified finding that a credential without an agent marker is
reachable.

A policy that lists one key both as a trusted signer and as an agent key is the
policy's defect, and the verifier reaches no verdict on it.

## What this record does not establish

- That the probe found every credential of a class. It tried the locators it
  lists; a credential at a locator the probe does not know about is not covered.
- That the probe's report was not altered inside the environment. The producer
  signs what the probe returned, from outside the agent's reach; a consumer that
  needs more pins the probe digest and the environment contract.
- Anything after `probedAt`.
