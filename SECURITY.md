# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this
repository. It is enabled. Do not open a public issue for a vulnerability that has not yet been
fixed — the report goes to the maintainer only, in a private draft advisory, until a fix is ready.

- **Acknowledgement: within 24 hours.**
- **Triage verdict (confirmed / not reproducible / out of scope, with reasoning): within 72
  hours.**
- If confirmed, a fix timeline is given at triage and updated if it changes. There is no fixed SLA
  on the fix itself — severity and complexity vary too much for one number to mean anything — but
  the report never goes silent after triage.

## In scope

| Area | Example |
|---|---|
| The reference verifier (`aee-verify`, `aee/`, `aeetest/`) accepting a statement it should reject | A malformed or adversarial `predicate` that passes verification when the spec requires a `fail` |
| The reference verifier rejecting a statement it should accept | A spec-conformant statement the verifier wrongly reports as invalid |
| The conformance vector corpus itself being wrong | A vector labelled `accept` that should be `reject`, or vice versa, per the pinned spec text it cites |
| The vendoring/pin-check machinery (`scripts/specpins.py`, `spec-drift-gate.py`, `spec-anchor-gate.py`) silently passing a stale or drifted citation | A citation gate that resolves to the wrong prose without failing |
| Memory-safety, injection, or supply-chain issues in this repository's own code or its declared dependencies | An unsafe deserialization path, a dependency with a known CVE this repo has not updated past |
| The CI gates (`ci.yml` and friends) being bypassable to merge a change that should have failed them | A gate that reports green on a red input |

## Out of scope

| Area | Why |
|---|---|
| The `adversarial-execution-evidence` predicate specification itself | This repository vendors and implements the spec; it does not author it. Report spec-level issues to the upstream `in-toto/attestation` thread this predicate is proposed in (PR #570). |
| A third party's own implementation of the predicate | Not this repository's code. If their implementation disagrees with this reference verifier, that is a conformance finding for their project, not a vulnerability in this one — file it against them, or open an issue here if you believe OUR reference verifier is what's wrong. |
| The underlying cryptographic primitives (Ed25519, SHA-256, RFC 8785 JCS) | This repository consumes these; it does not implement or claim to have improved them. Report a primitive-level break to the relevant standards body or library maintainer. |
| Anything about a private, unpublished repository | This repository is fully independent and contains no reference to, or code from, any private repository. A report describing behavior of software not published here is not about this codebase. |
| Denial of service via resource exhaustion on a machine you control, running this code against inputs you supply | This is a local conformance/verification toolkit, not a hosted service. There is no shared deployment to exhaust. |

## Fixed issues in published releases

### A named verifier could be replaced by the reference rail (fixed in 0.12.1)

**Affected:** the `agent-evidence-vectors` command and `packaging/run_vectors.py` at every tag
from v0.6.0 to v0.12.0, including PyPI 0.11.1 and 0.12.0. The composite action at v0.11.0,
v0.11.1 and v0.12.0, the three tags that ship `action.yml`.

**What happened.** The harness scanned the first token of `--verifier` (or
`AEE_EXTERNAL_VERIFIER`) for the predicate type URI. When the scan did not find it, the harness
judged the corpus with its own reference rail, printed that rail's totals, and exited 0. That
happened for a verifier that rejects every vector, for a file without the execute bit, for a path
that does not exist, and for every command resolved through `PATH`, because the scan tested the
bare name as a file path. The action failed a job only on the exit status, so each of those jobs
passed. At v0.12.0 the `vectors-w3c-report` and `vectors-observed-effect` corpora also ignored
`--verifier` entirely.

**How to tell whether a run was affected.** Open the report the run wrote. A report whose `rail`
field reads `reference` was produced by this package's own rail, whatever `--verifier` named, and
says nothing about the verifier under test. The console output of an affected run begins with
`rail: reference`.

**The fix.** From 0.12.1 a named verifier always runs. When it cannot be started the harness
exits 2 and says the verifier did NOT run. The report records `verifier.vectorsExecuted`, and a
count below the vector count fails the run. The action fails the job unless the report shows the
named verifier ran on every vector, which also covers a `tag:` input that installs an older
harness. Pin the action to `@v0.12.1` or later and re-run any conformance claim made with an
affected release.

### aee-verify reported success for statements it had not admitted (fixed after 0.18.2)

**Affected:** `aee-verify` at every tag up to and including v0.18.2.

**What happened.** Handed a valid statement and no consumer policy, `aee-verify`
exited 0 and printed `"result":"pass"` while every substrate row derived
`unattested` and no anchor had been compared. A pipeline gating on the exit
status reported a pass that no observer stood behind. Handed the observation key
and nothing else, it admitted the statement, because an unsupplied anchor
compared nothing. The same held for a statement whose `result` was `fail`, and for
one whose rows were all `basis: artifact`, whose tier half is satisfied
vacuously. None of these is a validity defect: the statements are valid, and the
verifier answered a question about the bytes where its exit status was read as an
answer about admission.

**How to tell whether a run was affected.** A run that invoked `aee-verify` on a
statement without `-keys` and both `-expected-*` digests, and read exit 0 as
assurance, was affected. So was any run that treated exit 0 as "the subject
passed" without checking `result` itself.

**The fix.** The exit status now answers one question, admission, and a policy
that pins nothing admits nothing and names every missing pin. `-validity-only`
asks the narrower question by name and says so in its report.
`vectors-admission/` holds the cases, and both rails here pass it.

### A renamed, redated subject was admitted (fixed after 0.18.2)

**Affected:** `aee-verify` at every tag up to and including v0.18.2.

**What happened.** The observer's records bind the run to seven digests, the
subject's sha256 among them, and not to the subject's name or the statement's
`issuedAt`. A party holding only the envelope key can rename the subject and move
the date after the run, re-sign the envelope, and every record still verifies.
`aee-verify` had no way to compare the subject against the artifact a consumer was
admitting and did not report which members no observer binds, so the renamed
statement was admitted and read as evidence about the artifact its name claimed.

**The fix.** `-expected-subject-digest` (or `expectedSubjectDigest` in the policy
document) pins the artifact, compared against `subject[0].digest.sha256` only, and
an unpinned subject is not admitted unless declined by name. The report lists
the producer-asserted members and the observer-signed `armedAt` instants, and
`-max-issuance-lag` bounds `issuedAt` against those instants. The name is not
folded into the run binding, and `spec/v1/statement.md` says why.

### A statement signed under a published test key was admitted (fixed after 0.18.2)

**Affected:** `aee-verify` at every tag up to and including v0.18.2.

**What happened.** The corpus signs its records with keys whose seeds are
published, so every vector can be regenerated byte for byte. A record that
verifies under such a key says only that someone ran the recipe. A consumer
policy that pinned one of those keys as its observation key admitted the
statement, and the public demonstration did exactly that.

**How to tell whether a run was affected.** A run whose key policy pinned a key
derived from a seed published in this repository, and read exit 0 as assurance.

**The fix.** Admission refuses a pinned observation key derived from a published
seed, as `observation-key-published`, unless the consumer declines that refusal
by name with `allowPublishedTestKeys` or `-allow-published-test-keys`. The tier
column is unchanged, because the tier is about signatures. Both admission rails
implement it and `vectors-admission/` carries the member refused for it.

### A perfect verifier failed corpora in the harness (fixed after 0.18.2)

**Affected:** the `agent-evidence-vectors` harness and the composite action at
every tag up to and including v0.18.2.

**What happened.** A verifier answering every member exactly as its manifest
declares drew exit 1 on `vectors-ai-agent-action` from four suite-level refusals:
the reference suite's closure rules required the `indeterminate` kind and refused
every directory other than `keys/`. The action fails a job on any refusal, so an
implementer of that predicate who pointed the action at its corpus got
`result: fail` whatever the verifier did. On `vectors-scitt-cose` a verifier
taking a reading the corpus declares for an indeterminate member failed, and
seven corpora whose expectations the exit-status contract cannot carry were
scored anyway, as failures.

**The fix.** Closure rules are properties of the suite, a declared reading's
verdict is admitted, and a corpus the contract cannot carry is refused by name
with exit 2. `scripts/oracle-every-corpus-test.py` runs a perfect verifier over
every corpus in CI.

## What a confirmed report gets you

Public credit in the fix's commit message and, if you want it, in `CITATION.cff`'s acknowledgements
— never without asking first. No bug bounty; this is not a funded program.

## The honest limit of what this suite proves

A conformance vector passing means the reference verifier's behavior on that one input matches the
pinned spec citation it carries — nothing more. It is not an attestation that any *other*
implementation of the predicate is correct, not an audit of any producer's signing key management,
and not a claim that the vectors in this corpus are exhaustive over every input an adversary could
construct (run `find vectors -name '*.json' | wc -l` for the current count rather than trusting a
number written here, which goes stale the moment a vector is added). New vectors are added when a
gap is found; the corpus is a floor, not a ceiling. See `DISPOSITIONS.md` for cases where a specific
objection to coverage was raised and how it was resolved.
