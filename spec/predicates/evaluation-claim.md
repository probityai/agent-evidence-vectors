# Predicate type: Evaluation claim

Type URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/evaluation-claim`

Status: v1. The field set below is fixed for v1. A change that adds a required field,
renames one or changes a type is published as v2 at a new URI, and this page stays.

## Purpose

An evaluation claim says how an implementation fared against a case set: a conformance
run, a benchmark, an agent evaluation. The usual record of such a run carries a count of
passes and failures. A count cannot say which cases were expected, which never ran, who
observed the run, which bytes were tested, or whether an action the run took is still
open. Each of those gaps is read as clean by a consumer that only sees the count.

This record removes the gaps by construction. It is one envelope in which every
coordinate a relying party needs is present, and each coordinate carries either a value
or `not_applicable` under a reason a profile authorises. A coordinate the producer does
not know is carried as `unknown`, `unresolved` or `failed`, and a record carrying one is
refused. Silence is not a state the record can express.

## Envelope

The record is a JSON object. It may be carried bare or as the `predicate` of an in-toto
Statement v1 whose `predicateType` is the type URI above. In a Statement, the single
`subject` names the implementation under test by `sha256` digest, and that digest must
equal the `bytes.implementation` digest in the record. A Statement is signed in a DSSE
envelope like any other in-toto Statement; this page defines the predicate only.

Members are parsed as strict JSON: a duplicate member name, a float, `NaN` or
`Infinity` makes the record malformed. Digests of documents are `sha256` over their
RFC 8785 (JCS) bytes, written `sha256:<64 lowercase hex>`.

```json
{
  "claim_type": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/evaluation-claim",
  "profile": {"id": "conformance/v1", "digest": "sha256:..."},
  "verdict": "pass",
  "coordinates": {
    "applicability": {"state": "value", "case_set": {"name": "...", "digest": "sha256:..."},
                      "applicable": ["c1", "c2"], "excluded": []},
    "population": {"state": "value", "coverage_denominator": 2,
                   "passed": ["c1", "c2"], "failed": [], "not_run": []},
    "vantage": {"state": "value", "observation_vantage": "substrate", "observer": "ci-runner"},
    "bytes": {"state": "value", "implementation": {"name": "...", "digest": "sha256:..."},
              "case_set": {"name": "...", "digest": "sha256:..."},
              "verifier": {"name": "...", "digest": "sha256:..."}},
    "epoch": {"state": "not_applicable", "reason": "no_authority_exercised"},
    "settlement": {"state": "not_applicable", "reason": "no_side_effecting_actions"}
  }
}
```

The record carries exactly `claim_type`, `profile`, `verdict` and `coordinates`.
`verdict` is `pass`, `fail` or `incomplete`. `coordinates` holds only the coordinates
defined below; an undefined one makes the record malformed.

## Coordinates

Every coordinate is an object with a `state`: `value`, `not_applicable`, `unknown`,
`unresolved` or `failed`. A `not_applicable` coordinate carries exactly `state` and
`reason`. A `value` coordinate carries the members below.

| Coordinate | Question it answers | Members when `value` |
| --- | --- | --- |
| `applicability` | Which cases of a pinned case set apply? | `case_set` (reference), `applicable` (ids), `excluded` (each `{id, reason}`) |
| `population` | Over what denominator, and what happened to each case? | `coverage_denominator`, `passed`, `failed`, `not_run` |
| `vantage` | Who observed, and could the observed party shape it? | `observation_vantage` (`substrate` or `artifact`), `observer` |
| `bytes` | Which exact bytes does the claim bind? | `implementation`, `case_set`, `verifier` (references); optional `related` (list of references) |
| `epoch` | Under which authority state did the run act? | `initial` (epoch id), `transitions` (each `{after_action, from, to, kind}`) |
| `settlement` | Is each side-effecting action resolved? | `actions` (each `{id, epoch, outcome, evidence?}`), `outcome` is `committed`, `not_run` or `unresolved` |

`observation_vantage` has the meaning the agent-evidence vocabulary gives it: `substrate`
means every input was obtained where the executed party could neither forge nor suppress
it; `artifact` means the claim rests on artifacts the executed party could have
influenced.

A transition `kind` is one of `revocation`, `suspension`, `consumption`, `root_change`,
`restart`, `re_registration` and `fork`. A transition takes effect after the action it
names, so that action is judged under the epoch the transition ends, and every later
action under the epoch it starts.

A reference is an object with any of `name`, `alias`, `uri` and `digest`. Only `digest`
identifies bytes. A name or alias locates bytes and never replaces a digest; a digest
of a superseded revision still identifies that revision.

## Profiles and the acceptance rule

A **profile** (`aev-claim-profile/v1`) states, for one kind of evaluation, which
coordinates may be `not_applicable` and under which reason tokens, which references must
be bound by digest (`immutable_references`), and which reasons may exclude an optional
case (`exclusion_reasons`). A profile lists every coordinate. A profile that authorises
an absence (`unknown`, `unresolved`, `failed`, `not_run`, `not_captured`, `unavailable`,
`missing`, `skipped`, `timeout`) as a reason for non-applicability is unusable.

An **acceptance rule** (`aev-claim-acceptance-rule/v1`) is the relying party's document.
It pins the profile by id and digest, lists the case-set digests it accepts and the
vantages it accepts. The rule is never taken from the record. A record names its profile
so that a mismatch is visible; the rule's profile is the one the record is judged under.
A producer therefore cannot satisfy a rule that requires the execution profile by
naming the conformance profile.

The published profiles are `conformance/v1` (epoch and settlement may be not applicable
under `no_authority_exercised` and `no_side_effecting_actions`) and `execution/v1` (no
coordinate may be not applicable, and settlement evidence is bound by digest). They ship
in the package under `claim_record/corpus/profiles/`.

Profiles and case sets are resolved by digest from bytes the verifier is given, offline.
The verifier re-hashes what it resolves, so a store keyed under the wrong digest resolves
nothing.

## Verdict rules

- `pass`: the denominator is above zero, nothing failed and nothing is not run.
- `fail`: at least one case failed.
- `incomplete`: nothing failed, and at least one case is not run or no case applied.

Applicable and excluded together are the case set's ids, each once; only an `optional`
case may be excluded, and only under a reason the profile authorises. Passed, failed and
not run together are the applicable ids, each once, and the denominator counts them.

## Refusal reasons

A verifier reports every reason it finds. A record is admitted when it finds none.

| Code | Meaning |
| --- | --- |
| `MALFORMED_RECORD` | The record or Statement is not the shape above. |
| `PROFILE_UNRESOLVED` | The pinned profile's bytes were not supplied, do not hash to the pin, or the profile is unusable. Nothing else is judged. |
| `PROFILE_MISMATCH` | The record names a profile other than the one the rule pins. |
| `MISSING_COORDINATE` | A coordinate is absent. |
| `UNRESOLVED_COORDINATE` | A coordinate is `unknown`, `unresolved` or `failed`. |
| `UNAUTHORISED_NOT_APPLICABLE` | `not_applicable` where the pinned profile allows no such reason, or epoch not applicable while actions were taken. |
| `INVALID_REFERENTIAL_PIN` | A reference the profile requires to be immutable is bound by a name, alias or URI only, or by a malformed digest. References outside the profile's list are not held to this. |
| `CASE_SET_NOT_ACCEPTED` | The rule does not accept the case set the record binds. |
| `CASE_SET_UNRESOLVED` | The rule accepts the case set, and its bytes were not supplied. |
| `APPLICABILITY_MISMATCH` | Applicable and excluded are not the case set exactly, or a required case or an unlisted reason is excluded. |
| `POPULATION_MISMATCH` | A case is missing from the results, listed twice or not in the case set, or the denominator is wrong. |
| `ABSENCE_READ_AS_CLEAN` | The verdict is `pass` while a case is not run, or while nothing applied. |
| `VERDICT_CONTRADICTED` | The verdict is `pass` with a failure, `fail` with none, or `incomplete` with nothing missing or with a failure. |
| `VANTAGE_NOT_ACCEPTED` | The rule does not accept the record's vantage. |
| `BYTES_MISMATCH` | The bytes coordinate binds another case set than applicability resolved, or another implementation than the Statement subject. |
| `STALE_EPOCH` | An action acts under an epoch a transition already ended. |
| `UNSETTLED_OUTCOME` | An action is unresolved, or says committed or not run with no evidence. |
| `UNSETTLED_ACROSS_EPOCH` | An unresolved action is followed by an authority transition. |

The codes are identifiers. A consumer may match on them, and they do not change within
v1.

## Relation to the in-toto Test Result predicate

The in-toto Test Result predicate (`https://in-toto.io/attestation/test-result/v0.1`)
names its first use case as verifying that all tests were in fact run, and carries
`passedTests`, `warnedTests` and `failedTests`. It carries no expected set and no list of
tests that did not run, so a record that omits a test reads as clean. The population and
applicability coordinates are the two members such a record needs: an expected case set
bound by digest, and a `not_run` list, with the verdict rules above. The reference
verifier here judges both, with adversarial cases for an empty suite, a missing case, a
duplicate and an unexpected case.

## Verify, emit and replay

```sh
pip install agent-evidence-vectors
agent-evidence-vectors claim verify --record claim.json --rule rule.json --case-set cases.json
agent-evidence-vectors claim emit --case-set cases.json --results results.json \
  --implementation-name impl --implementation-digest sha256:<hex> \
  --verifier-name verifier --verifier-digest sha256:<hex> \
  --observation-vantage substrate --observer ci --statement --output claim.json
agent-evidence-vectors claim run --output claim-record-result
```

`verify` exits 0 when the record is admitted with verdict `pass`, 3 when it is admitted
with `fail` or `incomplete`, 1 when it is refused and 2 on unusable input. `emit` records
every case the results do not name as not run. The conformance corpus and its cases are
described in [the corpus README](../../packaging/agent_evidence_vectors/claim_record/README.md).
