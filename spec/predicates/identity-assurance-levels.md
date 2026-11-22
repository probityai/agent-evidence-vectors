# Agent identity assurance levels (identity-assurance-levels/v1)

Contract identifier:
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels`

An agent identity claim is worth what its weakest unproven link is worth. This page names
seven levels, 0 to 6, and gives each one a single deciding test. A verifier prints the highest
level a record set proves and the first test above it that fails. The levels are built from
published standards text only (RFC 8693, RFC 9449, RFC 7800, RFC 7638, RFC 8705) and from the
corpora in this repository, so a verifier from any vendor can print the same number from the
same files.

Identity level N and record grade I, W+, W or S are different scales; see [the record grades page](record-grades.md). <!-- crosslink -->

A level says how far an agent's identity is proven. Customer-held identity and authority
roots change the inputs to a level and never change what a record is marked with elsewhere.

## The levels

| Level | Name | Sentence | Deciding test |
|---|---|---|---|
| 0 | Self-declared | The set names a subject, and nothing else about that name is checked. | T0: the set names a subject. |
| 1 | Issuer-signed marker | An issuer the verifier trusts signed a statement binding the agent to a principal or a key. | T1: a verified binding finding exists for that subject. |
| 2 | Marker survives | The marker is still in the message after every derivation, token exchange and hop. | T2: a marker-survival finding accepts for that subject. |
| 3 | Holder-bound | The credential confirms a key, and the presenter proved it holds that key on each use. | T3: a holder-bound finding accepts for that subject. |
| 4 | Narrowing chain | Every delegation from a root to the agent can only narrow what the root could do. | T4: an entitlement finding accepts for that subject. |
| 5 | No unmarked credential | No credential reachable by the agent lacks the marker. | T5: a reachability finding shows the agent contained. |
| 6 | Out-of-reach record | The record of what the agent did was written where the agent cannot reach it. | T6: an evidence-floor finding accepts at E2 or above. |

A level is claimed only with every lower level. A set that proves level 4 but skips level 3
is assigned level 2, the level below the gap.

## Level identifiers

Each level has a stable identifier: the contract identifier above with the fragment shown.
A verifier that names a level to another party writes the identifier, never only the number,
so the level means the same thing in every record that carries it. The fragments never change
meaning and never move.

<a id="level-0"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-0`: level 0, self-declared
<a id="level-1"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-1`: level 1, issuer-signed marker
<a id="level-2"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-2`: level 2, marker survives
<a id="level-3"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-3`: level 3, holder-bound
<a id="level-4"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-4`: level 4, narrowing chain
<a id="level-5"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-5`: level 5, no unmarked credential
<a id="level-6"></a>- `https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels#level-6`: level 6, out-of-reach record

## The tests

Each test reads findings. A finding is what a reader of another suite concluded about one
piece of evidence: the suite, the decision, the reason, the subject, and the SHA-256 of the
evidence. This contract re-judges no evidence. A test passes when a finding of one of its
suites is an `accept` with a reason it names, about exactly the set's subject (string
comparison, no case folding or normalisation). A refusal is never outvoted: if any finding of
the test's suites about the subject is a `reject`, the test fails.

| Test | Suites that can prove it | Reasons that prove it |
|---|---|---|
| T0 | none | the set has a non-empty subject |
| T1 | `agent-principal-binding/v1`, `agent-did-identity-binding/v1` | `agent_bound`, `subject_bound` |
| T2 | `actor-marker-survival/v1` | `marker_survives` |
| T3 | `holder-bound-credential/v1` | `holder_bound` |
| T4 | `delegator-right/v1` | `entitled` |
| T5 | `credential-reachability/v1` | `contained_verified` |
| T6 | `evidence-grade-floor/v1` | `grade_derived`, with `rung` E2, E3 or E4 |

Suite decisions differ in spelling. A finding carries the suite's decision folded to `accept`
or `reject`: the words `verified`, `allow`, `supported`, `accepted` and `accept` fold to
`accept`, and every other word (`rejected`, `deny`, `contradicted`, `not_established`,
`no_verdict`, `reject`) folds to `reject`. A finding whose suite answered `supported` with
the reason `exposed_verified` is an `accept` that no test names, so it proves nothing.

The subject of a finding is what the suite's own reader found the evidence to be about. This
contract takes the subject as given and compares it as an exact string; extracting it from
the evidence is the work of the suite that read the evidence.

## The answer

For one record set the reference reader prints `accept` with the reason
`level=<n> next=<test>:<why>`, or `next=none` at level 6. `<why>` is `no_finding`,
`subject_mismatch`, `finding_refused:<reason>`, `reason_not_proving:<reason>`,
`rung_below_floor:<rung>` or `rung_missing`. A set the reader cannot read is `reject` with
`contract_id_missing`, `contract_id_unknown`, `record_malformed`, `finding_malformed` or
`finding_conflict`. Two findings that disagree about one piece of evidence conflict, and so
do two that put one digest under different suites or about different subjects: one record is
one suite's record about one agent, so a single digest cannot prove several levels.

## Mapping the marks that exist today

| Existing mark | Where | Level inputs it feeds |
|---|---|---|
| `strict` principals | probity-records `check_principals` | T1 and T2 (every hop names its principal) |
| `basic` principals | probity-records `check_principals` | T1 only |
| `autonomous` (strict-equivalent) | the autonomous profile | T1 and T2 |
| `act-chain` | `act_grade` | T4 input: an RFC 8693 actor chain is present |
| `act-absent` | `act_grade` | no T4 input |
| `sender-constrained` | `possession_grade` | T3 input: a holder-bound finding is expected |
| `bearer` | `possession_grade` | T3 fails: no key is confirmed |
| reachability verdict `contained` | credential-reachability | T5 |
| reachability verdict `exposed` or `incomplete` | credential-reachability | T5 fails |

## The corpus per level

The corpus `vectors-identity-assurance` holds one record set per level, a set that skips
each level, and sets for every refusal code. Each set reuses the evidence of the corpora
above by digest and adds only what is missing. The one missing piece, holder-bound
presentation, is the corpus `vectors-holder-bound-credential`.

## Naming rule

This page says "level" for identity and never uses the other scale's word, except on the one
cross-link line at the top. The other scale's page uses its own word and never "level",
except on its own cross-link line. `scripts/lint-assurance-vocabulary.py` refuses a violation
in either direction. Code spans and the names of existing suites are exempt.
