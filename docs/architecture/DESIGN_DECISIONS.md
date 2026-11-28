# Design decisions

Choices a reader might otherwise flag as duplication, complexity, or dead code.
Each one is deliberate, and this file records why.

## Two independent verifier rails (do NOT de-duplicate across languages)

The suite ships two full reference verifiers: the stdlib-only Go verifier
(`aee/`) and the Python reference rail (`packaging/run_vectors.py`). They
re-implement the same primitives -- RFC 8785 JCS canonicalization, DSSE PAE,
RFC 6962 Merkle, ed25519, and the gate logic -- independently, in different
languages.

This cross-language duplication is deliberate. When two independent
implementations agree byte for byte, that agreement is what lets the corpus act
as a conformance authority: a bug or shortcut in one rail gets caught by the
other, and collapsing them onto a shared core would throw that away. Duplication
_within_ a language is debt worth removing; the cross-rail kind should stay.

## The generators' own self-verifier (a producer-side second opinion)

`vectors/accept/gen_valid_vectors.py` carries its own `verify()` -- a third
independent implementation of the gate logic -- run at build time as producer-QA
over every vector it emits. It is distinct from the two consumer rails: it
checks the generator's output before the vector is committed. It is deliberately
independent and is not shared with the rails.

## Hand-rolled ed25519 in the Python rail (test keys only)

`packaging/run_vectors.py` contains a pure-Python RFC 8032 ed25519
implementation rather than importing `cryptography`. This is deliberate: the
Python rail's zero-dependency portability is what lets a relying party run it
out of process with nothing but a stdlib Python, which is part of the
conformance-authority story. The keys are TEST keys only (never production), the
implementation is validated against `cryptography` and covered by a
known-answer test, and non-constant-time execution is an accepted non-goal.

## Generator primitives are copied, not shared (a deliberate non-abstraction)

The two generators each define the trivial primitives `jcs`, the sha256 hex
helper, and `pae` (about seven lines total). These are NOT factored into a
shared module. The generators are self-contained standalone scripts run directly
(`python3 vectors/<dir>/gen_*.py`); introducing a shared module would add
import-path machinery to both for a handful of trivial lines, trading real
coupling for negligible de-duplication, so the three similar lines are
duplicated rather than abstracted. (The generators' Merkle helpers
additionally diverge on purpose: the reject generator carries deliberately-wrong
attack variants -- `merkle_root_no_domain`, `merkle_root_dup_pad` -- that must
not be unified with the correct root.)

## Inherent complexity

A few functions have high cyclomatic complexity because the specification they
implement is itself branch-heavy, not because of tangled structure. The table
below explains why each one is complex.

The table covers every **non-test** Go function in `aee/`, `aeetest/`, `cmd/`,
and `witnessattestor/` and `corpora/` measured by gocyclo at **18 or above**; below that a
function is ordinary and needs no defence. Functions in `_test.go` files are out
of scope because their branch count tracks the number of cases they enumerate,
not the shipped verifier's structure. Every row today happens to live in `aee/`,
which is where the specification's branching lands.

`scripts/complexity-table-gate.py --rail go` enforces the table in CI. It fails
the build on a number that no longer matches, on an in-scope function at or above
the threshold with no row, and on a row whose function has been deleted or
refactored back below the threshold. Run it with `--sync` to rewrite the `Cyclo`
column from a fresh measurement after a legitimate change; adding or dropping a
row stays a hand edit, because the rationale is the part worth having and the
gate will not invent one.

| Function | Cyclo | Why it is inherent |
|---|---|---|
| `aee/validity.go` `checkSubstrateRow` | 33 | Per-row coverage in the order the requirements are stated: reference shape, then payload validity, then class match, then the method cap, each stage short-circuiting so a later one never reports on a row an earlier one already refused. The kind-specific constraints moved out to `armingConstraintsMet` and `sealedConstraintsMet`, and the closed-vocabulary guard to `rowFailsClosed`; what remains is the sequencing itself, which is the part that cannot be split without making the order a caller's business. |
| `aee/statement.go` `Gate0` | 36 | Statement well-formedness enumerates every reserved-member and vocabulary rule the spec lists; the branch count is the rule count. |
| `cmd/mutgen/mutate.go` `replaceExpr` | 35 | One arm per expression-bearing parent AST node, so the branch count is the node count. A reflect-keyed table would be shorter and would hide which parents are covered; a parent silently absent from it is a mutation that reports success and changes nothing, which scores as a forcing measurement that was never taken. |
| `cmd/mutgen/mutate.go` `collect` | 23 | Type dispatch over the AST node kinds that carry a weakening mutation, each with its own small enumeration rule. The branch count is the operator count, which is the published list in the command's own doc comment. |
| `aee/statement.go` `gate0CoverageIntegrity` | 19 | The coverage-partition invariant across three disjoint sets against the manifest. |
| `aee/jcs.go` `decodeValue` | 18 | Recursive JSON value dispatch with the I-JSON profile checks. |
| `corpusreaders/pyjson.go` `encodePythonOpts` | 19 | Type dispatch over every JSON value CPython's `json.dumps` writes, one arm each, all of them trivial. The branch count is the JSON value-kind count plus the two refusals that keep a float from being spelled by guess. Two corpora name a member by the digest of exactly these bytes, so an arm quietly absent from a shorter table-driven form would move a digest rather than fail. |
| `aee/types.go` `parsePredicate` | 19 | One guarded decode per optional predicate member, plus the normalization that makes the three empty predicate states one value. Each member must record presence separately from value, because the gates distinguish an absent member from one that is present but malformed, so the branch count is the predicate's member count; the extra branch turns the nil map `null` decodes to into an empty one, so no later reader can key on the difference the framework says does not exist. |
| `corpusreaders/restartrecords.go` `rrRBShape` | 25 | Member-by-member shape check of the one restart-record kind whose specification lists the most members, each with its own presence and type rule. The branch count is the member count, and the Python checker this reader is held to has the same arms in the same order. |
| `corpusreaders/restartrecords.go` `rrTime` | 22 | The conjunction of the two time grammars the Python checker applies (the TIME_RE pattern and strptime acceptance): fixed-width digit fields, then range checks per field, then the calendar check for the month length. The branch count is the rule count of that grammar. |
| `corpusreaders/restartrecords.go` `rrPretty` | 18 | Type dispatch over every JSON value kind CPython's `json.dumps(indent=2, sort_keys=True, ensure_ascii=True)` writes, one arm each, with the float refusal shared with the compact writer. |
| `corpusreaders/restartrecords.go` `rrR3Shape` | 18 | Member-by-member shape check of the R3 restart-record kind, each member with its own presence and type rule, mirroring the Python checker arm for arm. |
| `corpusreaders/monitorcoverage.go` `mcDecide` | 18 | The ordered rule table of `monitor-coverage/v1`: nine refusal rules checked in specification order, first failure wins. The branch count is the conjunctions inside the rule predicates (clean verdict, vantage, window, coverage completeness), and the Python checker this reader is held to has the same rules in the same order. |
| `corpusreaders/controldecision.go` `cdDecide` | 26 | The ordered rule table of the `control-decision/v1` record: seven refusal rules checked in specification order (signature, statement, verdict shape, policy digest present, input digest, policy digest, replayed verdict), first failure wins. The branch count is the rule count plus the type assertions each rule makes on decoded JSON, and the Python reader in the corpus this Go rail is held to has the same rules in the same order. |
| `corpusreaders/x402join.go` `x402EvidenceJoin` | 23 | The ordered rule table of `x402-evidence-join/v1`: fourteen refusal rules checked in specification order, first failure wins. The branch count is the conjunctions and null checks inside the rule predicates (seller key and domain binding, offer digest, payer and payee against the signed authorization, settlement against the ledger, delivery digest, fulfilment criteria), and the Python reader in `packaging/agent_evidence_vectors/x402join.py` this Go rail is held to has the same rules in the same order. |
| `corpusreaders/capabilityrequirement.go` `capreqTable` | 24 | The rule table of `capability-requirement/v1`: one named predicate per refusal reason (contract id, kind, requirement validity, run against another requirement, differing endpoints, run signature, held-out assessor signature, merged findings, overclaimed identity, behaviour mismatch, run distinctness and order, wrong comparison), each a closure over the decoded record, returned as a map so the caller walks the reasons in specification order and the first failure wins. The branch count is the conjunctions, loops and type assertions inside those predicates, and the Python reader this Go rail is held to has the same reasons in the same order. |
| `corpusreaders/principalaction.go` `paDecide` | 33 | The ordered rule table of `principal-action/v1`: envelope, signature under the producer key, statement shape, each principal in turn, then the act chain naming the agent, first failure wins. It mirrors the Python reader's `_decide` arm for arm, and the order is the rule. |
| `corpusreaders/principalaction.go` `paCheckPrincipal` | 31 | The per-principal check list in specification order (members, issuer, member shapes, key, thumbprint, kid, declared provider, pin, lifetime, trusted issuer, pinned key, act, ID-JAG), first failure wins, mirroring the Python `check_principal`. The branch count is the clause count. |
| `corpusreaders/principalaction.go` `paStatement` | 23 | Member-by-member shape check of the principal-action statement (type, subject digests, predicate type and members), each member with its own presence and type rule, as the Python reader checks them. |
| `corpusreaders/principalaction.go` `paMembersOK` | 20 | Member-by-member shape check of one principal: each required member with its own type rule and each optional member checked only when present. The branch count is the member count. |
| `corpusreaders/actormarker.go` `amShapeEntry` | 29 | Member-by-member shape check of one actor-marker chain entry, each member a guarded type assertion that returns false on the first mismatch, so the branch count is the number of members and types the contract names. |
| `corpusreaders/actormarker.go` `amDecode` | 24 | Decode of one token into its subject and ordered actors: one guarded step per claim, with the nested `act` chain walked iteratively and every malformed shape refused with the same error, as the Python checker does. |
| `aee/revocationlist.go` `readRevEntry` | 20 | One guarded read per member of a revocation entry, in the order the format names them, each failure naming the member it refused; strict JSON means every member needs its own type and range check. |
| `aee/revocationlist.go` `readRevBody` | 19 | One guarded read per member of the seven-member body, in the order the format names them, each failure naming the member it refused. |
| `corpusreaders/cborreceiptchain.go` `(*crcDecoder).item` | 29 | A CBOR decoder's item read: dispatch over the eight major types and the additional-information encodings of length, with the depth and size budget refusals. One arm per CBOR item kind, the RFC 8949 grammar itself. |
| `corpusreaders/cborreceiptchain.go` `crcJudgeStream` | 29 | The seven ordered checks of `cbor-receipt-chain/v1` (shape, signature, pinned signer, duplicate, single use, chain order, head anchor) and the three not-established outcomes, first failure wins, mirroring the Python `judge_stream`. |
| `corpusreaders/cborreceiptchain.go` `crcParse` | 21 | Parse of one receipt under the pinned format profile: the four-member map, each member's CBOR type, and the profile's field names for signer, previous digest, proof and outcome, each with its own refusal. |
| `corpusreaders/decisionrecord_binding.go` `drecConstraintProblem` | 24 | Per-kind shape check of one bounds constraint, one arm per constraint kind the decision-record format lists (equality, set membership, integer range, prefix and the rest), each with its own member and type rules, mirroring the reference reader arm for arm. The branch count is the constraint-kind count. |
| `corpusreaders/decisionrecord_binding.go` `drecOutsideBounds` | 24 | Walks a specification's members against the bounds in the format's stated order: unreadable bytes, non-object, extra members, then each bounded member under its constraint kind. The branch count is the refusal reasons the format defines, each its own guarded step. |
| `corpusreaders/ocsfrecord.go` `ocsfConsistency` | 24 | Reads the one outcome every way an OCSF record states it (action and disposition ids, captions, verdict, steps, status) and fails on each pairwise disagreement. The branch count is the number of places the format restates the outcome, one comparison each. |
| `corpusreaders/containmentjournal.go` `cjClaimsFailure` | 23 | The ordered claim-versus-evidence rules of the containment journal: each claim the record makes (channels closed, defended throughout, detector driven, authority chain checked, writes attributed and bound) is checked against the journal entries that would contradict it, first failure wins. The branch count is the claim count plus the entry-event kinds each claim reads. |
| `corpusreaders/ocsfjson.go` `(*ocsfParser).number` | 23 | A JSON number scanner under the reference reader's grammar: optional sign, the leading-zero rule, fraction, exponent, and the integer-versus-float decision, each with its own refusal. The branch count is the number grammar's production count, written out so each refusal stays visible. |
| `corpusreaders/ocsfrecord.go` `ocsfAttestationShape` | 23 | Member-by-member shape check of the record's attestation entry, each member with its own presence and type rule and optional members checked only when present, as the Python reader checks them. The branch count is the member count. |
| `corpusreaders/decisionrecord.go` `drecIssuerSignature` | 22 | The ordered checks of the issuer signature: absent, no trust policy, shape of the seal copy, refused policy, algorithm and signed bytes, key lookup, key kind and role, then the signature itself, first failure wins. The branch count is the check count and the not-checked outcomes the format distinguishes. |
| `corpusreaders/decisionrecord_json.go` `drecEq` | 22 | Python's `==` over decoded JSON: type dispatch over null, string, number (with the bool and integer-float equalities Python has), non-finite float, array and object, one arm each. The branch count is the value-kind count plus Python's cross-type cases. |
| `corpusreaders/decisionrecord_read.go` `drecCheckStageKind` | 22 | Per-kind rule check of one stage: one arm per stage kind the format lists (proposal, review, approval, standing approval and the rest), each stating which members it names and which it forbids. The branch count is the stage-kind count times its member rules. |
| `corpusreaders/auditrecord_principal.go` `arPrincipalShape` | 21 | Member-by-member shape check of the audit record's principal: required members, unknown members, then each member's own type rule, each gated by the format's per-check switch. The branch count is the member count. |
| `corpusreaders/auditrecord_principal.go` `arRulePrincipal` | 21 | The ordered principal rules of the audit record: shape, then subject, credential, key id, thumbprint, identity provider and pin checks against the delegation, agent and key members, each guarded by the format's per-check switch, first failure wins. The branch count is the rule count. |
| `corpusreaders/decisionrecord_binding.go` `drecBoundsProblem` | 21 | Member-by-member shape check of a bounds object: the exact member set, then each member's own type and range rule (version, counts, validity window). The branch count is the member count. |
| `corpusreaders/decisionrecord_json.go` `(*drecParser).str` | 21 | A JSON string scanner reproducing CPython's: control characters refused, each escape form handled, a high surrogate followed by an escaped low one joined, any other escaped surrogate lone. The branch count is the escape-form count of the grammar. |
| `corpusreaders/decisionrecord_json.go` `drecSame` | 21 | The format's strict equality over decoded JSON, where 1, 1.0 and true are three values: type dispatch over null, bool, string, integer, float, array and object, one arm each. The branch count is the value-kind count. |
| `corpusreaders/decisionrecord_read.go` `drecStructuralValidity` | 21 | Holds the attachment to the shape its schema publishes: member sets, profile and version, decision id, the specification list, then the stage list and its cross-references, each its own check. The branch count is the schema's rule count. |
| `corpusreaders/ocsfjson.go` `(*ocsfParser).str` | 21 | A JSON string scanner under the reference reader's grammar: control characters refused, each escape form handled, and the four-digit unicode escape. The branch count is the escape-form count of the grammar. |
| `corpusreaders/decisionrecord_read.go` `drecCheckValues` | 19 | Value-grammar check of one stage: one loop per member family (digests, stage ids, references, enumerated names), then the time member and the trace references, each held to its own pattern. The branch count is the family count. |
| `corpusreaders/decisionrecord_read.go` `drecReadInstant` | 18 | Reads an RFC 3339 time as seconds on one axis: type, pattern, then the offset presence, the time-of-day range, the calendar check for the month length and leap years, and the offset range, each refusing with its own reason. The branch count is the field count. |
| `corpusreaders/agentidentity.go` `aisDecide` | 28 | The ordered rule table of `agent-identity-statement/v1`: the consumer's pins, the history's shape, each envelope's signature, each statement's own checks, then the chain, then the decision's key, signature and the version in force, first failure wins. It mirrors the Python reader step for step, and the branch count is the number of checks the format lists. |
| `corpusreaders/agentidentity.go` `aisChain` | 25 | The chain checks of one agent's identity history in the order the format states them: a genesis version, no fork, no missing predecessor, versions that rise by one, times that never run backwards, nothing after a revocation, then one tip equal to the pinned head. Each check is one loop with its own refusal code, and the branch count is the check count. |
| `corpusreaders/cardreceipt.go` `crReleasePredicateOK` | 23 | Member-by-member shape check of the credential-release predicate under its two bases, a grant or a receipt: each member has its own presence and type rule, and the receipt basis adds its predicate type, result, digest and revocation list. The Python reader checks the same members in the same order, so the branch count is the member count. |

The Python generators' functions carrying `# noqa: C901` are explained in
[`docs/complexity-rationales.toml`](../complexity-rationales.toml), and
`--rail python` gates that file against a fresh ruff measurement on exactly the
terms above.

The sentence that half replaces was wrong in a way worth recording. It said the
ruff `C901` threshold was already that rail's equivalent of this gate, which is
the reason no gate was written. It is not: `C901` reports a function above the
threshold, and a recorded function is by definition one carrying a
`# noqa: C901`, which silences the report. The linter was therefore silent about
precisely the numbers that were written down, and both of them drifted under it,
one by seven. The gate reads them with `--ignore-noqa` for that reason. A
threshold a linter enforces and a number a document records are different claims,
and only the second one was ever unchecked.

## The core is stdlib-only and go-witness-free

`aee/` imports nothing outside the Go standard library; `aee/imports_test.go`
enforces this at test time. The go-witness dependency lives only in the separate
`witnessattestor/` module, so a relying party can vendor the core verifier with
zero third-party supply-chain surface.

## The surface-leakage null is precise, current and family-wise

Recorded 2026-10-09, when adding the suiteRevision 31 vectors exposed it. The
surface-leakage gate judged each surface against the 95th percentile of twenty
label shuffles, recorded once and reused while the class counts drifted. Three
measurements on the `vectors` corpus showed what that threshold was worth:

- Twenty shuffles moved the null by 0.005 to 0.05 when one vector was added.
  `paths` measured 0.5572 against a recorded 0.5577; with one more ordinary
  reject its re-derived null was 0.5439, and with a hundred shuffles 0.5516.
- At the 95th percentile of 2000 seeded shuffles the same `paths` figure sat at
  its bound: 0.5516 against 0.5530 as it stands, and 0.5556 against 0.5548 with
  one matched accept and reject pair added. No leak was added; the pair was
  refused for noise.
- The question is asked of every surface of every corpus at once. With thirteen
  surfaces carrying any spread, a per-surface 95th percentile refuses a corpus
  carrying no signal on about half of all runs.

The gate now does three things. It re-derives the null at the corpus's current
class counts whenever they differ from the counts the recorded null was taken
at, so a stale threshold is never applied. It takes the null from 2000 shuffles
drawn by a generator with a literal seed, computed as count-matrix products in
numpy so that it fits the CI budget. And it judges at the family-wise quantile,
one minus 0.05 divided by the number of surfaces judged, so the margin over the
old per-surface percentile is read off each surface's own shuffle distribution.
The false-alarm rate per run on a signal-free corpus falls from about 49% to at
most 5%. Power where it matters stays with the ratchet, which refuses any rise
past its tolerance whatever the null says; the gate's tests prove a giveaway
leak, a leak of about 0.03 over the recorded figure, and a leak hidden behind a
null recorded at other counts are all still refused.
