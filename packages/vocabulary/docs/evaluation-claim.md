# Evaluation claim terms

Name the rule that turns a record's inputs into its verdict, the outcomes of re-deriving that verdict, and the conditions under which a stated pass is empty, so a party that does not trust the producer can repeat the verdict and never has to take it on trust. The [README](../README.md) is the short version of the repository; this page covers the `evaluation_claim` section, added in 0.10.0. Every term is `proposed` and lists no issuer, and none is canonical.

## The terms

| term | what it names | check |
|---|---|---|
| `evaluator` | the URI of a published, versioned evaluation function | an absolute https URI; re-derive when held, `evaluator_unknown` when not; never substitute another function |
| `asserted_verdict` | the outcome of re-deriving a verdict a record asserts about itself | the assertion is never an input; a difference refuses the record whoever signed it |
| `verification_decision` | the verifier's decision on one record, with a third outcome | rejected if any check failed; indeterminate only when none failed and one was undecided; exit status 0, 1 or 2 |
| `check_outcome` | the outcome of one check in a fixed-order verification | every check after the first failure is `not_evaluated`, never `pass` |
| `vacuity_witness` | whether a property reported as holding was ever exercised | a pass with a falsified witness is refused and the case counts as not run |
| `evidence_attribution` | which parties a record binds | two signatures bind two parties; they never prove the record true or the parties independent |
| `signer_distinctness` | whether the signers counted toward a threshold are distinct keys and distinct authorities | a count met only by counting a key or an authority twice is refused; the issuer's own key listed among the signers is refused whatever the count; a required count below 1 is refused |
| `lifecycle_binding` | whether the authenticated execution report names the action the authenticated control authorized | grouped by decision and instruction, every pair compared, five states |
| `on_behalf_of` | the party an agent acted for | reported next to the signer that attributed it; never read as consent |
| `anchor_within` | the late bound on a record's external time anchor | checked with equality allowed, after a range check |
| `anchor_early_allowance` | the early bound on a record's external time anchor | an anchor earlier than issuance minus the allowance is refused; never borrowed from the late bound |
| `block_time_allowance` | the seconds added to one bound for the uncertainty of an anchor's clock | applied only to the bound it is declared for |
| `clock_skew_tolerance` | how far a record's issuance time may lie in the verifier's future | the future bound is the skew alone, never the maximum age |
| `conformance_extension` | an extension URI in a signed agent card naming the corpus and verifier its records are judged by | read only inside a card whose signature verifies; parameters pin versions |

## The values

| term | values |
|---|---|
| `asserted_verdict` | `rederived_agrees`, `asserted_verdict_contradicted`, `evaluator_unknown` |
| `verification_decision` | `accepted`, `rejected`, `indeterminate` |
| `check_outcome` | `pass`, `fail`, `not_evaluated` |
| `vacuity_witness` | `witnessed`, `vacuous_pass`, `no_witness` |
| `evidence_attribution` | `co_signed`, `single_signed`, `unattributed_evidence` |
| `signer_distinctness` | `distinct`, `key_named_not_signing`, `one_key_two_ids`, `own_key_as_cosigner`, `one_authority_threshold`, `below_threshold` |
| `lifecycle_binding` | `satisfied`, `failure`, `missing`, `not_evaluated`, `indeterminate` |

## The first evaluator: payment-scope/v1

`https://probityai.github.io/agent-evidence-vectors/evaluator/payment-scope/v1` judges one payment against the scope a principal granted. Inputs: the scope (`currency`, `amount_ceiling_minor`, `merchants`, `expires_at`, `actions`, `single_use`) and the payment (`currency`, `amount_minor`, `merchant`, `at`, `action`, `prior_uses`). Output: `within`, or `outside` with the first failing dimension in the fixed order currency, amount, merchant, expiry, action, single use. Amounts are integers in minor units, and a payment exactly at the ceiling is within. An input that is missing, of another type or out of range (a negative amount, a fraction, a boolean, a merchant list given as one string) makes the record malformed: `payment_scope_v1` raises `registry.MalformedInputs` and `asserted_verdict` refuses with `evaluator-inputs-malformed`, never re-deriving a verdict from it. The reference implementation is `registry.payment_scope_v1`:

```python
from agent_evidence_vocabulary import registry

scope = {"currency": "USD", "amount_ceiling_minor": 10, "merchants": ["m-1"], "expires_at": 2000,
         "actions": ["pay"], "single_use": True}
payment = {"currency": "USD", "amount_minor": 500, "merchant": "m-1", "at": 1000, "action": "pay", "prior_uses": 0}
registry.payment_scope_v1(scope, payment)       # ('outside', 'amount')
record = {"evaluator": "https://probityai.github.io/agent-evidence-vectors/evaluator/payment-scope/v1",
          "inputs": {"scope": scope, "payment": payment}, "asserted": "within"}
registry.asserted_verdict(record).value          # 'asserted_verdict_contradicted'
```

The signature on such a record proves who asserted `within`. Only the re-derivation shows that the payment of 500 minor units exceeded a ceiling of 10.

## Lifecycle binding

The `lifecycle_binding` profile reads a set of control, execution and decision records:

- group by (decision, instruction); every control in a group, from the issuing and the receiving side, is compared with every execution in it;
- two records with one identity make the group `indeterminate`, whatever their order;
- a group with no control, no execution or no copy of the decision record it cites is `missing`, and an execution that cites an instruction no control in the set covers is `not_evaluated`;
- each digest is computed by the convention declared for its pointer (`raw` or a named `canonicalization`);
- hash and signature pre-images carry a domain tag (format version, artifact type, hash or signature) from a closed registry, a line feed, then the canonical bytes; an unregistered tag fails closed. The registry is the six ASCII tags `agent-evidence/lifecycle-binding/v1/{decision,control,execution}/{hash,signature}`, and `registry.lifecycle_preimage(artifact_type, purpose, canonical)` builds the bytes, so the control signature input `agent-evidence/lifecycle-binding/v1/control/signature\n` followed by the canonical bytes can never verify as an execution signature or a hash;
- the signature suite is the one the verifier-accepted key binding names, the binding is resolved from the record's producer, and a revocation snapshot is required: a record that does not authenticate is a `failure`, one whose binding is not active is `not_evaluated`;
- the rules apply in that order (identity, uncovered execution, missing side, authentication, binding, digests) to every record of the group, the cited decision record included, so an unauthenticated decision is a `failure` even when another record is bound by an inactive key;
- a record of any type other than control, execution or decision is refused, never skipped;
- the group is `satisfied` only when every record authenticates under an active binding and every authorized digest equals every executed digest.

The claim is "the authenticated execution report names the action the authenticated control authorized". It never says that the executed bytes were observed. `registry.lifecycle_binding(artifacts, active_bindings)` returns the state per group.

How the states sit beside the other effect families in this repository's corpora: only `satisfied` and `failure` decide anything. `missing`, `not_evaluated` and `indeterminate` say the record set cannot answer, which is the `unknown` outcome of the `vectors-uncertain-effect` family (an outcome no runtime may report as `committed` or `not_run`), and none of the three is ever read as an observed effect in the `vectors-observed-effect` sense. `evidence_state` (ES0 to ES8) orders what responders observed about a whole system during an incident; it is a different axis, and no lifecycle state implies an `evidence_state` code.

## Agent capability credentials

A capability credential names an issuer, a subject agent, its capabilities, a validity window, a revocation reference and its signatures with their algorithms. A verifier takes the trusted issuers, a pinned check time, a revocation list and the required signer count as declared inputs, and checks, in order: every signature over the canonical bytes, `signer_distinctness`, the validity window under `clock_skew_tolerance`, revocation from the list, and capability names compared byte for byte (a case variant of a capability is a different capability). A credential whose revocation flag sits outside the signed bytes is refused, because anyone can flip it.

## Time members

An agent audit record that carries an issuance time and an external anchor states four bounds. The past bound on the issuance time is the maximum age plus the uncertainty of the record's clock. The future bound is `clock_skew_tolerance` alone. The anchor must fall no later than `anchor_within` plus `block_time_allowance` after issuance, and no earlier than `anchor_early_allowance` before it, because an anchor commits to bytes that already exist and an earlier anchor means a post-dated issuance time. Every bound admits equality, every time member is range-checked as an integer in 0 to 2^53-1 before any subtraction, and each bound is held by its own pair of vectors, one at the bound and one a second past it. `registry.time_bounds` applies the rule.
