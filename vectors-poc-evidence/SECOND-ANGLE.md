# Second-angle check on the headline claim (POC-CORPUS, 2026-10-25)

Headline as relayed: **171 vectors tie to 17 of the 127 requirement ids, and the pinned reference validator and
verifier differ from the corpus on 10 of them; 3 of the 10 are places where a sentence of the specification says
reject and the validator accepts.**

The first read of the headline was wider ("11 conformance gaps in the reference validator"). Four angles were used
to attack it, in this order. Each is a test in `tests/test_corpus.py`, so it reruns with the suite.

1. **Is each text-grounded finding actually in the text?** Every case with a `grounding` field carries a file and a
   verbatim quote from the pinned specification files copied under `build/spec-93d0e28/`.
   `test_finding_quotes_appear_verbatim_in_the_pinned_specification` checks each quote after collapsing whitespace.
   Result: three quotes resolve (MODIFY definition in `poc-evidence.schema.json`; rule 7 of `canonicalization.md`,
   twice). **This check removed one claimed finding.** `allow-with-dispatch-hash` had been written as a finding. The
   schema says the claim is "required when verdict is MODIFY" and is silent for other verdicts, so the case is now
   class `ambiguity` with the reference's behaviour as the expected outcome. The two platform-width cases and the
   integer case have no sentence in the specification behind them, so they are classed `platform-fact` and
   `interop` and are never counted as text-grounded.
2. **Is the reference accepting because of the stated fault, or because of another one?** Each negative token is
   one mutation from an accepted base (`test_negative_token_is_one_mutation_from_an_accepted_base`, which diffs the
   parsed claims against the base and allows one member), and the base is accepted by both the twin and the
   reference (`TOK-P-base` is absent from `REFERENCE-RESULTS.json`). The MODIFY case is diffed against an accepted
   MODIFY record, not the ALLOW base, because a MODIFY needs two members to change.
3. **Could a trivial rule reproduce the result without understanding the requirement?** The Merkle negatives were
   run against two deliberately wrong verifiers: one that hashes leaves without the 0x00 prefix, one that pairs an
   odd last node with itself. Each accepts exactly the case written for it and the twin rejects it
   (`test_interior_node_case_fools_a_verifier_without_leaf_prefix`,
   `test_odd_leaf_case_fools_a_duplicating_tree_verifier`). A case that no wrong verifier accepts would have been
   vacuous. The first draft of the odd-leaf case was vacuous: its root was the RFC root, so the duplicating
   verifier did not accept it. It was rebuilt with the duplicating tree's own root. The first draft of the
   "wrong tree size" case was also wrong: a size-7 proof does verify against size 8 when the root is the size-7
   root, because an RFC 6962 root does not commit to the size. It is now an `observation` case that expects
   acceptance, with a companion case at size 16 that expects rejection.
4. **Does the second verifier share the reference's blind spots?** It shares no code with `impl/` and
   `validate.py`. It reproduces the specification's own published canonical digests
   (`test_twin_jcs_matches_the_specifications_published_canonical_digests`), accepts every published positive and
   rejects every published negative for the stated code, and passes two RFC 8032 vectors for Ed25519. Limit: for
   the ten cases that differ from the reference, the twin was made to implement the reading stated in each case's
   note, so on those ten it is the corpus author's reading and not independent evidence. The report says so.

Not yet checked, and why it matters for what the comment may claim: the editors have not been shown any of this, so
"the working group should say which reading is normative" is the strongest honest wording for rule 2, the
allow-with-dispatch case and the preimage of `dispatched_snapshot_hash`. The comment uses that wording.
