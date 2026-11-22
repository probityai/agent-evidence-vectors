# Identity assurance vectors

Cases for `identity-assurance-levels/v1`: how far is an agent's identity proven? The
[levels page](../../spec/predicates/identity-assurance-levels.md) defines seven levels, 0 to
6, each with one deciding test, and a level is claimed only with every lower level. A
verifier that passes these cases prints, for a set of findings about one subject, the highest
level the set proves and the first test above it that fails, and it never skips a gap.

For anyone who states an agent's identity assurance to another party, and anyone who writes
the check that a stranger runs over such a statement.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-identity-assurance
python3 corpora/vectors-identity-assurance/check_vectors.py --verifier './verifier'
```

## The record

A record is a `subject` and a list of `findings`. A finding is the suite, the folded
`decision` (`accept` or `reject`), the `reason`, the `subject` it is about, the SHA-256 of
the evidence, and for the evidence-floor suite the `rung`. The answer is a pure function of
the set: it re-judges no evidence, so a verifier that already reads each suite composes it
over its own findings.

The answer is `accept` with the reason `level=<n> next=<test>:<why>`, or `next=none` at
level 6. A set that cannot be read is a `reject` with one of five codes.

## Evidence reused by digest

Every finding points at a member of a sibling corpus by digest: the principal binding,
identity binding, actor-marker-survival, holder-bound-credential, delegator-right,
credential-reachability and evidence-floor corpora. `reuse.json` holds the pointers and
`reuse.py` checks each against the sibling when the sibling is in the tree.
`python3 reuse.py --require-all` fails when a sibling is absent, and the default run prints
how many pointers it verified and how many are pending. This corpus copies none of the
siblings' bytes.

## What the cases force

| Group | Members |
| --- | --- |
| One set per level | `level-0-declared-only` to `level-6-out-of-reach-record`, plus a DID-bound level 1 and an anchored level 6 |
| A set that skips a level | `skips-issuer-marker`, `skips-marker-survival`, `skips-holder-bound`, `skips-narrowing-chain`, `skips-no-unmarked-credential`, `skips-two-levels`: graded at the level below the first gap |
| A refusal that stands | a stripped marker, a forged binding, a bearer credential, a widened delegation, a probe signed with the agent's key, a record that stamped itself |
| An answer that proves nothing | a verified exposure, a floor finding below E2, a floor finding with no rung, a finding about another subject |
| Order | the same findings in reverse give the same level |
| A set the reader refuses | no contract, another contract, an extra member, an empty or padded subject, a bad decision, digest, rung or evidence, the same evidence reported both ways |

`python3 gen_vectors.py` regenerates the corpus byte for byte from `reuse.json`.

## Status

Version 1.
