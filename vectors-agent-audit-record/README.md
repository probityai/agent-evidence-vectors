# Agent audit record conformance vectors

The conformance corpus of the Internet-Draft
[`draft-gilda-wimse-agent-audit-record-03`](https://datatracker.ietf.org/doc/draft-gilda-wimse-agent-audit-record/03/),
Appendix B, published member for member. Every row of that table is one member
here, and each [`MANIFEST.json`](MANIFEST.json) entry carries the row's
identifier in `draftId` (`A1`, `F3b`, `TI4`, ...) and its `from` column in
`parentDraftId`. [`INDEX.md`](INDEX.md) lists the rows beside their files.

Each member is a DSSE envelope whose payload is an in-toto Statement carrying one
agent audit record. The bytes are in `statements/`; what a conforming verifier
must reach is in the manifest, never in the file, so a member cannot be scored
without being read.

## Running it

```sh
# The reference reader, from the published package. Prints one line per
# failing member and exits 0 when every member behaves as the manifest says.
uvx agent-evidence-vectors --corpus vectors-agent-audit-record

# From a checkout: rebuild every member (byte-identical on every machine),
# then judge the committed bytes, verify every signature with a second
# Ed25519 library, and sweep every rule for load-bearing effect.
uv run --extra generators python vectors-agent-audit-record/gen_vectors.py
uv run --extra generators python vectors-agent-audit-record/check_vectors.py
```

To score your own verifier, run it over each `statements/<id>.json` with the
observer public key from `keys.observer.publicKey`, then score each verdict:

- an accept or reject member conforms when your verdict equals
  `expected.verdict`;
- an indeterminate member (`N1`, `N2`) is a row the draft leaves open. It
  carries no `expected.verdict`, and your verifier conforms on it when its
  verdict is any one listed under `readings`: `valid` or `indeterminate` for
  both rows. The reference reader takes `valid` on both.

`agent_evidence_vectors.auditrecord.conforming_verdicts(entry)` returns that set
for any manifest entry, so a scorer does not have to restate the rule:

```python
from agent_evidence_vectors.auditrecord import conforming_verdicts

conforms = my_verdict in conforming_verdicts(entry)
```

`expected.codes` are the reference reader's names for its first refusal. The
draft does not define codes, so a verifier is scored on the verdict alone; the
codes are published so two implementations can compare where they stopped.

## Could not evaluate, and the human act behind a permit

`A2` and `A10` are one record twice. Both report a deny beside no effect, so
both derive `agreement` of `agree`. `A2` says the decision point evaluated the
request; `A10` says it could not, because its standing source was unavailable,
and denied anyway. Under revision 01 there was no member to say which, so a
verifier that lost its input wrote a record identical to a correctly enforced
denial. Revision 02 carries `evaluation.status` and `evaluation.unavailableInput`
beside the decision and leaves `decision.reported` and the agreement table as
they were. `EV3` is a revision 01 record: it has no `evaluation` member, and no
revision since gives a member a default, so it is malformed.

Revision 03 closes the member. `A12` is a permit that was not evaluated because
the policy source was unavailable: a decision point failing open, accepted so
that it can be found. `A13` is the deny that leaked (`A3`) enforced while the
key source and the consumption state were unavailable, and it still derives
`disagree`, because evaluation is not an input to agreement. The rejects refuse
each shape that would blur an outage into a decision: no input named (`EV1`,
`EV6`), an input named twice (`EV5`), an input outside the closed set (`EV4`),
an evaluated decision carrying the member in any spelling (`EV2`, `EV7`, `EV8`),
a status outside its set (`EV9`), and a member the draft does not define, such
as a free-text reason (`EV10`).

`A11` carries the optional `oversight` member: the kind of act a person took
behind the permit (`observation`, `check`, `decision` or `release`) and the
digest of the overseer's own signed record. `OV1` and `OV2` refuse an act outside
that set and a member the draft does not define.

## What the members are built from

Every reject member is its `from` member with the one mutation its row names.
Where the mutation moves a value another member is a function of, the dependent
value moves with it (the rows that say "roots and chain moved to match"). The
keys are published test keys derived from fixed seeds in
[`gen_vectors.py`](gen_vectors.py): the observer key signs every envelope, and
the agent key signs nothing and is the key `agent.signers` names.

Three readings the draft leaves to the corpus, stated so they can be checked:

- `T2` is signed over its declaration-order bytes. A verifier that checks the
  signature over the carried bytes accepts it; one that derives the RFC 8785
  bytes itself, as the draft requires, refuses it.
- `F5` reaches "beacon-anchored with externalAnchor removed" by changing
  `timeBasis` on `A1`, which carries `asserted` and no anchor. `N1` is `A1`
  with an anchor carried under `beacon-anchored`, so `A1` itself raises no
  anchor question.
- `priorCommitment.sig` is carried and not checked: revision 02 names the
  member and defines no preimage for it.

## What the rule sweep reports

`check_vectors.py` disables one rule of the reader at a time. Four Appendix B
rows are still refused when their own rule is off, by a later check: `S1` and
`I1r` (the subject-interval rule), `F1` (membership), `E3` (the empty-tree
constant, whose mutation also breaks the commitment digest), and `V2` (the glob
rule, whose scope also puts the write out of scope). The verdict holds in each
case. The sweep prints these as notes, and they are candidates for isolating
members in a later revision of the draft.
