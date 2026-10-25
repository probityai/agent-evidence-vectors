# Agent audit record conformance vectors

The conformance corpus of the Internet-Draft
[`draft-gilda-audit-agent-audit-record-00`](https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/00/),
Appendix B, published member for member and in the table's order. Every row of
that table is one member here, and each [`MANIFEST.json`](MANIFEST.json) entry
carries the row's identifier in `draftId` (`A1`, `F3b`, `R4`, ...) and its
`from` column in `parentDraftId`. After the last row come seven members for
sentences of Section 5.4 that Appendix B has no row for; each carries
`draftSection` and continues the identifier series beside it (`FR13b`, `FR16`,
`FR17a` to `FR17c`, `FR18`, `EV14`). The last five members are rows of revision
01 of the draft (`TI6`, `V4`, `V5`, `FR14`, `FR15`); each carries
`draftRevision` and the identifier -01 prints. [`INDEX.md`](INDEX.md) lists
every member beside its file.

## Which revision this tests

| Release | Draft revision the corpus tests | Members |
| --- | --- | --- |
| v0.26.0 and later | `draft-gilda-audit-agent-audit-record-00`, and five rows of `-01` | the 99 Appendix B rows, 7 Section 5.4 members and 5 rows of -01 |
| v0.17.0 to v0.25.0 | `draft-gilda-wimse-agent-audit-record-02` | 68 at v0.18.1, 71 at v0.25.0 |

A record under revision 02 carries no `evaluation.inputs`, which Section 5.4 of
-00 requires under both statuses, so every member of v0.25.0 and earlier is
malformed under -00 (`EV13`). A run of an earlier release checks the previous
revision and is not a conformance claim for -00. To test -00, pin v0.26.0 or
later. Every member keeps its Appendix B identifier; the file identifiers are
digests of member bytes and moved where a member gained its inputs.
[`ID-MAP.json`](ID-MAP.json) maps each `draftId` to its file identifier at
v0.18.1, v0.25.0 and v0.26.0 and says what changed.

Each member is a DSSE envelope whose payload is an in-toto Statement carrying one
agent audit record, except `R1` to `R9`: each of those is a retained record, a
JSON object carrying the `envelope` beside its `retention` entry (Section 4.7).
What a conforming verifier must reach is in the manifest, never in the file, so
a member cannot be scored without being read.

## Running it

```sh
# The reference reader, from the published package. Prints one line per
# failing member and exits 0 when every member behaves as the manifest says.
uvx agent-evidence-vectors==0.26.0 --corpus vectors-agent-audit-record

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
- the indeterminate member `N2` is a row the draft leaves open. It carries no
  `expected.verdict`, and your verifier conforms on it when its verdict is any
  one listed under `readings`: `valid` or `indeterminate`. The reference reader
  takes `valid`. `N1` had two readings under revision 02; -00 gives it one,
  `valid`, because the anchor in `correlation.externalAnchor` dates nothing by
  itself;
- a retained member (`R1` to `R9`) is scored twice: the envelope's verdict
  against `expected.verdict`, and your dating check against `expected.dating`
  (below).

`agent_evidence_vectors.auditrecord.conforming_verdicts(entry)` returns that set
for any manifest entry, so a scorer does not have to restate the rule:

```python
from agent_evidence_vectors.auditrecord import conforming_verdicts

conforms = my_verdict in conforming_verdicts(entry)
```

`expected.codes` are the reference reader's names for its first refusal. The
draft does not define codes, so a verifier is scored on the verdict alone; the
codes are published so two implementations can compare where they stopped.

## Independent runs

The first reader from outside this repository is Mayur Agnihotri's
[agent-audit-record-reader](https://github.com/Mayur021/agent-audit-record-reader),
written from the draft, RFC 8785, RFC 7493 and DSSE and sharing no code with the
reference reader. It agreed on 47 of 47 members of v0.16.0, the revision 01
corpus. Our rerun of it, pinned by digest, is in
[`interop/wimse-agent-audit-record-reader-2026-10-01`](../interop/wimse-agent-audit-record-reader-2026-10-01/README.md).
Lars Kersten Kroehl of MolTrust ran all 68 members of v0.18.1, the revision 02
corpus, with the reference reader and reproduced every declared verdict
([AUDIT list, 21 October 2026](https://mailarchive.ietf.org/arch/msg/audit/Wdv-fOIodjvF3z9OUFNfXLGP0ts)).
He also pointed out that the corpus still tested revision 02 while -00 had
replaced it; v0.26.0 is the regenerated corpus. No outside reader has run the
-00 corpus yet.

## Replaying the write chain

Section 5.3 requires the ordered writes to reproduce `afterRoot` from
`beforeRoot`. The replay is four comparisons: a running root starts at
`beforeRoot`; each write in `effect.writes`, in array order and whatever its
attribution or `inScope`, carries a `preStateDigest` equal to the running root,
and its `postStateDigest` becomes the running root; the root after the last
write equals `afterRoot`; and a record with no write carries equal roots. Each
comparison has its own reject member: `E4` breaks only the start, `E2` a link
between two writes, `E5` only the end, and `E6` is the empty case. Appendix B
has a row for `E2` only, so `E4`, `E5` and `E6` are Section 5.3 members.
[`scripts/write-chain-replay-test.py`](../scripts/write-chain-replay-test.py)
drops each comparison from the reference reader in turn and requires the judge
to catch exactly that member.

## Could not evaluate, and the human act behind a permit

`A2` and `A10` are one record twice. Both report a deny beside no effect, so
both derive `agreement` of `agree`. `A2` says the decision point evaluated the
request; `A10` says it could not, because its standing source was unavailable,
and denied anyway. Under revision 01 there was no member to say which, so a
verifier that lost its input wrote a record identical to a correctly enforced
denial. Revision 02 carries `evaluation.status` and `evaluation.unavailableInput`
beside the decision and leaves `decision.reported` and the agreement table as
they were. `EV1` to `EV4` refuse the shapes that would blur the two, and `EV3`
is a revision 01 record: it has no `evaluation` member, and no member has a
default, so it is malformed. -00 closes the member: `EV11` refuses a status
outside the closed set and `EV12` a free-text `reason` beside it.

-00 adds `policy-source` to the inputs and says what `decision.policyDigest`
names when the policy itself was the input the decision point could not obtain:
the fallback it enforced. `A18` is a permit under the allow-all fallback, a
decision point failing open; `A20` a deny under the deny-all fallback, from a
decision point that does not hold the profile the request names; and `A19` is
`A3`, a deny that leaked, recorded during an outage of two inputs, which still
derives `disagree` because `evaluation` is not an input to `agreement`.

`A11` carries the optional `oversight` member: the kind of act a person took
behind the permit (`observation`, `check`, `decision` or `release`) and the
digest of the overseer's own signed record. `OV1` and `OV2` refuse an act outside
that set and a member the draft does not define.

## Rows that began as section members

Revision 02's accept rows carried one value of each closed set: `A10` named
`standing-source` and `A11` named `check`. A reader that knew only those two
values scored every row, and so did one that skipped several sentences of
Sections 5.4 and 5.5. An outside reader written from the section text found
this ([draft-ietf-wimse-aims#157](https://github.com/ietf-wg-wimse/draft-ietf-wimse-aims/pull/157#issuecomment-6084026969)),
and these members closed it. Each is a row of -00's Appendix B:

- `A12`, `A13` and `A14` name `key-source`, `consumption-state`, and all three
  inputs at once, each once and in neither the draft's order nor sorted order.
- `A15`, `A16` and `A17` carry the acts `observation`, `decision` and `release`;
  `A16` also leaves out `recordDigest`, which Section 5.5 makes optional.
- `EV5`, `EV6` and `EV7` refuse a not-evaluated `unavailableInput` that is
  empty, that names one input twice, and that is a string rather than an array.
- `EV8`, `EV9` and `EV10` refuse an evaluated record carrying `unavailableInput`
  as `null`, the empty array and the empty string: the "in any spelling" of
  Section 5.4, which `EV2` tests only in its canonical spelling.
- `OV3` refuses an oversight member with no `act`, which Section 5.5 requires.

`check_vectors.py` holds each of these to the sentence it tests: it weakens the
reference reader one sentence at a time and requires the corpus to fail on
exactly that sentence's members, so a member that stopped forcing its sentence
would be caught.

## Freshness: Section 5.4

Every evaluation carries
`inputs`, one entry per input the decision depended on, each with `input`,
`lastResult` and `maxAge`. An entry's age runs from `lastResult` to
`decision.reportedAt`, never to `issuedAt`; an age equal to `maxAge` is fresh;
`lastResult` of `none` is never established; and a `lastResult` more than the
300-second skew tolerance after `reportedAt` is malformed. The unavailable
inputs are derived from the entries: under `evaluated` they must be none, and
under `not-evaluated` `unavailableInput` must name exactly them. Every member
carries entries that agree with it, so a record shaped for revision 02, with no
`inputs`, is refused (`EV13`).

- `FR1` to `FR13` are Appendix B rows. `FR2` sits on the boundary
  and on the reference time at once: its age is exactly `maxAge` at
  `reportedAt` and nine seconds past it at `issuedAt`.
- `FR13b` and `EV14` isolate two sentences the rows reach only through a later
  check: a negative `maxAge` stales its entry, so `FR13` is refused by the
  derived set as well, and `FR13b` names that entry so only the sign refuses it;
  `EV14` is an all-fresh record marked `not-evaluated` with an empty
  `unavailableInput`, which matches the empty derived set and is refused only
  because `not-evaluated` names at least one input.
- `FR16` refuses a record with no `decision.reportedAt`, the time every age is
  measured to. `FR18` puts a `lastResult` exactly the skew tolerance after
  `reportedAt` and is accepted, so a verifier allowing no skew is caught.
- `FR17a` to `FR17c` are one forwarded value judged at two hops. The first hop
  reads standing at 10:00:00 under its own `maxAge` of 7200 and evaluates. The
  second copies the source's `lastResult` unchanged, applies its own `maxAge` of
  3600, finds the value 3842 seconds old, and must record `not-evaluated`
  (`FR17b`); recording `evaluated`, the first hop's verdict, is malformed
  (`FR17c`). A verifier sees only each record's own entries, so each hop's
  verdict follows from its own `maxAge` and `reportedAt`.

A verifier cannot tell from the bytes which entry was forwarded: `FR1`, `FR3`
and `FR4` fix that the age runs from the carried `lastResult`, which is all a
forwarded entry can be held to. `FR16` to `FR18`, `FR13b` and `EV14` are
proposed rows for a later revision of the draft. PR #248 first numbered them
`FR14`, `FR15a` to `FR15c` and `FR16`, before any release carried them; they
moved so that `FR14` and `FR15` name the rows revision 01 prints (below), and
[`ID-MAP.json`](ID-MAP.json) records each move.

## Rows of revision 01

Revision 01 of the draft changes two rules, and five members test the change.
Each carries `draftRevision` of `draft-gilda-audit-agent-audit-record-01` and
the identifier -01 prints in its Appendix B, so a reader that conforms only to
-00 fails exactly these members. The -01 sentences each member tests are pinned
by SHA-256 in [`REVISION-01-PIN.json`](REVISION-01-PIN.json).

- Section 5.4: where a decision depended on several values of one input, the
  entry takes `lastResult` and `maxAge` from one value, the one whose
  `lastResult` plus `maxAge` is earliest. `FR14` is `A2` judging two delegation
  paths whose two values of `standing-source` are both fresh: 30 seconds old
  under 60, and 3600 under 7200. The entry carries the first value's pair, and
  the record is valid. `FR15` carries the pair -00 wrote, the oldest
  `lastResult` beside the smallest `maxAge` (age 3600 under 60), still recorded
  as `evaluated`, and is malformed. A verifier holding only the record cannot
  recover the two values, so `FR14`'s manifest entry lists them under
  `aggregation`, and the judge requires
  `agent_evidence_vectors.auditrecord.aggregate_values` over them to yield the
  entry the record carries. A producer tests its own aggregation the same way:
  feed it the listed values and compare. Reported by Mikhail Sergeev,
  [#249](https://github.com/probityai/agent-evidence-vectors/issues/249).
- Section 5.7: a gap inside `pathScope` beside `scopeComplete` of `true` is
  malformed at any tier (`V4` on `A1`, authoritative; `V5` on `A5`, voluntary),
  and the tier's coverage clause is `scopeComplete` of `true`. -00's clause,
  "complete, or every gap outside `pathScope`", passed `TI6`: authoritative
  with `scopeComplete` of `false` and gaps naming only paths outside the
  scope. `TI4` (`false` beside a gap inside the scope) is refused under both
  revisions, and `A1` (authoritative, `true`, no gaps) is the valid control.
  Reported by Mikhail Sergeev,
  [#250](https://github.com/probityai/agent-evidence-vectors/issues/250).

`check_vectors.py` proves both changes are load-bearing: restoring the -00
coverage clause fails exactly `TI6`, `V4` and `V5`, and restoring independent
minima in `aggregate_values` fails `FR14`'s aggregation check.

## Retained records and the dating check: Section 4.7

A signature says who signed a record and nothing about when. `R1` to `R9` are
the record `A1` beside the retention entry a retaining party keeps for it. The
envelope is valid in every one, and what each row tests is the dating check of
Section 4.7.1, which the manifest carries in `expected.dating` beside the
verdict and which never changes it:

- `datedAt` is the time of the earliest anchor, of either origin, that
  validates over `envelopeDigest`; it is absent when none validates (`R8`).
  No issuance time the record states dates it, so `R2` is dated by the
  sender's own anchor at 11:04:20, earlier than the retaining party's.
- `entry` is `well-formed` or `malformed`, and `codes` names the reference
  reader's first refusal: a received record with no anchor of origin
  `retainer` (`R4`), a `receivedAt` more than the 300-second skew tolerance
  before `issuedAt` (`R6`) or after the retaining party's earliest anchor
  (`R3`), a retaining party's first anchor later than `anchorWithin` plus the
  tolerance (`R7`), and `receivedAt` beside `received` of `false` (`R9`).
- `receipt` is present for a received record with a well-formed entry, and it
  is always `asserted-consistent`, never established: `R5` anchors the digest
  six seconds before the stated receipt, and nothing in the entry can tell.

Every anchor in these members is a `transparency-log` anchor that validates as
a hash commitment, the one kind a verifier can check offline with a hash
function alone. Its `proof` is the base64 of an RFC 9162 TransItem of type
`inclusion_proof_v2` (Section 4.12 of RFC 9162), the logged entry is the 32
bytes of `envelopeDigest`, so the leaf hash is `SHA-256(0x00 || envelopeDigest)`,
and the path recomputes by Section 2.1.3.2 of RFC 9162 to a tree head the
verifier already holds. The manifest publishes those heads under
`anchorTrust.treeHeads`, each with the log identifier, size, root and
timestamp; a head held this way, rather than by its signature, is what makes
the anchor a hash commitment under Section 4.7.2, and the head's timestamp is
the anchor's time. `envelopeDigest` is the SHA-256 of the RFC 8785 bytes of the
envelope object as the file carries it. No member yet carries an `rfc3161` or
`opentimestamps` anchor, and the reference reader dates nothing from either.

## What the members are built from

Every reject member is its `from` member with the one mutation its row names.
Where the mutation moves a value another member is a function of, the dependent
value moves with it (the rows that say "roots and chain moved to match"). The
keys are published test keys derived from fixed seeds in
[`gen_vectors.py`](gen_vectors.py): the observer key signs every envelope, and
the agent key signs nothing and is the key `agent.signers` names.

Four readings the draft leaves to the corpus, stated so they can be checked:

- `T2` is signed over its declaration-order bytes. A verifier that checks the
  signature over the carried bytes accepts it; one that derives the RFC 8785
  bytes itself, as the draft requires, refuses it.
- `F5` reaches "beacon-anchored with externalAnchor removed" by changing
  `timeBasis` on `A1`, which carries `asserted` and no anchor. `N1` is `A1`
  with an anchor carried under `beacon-anchored`, so `A1` itself raises no
  anchor question.
- `priorCommitment.sig` is carried and not checked: the draft names the
  member and defines no preimage for it.
- The retention entry's `validationData` carries the observer's key set
  (`application/jwk-set+json`) for the envelope and nothing for the anchors,
  which are hash commitments and need no path. The draft says what the member
  carries and does not make it required, so no member omits it.

## What the rule sweep reports

`check_vectors.py` disables one rule of the reader at a time. Four Appendix B
rows are still refused when their own rule is off, by a later check: `S1` and
`I1r` (the subject-interval rule), `F1` (membership), `E3` (the empty-tree
constant, whose mutation also breaks the commitment digest), and `V2` (the glob
rule, whose scope also puts the write out of scope). The verdict holds in each
case. The sweep prints these as notes, and they are candidates for isolating
members in a later revision of the draft.

It then disables each rule of the dating check in turn, including anchor
validation and the choice of the earliest anchor, and requires each to move
some retained member off its declared dating result without moving its
verdict. The check that an entry's `envelopeDigest` names the envelope beside
it has no row and is the one dating rule the sweep exempts.
