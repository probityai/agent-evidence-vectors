# Proposed text for draft-gilda-audit-agent-audit-record-04: decision.evaluatedAt and the freshness boundary

Change text for the next revision of Section 5.4 and Appendix B. Each paragraph names the members
of `vectors-agent-audit-record` that test it. The predicate URI does not change: `evaluatedAt` is an
optional member, and a record without it is measured at `decision.reportedAt` as under revision
03. Two shipped members change verdict, so the release that carries this text is a minor release
under [RELEASING.md](../../RELEASING.md).

## 1. Why the member exists

Revision 03 measures every input's age at `decision.reportedAt`. A decision point that reports a
decision later than it takes it, because it batches or queues its records before sending them,
writes a correct record that a verifier reads as wrong: an input that was fresh when the decision
was taken is stale by the time the record says it was reported, so a record under `evaluated` is
refused as `evaluation-inconsistent`. Nothing in the signed bytes says when the decision was taken,
so the verifier has no way to tell a late report from a stale input. `decision.evaluatedAt` carries
that instant, and every age is measured at it.

The member was proposed on the WIMSE list on 9 November 2026, in the thread on a principal-standing
name for the Section 5.4 closed set, and Marc Miro supported it there. He also asked for the bound
in the other direction: a decision is not reported before it is evaluated, so an `evaluatedAt`
later than `reportedAt` by more than the skew tolerance is malformed. That bound is `FR25`.

## 2. The boundary moves to at-or-past

Revision 03 says an age equal to `maxAge` is fresh. Section 3 of `draft-jackson-wimse-evaluation-05`
forbids using an input "at or past its horizon". No record satisfied both texts at the boundary, so
`PS1b` was published as an indeterminate member with two readings. Revision 04 adopts the
evaluation draft's boundary: an input is fresh while its age is less than `maxAge`, and an input
exactly `maxAge` old is stale. The same thread agreed it on 9 November 2026.

## 3. The text

Replace the age and boundary sentences of Section 5.4 with:

> `decision` MAY carry `evaluatedAt`, the time at which the decision point evaluated its inputs
> and took the decision, an RFC 3339 date-time like `decision.reportedAt`. A decision point that
> reports a decision later than it takes it, as when records are batched or queued before they
> are sent, SHOULD carry it. The reference time for every entry is `decision.evaluatedAt` when
> the record carries it, and `decision.reportedAt` otherwise. An input's age is the reference time
> minus `lastResult`. An input is fresh while its age is less than `maxAge`. It is stale when its
> age is equal to `maxAge` or greater, so an input exactly `maxAge` old is already stale (vector
> `FR2`) and one a second younger is fresh (vector `FR23`). A late-reporting decision point is
> judged at the instant it decided: an input fresh at `decision.evaluatedAt` stays fresh however
> long the report took (vectors `FR21` and `FR22`), and the boundary falls at
> `decision.evaluatedAt` and not at `decision.reportedAt` (vectors `FR23` and `FR24`). A
> `lastResult` later than the reference time by more than the skew tolerance of 300 seconds is
> malformed, because a decision cannot rest on a value produced after it was taken (vectors `FR9`
> and `FR27`). A `decision.evaluatedAt` later than `decision.reportedAt` by more than the same
> tolerance is malformed, because a decision is not reported before it is evaluated (vector
> `FR25`); within the tolerance it is not (vector `FR26`).

And in the paragraph that derives the unavailable inputs, replace "A held value older than the
maximum age the decision point applies to its input" with "A held value whose age is equal to or
greater than the maximum age the decision point applies to its input". Under the boundary above, a
value exactly `maxAge` old is one the decision point could not obtain, and "older than" would leave
that case out (`FR2`, `FR24`, `PS1b`).

## 4. Verifying a record

> A verifier takes the reference time before it reads any entry. When `decision.evaluatedAt` is
> present and later than `decision.reportedAt` by more than the skew tolerance, the record is
> malformed (`FR25`). Each entry's skew and age are then measured to the reference time (`FR9`,
> `FR27`, `FR21` to `FR24`), and the unavailable inputs are derived from the entries as before.

The reference reader refuses both skew cases with `evaluation-result-after-decision`, the code
`FR9` already carries, and a record whose recorded status disagrees with the derived set with
`evaluation-inconsistent`. An `evaluatedAt` that is not an RFC 3339 date-time is
`timestamp-malformed`. The Python reader (`packaging/agent_evidence_vectors/auditrecord.py`,
`reference_time`) and the Go reader (`corpusreaders/auditrecord.go`, `arReferenceTime`) apply the
same rule.

## 5. Members that change verdict

| member | file | under revision 03 | under revision 04 |
| --- | --- | --- | --- |
| `FR2` | `vb2d65dfff88bebcf` | valid: an age equal to `maxAge` is fresh | malformed, `evaluation-inconsistent`: the input is stale under `evaluated` |
| `PS1b` | `v12896bcb35edd1b1` | indeterminate, `valid` or `malformed`; the reference reader took `malformed` | valid: the input is stale, and `not-evaluated` naming it matches the derived set |

The bytes and identifiers of both members are unchanged. A verifier that passed them at the
previous release passes them now only if it applies the at-or-past boundary.

## 6. Members that are new

| member | parent | verdict | what it isolates |
| --- | --- | --- | --- |
| `FR21` | root | valid | `evaluatedAt` 1800 seconds before `reportedAt`, `standing-source` fresh at `evaluatedAt` and stale at `reportedAt`, under `evaluated` |
| `FR22` | `FR21` | malformed | `not-evaluated` naming that input: only the set derived at `reportedAt` matches it |
| `FR23` | root | valid | `standing-source` one second younger than `maxAge` at `evaluatedAt` |
| `FR24` | `FR23` | malformed | `standing-source` exactly `maxAge` old at `evaluatedAt`, under `evaluated` |
| `FR25` | `FR1` | malformed | `evaluatedAt` 301 seconds after `reportedAt`, every entry fresh at either time |
| `FR26` | root | valid | `evaluatedAt` 300 seconds after `reportedAt`, exactly the tolerance |
| `FR27` | `FR21` | malformed | `policy-source`'s `lastResult` 301 seconds after `evaluatedAt` and before `reportedAt` |

`FR25` is built on `FR1` and not on `FR21`. On `FR21`, an `evaluatedAt` 301 seconds after
`reportedAt` also makes `standing-source` stale under `evaluated`, so the record is refused by the
derived set whether or not a verifier holds the bound, and the member would test nothing. On `FR1`
every entry is fresh at either time, so only the bound refuses it.

`FR27` is a Section 5.4 member with no Appendix B row of its own: a verifier that measures a
`lastResult`'s skew to `reportedAt` instead of the reference time accepts it, and no row isolates
that reading.

## 7. What the corpus checker holds

`corpora/vectors-agent-audit-record/check_vectors.py` weakens the freshness rule one reading at a
time and requires each reading to fail exactly the members named here and no others:

| weakened reading | members that fail it |
| --- | --- |
| age measured to `issuedAt` rather than the reference time | `FR9`, `FR21`, `FR22`, `FR23`, `FR25` |
| an age equal to `maxAge` read as fresh, the boundary of revisions 00 to 03 | `FR2`, `FR24`, `PS1b` |
| `evaluatedAt` ignored, every age measured to `reportedAt` | `FR21`, `FR22`, `FR23` |
| an `evaluatedAt` after `reportedAt` accepted however late | `FR25` |
| an `evaluatedAt` after `reportedAt` refused with no skew tolerance | `FR26` |
| a `lastResult`'s skew measured to `reportedAt` rather than the reference time | `FR27` |
| a `lastResult` after the reference time accepted however late | `FR9`, `FR27` |

Three readings the checker held before this change now fail the new or moved members as well: a
reader that accepts the `v2` URI with the `v1` input set also fails `PS1b`, a reader that does not
match `unavailableInput` against the entries also fails `FR22`, and a reader that does not check
`evaluated` against the entries also fails `FR2` and `FR24`.

## 8. What the member does not establish

That the decision was in fact taken at `evaluatedAt`. The record asserts the time, and nothing in
the record shows the decision was taken then. The text bounds it from above, at `reportedAt` plus
the skew tolerance, and not from below, so a record that dates its decision early makes an input
held past `maxAge` read as fresh. A verifier that holds an independent observation of when the
decision was taken, such as a transparency log entry or the decision point's own retained log, can
check the asserted time against it; the record alone cannot.

## 9. Appendix B rows

Change the row of `FR2` to malformed, and add rows `FR21` to `FR26` as `MANIFEST.json` of
`vectors-agent-audit-record` states them (`row`, `parentDraftId` and `expected`), with `FR25`'s
parent `FR1`. Cite `FR27` beside `FR9` in Section 5.4 and `PS1b` beside `FR2` in the boundary
sentence.
