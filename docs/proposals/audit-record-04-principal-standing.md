# Proposed text for draft-gilda-audit-agent-audit-record-04: principal standing from a published commitment

Change text for Section 5.4 (Evaluation), for the input `principal-standing-source`
under the `v2` predicate type URI. Tested by `PS3` to `PS5` of
`vectors-agent-audit-record`, which the corpus marks `proposed` until a published
revision carries this text. Source:
[#402](https://github.com/probityai/agent-evidence-vectors/issues/402).

Add after the paragraph that defines `principal-standing-source`:

> Principal standing MAY be established from a signed standing commitment the
> source publishes, against which the presenter proves standing, with the
> relying party pinning the publisher and a maximum age. The entry then carries
> the as-of time of the commitment the decision point held as `lastResult`, and
> the pinned maximum age as `maxAge`.
>
> * With no commitment held, `lastResult` is `none`, the input was never
>   established, and the record is `not-evaluated` naming
>   `principal-standing-source` (vector `PS3`).
> * With a current commitment against which the proof shows the standing
>   withdrawn, every entry is fresh, the record is `evaluated`, and the decision
>   is `deny` (vector `PS4`).
> * With a current commitment and a proof that is missing or does not verify
>   against it, the commitment does not establish standing and the relying party
>   cannot tell this from a withdrawal: the record is `evaluated` with `deny`, and
>   its entry carries the commitment's as-of time. A record naming the input
>   unavailable fails the recompute of Section 4.6, because the input the
>   decision depended on was current (vector `PS5`).
