# Revision 04, Section 5.9: the consumption members and rows the corpus carries beyond revision 03

Input to `draft-gilda-audit-agent-audit-record-04`. Source: Laurent-Lemonnier on
[#401, comment of 2026-11-07](https://github.com/probityai/agent-evidence-vectors/issues/401#issuecomment-6699265775),
checked against the text of `-03` and release 0.35.0 of this package.

## The gap

Section 5.9 of `-03` says `consumption` "MUST carry each of these members and
no other (vector `CS9`)": `limitDigest`, `unit`, `limit`, `consumed`, `reserved`,
`requested`, `held`, `stateRevision`. A `held` entry carries `operationKey`,
`requestDigest` and `amount`. `-03` cites `CS1` to `CS17` and no later row.

`vectors-agent-audit-record` at 0.35.0 has 193 members. Its README writes `CS41`
to `CS49` as "rows written for revision 04": `consumption.payee` and `payee` on
each held entry (the SHA-256 digest of the payee's CAIP-10 account id), and
`consumption.settled` with exactly `amount`, `asset`, `payee`, `source` and
`transaction`. A verifier of the letter of `-03` refuses those members as
`consumption-malformed`, which is what Laurent's first pass did. `CS18` to `CS40`
sit in the README only as well.

## What `-04` needs

1. Section 5.9 lists `payee` on `consumption` and on each `held` entry, and
   `settled` with its five members, and keeps "and no other" over the extended
   list.
2. The rules the README states for `CS41` to `CS49` go into the text: a retry
   pays the held entry's payee; another payee under the same key is
   `consumption-key-reused`; settled `source` is `chain`; an `upto` permit that
   settles at or below its maximum is valid; a settled amount above `requested`,
   or another asset or payee, is refused with its own code; `consumed` takes the
   settled amount; a later record that counts less is
   `consumption-set-settled-uncounted`.
3. The refusal-code table names each code the new rules use.
4. Appendix B carries `CS18` to `CS49` as `MANIFEST.json` states them.

The staged `-04` (`research/1105-wg-leadership-2026-10-29/outbound/ietf-audit/draft-04`)
carries none of items 1 to 4 yet. It is the same Section 5.9 as `-03`.

## Not a claim about `-03`

An independent verifier that agrees with all 193 members agrees with the corpus
and its README. It does not show conformance to `-03`, because `-03` does not
define `CS18` to `CS49`. Reports of such runs say which text they were read from.
