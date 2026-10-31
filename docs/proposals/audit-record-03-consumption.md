# Proposed text for draft-gilda-audit-agent-audit-record-03: consumption across a replaced limit, and the exact asset

Change text for the next revision of the consumption section (Section 5.9 of
-02). Each paragraph names the members of `vectors-agent-audit-record` that test
it. Sources: modelcontextprotocol/financial-services-interest-group#17
(kingyewchoo's replaced-limit question, atharnouman's enforcement answer,
vendrell46's stablecoin case) and probityai/agent-evidence-vectors#307.

## 1. Members of `consumption`

Replace "`consumption` MUST carry each of these members and no other" with:

> `consumption` MUST carry each of these members, except that `unit` is absent
> when `asset` is present, and MAY carry `supersedes` and `asset`; it MUST NOT
> carry any other member (vector `CS9`).

Replace the `unit` bullet with:

> * `unit`, the unit amounts are counted in; for money, an ISO 4217 alphabetic
>   code. A record that carries `asset` MUST NOT carry `unit` (vector `CS37`).

Add after the `stateRevision` bullet:

> * `asset`, OPTIONAL, for an amount counted in an asset no ISO 4217 code
>   names, such as a token on one chain. It is an object carrying exactly `id`,
>   a CAIP-19 asset identifier naming the chain and the asset (for a token, its
>   contract), and `decimals`, a non-negative integer of at most 255 giving the
>   decimal places of the smallest subunit every amount of the record is in
>   (vectors `CS34` to `CS36`). USDC on Base,
>   `eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` with
>   `decimals` 6, and USDC on Solana are two assets.
> * `supersedes`, OPTIONAL, the digest of the limit document that this record's
>   `limitDigest` replaced, for a limit raised or cut while permits are held. It
>   MUST differ from `limitDigest` (vectors `CS23`, `CS24`).

## 2. Checks across records

Replace "a retaining party that holds the records under one `limitDigest` runs
them" and the ordering sentence with:

> Two `limitDigest` values belong to one ledger when a record names one as the
> other's `supersedes`, transitively, and `stateRevision` orders the whole
> ledger, so a replacement does not restart it (vectors `CS18` to `CS22`).
> Limit documents no `supersedes` links are separate ledgers (vector `CS25`).
> A retaining party runs the checks below over each ledger. Every record of one
> ledger MUST name the same `unit`, or the same `asset` with the same
> `decimals` (vectors `CS38` to `CS40`).

Add after the two existing checks:

> A held permit is a claim keyed by the principal (`delegation.subject`), the
> agent key (`agent.signers`) and `decision.operationKey`, never by the limit
> document. A call denied before its tool ran, or whose record shows
> `effect.observed` of `none`, leaves no claim, and a retry of it is a new
> operation under the limit then in force (vectors `CS26` to `CS28`). Any other
> call keeps its claim when the limit is replaced: it stays in `held` of every
> later record of the ledger until a record of its operation shows `none` or
> `occurred`, and an `unknown` outcome does not release it (vectors `CS29`,
> `CS30`). A permit whose operation key a record in the same scope holds, and
> which does not itself hold that key, presents a retry as a new operation
> unless it is the original call at a lower `stateRevision` of the same ledger;
> a retaining party MUST treat the set as malformed, whether or not the later
> limit document names the earlier one in `supersedes` (vectors `CS31`, `CS32`).
> The same operation key under another principal and agent key is another
> claim (vector `CS33`).

## 3. Appendix B rows

Add rows `CS18` to `CS40` as `MANIFEST.json` of `vectors-agent-audit-record`
states them (`row` and `expected`).

## 4. Not yet proposed

The payee and the settled terms of #307 (the payee digest on `requested` and
each held entry, and the terms the server set at settlement beside the
approved terms) wait for the use-case prose on the FSIG repository, per the
order of work in #307.
