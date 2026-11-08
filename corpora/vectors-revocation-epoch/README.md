# Revocation-epoch vectors

Cases for `revocation-epoch/v1`: was this permit, and the effect it led to, checked against the revocation state in force, and did no revocation witnessed before the effect cover it? Each case is one record: the grant the permit rests on, the trusted issuers of signed revocation lists, the freshness limit, every list, the permit and the effect with the list each was checked against, and the witness log that orders all of them. A verifier that only checks that the grant is not in the newest list allows most of the denied cases here, and refuses three of the controls.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Revocation that only the permit broker reads is cooperative: work already admitted keeps running, and a worker that ignores the list still reaches the network. These cases ask the record to show the opposite. A trusted issuer publishes lists under a strictly increasing `epoch`. The permit names the list it was checked against (`permit.srl`, an epoch and a digest), the effect names the list checked where it landed (`effect.srl`), and the witness log fixes the order of grants, lists, permits and effects. A permit or effect that checked no list carries no `srl` member at all. Absent is not empty: an empty list at a stated epoch is a legitimate state (`allow-empty-list-epoch-1`), and a missing member is a refusal (`srl-absent-at-permit`).

## The record

| Member | Content |
| --- | --- |
| `grant` | the grant the permit rests on: `grantId`, `parentDigest` (null at the root), `issuer`, `holder` and the rest of the shared grant object |
| `trustedSrlIssuers` | the key ids that may issue lists |
| `freshnessSeconds` | a list may be used for a decision only while it is younger than this, for example 5 seconds for an irreversible action |
| `srls` | every list: `epoch`, `issuedAt`, `issuerKeyId`, `revoked` (grant digests and key ids) |
| `permit` | `permitId`, `grantDigest`, `authorityKeyId`, `issuedAt`, `srl` `{epoch, digest}` and the call it admits |
| `effect` | `effectId`, `permitId`, `grantDigest`, `observerKeyId`, `observedAt`, `outcome` (`applied`, `not-applied` or `uncertain`), `srl` `{epoch, digest}` |
| `witness` | `[{seq, kind, digest, at}]`, `seq` from 1 with no gap |

Every digest is `sha256:` over the JCS bytes of its object, and the reader recomputes each one it relies on: the grant's, every list's, the permit's and the effect's. A list covers the work when it revokes the grant's digest, the parent grant's digest, the holder key or the key that minted the permit. A revocation is never undone: a list witnessed before the effect that covers it stops the effect even when a later list drops the entry (`effect-after-revocation-dropped-in-later-list`). A restored principal gets a new grant.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the revocation-epoch contract | `contract_id_unknown` |
| the record has the fields and types the contract names, every number is an integer, every time parses, and the witness log's `seq` strictly increases while its `at` never goes back | `malformed_record` |
| every list comes from a trusted issuer | `srl_issuer_untrusted` |
| the permit and the effect name the recomputed grant digest, and the effect names the permit | `grant_binding_mismatch` |
| no epoch carries two different lists, a later epoch is issued later, and the witness log never sees an epoch go back | `srl_epoch_not_monotonic` |
| the permit and the effect each carry an `srl` member | `srl_absent` |
| each names an epoch that a list has, with that list's recomputed digest | `srl_digest_mismatch` |
| the permit's list was in force at issue: younger than `freshnessSeconds` at the later of `issuedAt` and the permit's witness time, not issued after it, not witnessed after the permit, and no newer list witnessed before the permit | `srl_stale_at_permit` |
| the permit's list does not cover the work | `revoked_at_permit` |
| no list witnessed before the effect covers the work, unless the effect was `not-applied` | `effect_after_revocation` |
| the witness log orders the work: no gap from 1, the permit, the effect and every list in it, every witnessed list in the record, the permit before the effect, the effect's list before the effect | `revocation_order_ambiguous` |
| the effect names the newest list witnessed before it | `effect_epoch_behind` |
| the effect's list was younger than `freshnessSeconds` at the later of `observedAt` and the effect's witness time, and not issued after it | `srl_stale_at_effect` |

A record that passes every check is `allow`. The reason is `revocation_enforced_at_effect` when a covering list was witnessed before an effect that was `not-applied`: the permit was minted before the revocation, and the enforcement point where the effect lands read the newer list and refused it (`allow-revoked-in-flight-refused-at-effect`). Otherwise it is `not_revoked`. An `uncertain` effect after a revocation is not a refusal and is denied. A gap or an unordered pair in the witness log is a denial, never an allow: an entry the log does not show could be the revocation.

Freshness is measured to the later of the time the record claims and the time the witness first saw it, so a backdated permit or effect does not buy a stale list more time. The boundary sits on both sides of the limit: one second under is allowed (`allow-permit-list-one-second-under-limit`, `allow-effect-list-one-second-under-limit`) and exactly the limit is refused (`srl-stale-at-permit-at-limit`, `srl-stale-at-effect-at-limit`). When a list and an effect share an instant, the witness order decides (`allow-race-effect-witnessed-first`, `effect-after-revocation-race-list-first`).

## Related corpora

[vectors-delegation-lifecycle](../vectors-delegation-lifecycle/README.md) judges signed revocation records of individual grants against a presentation time, with disputes and resolutions. [vectors-restart-records](../vectors-restart-records/README.md) judges the records of stopping a system and deciding it may run again. This corpus judges the list state a permit and an effect were checked against, and the order the witness log gives them.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-revocation-epoch
```

To judge your own verifier, run it as `<verifier> <case-dir>/record.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`. The expected decision and reason of every case, and what it departs from, are in `MANIFEST.json`.

## Controls

Every check is forced by at least one case: switching it off changes a verdict. Each denied case is named by its own check, so switching that check off changes the answer. A verifier that denies everything fails the allowed cases, one that allows everything fails the denied ones, and one that checks only the newest list fails the cases `tests/test_corpus.py` lists by name. A fixture whose bytes differ from the manifest is refused before execution. The tests regenerate the corpus byte for byte from `gen_vectors.py`, and the Go reader in `corpusreaders/revocationepoch.go` derives every verdict from the records.
