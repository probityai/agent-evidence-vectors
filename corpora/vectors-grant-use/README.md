# Grant-use vectors

Cases for `grant-use/v1`: may this effect stand as an authorised use of this grant? Each case is one record: the grant chain from root to leaf, the trusted root keys, the authority keys and the keys held inside the agent's worker, every permit minted on the leaf grant so far, the other effects recorded against those permits, the effect being judged with the call it applied, and the witness log. A verifier that checks only that the leaf grant names the tool and has not expired, which is what most capability libraries check, allows most of the denied cases here. `tests/test_corpus.py` names exactly which ones.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

## The model

A grant names the tools its holder may call, the arguments each call may carry, how many times it may be used, when it is in force, how deep it may be delegated, which hop kinds may carry it onward, and the caveats it binds. A child grant may only narrow its parent. A use of the leaf grant is one single-use permit, minted by the grant's holder: an authority whose key is not held inside the agent's worker. The permit names the leaf grant's digest and the workflow, run, call, tool and argument digest it authorises. The effect names its permit and the grant, so an auditor walks grant to permit to effect. A witness log orders the permits and effects.

Digests are `sha256:` and the lowercase hex SHA-256 of the canonical JSON bytes (keys sorted, no whitespace, UTF-8). With strings and integers only, those are the RFC 8785 bytes, and the record carries no other number. The reader recomputes every digest it relies on: a digest field is a claim to check.

| Constraint | Admits | Narrowed by |
| --- | --- | --- |
| `{"exact": v}` | `v`, same JSON type | `exact` of the same value, a one-member `oneOf`, or a one-integer `range` |
| `{"oneOf": [...]}` | any member | `exact` or `oneOf` inside the set, or a `range` whose every integer is in it |
| `{"range": [lo, hi]}` | an integer with `lo <= x <= hi`; both ends inclusive | an inner `range`, or `exact` and `oneOf` integers inside it |
| `{"prefix": p}` | a string starting with `p` | a longer `prefix` starting with `p`, or `exact` and `oneOf` strings starting with it |

An argument a grant constrains must be present. Under `closedWorld` an argument the grant does not name is refused, and a child may not name an argument its closed-world parent refuses. Grants and permits are in force from `notBefore` or `issuedAt` inclusive to `expiresAt` exclusive. `maxDepth` is the greatest depth a grant derived from this one may sit at; the root is at depth 0. An unwitnessed permit counts as spent before the one being judged. The effect's outcome (`applied`, `not-applied`, `uncertain`) does not move the verdict: the question is authority, not success. Revocation is the question of the `revocation-epoch` vectors; the `srl` members these records carry are read there.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the grant-use contract | `contract_id_unknown` |
| the record has the fields and types the contract names, carries only integer numbers, every instant is `YYYY-MM-DDTHH:MM:SSZ`, counts are safe integers, no grant sits deeper than its own `maxDepth`, ids are unique, and no evidence is stamped after `decisionTime` | `malformed_record` |
| the root has no parent and a trusted root issued it; each grant sits one level below its parent, names its parent's recomputed digest, and was issued by its parent's holder | `grant_chain_broken` |
| no grant admits more than its parent: tools, constraints by type, closed world, uses, in-force window, depth, hop kinds, caveats | `grant_widened` |
| the effect was observed while every grant on the chain was in force | `grant_not_in_force` |
| the leaf grant names the called tool | `tool_not_granted` |
| the call's arguments have the digest the effect records | `call_args_unbound` |
| the arguments satisfy every leaf constraint, and under a closed world carry nothing else | `argument_outside_constraint` |
| the permit the effect names was minted | `permit_missing` |
| the permits on the leaf grant witnessed at or before this one do not exceed `maxUses` | `uses_exhausted` |
| the permit names the recomputed digest of the leaf grant | `permit_not_for_grant` |
| the leaf grant's holder minted the permit | `permit_not_from_holder` |
| that key is a listed authority key | `permit_authority_unknown` |
| that key is not held in the worker | `authority_key_in_worker` |
| the permit was minted while every grant was in force, and the effect observed while the permit was | `permit_not_in_force` |
| no other effect on the same permit is witnessed before this one | `permit_reused` |
| the effect's workflow, run and call, and the called tool, are the permit's | `permit_identity_mismatch` |
| the effect's argument digest is the permit's | `effect_args_mismatch` |
| the effect names the permit's grant digest | `effect_grant_unlinked` |
| the witness log runs from 1 without a gap and witnesses the permit, then the effect, each under its own kind | `effect_unwitnessed` |

A record that passes every check is `allow` with reason `authorized_use`. The expected decision and reason for every case are in `MANIFEST.json`, with one line per case saying what it departs from.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-grant-use
```

To judge your own verifier, run it as `<verifier> <case-dir>/record.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`. The Go reader in `corpusreaders/grantuse.go` derives the same verdict for every case from the record alone.

## Controls

Every denied case departs from a conformant record in one place, and each check is forced by at least one case: switching it off changes a verdict. Switching off the one check a denied case names turns it into an allow, except for the two cases `tests/test_corpus.py` names with the reason. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. `tests/test_corpus.py` holds each of these as a test, and regenerates the corpus byte for byte from `gen_vectors.py`.
