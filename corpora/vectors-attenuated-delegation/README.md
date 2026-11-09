# Attenuated-delegation vectors

Cases for `attenuated-delegation/v1`: did every execution hop (child workflow, sub-agent, agent-to-agent call, tool-to-tool call) receive only an attenuation of its parent's capability, issued by its parent's holder, and does the key presenting it at the end hold the last grant? A verifier that checks only that each child's tools are a subset of its parent's allows widened constraints, extended lifetimes, dropped caveats, grants minted by a non-holder, forbidden hop kinds and capabilities presented by a non-holder.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

`vectors-delegator-right` judges entitlements held at an authoritative source and `vectors-delegation-lifecycle` judges presentations against registrations; this corpus judges the capability's own structure across execution hops.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-attenuated-delegation
```

A verifier under test runs as `<verifier> <case-dir>/record.json --json`, prints `decision` and `reason` as JSON, exits 0 for `allow` and 1 for `deny`, and is passed with `--verifier`. The Go reader in `corpusreaders/` applies the same checks.

## The record

`hops[]` holds each hop's `hopKind` (`root` first, then `child-workflow`, `sub-agent`, `a2a` or `tool`), its `grant`, and `presentedBy`, the key that handed the grant across. A grant names `parentDigest` (null at the root), `issuer`, `holder`, `tools`, per-argument `constraints` (`exact`, `oneOf`, integer `range` or `prefix`), `closedWorld`, `maxUses`, `notBefore` (inclusive), `expiresAt` (exclusive), `depth`, `maxDepth`, onward `hopKinds` and `caveats`. The record also carries `trustedRoots` and the `presentation` (`presenterKeyId`, `tool`, `args`, `at`). A grant digest is `sha256:` plus the hex SHA-256 of its RFC 8785 bytes, and the reader recomputes every one it links by.

## The checks, in order

The verifier names the first check that fails; each compares a hop's grant with its parent's.

| Check | Reason on failure |
| --- | --- |
| `contractId` present | `contract_id_missing` |
| `contractId` is this contract | `contract_id_unknown` |
| fields, types, times and constraints well formed; only the first hop is `root` | `malformed_record` |
| each `parentDigest` is the recomputed digest of the grant before; no grant repeats | `chain_unlinked` |
| the root names no parent, a trusted root issued it and handed it over | `root_untrusted` |
| each grant was issued and handed over by its parent's holder | `issuer_not_parent_holder` |
| each hop kind is in the parent's `hopKinds`, which the child does not widen | `hop_kind_not_permitted` |
| depth starts at 0, rises by one, stays within every `maxDepth`, which no hop raises | `depth_exceeded` |
| tools are among the parent's | `tool_widened` |
| every parent constraint kept as a subset of its values; closed world stays closed and names nothing new | `constraint_widened` |
| lifetime inside the parent's | `lifetime_extended` |
| every parent caveat carried | `caveat_dropped` |
| `maxUses` not above the parent's | `uses_raised` |
| the presenter holds the last grant | `presenter_not_holder` |
| tool, arguments and time inside the last grant | `presentation_outside_leaf` |

A record that passes every check is `allow` with reason `attenuated`. Equal is an attenuation. Constraints compare by the values they admit: `exact` inside a `range`, a `oneOf` subset and a longer `prefix` narrow; `exact` to `oneOf`, a `oneOf` superset, a range wider at either end, a shorter prefix and a dropped constraint widen.

## Controls

Every hop kind has an allowed case; a four-hop chain narrows at each hop and ends at exactly `maxDepth`. Every limit has a case on each side. Each denial departs from a conformant chain in one place; each check is forced by some case. Expected verdicts and counts live in `MANIFEST.json`. `tests/test_corpus.py` shows that deny-everything and allow-everything verifiers fail, that the tool-subset verifier lets through every denial outside its own checks, that a mutated fixture is refused before execution, and that `gen_vectors.py` regenerates the corpus byte for byte.
