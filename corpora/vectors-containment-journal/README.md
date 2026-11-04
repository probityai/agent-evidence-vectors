# Containment-journal vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-4c6278?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Cases for `containment-journal/v1` and `blast-radius-receipt/v1`: whether a multi-agent
defence contained what it says it contained. A defence that rewrites the agents'
communication graph (TopoSHIELD, Huang et al. 2026, Findings of ACL 2026,
doi 10.18653/v1/2026.findings-acl.426, is one example) reports that it cut a
compromised agent's channels, isolated it, fell back safely when its detector failed and
let the agent back only on evidence. A cut can only be checked against the deliveries
that follow it, and a return only against the evidence that precedes it, so every event
is an entry of one hash-chained journal.

- Journal: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/containment-journal`
- Receipt: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/blast-radius-receipt`

For anyone who builds, evaluates or audits a defence for cooperating agents and wants a
reader that recomputes its containment claims from the run itself.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-containment-journal
python3 corpora/vectors-containment-journal/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, judges `receipt.json` beside it when present,
prints `{"decision": ..., "reason": ...}` and exits 0 for `allow`, 1 for `deny`.

## The journal

Entries are `topology`, `delivery`, `decision`, `fallback`, `restart`, `assessment`,
`restoration`, `response`, `tool_call`, `retrieval` and `refusal`, each chained to the one before by
digest. The journal also states the defence's claims (`channelsClosed`,
`restorationGated`, `defendedThroughout`, `detectorDriven`, `responseBoundSeconds`,
`retrievalAttested`, `authorityChainChecked`).

## What the cases force

The reader names the first rule that fails. One denied case forces each rule: the
canonical form and shape, the chain, each delivery against the graph in force, each
decision's deltas and detector estimates, each fallback's posture, each restart,
assessment and admitted restoration, each response's authority and timing, an admitted
retrieval outside the snapshot, a tool call that ran for an isolated agent, and the
run-level claims. A blast-radius receipt is judged beside an allowed journal, and the reach
is recomputed from the journal. Every member, the inclusion-path hashing and every reason
code in order are in [the predicate document](../../spec/predicates/containment-journal.md);
the revisions are in [CHANGES.md](CHANGES.md); counts are in `MANIFEST.json`.

## Synthetic, and labelled so

Every member is synthetic. Agents are `agent-a` to `agent-d`, message bodies and
configuration digests are fixed labels, and no member records a real system, run or
measurement. The manifest says so in `synthetic`.

## What it does not test

Whether the defence works. A consistent journal shows that its claims follow from the
events it records, not that it recorded every event or that its detector is any good.
Regenerate with `python3 corpora/vectors-containment-journal/gen_vectors.py`.
