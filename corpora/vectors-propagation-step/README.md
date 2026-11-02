# Propagation-step vectors

Cases for `propagation-step/v1`: one hop's attribution between two agents. In a
multi-agent incident, agent B misbehaves after agent A was compromised, and a report
says the compromise propagated from A to B. That is a claim about an edge: a message A
sent that reached B before B acted. Two agents that read the same poisoned source
misbehave too, with no edge between them. Attributing that common cause as propagation
sends containment to the wrong agent.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who writes or reads incident attributions in multi-agent systems and wants a
reader that holds a propagation claim to a message digest chain.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-propagation-step
python3 corpora/vectors-propagation-step/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and
exits 0 for `allow`, 1 for `deny`.

## What the cases force

Eight checks in order: `contract_id_missing`, `contract_id_unknown`,
`hop_endpoints_missing`, `chain_digest_mismatch` (a link whose digest is not the logged
message's), `chain_not_connected`, `edge_after_effect`, `propagation_without_edge` (a
common-cause exposure with no edge attributed as propagation), and
`common_cause_unsupported` (a common cause with no source both agents read before the
effect). The controls show propagation through a two-link chain, a common cause through
a shared source, and a hop left `not_established` when both explanations hold. Counts
are in `MANIFEST.json`.

## Synthetic, and labelled so

Every member is synthetic. Agents, sources and message bodies are fixed labelled
strings, and no member records a real system or incident.

## What it does not test

Whether the message caused the behaviour. A connected chain that precedes the effect is
a necessary condition for a propagation claim, not proof of causation. Regenerate with
`python3 corpora/vectors-propagation-step/gen_vectors.py`.
