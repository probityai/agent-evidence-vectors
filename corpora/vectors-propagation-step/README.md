# Propagation-step vectors

Cases for `propagation-step/v1`: one hop's attribution between two agents. In a
multi-agent incident, agent B misbehaves after agent A was compromised, and a report
says the compromise propagated from A to B. That is a claim about an edge: a message A
sent that reached B before B acted. Two agents that read the same poisoned source
misbehave too, with no edge between them. Attributing that common cause as propagation
sends containment to the wrong agent.

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
