# Actor-marker survival vectors

Cases for `actor-marker-survival/v1`: does the marker naming the acting agent survive every
hop of a delegated request? A user signs in, an agent acts for them, and the request then
passes gateways, queues, protocol bridges and further agents before it reaches a resource.
At each hop the agent marker can be stripped, replaced, reordered, truncated to a
well-formed shorter chain, or downgraded to "the user did this alone", and the token that
arrives still parses. A verifier that passes these cases refuses each of those, names
which one happened, and accepts the chains in which the marker held.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who builds a component that receives and forwards on-behalf-of principals (an
OAuth token-exchange service, an A2A agent, an API gateway, a job queue, a protocol
bridge), and for anyone who writes the check that a stranger runs over such a chain.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-actor-marker-survival
python3 corpora/vectors-actor-marker-survival/check_vectors.py --verifier './verifier'
python3 corpora/vectors-actor-marker-survival/check_vectors.py --hop-command './my-hop'
```

## The record

A record is a list of signed statements. The first is the origin: the issuer that
authenticated the user states the token it sent, and may carry user-presence evidence.
Every later statement is one hop: the component states the token it `received` and the
token it `sent`, each in the native form of the protocol it spoke on that side, with
`prev`, the SHA-256 of the previous statement's signed bytes. Two native forms are read:

| `protocol` | Form | Actor order |
| --- | --- | --- |
| `rfc8693` | `{"header": {...}, "claims": {"sub", "exp", "act": {...}}}` | RFC 8693 section 4.1: the outermost `act` is the current actor and the least recent actor is the most deeply nested |
| `a2a-actor-chain` | `{"actorChain": {"origin": {"sub"}, "actors": [{"sub"}, ...]}}`, the `Message.metadata` member proposed in a2aproject/A2A issue 2028 | each delegating peer appends its own hop |

Each statement is signed with Ed25519 over its RFC 8785 canonical bytes. Every case
directory pins those bytes as `signing-input-<n>.jcs`, so a canonicalizer is checked byte
for byte before any signature is. The verifying key and the writer's role come from
`TRUST.json`, which the manifest pins by digest; they never come from the record. A writer
whose role is `agent` acts and must append itself; a `relay` (gateway, queue, bridge)
must forward the principals it received unchanged.

## What the cases force

The reader applies twenty checks in order and names the first that fails. Each refusal is
an accepted chain with one edit, re-sealed so every earlier check passes:

| Reason | The edit |
| --- | --- |
| `contract_id_missing`, `contract_id_unknown` | no contract, another contract |
| `record_malformed` | a token in a protocol the contract does not read |
| `statement_writer_unknown` | a hop written by a component not in the trust bundle |
| `statement_signature_invalid` | a statement edited after signing; one signed with another writer's key |
| `hop_link_broken` | a statement dropped from a four-hop chain; one replayed from an earlier chain |
| `audience_mismatch` | the next hop is not the component the token was sent to |
| `received_not_sent` | the token changed between two hops |
| `unknown_critical_attribute_ignored` | an agent acted on a token whose `crit` lists a parameter it does not understand (RFC 7515 section 4.1.11) |
| `principals_expired_at_use` | a queue dispatched stored principals after their `exp` |
| `marker_unsigned` | the agent named itself in an unsigned header and sent the user alone in the token |
| `deferred_dispatch_without_stored_principals` | a queue dispatched as its own service account |
| `subject_replaced` | a gateway forwarded the actors for another user |
| `downgraded_to_user_alone` | a gateway received two agents and forwarded the user alone |
| `chain_truncated` | the last agent sent a well-formed token naming only itself |
| `marker_stripped` | an agent forwarded the prior actor without its own marker |
| `agent_replaced` | a gateway put its own identity where the agent was |
| `actor_order_changed` | a bridge nested an A2A list outermost-first, reversing it |
| `actor_inserted` | a gateway added an agent it did not receive |
| `user_alone_without_human_evidence` | the chain delivered the user alone and the origin carried no user-presence evidence |

Eight accepted chains keep a verifier from refusing everything: two hops, four hops, a
deferred hop, an A2A-to-OAuth protocol change, the user alone with presence evidence, an
unknown header parameter that is not critical, a marker signed in the token and copied in a
header, and a subject outside ASCII. Counts are in `MANIFEST.json`.

## Two contracts

A verifier takes `record.json --trust TRUST.json --json`, prints
`{"decision": ..., "reason": ...}` and exits 0 for `accept` and 1 for `reject`.

A hop implementation is tested directly with `--hop-command`. The command reads one JSON
object on standard input, `{"role", "self", "received": {"protocol", "token"}, "send":
{"protocol", "to"}, "at"}`, and prints the `{"protocol", "token"}` it sends, or exits
non-zero to refuse. It is replayed through every hop of every accepted chain and must send
the principals the corpus states, in the protocol asked for; it is handed the token with an
unknown critical parameter and must refuse it. The same run is
`agent-evidence-vectors runtime --corpus vectors-actor-marker-survival --runtime './my-hop'`,
and in the GitHub Action it is `corpus: vectors-actor-marker-survival` with `runtime: ./my-hop`,
so your own hop runs in your CI.

## Sources

The rules rest on public text only, and each member names the sentence it relies on:
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) section 4.1,
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) section 4.1.11,
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) section 4.2,
[draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/)
section 9.10, the truncation report in
[its issue 73](https://github.com/oauth-wg/oauth-identity-assertion-authz-grant/issues/73), and the
`actorChain` shape proposed in [a2aproject/A2A issue 2028](https://github.com/a2aproject/A2A/issues/2028).
Every member is synthetic; the keys are derived from public seeds in `gen_vectors.py` and sign
nothing outside this corpus.
