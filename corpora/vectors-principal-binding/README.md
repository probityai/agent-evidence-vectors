# Agent-to-principal binding vectors

Cases for `agent-principal-binding/v1`: one binding of an agent to the
principal it acts for and the scope it may use, written in the native form of
an effort that defines such a binding, and the relying party's request (the
agent, principal and scope it is being asked to accept). The expected decision
and reason for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Several efforts now define this binding, each in its own record. The corpus
asks every one of them the same two questions, with the same agent, principal
and scope: does the binding produce a record a verifier can recompute from its
bytes, and does the verifier refuse when one field is changed? Each rejected
case differs from its form's accepted case in one thing.

Two native forms are covered:

| Profile | Native record | Agent | Principal | Scope |
| --- | --- | --- | --- | --- |
| `uma-for-agents` | [UMA for Agents](https://u4a.ai/docs/reference/wire-contract/) terms agreement (Beat 3): the proffered template echoed and signed by the agent as a compact EdDSA JWS | `iss` | `aud`, the owner's authorization server | `scope` |
| `hcp-grant` | [Human Context Protocol](https://github.com/loyalagents/hcp-spec) 2.0 draft 3 grant (section 6.1.5) | `client.id` | `authorizingPrincipal.id` | `scopes` |

The HCP draft defines the grant the Authorization Service records but no
signature over it, so these cases carry it inside an envelope
(`{"grant", "kid", "sig"}`) signed by the Authorization Service over the
grant's RFC 8785 form. The wire contract of UMA for Agents lists five echoed
fields (nonce, family, template id, terms URI, purpose); these cases also
require the scope to be echoed, since an echo that widens the scope widens the
binding.

| Case | Signature verifies | Expected |
| --- | --- | --- |
| uma-bound | yes | verified, `agent_bound` |
| uma-other-agent | yes | rejected, `agent_mismatch` |
| uma-other-principal | yes | rejected, `principal_mismatch` |
| uma-scope-widened | yes | rejected, `scope_exceeded` |
| uma-edited-after-signing | no | rejected, `signature_invalid` |
| uma-signed-by-other-key | no | rejected, `signature_invalid` |
| uma-purpose-not-echoed | yes | rejected, `echo_mismatch` |
| uma-scope-not-echoed | yes | rejected, `echo_mismatch` |
| uma-prohibition-dropped | yes | rejected, `terms_weakened` |
| uma-expiry-extended | yes | rejected, `terms_weakened` |
| hcp-bound | yes | verified, `agent_bound` |
| hcp-other-agent | yes | rejected, `agent_mismatch` |
| hcp-other-principal | yes | rejected, `principal_mismatch` |
| hcp-scope-widened | yes | rejected, `scope_exceeded` |
| hcp-edited-after-signing | no | rejected, `signature_invalid` |
| hcp-grant-revoked | yes | rejected, `grant_inactive` |
| hcp-scopes-beyond-access | yes | rejected, `scope_not_backed` |
| hcp-principal-not-subject | yes | rejected, `principal_mismatch` |

The first four rows of each form are the shared test: the same request
changed in its agent, its principal or its scope, against a binding whose
signature verifies. A verifier that checks only the signature accepts all
three changes. The rows after them are each form's own failure: an echo that
does not match what the owner proffered, terms weakened in the echo, a grant
revoked, scope strings that grant more than the grant's access, and an
Authorizing Principal who is not the Context Subject with no delegation named.

## Running it

The package judges the corpus with its own reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-principal-binding
```

A verifier under test takes `case.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `verified` and 1 for
`rejected`:

```sh
agent-evidence-vectors --corpus vectors-principal-binding --verifier './verifier'
python3 vectors-principal-binding/check_vectors.py --verifier './verifier'
```

The reader checks in this order and names the first check that fails:
signature under the trusted key, echo of the template, terms not weakened,
grant active, scope strings backed by access, agent, principal, scope. The
order is part of the contract, so a binding that fails two checks has one
expected reason.

Regenerate the cases with `python3 vectors-principal-binding/gen_vectors.py`.
The keys are Ed25519 seeds derived from published labels in the generator, so
anyone can rebuild every signature; they protect nothing.

Passing these cases does not establish that the principal approved the
binding in person, that the agent key is held only by the agent, or that the
binding is current at the relying party beyond the status the record carries.
