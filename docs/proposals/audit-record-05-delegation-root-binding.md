# Proposed text for draft-gilda-audit-agent-audit-record-05: what a key set establishes about the delegation root

Change text for the next revision of Sections 4.7 and 4.7.1. A delegation-root element records the
certification path or key set the chain verifier held at decision time. A certification path names
the party the root key was issued to and the signature algorithm of each certificate on it. A key
set whose keys carry no certificate gives the key and its algorithm family and names no party, so
it records that the verifier held a key and nothing about what bound that key to a party.

Proposed text for Section 4.7, after the sentence on the delegation-root element:

> A delegation-root element that is a key set records the key the chain verifier held and its
> algorithm family. It names no party, and a verifier MUST NOT read it as binding the root key to
> one.

Proposed text for Section 4.7.1, after the sentence that establishes the delegation root:

> Beside the root's result the verifier reports the root key's JWK thumbprint [RFC7638] where the
> key set holds one key, and the binding of that key to a party. For a key set the binding is not
> established, whether or not its digest equals delegation.rootDigest, and the verifier MUST NOT
> report it as a pass (vectors R13 and R25).

The member that tests this text is `R25`: `R13` with the root a key set holding one P-256 key and
no certificate. The record is valid, the root is established under `P-256`, the manifest carries
the key's thumbprint, and the binding is `not-established`. `R13` keeps its published verdict and
result and now declares the same binding. A verifier that reports the binding established for
either member disagrees with the corpus; a verifier that omits the binding is read as reporting it
not established.

The case was raised on the WIMSE list on 23 October 2026 by Rafael Asor, as a third vector beside
`R13` (root carried) and `R14` (root omitted), and V.K. Uppalapati asked that the verdict be stated
in the element's definition rather than only in a vector, because an implementer who sees a
populated field will otherwise read it as a pass. The member that completes the set is a
delegation-root element holding a certification path that names the party, whose binding a
verifier establishes by validating the path; it is not yet in the corpus.
