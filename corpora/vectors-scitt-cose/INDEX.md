# SCITT/COSE carriage vectors for adversarial execution evidence

Emitted by `gen_vectors.py`. Do not edit: an edit here is overwritten on
the next build and `scripts/regenerability-gate.py` refuses the push that
makes one.

Profile: `aee-scitt-cose/v0.1`, specified in `profiles/scitt-cose.md`.
Payload predicate: `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

Each member is a Transparent Statement as RFC 9943 Section 7 defines one.
The `parent` column names the conforming member a refusal is one mutation
from. An indeterminate member has no parent because there is no conforming
form of a question the documents do not answer.

| vector | verdict | conditions | what it carries | parent |
| --- | --- | --- | --- | --- |
| `v0636cd5206c6a98c` | reject | `sc-c-2` | RFC 9942 Section 5.2.1: "vdp (label: 396): REQUIRED" and "inclusion-proof (label: -1): REQUIRED". A receipt with a signature and no proof establishes that a transparency service signed something, and nothing about this statement being in its log. | `v11816a7dc863a687` |
| `v0fa72e24c8012749` | accept | `sc-c-2` `sc-c-3` | RFC 9943 Section 7: label 394 is an array that can carry more than one Receipt, and Section 7.1 lets a Relying Party "decide to verify only a single Receipt that is acceptable to them". Both are verifiable here, so a verifier that requires all of them and one that requires one both accept. |  |
| `v11816a7dc863a687` | accept | `sc-c-1` `sc-c-2` `sc-c-3` `sc-c-4` `sc-c-5` `sc-c-6` `sc-c-7` `sc-c-8` `sc-c-9` `sc-c-10` `sc-c-11` `sc-c-12` `sc-c-13` `sc-c-14` | RFC 9943 Section 6 and Section 7: a COSE_Sign1 Signed Statement with protected CWT Claims carrying iss and sub, and a Receipt in label 394 of its unprotected header. Every reject member below is these bytes with one mutation. |  |
| `v13df07bd26f63dae` | accept | `sc-c-2` `sc-c-14` | RFC 9162 Section 2.1.1: MTH({d0}) is SHA-256(0x00 \|\| d0), so a log of one entry has an empty inclusion path. The boundary a proof-checker written for the interior case gets wrong. |  |
| `v1c44afeeeec6013c` | reject | `sc-c-8` | RFC 9864 Section 4.2.2: "Name: EdDSA, Value: -8, ... Recommended: Deprecated." The signature here verifies. What the profile refuses is the polymorphic identifier, because -8 does not say which curve was used and leaves the verifier to infer it from the key. | `v11816a7dc863a687` |
| `v2c7975eac1701b6c` | reject | `sc-c-14` | RFC 9942 Section 5.2 quotes RFC 9162 as a normative block: "If leaf_index is greater than or equal to tree_size, then fail the proof verification." A proof-checker that walks the path without the bound returns a root here, and the root it returns is a function of nothing. | `vf9463fb9663b49d5` |
| `v2cade3228c1da11a` | reject | `sc-c-12` | RFC 9943 Section 6: "The protected header of a Signed Statement and a Receipt MUST include the CWT Claims header parameter as specified in Section 2 of [RFC9597]. The CWT Claims value MUST include the Issuer Claim (Claim label 1) and the Subject Claim (Claim label 2)." Without them the object is a signed blob that no transparency service can register and no relying party can attribute. | `v11816a7dc863a687` |
| `v3283077e1d1b5d8c` | indeterminate | `sc-c-15` | RFC 9943 Section 7 says a Receipt "contains inclusion proofs" while the CDDL of RFC 9942 Section 4.3 admits Receipt_For_Consistency as a Receipt. A consistency proof establishes that the log is append-only and says nothing about this statement being in it. Neither document says what a Relying Party concludes from a Transparent Statement whose only receipt is a consistency receipt. |  |
| `v38bad1bbcbdbdf3d` | accept | `sc-c-1` `sc-c-13` | RFC 9943 Section 6.2: "Statement payloads might be too large or too sensitive to be sent to a remote TS." The signature still covers the full payload (RFC 9052 Section 4.4, field 5), so the verifier has to be handed the bytes out of band and reattach them. |  |
| `v41d9bfda6adac0af` | accept | `sc-c-5` `sc-c-6` | RFC 9052 Section 3.1 makes only a crit-listed parameter mandatory to understand, so an unlisted one is ignored. This is the twin that stops a verifier scoring full marks by refusing every extension it does not recognize. |  |
| `v4b65541710f581c3` | reject | `sc-c-13` | RFC 9942 Section 5.2.1: "vds (label: 395): REQUIRED. VDS algorithm identifier." Section 5.2.1 also says why: "The VDS in the protected header is necessary to understand the inclusion proof structure in the unprotected header." Absent, the proof bytes are an array whose meaning the verifier has to guess. | `v11816a7dc863a687` |
| `v5d470e62bc419824` | reject | `sc-c-6` | The profile's own requirement, and the reason it exists. The field is present and correct and no crit array lists it, so a verifier that does not implement this profile ignores the one column that says the observation came from a vantage the observed party could not reach, and reports the statement valid anyway. Fail-closed is a property of the crit listing, not of the field. | `v11816a7dc863a687` |
| `v71d601cc7c6464a1` | indeterminate | `sc-c-16` | RFC 9052 Section 3.1: "Applications SHOULD provide this header parameter if the content structure is potentially ambiguous." The CDDL of RFC 9943 Section 6.1 marks content_type optional and this profile has registered no media type, so a service that dispatches policy on content type and one that reads typ reach different answers about the same bytes. |  |
| `v7ee2786688bfdb79` | indeterminate | `sc-c-18` | Both receipts verify, both are signed by the same transparency service, both declare tree size 8, and their roots differ, which is an append-only log presenting two histories. RFC 9943 Section 7.1 permits a Relying Party to "verify only a single Receipt that is acceptable to them", so the reading that accepts is conforming and the reading that detects the fork is conforming, and detecting it at all needs consistency proofs and monitoring that no relying-party requirement in either document asks for. |  |
| `v8819ae608ecb37ff` | reject | `sc-c-7` | RFC 9942 Section 5.2.1: "alg (label: 1): REQUIRED. Signature algorithm identifier." The same confusion as the statement member, one level down, and a verifier that checks the outer envelope strictly and the receipt loosely passes the first and fails here. | `v11816a7dc863a687` |
| `v8de7afebda214319` | reject | `sc-c-12` | RFC 9597 Section 2 permits the CWT Claims header parameter in either bucket and not in both. The copies here agree, which is the point: a verifier that prefers one bucket accepts a message whose unprotected copy an attacker can rewrite, and the agreeing copy is what makes that preference invisible in testing. | `v11816a7dc863a687` |
| `va145ee9bd51df5f8` | indeterminate | `sc-c-17` | RFC 9943 Section 7: "The Registration time is recorded as the timestamp when the TS added the Signed Statement to its VDS." No header carries it, and RFC 9942 Section 7.2 states "The details of expressing validity periods are out of scope for this document." So a receipt can be complete and still place the registration nowhere in time. |  |
| `va6a19109d269c858` | reject | `sc-c-3` | RFC 9942 Section 4.4: a detached payload "force[s] verifiers to recompute the root from the proof". The receipt is genuine and its signature is valid over the root of a log that contains a DIFFERENT statement, so a verifier that checks the signature without recomputing from this statement's bytes accepts a receipt for somebody else's execution. | `v11816a7dc863a687` |
| `vacced92411f5ac61` | reject | `sc-c-7` | The protected header declares -7, ECDSA with SHA-256, and the signature is Ed25519 over the same Sig_structure. RFC 9052 Section 4.4 has a verifier pass alg to the verification algorithm, so a verifier that reads the key type instead of the declared algorithm accepts it. RFC 9864 Section 4.2.2 also marks -7 Deprecated. | `v11816a7dc863a687` |
| `vad7cde281e84a54b` | reject | `sc-c-1` | RFC 9943 Section 6: iss and sub "are used to identify the Artifact the Statement pertains to". Here sub names a digest the payload does not carry, so the signed claim about which artifact this is contradicts the artifact itself. | `v11816a7dc863a687` |
| `vb93d431e43fe61e2` | reject | `sc-c-11` | RFC 9943 Section 7.1: "A Relying Party MUST trust the verification key or certificate and the associated identity of at least one Issuer of a Receipt." The signature verifies under the trusted key and the iss claim names a different party, so a verifier that checks the key and ignores the identity attributes the statement to whoever the header says. | `v11816a7dc863a687` |
| `vc1d2e16ca13eaeb3` | reject | `sc-c-9` | RFC 8392 Section 3.1.4 defines exp, and RFC 9942 Section 7.2 points at it: "See the iat, nbf, and exp claims in [RFC8392] for one way to accomplish this." The claim is present, it is in the past at the verification time the vector declares, and this profile makes a present exp binding rather than advisory. | `v11816a7dc863a687` |
| `vc73a5ea351b6a6af` | reject | `sc-c-13` | RFC 9942 Section 4.3: "When the 'receipts' header parameter is present, the verifier MUST confirm that the associated VDS and VDPs match entries present in the registries established in this specification." Table 2 registers 0 Reserved and 1 RFC9162_SHA256 and nothing else, so 2 names a structure whose proof format is undefined. | `v11816a7dc863a687` |
| `vc8520277aa73cf0a` | reject | `sc-c-10` | RFC 8392 Section 3.1.5 defines nbf. RFC 9942 Section 7.2 asks for "activation not too far in the future" and leaves the mechanism to a profile. A statement about an execution that has not started yet is the one direction a monotonic clock check catches and a not-after-only check does not. | `v11816a7dc863a687` |
| `vecb11244fd522443` | reject | `sc-c-4` | RFC 9052 Section 3.1: "If the 'crit' value list includes a label for which the header parameter is not in the protected-header-parameters bucket, this is a fatal error in processing the message." The observer position is in the bucket the signature does not cover, so it can be swapped without breaking anything. | `v11816a7dc863a687` |
| `vf9463fb9663b49d5` | accept | `sc-c-2` `sc-c-14` | RFC 9943 Figure 11 is an inclusion proof of tree size 8 at leaf index 7 with three intermediate hashes. This is that shape, so a verifier that only ever walks a left spine fails here and passes the base. |  |
| `vfd2e3344cb6eefa6` | reject | `sc-c-5` | RFC 9052 Section 3.1: crit "is used to indicate which protected header parameters an application that is processing a message is required to understand". This profile defines no parameter at -70055, so a conforming verifier cannot understand it and must refuse rather than proceed on the part it did understand. | `v41d9bfda6adac0af` |

## Conditions

| id | what it requires |
| --- | --- |
| `sc-c-1` | sub is the digest the in-toto subject carries |
| `sc-c-2` | the receipt carries an inclusion proof |
| `sc-c-3` | the recomputed root is the root the receipt signs |
| `sc-c-4` | every crit-listed parameter sits in the protected bucket |
| `sc-c-5` | every crit-listed parameter is one the verifier can process |
| `sc-c-6` | the observer position is protected and crit-listed |
| `sc-c-7` | the declared algorithm is the algorithm that signed |
| `sc-c-8` | the algorithm identifier is fully specified |
| `sc-c-9` | exp, where present, is in the future |
| `sc-c-10` | nbf, where present, is in the past |
| `sc-c-11` | iss is the identity bound to the verification key |
| `sc-c-12` | protected CWT Claims are present exactly once |
| `sc-c-13` | vds names a registered verifiable data structure |
| `sc-c-14` | the inclusion proof is applicable to the tree it declares |
| `sc-c-15` | which proof types a receipt must carry |
| `sc-c-16` | how the payload format is declared |
| `sc-c-17` | how registration time reaches a verifier |
| `sc-c-18` | what two roots at one tree size mean to a relying party |
