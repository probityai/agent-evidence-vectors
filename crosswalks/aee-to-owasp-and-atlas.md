# AEE to the OWASP agentic taxonomies, NIST AI RMF, and MITRE ATLAS

Written 2026-07-28. Offered as a basis for collaboration.

Most crosswalks in this space answer "which of your categories does my finding belong to." AEE cannot answer that, because it produces no findings. It describes how an observation was obtained and whether a third party can re-check it.

So this maps in the other direction: for each category, what would count as evidence that a claim about it is true, and which part of that is currently unaddressed by any taxonomy in the list.

## The direct hit

**MCP08, Lack of Audit and Telemetry.** This is the one category in either OWASP agentic top ten whose subject matter is the record itself rather than an attack against the system. Every other entry names something an adversary does; this one names the absence of the thing that would let you find out.

That makes it the natural home for an evidence predicate, and it is also where the category as currently written stops short. "Lack of audit and telemetry" is satisfied by the presence of logs. It does not distinguish between a log the workload wrote about itself and a record produced by an observer the workload could not edit. Those two artifacts look identical in an audit checklist and behave completely differently under an adversary who has compromised the workload.

The distinction AEE draws, and the one worth adding to the category's guidance, is between two values of a single field. A reconstructed basis means the account was assembled after the fact, from records the observed party produced or could have influenced. An intercepted basis means an observer in the data path recorded the event as it happened.

A telemetry pipeline that is fail-open, or an execution log the observed process can write to, is reconstructed no matter how complete it looks. Both are real patterns in shipping products, and both pass a "do you have audit and telemetry" question as currently phrased.

## Where the rest of MCP Top 10 needs evidence rather than classification

Verified titles, read from the published crosswalk corpus on 2026-07-28.

| ID | Title | The evidentiary question the category leaves open |
|---|---|---|
| MCP01 | Token Mismanagement and Secret Exposure | Did the secret leave the boundary? Answerable only if something outside the workload watched egress. networkPosture records whether it could have. |
| MCP02 | Privilege Escalation via Scope Creep | Scope at which moment? A claim about privilege needs the run pinned, not the config inspected later. |
| MCP03 | Tool Poisoning | Poisoned when? A static read gives the examination method; whether the poisoned definition was ever used is a runtime claim. |
| MCP04 | Software Supply Chain Attacks | The corpus digest is the whole claim. Without it, "we scanned it" names no artifact. |
| MCP05 | Command Injection and Execution | Executed or merely reachable? This is exactly the examination versus interception split. |
| MCP06 | Intent Flow Subversion | Requires ordered observations, which requires an observer with a clock the workload does not set. |
| MCP07 | Insufficient Authentication and Authorization | A configuration claim, checkable statically. examination is honest and sufficient here. |
| MCP08 | Lack of Audit and Telemetry | See above. The category is where the predicate belongs. |
| MCP09 | Shadow MCP Servers | Discovery is an observation about a network, so the observation environment is the evidence. |
| MCP10 | Context Injection and Over-sharing | What actually crossed the boundary, not what policy said should. |

The pattern across the ten: seven of the rows above (MCP01, 02, 03, 05, 06, 09 and 10) describe conditions that can only be confirmed or denied by something that watched a real execution. MCP04 and MCP07 are answerable statically, and MCP08 is about the record itself.

## NIST AI RMF

Four subcategories appear in the published record corpus with enough frequency to be worth mapping. MEASURE-2.5 and MEASURE-2.6 are where an evidence predicate belongs: they concern whether a measurement is valid and reliable, which is a question about the measuring apparatus rather than the system measured. MANAGE-1.3 and MANAGE-2.2 concern acting on findings, which presumes the findings can be trusted.

An attested, offline-re-verifiable record is a direct answer to the MEASURE family. It is the difference between asserting a control was tested and being able to hand someone the test's own record.

## MITRE ATLAS

The technique IDs carried by the record corpus cluster on AML.T0054, AML.T0048, AML.T0043 and AML.T0011. ATLAS describes adversary behaviour and deliberately says nothing about the provenance of the observation that detected it, which is the correct scope for a technique catalogue and the reason there is no conflict here.

The useful pairing is that an ATLAS technique names what to look for, and an AEE record carries what was seen, under which method, by an observer in a stated position. Neither replaces the other.

## The gap this crosswalk exists to name

Across all four taxonomies, the categories describe what can go wrong and, in the RMF case, what should be measured. Nothing in the material read for this pass specifies what a claim about the result must be able to prove, or to whom. That is a statement about what was read and not a proof of absence: this pass covered the MCP Top 10 titles, the NIST subcategory identifiers and the ATLAS technique identifiers carried by the record corpus, not the full text of all four taxonomies.

That is not a criticism. A taxonomy that also mandated an evidence format would be doing two jobs badly. But it does leave a layer unoccupied, and a detection rule evaluated over a record the observed party controls is confidently wrong in the most dangerous direction: it reports a clean result on a compromised system, and the cleanliness is exactly what the compromise produced.

## What this does not claim

AEE detects nothing and classifies nothing. It cannot tell you that a component is malicious. It can only make the account of how you found out checkable by someone who was not there.

Two limits worth stating in the same breath: AEE is presently exercised by a first-party implementation set, so agreement between implementations is a drift check rather than independent corroboration, and the predicate is a proposal to in-toto, made in attestation pull request 570, rather than a ratified standard.

## Provenance

MCP Top 10 titles were read from the published AVE crosswalk corpus on 2026-07-28, and the NIST AI RMF and MITRE ATLAS identifiers derive from the same 59-record corpus. ASI Top 10 identifiers appear there too, but their category titles were not verified against a primary OWASP source for this pass, so they are referenced by ID only and not characterised. The AEE field vocabulary comes from spec/predicates/adversarial-execution-evidence.md. This mapping was written against suiteRevision 9 of the conformance suite, then 158 vectors; vectors/MANIFEST.json gives the current revision and size. The predicate is proposed upstream in in-toto/attestation pull request 570.
