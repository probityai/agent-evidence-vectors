# OpenCRE links

Nine terms in [`vocabulary.yaml`](../vocabulary.yaml) carry an `opencre` list
that links each one to the Common Requirement in [OpenCRE](https://www.opencre.org)
whose standards state the same requirement. The links live in the registry
itself, which is the self-maintaining method OpenCRE's contributing guide
prefers: OpenCRE's importer reads `https://www.opencre.org/cre/NNN-NNN` URLs from
the file at a release tag, so a link moves with its term and needs no separate
mapping sheet. The `meta.opencre_links` key in the registry states the field's
rules.

Each link declares its fit with a crosswalk match type. `structural` means the
term and the requirement answer the same question in a different shape.
`partial` means real overlap with a named divergence, which the basis states.
No link here is `exact`.

| term | CRE | match | basis |
| --- | --- | --- | --- |
| `evidence_dimensions.observation_vantage` | [026-280](https://www.opencre.org/cre/026-280) Securely transfer logs (remotely) | partial | Both keep the record of an execution where the executed party cannot alter it; the requirement moves logs off the host, while this term grades where each input was obtained. |
| `posture_and_coverage.containment_posture` | [515-021](https://www.opencre.org/cre/515-021) Sandbox, containerize and/or isolate applications at the network level | structural | The term records which network isolation the artifact actually ran inside, read from the substrate, so a consumer can require the isolation that requirement asks for. |
| `posture_and_coverage.coverage_denominator` | [433-442](https://www.opencre.org/cre/433-442) Verification | partial | Testing at a stated depth and coverage (SA-11) needs the assessed population named; the term commits that population so an empty result over nothing assessed cannot pass as a clean one. |
| `record_lifecycle.revision_reason` | [757-271](https://www.opencre.org/cre/757-271) Use source code control system with change traceability and access control | partial | Both require every change to carry its reason so changes can be traced; the requirement covers source check-ins, while this term covers a published record's derived values. |
| `change_admission.admission_decision` | [112-648](https://www.opencre.org/cre/112-648) Change management | structural | Each proposed change to an agent's harness gets one recorded admit or reject decision, and a rejection is signed like an admission. |
| `change_admission.admission_gate` | [124-564](https://www.opencre.org/cre/124-564) Configuration Management | structural | Names the checks a harness change must pass before it is admitted, the change-control and impact-analysis step (CM-3, CM-4) applied to an agent's harness. |
| `change_admission.admission_gate` | [547-824](https://www.opencre.org/cre/547-824) AI model performance validation | partial | The heldout and no_regression gates validate the changed agent's behaviour on fresh runs; the change is to the harness, not the model, and the other gates are not validation. |
| `change_admission.replay_coverage` | [433-442](https://www.opencre.org/cre/433-442) Verification | partial | States whether a replay checked every recorded trace or stopped early, the coverage a test result has to declare (SA-11); it covers replays of guards only. |
| `change_admission.authority_change` | [524-603](https://www.opencre.org/cre/524-603) Limit modification of access controls to specifically authorized actors/users | structural | A harness change that adds a tool or removes a guard modifies the agent's access policy, and needs a human-signed approval naming the exact candidate. |
| `done_verification.acceptance_observed` | [433-442](https://www.opencre.org/cre/433-442) Verification | partial | Testing in development and acceptance (ISO 27001, SA-11) asks that tests be run and their results kept; the term adds that a separate verifier reruns the contract's commands on the rebuilt final tree, which the requirement does not ask for. |
| `change_admission.authority_change` | [220-442](https://www.opencre.org/cre/220-442) Model action privilege minimization | partial | Holds a candidate's tool allowlist to its parent's unless a human approves the widening; it bounds growth, and does not show the parent's set was minimal. |

## Terms with no link

Each was checked against all 522 CREs that OpenCRE's REST API returned on
2026-10-13, reading every candidate's linked standards. The seven
`done_verification` terms below were searched on 2026-10-17 in the names
and linked standards of the same 522 CREs. The fourteen `incident_response` terms
were searched on 2026-10-30 by text in the OpenCRE REST API for incident
response, containment, revoke, restoration, recovery, escalation, separation
of duties, roles and responsibilities, and accountability. The results were
plans, training, user-credential and password items, and role-assignment items
(ISO 27001 5.2, NIST SSDF PO.2.1, PCI DSS role requirements); searches for
revoke access, revocation of credentials and delegated authority returned no
result. That search did not read every CRE, so each row names the nearest
requirement found and what it does not ask for. The `multi_agent_run` terms
were searched on 2026-11-03 the same way, for multi-agent, agent communication,
inter-agent, message routing, topology, network segmentation, segregation,
isolation, sandbox, restart, restore, recovery, configuration integrity,
assessment, evaluation, detection, anomaly, model output, error handling and
fail securely. Multi-agent, agent communication, inter-agent, message routing,
restart and configuration integrity returned no result; the rest returned
network segregation and isolation items (515-021, 273-600, 708-355), recovery
and incident items (240-464, 463-577), detection and monitoring items (058-083,
843-475), and error-handling items (842-876, 513-183, 141-555). Each row names
the nearest of these and what it does not ask for.

| term | why no CRE fits |
| --- | --- |
| `evidence_dimensions.observation_directness` | no standard in OpenCRE separates a live capture from a post-hoc reconstruction |
| `evidence_dimensions.witness_scope` | a label for whose account a record is; segregation of duties (284-521) is an anti-fraud authorization control |
| `evidence_dimensions.field_evidence_partition` | no requirement splits one signed object's fields by which signer backs each |
| `evidence_dimensions.issuance_time_basis` | the time requirements (770-362, NIST AU-8) trust the system clock, the opposite of an issuer-independent time floor |
| `evidence_dimensions.commitment_anchor` | the time requirements (770-362, NIST AU-8) trust the system clock, and none bounds when a record existed by an external anchor over its digest |
| `evidence_dimensions.anchor_time_rule` | no requirement names the rule by which an anchoring ceiling is derived |
| `evidence_dimensions.attestation_tier` | no requirement separates a subject the signer re-derived from one it signed as supplied |
| `evidence_dimensions.origin_kind` | no requirement names which party assembled a record |
| `evidence_dimensions.independence_basis` | no requirement records whether a guarantee was shown by sources independent of the party it is about |
| `evidence_dimensions.party_role` | no requirement assigns named roles to the parties around one evidence set |
| `evidence_dimensions.control_relation` | no requirement states who can direct the party a claim is about |
| `evidence_dimensions.evidence_origin_class` | no requirement classes an evidence item by the act that produced it |
| `evidence_dimensions.intent_binding` | no requirement fixes whether an action's authorizing intent was committed before it ran or asserted after |
| `posture_and_coverage.does_not_assert` | the transparency requirements tell users about a system's limits, not what one signed claim withholds |
| `posture_and_coverage.claim_subject` | no requirement separates claims about a tool, an agent and an organization |
| `posture_and_coverage.base_state_resolution` | no requirement fixes how the before-state of an observed change interval is resolved |
| `posture_and_coverage.set_sufficiency` | no requirement grades an evidence set's sufficiency apart from each item's reliability |
| `posture_and_coverage.material_change_trigger` | change management (112-648) governs changes to a system; ending a standing claim when an assumed circumstance changes is a different requirement |
| `outcome_lattice.result` | the nearest, 307-507, is about where build and runtime code comes from; a verdict a relying party recomputes from carried records has no CRE |
| `change_admission.evaluation_mode` | no requirement distinguishes a fresh evaluation from a replayed or cached one |
| `done_verification.done_contract` | no requirement fixes the definition of done for an automated worker before it acts and binds later records to its digest |
| `done_verification.done_receipt` | no requirement asks for a replayable bundle from which a third party recomputes a done verdict |
| `done_verification.protected_path` | the nearest, change management (112-648), governs changes to a system; a list of files an automated worker must not touch during one task is a different requirement |
| `done_verification.claimed_tool_output` | no requirement separates what an automated worker says it ran from what was recorded |
| `done_verification.observed_tool_output` | the nearest, secure log transfer (026-280), moves logs off a host; recording what an automated worker executed from a vantage it cannot reach is a different requirement |
| `done_verification.stop_decision` | no requirement keys the continuation of an automated loop to a published table of verdicts |
| `done_verification.inconclusive_verdict` | no requirement gives the unknown outcome of a check its own value apart from pass and fail |
| `change_admission.replay_snapshot` | archiving build data for a release (461-680) is the nearest, and pinning the evaluation input of one decision is a different requirement |
| `multi_agent_run.message_delivery_disposition` | segregation of networks (515-021) and of components of differing trust levels (273-600) ask that channels be separated; none asks that each message be classed, against the topology rebuilt from a run's own record, as delivered over a present edge, delivered over a removed one, or dropped |
| `multi_agent_run.topology_enforcement` | the isolation items found (515-021, 708-355 with NIST SC-3 and SC-39) require that separation be enforced; none asks a record to say whether a declared topology was enforced by a router or only stated to the agents it restricts |
| `multi_agent_run.topology_decision_basis` | the detection items found (058-083 monitoring, 843-475 with NIST AI 100-2 detection techniques) ask that attacks be detected; none asks what label or input steered one containment decision, or separates a detector from knowledge of which agents were compromised |
| `multi_agent_run.restart_scope` | system recovery and reconstitution (240-464 with NIST CP-10) asks that a system be restored to a known state; none separates a restart that cleared an agent's memory from one that also changed the configuration that caused the fault, shown by two configuration digests |
| `multi_agent_run.restoration_evidence_binding` | assessment and decision on information security events (463-577 with ISO 27001 5.25) and recovery (240-464) ask for a decision before recovery; none binds the decision to re-enable one agent to the earlier record entries it rests on by digest, so a third party re-derives it |
| `multi_agent_run.assessment_availability` | the error-handling items found (842-876, 513-183) govern how a system reports its own errors; none asks that a missing assessment score carry its cause as a value and never be read as a score of zero |
| `multi_agent_run.generation_outcome` | error handling (842-876 with NIST SI-11) and fail securely (141-555) govern how an application handles its errors; none asks that the result of one agent's call to its model be recorded as produced, errored or empty, apart from the agent choosing to say nothing |
| `principal_identity.identity_provider` | the identity and authentication items found govern how a system authenticates users and services; none asks a record to name, from the issuer URL it signs, which identity provider vouched for a principal, or to separate a self-issued principal from one a third party vouched for |
| `principal_identity.issuer_key_pinning` | the key-management and certificate-validation items found ask that keys be managed and certificates validated; none asks a record to say whether a client pinned an issuer's signing key by RFC 7638 thumbprint before its first call and refused on a mismatch, with no fallback |
| `incident_response.response_decision` | no requirement makes a decision not to act a signed record of its own; the incident-response and plan items found read as procedures to maintain, not as a record of one choice at one decision point |
| `incident_response.response_function` | no requirement names the functions an incident action serves (monitoring, notification, restriction, isolation, pause, remediation, restoration) as a closed list a record carries |
| `incident_response.evidence_state` | the incident and monitoring items found ask for detection and logging to exist; none orders what responders have observed about one system, from an unmeasured silence to a requested restart, into codes with observable entry conditions a third party re-derives |
| `incident_response.enforcement_vantage` | no requirement says where an action was enforced and observed relative to the party it restricts; segregation of duties (284-521) separates who may act, not where enforcement was seen |
| `incident_response.control_failure_posture` | no requirement names the posture applied when a decision service returns no usable decision (denied, proceeded, started without one, answered late) as a value a third party counts |
| `incident_response.revocation_state` | the user-credential and password items found cover issuing and rotating credentials; none separates a revocation issued from one a relying party recorded refusing |
| `incident_response.containment_scope` | the sandbox and isolate requirement (515-021) fits one network posture at one time; a partition of every channel a subject could use against a manifest the subject does not control, observed over an interval, is a different requirement |
| `incident_response.pause_hold` | no requirement separates an effect the paused subject caused after the pause from state it left behind before it |
| `incident_response.escalation_outcome` | no requirement asks that the alert, notification and first-action times be carried so the delay from alert to action is computed from the record |
| `incident_response.restoration_decision` | change management (112-648) governs changes to a system; the decision that ends a recorded containment, bound to it by digest with an approver different from the activator, is a different requirement |
| `incident_response.restoration_gate` | no requirement asks whether an observed restart was preceded by a decision that met the stated requirements, with the restart time taken from the substrate |
| `incident_response.incident_identifier` | no requirement asks for an identifier, scoped by its issuer, that lets two organisations' signed records of one incident be joined |
| `incident_response.decision_role` | the role-assignment requirements found (ISO 27001 5.2, NIST SSDF PO.2.1, PCI DSS roles and responsibilities) assign roles in advance; none records the role a named party held in one decision, or separates advice from authority |
| `incident_response.authority_basis` | no requirement names the kind of grant (a role, a standing policy, a contract, an executive approval) that let an authorizer act, as a value a record carries |
| `incident_response.revocation_coverage` | the user-credential and password items found cover issuing and rotating credentials; none states how much of an issuance population a revocation reached against a manifest the revoker does not control |

## History

On 2026-09-25 three terms (`result`, `observation_vantage` and
`coverage_denominator`) were proposed under CRE 307-507 in
[OpenCRE #1045](https://github.com/OWASP/OpenCRE/issues/1045#issuecomment-5833174570),
and on 2026-10-01 `opencre-links.json` recorded them in this repository. Read
against 307-507's own standards (ASVS V10.3.2, NIST SSDF PS.2.1), none of the
three holds: those sections are about the integrity and origin of code and
resources a deployer loads. The links above replace that file, so the registry
is the one place a link is declared.

`scripts/check_opencre_links.py` holds the registry and this page to each other
on every push, and asks opencre.org that every linked CRE exists.
