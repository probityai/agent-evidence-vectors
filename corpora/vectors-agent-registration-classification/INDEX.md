# Test vector index

| ID | Registration credit | Reason |
|---|---|---|
| valid-new-registration | true | registration_evidence_sufficient_for_fixture |
| anonymous-mcp-discovery | false | not_registration_event |
| signed-report-not-registration | false | not_registration_event |
| quarantined-report | false | not_durably_committed |
| consent-revoked | false | consent_not_affirmative |
| wrong-consent-purpose | false | consent_scope_mismatch |
| child-agent | false | ephemeral_or_child_agent |
| duplicate-swarm | false | swarm_already_registered |
| duplicate-agent | false | agent_already_registered |
| nonce-not-issued | false | challenge_binding_mismatch |
| challenge-expired | false | challenge_expired_or_not_yet_issued |
| challenge-replayed | false | challenge_replayed |
| challenge-state-missing | false | challenge_state_unverified |
| challenge-state-null | false | challenge_state_unverified |
| challenge-state-text | false | challenge_state_unverified |
| wrong-challenge-key | false | challenge_key_mismatch |
| forged-agent-signature | false | agent_proof_invalid |
| tampered-committed-digest | false | durable_receipt_binding_mismatch |
| forged-registry-receipt | false | durable_receipt_signature_invalid |
| missing-registry-receipt | false | malformed_or_missing_evidence |
| agent-id-null | false | malformed_or_missing_evidence |
| swarm-id-null | false | malformed_or_missing_evidence |
| parent-marker-absent | false | malformed_or_missing_evidence |
| duplicate-consent-scope | false | evidence_bytes_not_strict_json |
