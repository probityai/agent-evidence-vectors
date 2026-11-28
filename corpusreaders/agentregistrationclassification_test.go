package corpusreaders_test

// The registration reader derives every verdict from the record and its context.
// Each case below moves one committed case's bytes into the positive member's
// slot and requires the reader to report the move: a reader that echoed the
// declared reason would pass the committed corpus and fail every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const arcDir = "vectors-agent-registration-classification"

func TestAgentRegistrationClassificationCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(arcDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["registration_credit"] != 1 || counts["no_registration_credit"] == 0 {
		t.Fatalf("one credited case and the refusals must be present: %v", counts)
	}
}

func TestAgentRegistrationClassificationEachCaseMovesTheVerdict(t *testing.T) {
	cases := []struct{ from, reason string }{
		{"anonymous-mcp-discovery", "not_registration_event"},
		{"challenge-expired", "challenge_expired_or_not_yet_issued"},
		{"challenge-replayed", "challenge_replayed"},
		{"challenge-state-null", "challenge_state_unverified"},
		{"child-agent", "ephemeral_or_child_agent"},
		{"consent-revoked", "consent_not_affirmative"},
		{"duplicate-agent", "agent_already_registered"},
		{"duplicate-consent-scope", "evidence_bytes_not_strict_json"},
		{"forged-agent-signature", "agent_proof_invalid"},
		{"forged-registry-receipt", "durable_receipt_signature_invalid"},
		{"tampered-committed-digest", "durable_receipt_binding_mismatch"},
		{"wrong-challenge-key", "challenge_key_mismatch"},
		{"agent-id-null", "malformed_or_missing_evidence"},
	}
	for _, c := range cases {
		copied := filepath.Join(t.TempDir(), arcDir)
		copyTree(t, corpusPath(arcDir), copied)
		for _, name := range []string{"record.json", "context.json"} {
			body, err := os.ReadFile(filepath.Join(copied, "cases", c.from, name)) // #nosec G304 -- a test reading its own corpus copy
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(copied, "cases", "valid-new-registration", name)
			if err := os.WriteFile(target, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		result, err := corpusreaders.Judge(copied)
		if err != nil {
			t.Fatal(err)
		}
		var findings []string
		for _, m := range result.Members {
			if m.ID == "valid-new-registration" {
				findings = m.Findings
			}
		}
		if !strings.Contains(strings.Join(findings, " "), "reason="+c.reason+",") {
			t.Errorf("%s: the reader did not derive %s: %v", c.from, c.reason, findings)
		}
	}
}
