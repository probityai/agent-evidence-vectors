package corpusreaders_test

// The principal-action reader derives every decision from the envelope and the
// pins. Each case below moves one member's envelope into the strict baseline and
// requires the reader to report the move, so a reader that echoed the declared
// decision passes the committed corpus and fails here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const paDir = "vectors-principal-action"

func TestPrincipalActionCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(paDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["verified"] == 0 || counts["rejected"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestPrincipalActionEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct{ from, want string }{
		{"statement-malformed", "rejected/statement_malformed/"},
		{"recorder-signature-invalid", "rejected/recorder_signature_invalid/"},
		{"statement-not-canonical", "rejected/statement_not_canonical/"},
		{"action-digest-mismatch", "rejected/action_digest_mismatch/"},
		{"agent-thumbprint-mismatch", "rejected/principal_agent:principal_thumbprint_mismatch/"},
		{"user-provider-mismatch", "rejected/principal_user:principal_provider_mismatch/"},
		{"agent-pin-mismatch", "rejected/principal_agent:principal_pin_mismatch/"},
		{"user-expired", "rejected/principal_user:principal_expired/"},
		{"agent-key-not-pinned", "rejected/principal_agent:principal_key_not_pinned/"},
		{"act-names-another-agent", "rejected/principal_act_names_another_agent/"},
		{"approver-not-an-approval-signer", "rejected/principal_approver_not_an_approval_signer/"},
		{"basic-four-principals-act-absent", "verified/basic/act-absent"},
	}
	for _, c := range cases {
		copied := filepath.Join(t.TempDir(), paDir)
		copyTree(t, corpusPath(paDir), copied)
		body, err := os.ReadFile(filepath.Join(copied, "cases", c.from, "envelope.json")) // #nosec G304 -- a test reading its own corpus copy
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(copied, "cases", "strict-four-principals", "envelope.json")
		if err := os.WriteFile(target, body, 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := corpusreaders.Judge(copied)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range result.Members {
			if m.ID == "strict-four-principals" && strings.Contains(strings.Join(m.Findings, " "), "derived "+c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("moving %s into strict-four-principals: no finding naming %s", c.from, c.want)
		}
	}
}

// The pins are the verifier's policy. Unreading them refuses the baseline at the
// first issuer check, so a reader that ignored the pins is caught.
func TestPrincipalActionPinsDecide(t *testing.T) {
	copied := filepath.Join(t.TempDir(), paDir)
	copyTree(t, corpusPath(paDir), copied)
	caseFile := filepath.Join(copied, "cases", "strict-four-principals", "case.json")
	body, err := os.ReadFile(caseFile) // #nosec G304 -- a test reading its own corpus copy
	if err != nil {
		t.Fatal(err)
	}
	unpinned := strings.Replace(string(body), "\"pins\"", "\"unread\"", 1)
	if err := os.WriteFile(caseFile, []byte(unpinned), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpusreaders.Judge(copied)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range result.Members {
		if m.ID == "strict-four-principals" &&
			strings.Contains(strings.Join(m.Findings, " "), "derived rejected/principal_user:principal_issuer_untrusted/") {
			return
		}
	}
	t.Error("with its pins unread the baseline must be refused as untrusted")
}
