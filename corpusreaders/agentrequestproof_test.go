package corpusreaders_test

// The request-proof reader derives every decision from the envelopes. The cases
// below move one member's envelope into a verified member and require the
// reader to report the move. A reader that echoed the declared decision passes
// the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const arpDir = "vectors-agent-request-proof"

func TestAgentRequestProofCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(arpDir))
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

func TestAgentRequestProofEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct{ from, want string }{
		{"statement-malformed", "rejected/statement_malformed"},
		{"recorder-signature-invalid", "rejected/recorder_signature_invalid"},
		{"wrong-typ", "rejected/typ_mismatch"},
		{"alg-none", "rejected/alg_not_allowed"},
		{"thumbprint-mismatch", "rejected/thumbprint_mismatch"},
		{"proof-signature-invalid", "rejected/proof_signature_invalid"},
		{"principal-mismatch", "rejected/principal_mismatch"},
		{"htm-htu-mismatch", "rejected/htm_htu_mismatch"},
		{"body-digest-mismatch", "rejected/body_digest_mismatch"},
		{"expired", "rejected/proof_expired"},
	}
	for _, c := range cases {
		copied := filepath.Join(t.TempDir(), arpDir)
		copyTree(t, corpusPath(arpDir), copied)
		body, err := os.ReadFile(filepath.Join(copied, "cases", c.from, "envelope-1.json")) // #nosec G304 -- a test reading its own corpus copy
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(copied, "cases", "request-bound", "envelope-1.json")
		if err := os.WriteFile(target, body, 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := corpusreaders.Judge(copied)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range result.Members {
			if m.ID == "request-bound" && strings.Contains(strings.Join(m.Findings, " "), "derived "+c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("moving %s into request-bound: no finding naming %s", c.from, c.want)
		}
	}
}

func TestAgentRequestProofReplayNeedsTheEarlierRecord(t *testing.T) {
	copied := filepath.Join(t.TempDir(), arpDir)
	copyTree(t, corpusPath(arpDir), copied)
	caseFile := filepath.Join(copied, "cases", "replayed-jti", "case.json")
	body, err := os.ReadFile(caseFile) // #nosec G304 -- a test reading its own corpus copy
	if err != nil {
		t.Fatal(err)
	}
	dropped := strings.Replace(string(body), "\"envelope-1.json\",\n    ", "", 1)
	if dropped == string(body) {
		t.Fatal("the replay case does not list an earlier envelope")
	}
	if err := os.WriteFile(caseFile, []byte(dropped), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpusreaders.Judge(copied)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range result.Members {
		if m.ID == "replayed-jti" && strings.Contains(strings.Join(m.Findings, " "), "derived verified/request_bound") {
			return
		}
	}
	t.Error("without the earlier record the replayed proof must verify on its own")
}

// The audience, kid and tenant checks read pins from case.json. Without the
// pins the same valid proof verifies, so a reader that ignored them would
// match the declared rejection only by echoing it.
func TestAgentRequestProofPinsDecideTheirCases(t *testing.T) {
	for _, name := range []string{"audience-mismatch", "kid-mismatch", "tenant-mismatch", "tenant-claim-absent"} {
		copied := filepath.Join(t.TempDir(), arpDir)
		copyTree(t, corpusPath(arpDir), copied)
		caseFile := filepath.Join(copied, "cases", name, "case.json")
		body, err := os.ReadFile(caseFile) // #nosec G304 -- a test reading its own corpus copy
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "\"pins\"") {
			t.Fatalf("%s carries no pins", name)
		}
		unpinned := strings.Replace(string(body), "\"pins\"", "\"unread\"", 1)
		if err := os.WriteFile(caseFile, []byte(unpinned), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := corpusreaders.Judge(copied)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range result.Members {
			if m.ID == name && strings.Contains(strings.Join(m.Findings, " "), "derived verified/request_bound") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: with its pins unread the proof must verify", name)
		}
	}
}
