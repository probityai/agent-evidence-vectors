package corpora_test

// The authority-at-dispatch reader derives every decision from the record and
// the dispatched bytes. Swapping one member's record or bytes for another's
// must move the derived decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const adDir = "vectors-authority-at-dispatch"

func adStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), adDir)
	copyTree(t, corpusPath(adDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func adRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(adDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAuthorityDispatchCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(adDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestAuthorityDispatchEachCheckMovesTheVerdict(t *testing.T) {
	reasons := []string{"contract-id-missing", "contract-id-unknown", "evidence-age-inconsistent",
		"stale-authority-evidence", "revoked-before-dispatch", "grant-expired",
		"scope-amplified-across-hops", "dispatched-object-differs", "dispatched-action-differs"}
	for _, from := range reasons {
		t.Run("allow-direct with the record of "+from, func(t *testing.T) {
			dir := adStage(t, "allow-direct", "record.json", adRead(t, from, "record.json"))
			got := scDerived(t, dir, "allow-direct")
			if !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("allow-direct with changed bytes", func(t *testing.T) {
		dir := adStage(t, "allow-direct", "dispatched.bin", adRead(t, "dispatched-bytes-differ", "dispatched.bin"))
		got := scDerived(t, dir, "allow-direct")
		for _, want := range []string{"derived deny/dispatch_not_approved", "dispatch matches approval: false"} {
			if !strings.Contains(got, want) {
				t.Fatalf("want %q in %q", want, got)
			}
		}
	})
	t.Run("a denied record with the allowed record", func(t *testing.T) {
		dir := adStage(t, "revoked-before-dispatch", "record.json", adRead(t, "allow-direct", "record.json"))
		if got := scDerived(t, dir, "revoked-before-dispatch"); !strings.Contains(got, "derived allow/authorized") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestAuthorityDispatchUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"dispatch":{"payloadFile":"absent.bin"}}`, "absent.bin cannot be read"},
		{`{"contractId":"https://probityai.github.io/agent-evidence-observer/contract/authority-at-dispatch/v1",` +
			`"decisionTime":"soon","dispatch":{"payloadFile":"dispatched.bin"},` +
			`"authorityEvidence":{"observedAt":"2026-10-03T11:59:30Z"}}`, "does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := adStage(t, "allow-direct", "record.json", []byte(tc.body))
			if got := scDerived(t, dir, "allow-direct"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}

func TestAuthorityDispatchDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), adDir)
	copyTree(t, corpusPath(adDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"authorized"`, `"authorized "`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("want a corpusDigest finding")
	}
	if err := os.WriteFile(path, []byte(`{"suite":"authority-at-dispatch/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
