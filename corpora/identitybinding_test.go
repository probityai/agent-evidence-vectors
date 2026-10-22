package corpora_test

// The identity-binding reader derives every decision from the envelope and the
// resolution fixtures. The cases below swap one member's file for another's, or
// damage one, and require the reader to report the move. A reader that echoed
// the declared decision passes the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const ibDir = "vectors-identity-binding"

// ibStage copies the corpus and writes body over member/name.
func ibStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ibDir)
	copyTree(t, corpusPath(ibDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ibRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ibDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestIdentityBindingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(ibDir))
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

func TestIdentityBindingEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, file, from, want string
	}{
		{"web-verified", "envelope.json", "payload-altered", "derived rejected/signature_invalid"},
		{"web-verified", "envelope.json", "key-not-in-authentication", "derived rejected/key_not_authorized"},
		{"web-signed-before-rotation", "envelope.json", "web-key-rotated-out", "derived rejected/key_rotated_out"},
		{"web-key-rotated-out", "envelope.json", "web-signed-before-rotation", "derived verified/subject_bound"},
		{"wba-verified", "did-alice.json", "wba-deactivated-before-signing", "derived rejected/key_rotated_out"},
		{"wba-verified", "did-alice.json", "wba-fingerprint-mismatch", "derived rejected/binding_fingerprint_mismatch"},
		{"wba-fingerprint-mismatch", "did-alice.json", "wba-verified", "derived rejected/signature_invalid"},
		{"wba-verified", "envelope.json", "did-unresolvable", "derived rejected/did_unresolvable"},
		{"wba-verified", "envelope.json", "did-malformed", "derived rejected/did_malformed"},
		{"web-verified", "envelope.json", "subject-swap", "derived rejected/signer_not_subject"},
		{"payload-altered", "envelope.json", "web-verified", "the signature verifies: true"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := ibStage(t, tc.member, tc.file, ibRead(t, tc.from, tc.file))
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

func TestIdentityBindingUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct {
		member, file string
		body         string
		want         string
	}{
		{"web-verified", "case.json", "{", "case.json does not parse"},
		{"web-verified", "envelope.json", "[]", "envelope.json does not parse"},
		{"web-verified", "envelope.json", `{"payload":"!!","signatures":[{"keyid":"x"}]}`, "the payload is not base64"},
		{"web-verified", "envelope.json", `{"payload":"e30=","signatures":[]}`, "carries no signature"},
		{"web-verified", "did-alice.json", "{", "did-alice.json does not parse"},
		{"web-verified", "envelope.json", `{"payload":"eyJzaWduZWRBdCI6Im5vdyJ9","signatures":[{"keyid":"x"}]}`, "does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.file+" "+tc.want, func(t *testing.T) {
			dir := ibStage(t, tc.member, tc.file, []byte(tc.body))
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

func TestIdentityBindingMissingResolutionFileIsUnresolvable(t *testing.T) {
	copied := filepath.Join(t.TempDir(), ibDir)
	copyTree(t, corpusPath(ibDir), copied)
	if err := os.Remove(filepath.Join(copied, "cases", "web-verified", "did-alice.json")); err != nil {
		t.Fatal(err)
	}
	got := scDerived(t, copied, "web-verified")
	for _, want := range []string{"did-alice.json is declared and absent", "derived rejected/did_unresolvable"} {
		if !strings.Contains(got, want) {
			t.Fatalf("want %q in %q", want, got)
		}
	}
}

func TestIdentityBindingDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), ibDir)
	copyTree(t, corpusPath(ibDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"subject_bound"`, `"subject_bound "`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) == 0 || !strings.Contains(result.Findings[0], "corpusDigest") {
		t.Fatalf("want a corpusDigest finding, got %v", result.Findings)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("an unparseable manifest must be an error")
	}
}
