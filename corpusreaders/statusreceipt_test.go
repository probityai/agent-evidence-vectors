package corpusreaders_test

// The status-receipt reader derives every decision from the two envelopes and
// case.json. The cases below move one member's file onto another member, or
// damage one, and require the reader to report the move. A reader that echoed
// the declared decision passes the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const srbDir = "vectors-status-receipt-binding"

func srbStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), srbDir)
	copyTree(t, corpusPath(srbDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func srbRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(srbDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestStatusReceiptCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(srbDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accept"] == 0 || counts["reject"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestStatusReceiptEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, file, from, want string
	}{
		{"accept-bound", "credential.json", "capabilities-escalated", "derived reject/credential_digest_mismatch"},
		{"accept-bound", "credential.json", "key-swapped", "derived reject/credential_digest_mismatch"},
		{"accept-bound", "credential.json", "key-added", "derived reject/credential_digest_mismatch"},
		{"capabilities-escalated", "credential.json", "accept-bound", "derived accept/credential_bound"},
		{"accept-bound", "receipt.json", "receipt-status-only", "derived reject/receipt_unbound"},
		{"accept-bound", "receipt.json", "receipt-for-earlier-version", "derived reject/credential_digest_mismatch"},
		{"accept-bound", "receipt.json", "receipt-for-other-credential", "derived reject/credential_id_mismatch"},
		{"accept-bound", "receipt.json", "receipt-altered-after-signing", "derived reject/receipt_signature_invalid"},
		{"accept-bound", "receipt.json", "receipt-window-inverted", "derived reject/receipt_malformed"},
		{"accept-bound", "receipt.json", "receipt-member-unexpected", "derived reject/receipt_malformed"},
		{"accept-bound", "receipt.json", "credential-suspended", "derived reject/credential_not_active"},
		{"accept-bound", "credential.json", "credential-signed-by-unlisted-key", "derived reject/credential_signature_invalid"},
		{"accept-bound", "credential.json", "credential-altered-after-signing", "derived reject/credential_signature_invalid"},
		{"accept-bound", "credential.json", "credential-kid-repeated", "derived reject/credential_malformed"},
		{"accept-bound", "case.json", "receipt-expired", "derived reject/receipt_expired"},
		{"accept-bound", "case.json", "receipt-not-yet-valid", "derived reject/receipt_not_yet_valid"},
		{"receipt-signed-by-other-key", "receipt.json", "accept-bound", "the receipt signature verifies: true"},
		{"credential-signed-by-unlisted-key", "credential.json", "accept-bound", "the credential signature verifies: true"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := srbStage(t, tc.member, tc.file, srbRead(t, tc.from, tc.file))
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

func TestStatusReceiptUnreadableInputsAreRefusals(t *testing.T) {
	cases := []struct {
		member, file, body, want string
	}{
		{"accept-bound", "case.json", "{", "case.json does not parse"},
		{"accept-bound", "receipt.json", "[]", "derived reject/receipt_malformed"},
		{"accept-bound", "receipt.json", `{"payload":null,"payloadType":"x","signatures":[]}`, "derived reject/receipt_malformed"},
		{"accept-bound", "credential.json", `{"payload":"e30=","payloadType":null,"signatures":[{"keyid":null,"sig":""}]}`, "derived reject/credential_malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.file+" "+tc.want, func(t *testing.T) {
			dir := srbStage(t, tc.member, tc.file, []byte(tc.body))
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

func TestStatusReceiptSharedReceiptIsRecomputed(t *testing.T) {
	copied := filepath.Join(t.TempDir(), srbDir)
	copyTree(t, corpusPath(srbDir), copied)
	path := filepath.Join(copied, corpusreaders.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"sharedReceipt": [
        "receipt-status-only-forged-credential"
      ]`, `"sharedReceipt": []`, 1)
	if damaged == string(raw) {
		t.Fatal("the manifest no longer carries the status-only pair")
	}
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpusreaders.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	joined := strings.Join(result.Findings, "\n")
	for _, want := range []string{"receipt-status-only: sharedReceipt", "corpusDigest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("want %q in %q", want, joined)
		}
	}
}
