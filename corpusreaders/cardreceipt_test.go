package corpora_test

// The agent-card-receipt and credential-release reader derives every decision
// from the member's own files. Moving one member's files into another must move
// the derived decision to the one the first member declares, and the reader must
// report the move.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const (
	crReceiptDir = "vectors-agent-card-receipt"
	crReleaseDir = "vectors-credential-release"
	crReceiptCtl = "accept-card-without-signatures"
	crReleaseCtl = "accept-release-on-passing-receipt"
)

type crRow struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Expected struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"expected"`
}

func crRows(t *testing.T, dir string) []crRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(dir), corpora.ManifestName)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []crRow `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Vectors
}

func crStage(t *testing.T, dir string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dir)
	copyTree(t, corpusPath(dir), copied)
	return copied
}

func crWrite(t *testing.T, corpus, member, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(corpus, "cases", member, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func crTransplant(t *testing.T, dir, into, from string) string {
	t.Helper()
	copied := crStage(t, dir)
	entries, err := os.ReadDir(filepath.Join(copied, "cases", from))
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(copied, "cases", from, entry.Name())) // #nosec G304 -- a test reading its own copy
		if err != nil {
			t.Fatal(err)
		}
		crWrite(t, copied, into, entry.Name(), string(body))
		kept[entry.Name()] = true
	}
	for _, name := range []string{"card.json", "context.json", "receipt.json", "revocations.json", "statement.json"} {
		if !kept[name] {
			_ = os.Remove(filepath.Join(copied, "cases", into, name)) // absent in the source member, so absent in the copy
		}
	}
	return copied
}

func TestCardReceiptCommittedCorporaAreClean(t *testing.T) {
	for _, dir := range []string{crReceiptDir, crReleaseDir} {
		result, err := corpora.Judge(corpusPath(dir))
		if err != nil {
			t.Fatalf("%s: judge: %v", dir, err)
		}
		if !result.OK() || len(result.Members) == 0 {
			t.Fatalf("%s: findings: %v %v", dir, result.Findings, result.Members)
		}
		counts := result.CountsByVerdict()
		if counts["accept"] == 0 || counts["reject"] == 0 {
			t.Fatalf("%s: both verdicts must be present: %v", dir, counts)
		}
	}
}

// Every member's files, placed under a different member, derive the first
// member's declared decision: the verdict is a function of the bytes alone.
func TestCardReceiptEveryMemberIsDerivedFromItsFiles(t *testing.T) {
	for _, tc := range []struct{ dir, control string }{
		{crReceiptDir, crReceiptCtl}, {crReleaseDir, crReleaseCtl},
	} {
		for _, row := range crRows(t, tc.dir) {
			t.Run(tc.dir+"/"+row.ID, func(t *testing.T) {
				staged := crTransplant(t, tc.dir, tc.control, row.ID)
				want := "derived " + row.Expected.Decision + "/" + row.Expected.Reason
				got := scDerived(t, staged, tc.control)
				if row.ID == tc.control {
					if got != "" {
						t.Fatalf("the control must be clean, got %q", got)
					}
					return
				}
				if !strings.Contains(got, "does not match its manifest digest") && !strings.Contains(got, "is declared and absent") {
					t.Fatalf("the transplant must be reported, got %q", got)
				}
				if row.Expected.Decision == "accept" {
					if strings.Contains(got, "derived ") {
						t.Fatalf("an accepting member must derive the control's accept, got %q", got)
					}
					return
				}
				if !strings.Contains(got, want) {
					t.Fatalf("want %q in %q", want, got)
				}
			})
		}
	}
}

func TestCardReceiptUnreadableInputsMoveTheVerdict(t *testing.T) {
	t.Run("a receipt with no parseable statement", func(t *testing.T) {
		staged := crStage(t, crReceiptDir)
		crWrite(t, staged, crReceiptCtl, "statement.json", "{")
		if got := scDerived(t, staged, crReceiptCtl); !strings.Contains(got, "derived reject/statement_malformed") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("a card that is not JSON", func(t *testing.T) {
		staged := crStage(t, crReceiptDir)
		crWrite(t, staged, crReceiptCtl, "card.json", "{")
		if got := scDerived(t, staged, crReceiptCtl); !strings.Contains(got, "derived reject/card_malformed") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("a check time after the receipt expires", func(t *testing.T) {
		staged := crStage(t, crReceiptDir)
		body, err := os.ReadFile(filepath.Join(staged, "cases", crReceiptCtl, "context.json")) // #nosec G304 -- a test reading its own copy
		if err != nil {
			t.Fatal(err)
		}
		later := strings.Replace(string(body), `"now": "2026-10-27T12:00:00Z"`, `"now": "2099-01-01T00:00:00Z"`, 1)
		crWrite(t, staged, crReceiptCtl, "context.json", later)
		if got := scDerived(t, staged, crReceiptCtl); !strings.Contains(got, "derived reject/receipt_expired") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("a release with no receipt", func(t *testing.T) {
		staged := crStage(t, crReleaseDir)
		if err := os.Remove(filepath.Join(staged, "cases", crReleaseCtl, "receipt.json")); err != nil {
			t.Fatal(err)
		}
		if got := scDerived(t, staged, crReleaseCtl); !strings.Contains(got, "derived reject/receipt_digest_mismatch") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("a release with no revocation list", func(t *testing.T) {
		staged := crStage(t, crReleaseDir)
		if err := os.Remove(filepath.Join(staged, "cases", crReleaseCtl, "revocations.json")); err != nil {
			t.Fatal(err)
		}
		if got := scDerived(t, staged, crReleaseCtl); !strings.Contains(got, "derived reject/revocation_list_digest_mismatch") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("an undeclared file in a member", func(t *testing.T) {
		staged := crStage(t, crReceiptDir)
		crWrite(t, staged, crReceiptCtl, "extra.json", "{}")
		if got := scDerived(t, staged, crReceiptCtl); !strings.Contains(got, "extra.json is present and not declared") {
			t.Fatalf("got %q", got)
		}
	})
}

func TestCardReceiptDamagedManifestIsAFinding(t *testing.T) {
	for _, dir := range []string{crReceiptDir, crReleaseDir} {
		copied := crStage(t, dir)
		path := filepath.Join(copied, corpora.ManifestName)
		raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
		if err != nil {
			t.Fatal(err)
		}
		// The counts block sits outside the digest, so damage a row after the vectors key.
		rows := strings.Index(string(raw), `"vectors"`)
		damaged := string(raw)[:rows] + strings.Replace(string(raw)[rows:], `"accept"`, `"accept "`, 1)
		if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := corpora.Judge(copied)
		if err != nil {
			t.Fatalf("judge: %v", err)
		}
		if len(result.Findings) == 0 {
			t.Fatalf("%s: want a corpusDigest finding", dir)
		}
		if err := os.WriteFile(path, []byte(`{"suite":"`+result.Suite+`","vectors":7}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := corpora.Judge(copied); err == nil {
			t.Fatalf("%s: a manifest whose rows are not a list must be an error", dir)
		}
	}
}
