package corpusreaders_test

// The key-directory reader derives the decision and the resulting cache from the
// fetch as recorded. The cases below swap one member's case file for another's
// and require the reader to report the move, so a reader that echoed the
// declared answer passes the committed corpus and fails here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const kdDir = "vectors-key-directory-observation"

func kdStage(t *testing.T, member, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), kdDir)
	copyTree(t, corpusPath(kdDir), copied)
	for _, name := range []string{"case.json", "response.body"} {
		target := filepath.Join(copied, "cases", member, name)
		body, err := os.ReadFile(filepath.Join(corpusPath(kdDir), "cases", from, name)) // #nosec G304 -- a test reading its own corpus
		if err != nil {
			_ = os.Remove(target)
			continue
		}
		if err := os.WriteFile(target, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return copied
}

func TestKeyDirectoryCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(kdDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["attributed"] == 0 || counts["not_attributed"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestKeyDirectoryEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct{ member, from, want string }{
		{"empty-key-set-evicts", "status-404-keeps-cache", "derived not_attributed/discovery_failed cache kept"},
		{"status-404-keeps-cache", "empty-key-set-evicts", "derived not_attributed/key_absent_from_directory cache replaced"},
		{"key-listed", "redirect-not-followed", "derived not_attributed/redirect_not_followed"},
		{"key-listed", "html-error-page-with-200", "derived not_attributed/not_a_directory"},
		{"empty-key-set-evicts", "refused-with-empty-key-set-keeps-cache", "derived not_attributed/discovery_failed cache kept"},
		{"refused-with-empty-key-set-keeps-cache", "empty-key-set-evicts", "derived not_attributed/key_absent_from_directory cache replaced"},
		{"key-listed", "limit-refused-keeps-cache", "derived not_attributed/discovery_failed cache kept"},
		{"key-listed", "no-keys-member-keeps-cache", "derived not_attributed/not_a_directory cache kept"},
		{"key-listed", "empty-body-keeps-cache", "derived not_attributed/not_a_directory cache kept"},
		{"kid-thumbprint-at-well-known", "kid-not-thumbprint-at-well-known", "derived not_attributed/kid_not_thumbprint"},
		{"kid-not-thumbprint-at-well-known", "kid-thumbprint-at-well-known", "derived attributed/key_in_directory"},
	}
	for _, tc := range cases {
		t.Run(tc.member+"<-"+tc.from, func(t *testing.T) {
			result, err := corpusreaders.Judge(kdStage(t, tc.member, tc.from))
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			found := false
			for _, m := range result.Members {
				if m.ID != tc.member {
					continue
				}
				for _, f := range m.Findings {
					if strings.Contains(f, tc.want) {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("moving %s into %s did not report %q: %v", tc.from, tc.member, tc.want, result.Members)
			}
		})
	}
}
