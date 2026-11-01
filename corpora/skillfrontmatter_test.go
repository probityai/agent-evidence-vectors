package corpora_test

// The skill-frontmatter reader derives every outcome from the SKILL.md. The
// committed corpus reaches each refusal code; the cases below put one member's
// file in another member's place, so the derived outcome moves, and require the
// reader to say so. A reader that echoed the manifest would pass the committed
// corpus and fail every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const sfDir = "vectors-skill-frontmatter"

func sfStage(t *testing.T, member, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), sfDir)
	copyTree(t, corpusPath(sfDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, "SKILL.md")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "SKILL.md"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestSkillFrontmatterCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(sfDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accepted"] != 20 || counts["refused"] != 43 || counts["needs-yaml"] != 2 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestSkillFrontmatterReaderDerivesRatherThanEchoes(t *testing.T) {
	cases := []struct{ member, from, want string }{
		{"minimal", "bom", "derived error byte-order-mark line=1"},
		{"minimal", "document-end", "derived error document-end-marker"},
		{"minimal", "duplicate-different-value", "derived error duplicate-key"},
		{"minimal", "unterminated", "derived error unterminated-frontmatter"},
		{"bom", "minimal", "derived ok keys=[name description]"},
		{"duplicate-same-value", "dashes-inside-value", "derived ok keys="},
		{"crlf", "cr-only", "derived ok keys=[name]"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the file of "+tc.from, func(t *testing.T) {
			result, err := corpora.Judge(sfStage(t, tc.member, tc.from))
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			for _, m := range result.Members {
				if m.ID == tc.member {
					if got := strings.Join(m.Findings, "; "); !strings.Contains(got, tc.want) {
						t.Fatalf("want a finding containing %q, got %q", tc.want, got)
					}
					return
				}
			}
			t.Fatalf("member %s is not in the result", tc.member)
		})
	}
}

func TestSkillFrontmatterMutatedFileIsRefusedByDigest(t *testing.T) {
	copied := filepath.Join(t.TempDir(), sfDir)
	copyTree(t, corpusPath(sfDir), copied)
	path := filepath.Join(copied, "cases", "minimal", "SKILL.md")
	if err := os.WriteFile(path, []byte("---\nname: changed\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	for _, m := range result.Members {
		if m.ID == "minimal" && strings.Contains(strings.Join(m.Findings, "; "), "does not match its manifest digest") {
			return
		}
	}
	t.Fatal("a changed SKILL.md was not refused by its digest")
}
