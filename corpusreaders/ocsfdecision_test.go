package corpusreaders_test

// The OCSF decision reader judges the corpus on its own, in Go, from the
// published rule. These tests hold it to the manifest's declaration for all 28
// members, and each negative control changes ONE thing in a copy and requires a
// finding that names the member (or the corpus-level check) it concerns.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const ocsfDir = "vectors-ocsf-decision"

func ocsfStage(t *testing.T) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ocsfDir)
	copyTree(t, corpusPath(ocsfDir), copied)
	return copied
}

func ocsfEdit(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	changed := edit(string(body))
	if changed == string(body) {
		t.Fatalf("the edit changed nothing in %s", path)
	}
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ocsfFindings is every finding the reader makes over dir, member findings
// prefixed with the member id so a case can require the id.
func ocsfFindings(t *testing.T, dir string) []string {
	t.Helper()
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	var out []string
	for _, m := range result.Members {
		for _, f := range m.Findings {
			out = append(out, m.ID+": "+f)
		}
	}
	return append(out, result.Findings...)
}

func ocsfRequire(t *testing.T, findings []string, fragments ...string) {
	t.Helper()
	for _, f := range findings {
		all := true
		for _, want := range fragments {
			all = all && strings.Contains(f, want)
		}
		if all {
			return
		}
	}
	t.Fatalf("no finding carries %q; findings: %q", fragments, findings)
}

// All 28 members read to the verdict, the code and every dimension status the
// manifest declares, with no corpus-level finding.
func TestOCSFDecisionCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(ocsfDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Members) != 28 {
		t.Fatalf("judged %d members, want 28", len(result.Members))
	}
	if !result.OK() {
		for _, m := range result.Members {
			for _, f := range m.Findings {
				t.Errorf("%s: %s", m.ID, f)
			}
		}
		for _, f := range result.Findings {
			t.Errorf("corpus: %s", f)
		}
	}
	counts := result.CountsByVerdict()
	if counts["accept"] != 6 || counts["reject"] != 22 {
		t.Fatalf("counts by verdict are %v, want 6 accept and 22 reject", counts)
	}
}

// A member whose declared verdict, code or dimension status is changed reads
// otherwise than declared, and the finding names it.
func TestOCSFDecisionDeclarationIsHeldToTheBytes(t *testing.T) {
	cases := []struct {
		name, member string
		edit         func(string) string
		want         string
	}{
		{"verdict", "baseline-chain-as-emitted", func(s string) string {
			return strings.Replace(s, `"verdict": "accept"`, `"verdict": "reject"`, 1)
		}, "read accept"},
		{"code", "baseline-key-id-swapped", func(s string) string {
			return strings.Replace(s, `"code": "key_binding:failed"`, `"code": "signature:failed"`, 1)
		}, "read reject"},
		{"dimension", "baseline-published-signed-pair", func(s string) string {
			return strings.Replace(s, `"signature": "verified"`, `"signature": "failed"`, 1)
		}, "signature: declared failed, read verified"},
		{"strict dimension", "strict-chain-complete", func(s string) string {
			return strings.Replace(s, `"tail_anchored": "verified"`, `"tail_anchored": "not_checked"`, 1)
		}, "strict.tail_anchored: declared not_checked, read verified"},
		{"dimension the reader does not have", "baseline-chain-as-emitted", func(s string) string {
			return strings.Replace(s, `"tail": "verified"`, `"tail_x": "verified"`, 1)
		}, "no such dimension"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := ocsfStage(t)
			// Only the first occurrence in the named member's own entry changes.
			ocsfEdit(t, filepath.Join(dir, corpusreaders.ManifestName), func(s string) string {
				at := strings.Index(s, `"id": "`+tc.member+`"`)
				if at < 0 {
					t.Fatalf("the manifest has no %s", tc.member)
				}
				return s[:at] + tc.edit(s[at:])
			})
			ocsfRequire(t, ocsfFindings(t, dir), tc.member+":", tc.want)
		})
	}
}

// A byte changed in a member's records moves what the member reads to, and
// the finding names the member.
func TestOCSFDecisionFlippedRecordNamesItsMember(t *testing.T) {
	cases := []struct{ member, from, to string }{
		// The published pair's first record: the sealed disposition caption changes.
		{"baseline-published-signed-pair", `disposition\":\"Logged`, `disposition\":\"Loggeds`},
		// A key id that names the retired key.
		{"baseline-chain-as-emitted", `corpus-key-1`, `corpus-key-0`},
		// A stream stamp.
		{"baseline-published-decisions-unchained", `stream_seq\":41}`, `stream_seq\":44}`},
	}
	for _, tc := range cases {
		t.Run(tc.member, func(t *testing.T) {
			dir := ocsfStage(t)
			ocsfEdit(t, filepath.Join(dir, "members", tc.member+".json"), func(s string) string {
				return strings.Replace(s, tc.from, tc.to, 1)
			})
			ocsfRequire(t, ocsfFindings(t, dir), tc.member+":")
		})
	}
}

func TestOCSFDecisionCorpusLevelChecks(t *testing.T) {
	t.Run("a member file that is not listed", func(t *testing.T) {
		dir := ocsfStage(t)
		body, err := os.ReadFile(filepath.Join(dir, "members", "baseline-chain-as-emitted.json")) // #nosec G304 -- a test reading its own copy
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "members", "baseline-extra.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		ocsfRequire(t, ocsfFindings(t, dir), "members/baseline-extra.json", "not listed")
	})
	t.Run("a listed member file that is gone", func(t *testing.T) {
		dir := ocsfStage(t)
		if err := os.Remove(filepath.Join(dir, "members", "strict-no-head.json")); err != nil {
			t.Fatal(err)
		}
		findings := ocsfFindings(t, dir)
		ocsfRequire(t, findings, "strict-no-head:", "cannot be read")
		ocsfRequire(t, findings, "corpus digest does not recompute")
	})
	t.Run("a member the corpus digest does not cover", func(t *testing.T) {
		dir := ocsfStage(t)
		ocsfEdit(t, filepath.Join(dir, corpusreaders.ManifestName), func(s string) string {
			at := strings.Index(s, `"corpusDigest": "`) + len(`"corpusDigest": "`)
			return s[:at] + "1" + s[at+1:]
		})
		ocsfRequire(t, ocsfFindings(t, dir), "corpus digest does not recompute")
	})
	t.Run("counts that disagree with the members", func(t *testing.T) {
		dir := ocsfStage(t)
		ocsfEdit(t, filepath.Join(dir, corpusreaders.ManifestName), func(s string) string {
			return strings.Replace(s, `"accept": 6`, `"accept": 7`, 1)
		})
		ocsfRequire(t, ocsfFindings(t, dir), "counts disagree")
	})
	t.Run("a vendored source file that drifted", func(t *testing.T) {
		dir := ocsfStage(t)
		ocsfEdit(t, filepath.Join(dir, "source", "SAMPLE-OUTPUT.md"), func(s string) string {
			return strings.Replace(s, "e", "E", 1)
		})
		ocsfRequire(t, ocsfFindings(t, dir), "SAMPLE-OUTPUT.md", "pinned digest")
	})
	t.Run("a vendored source file of another length", func(t *testing.T) {
		dir := ocsfStage(t)
		ocsfEdit(t, filepath.Join(dir, corpusreaders.ManifestName), func(s string) string {
			return strings.Replace(s, `"length": 9437`, `"length": 9438`, 1)
		})
		ocsfRequire(t, ocsfFindings(t, dir), "SAMPLE-OUTPUT.md", "bytes")
	})
	t.Run("a manifest that pins nothing", func(t *testing.T) {
		dir := ocsfStage(t)
		ocsfEdit(t, filepath.Join(dir, corpusreaders.ManifestName), func(s string) string {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal([]byte(s), &doc); err != nil {
				t.Fatal(err)
			}
			return strings.Replace(s, `"files": {`, `"files_x": {`, 1)
		})
		ocsfRequire(t, ocsfFindings(t, dir), "pins no vendored source file")
	})
}
