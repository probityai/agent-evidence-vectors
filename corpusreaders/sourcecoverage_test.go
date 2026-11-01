package corpora_test

// The source coverage reader applies five rules in order. The committed corpus
// shows each rule reached once; the cases below mutate one committed member so
// that exactly one rule changes its outcome, and require the reader to derive
// the new decision. A reader that returned the declared decision without
// reading the bytes passes the committed corpus and fails every case here.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const scDir = "vectors-source-coverage"

func scStage(t *testing.T) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), scDir)
	copyTree(t, corpusPath(scDir), copied)
	return copied
}

func scHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// scEdit rewrites one JSON file of one member through edit.
func scEdit(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scAssessment(doc map[string]any, caseName string) map[string]any {
	assessments := doc["assessments"].(map[string]any)
	return assessments["source-coverage-"+caseName].(map[string]any)
}

func scCapture(doc map[string]any) map[string]any {
	return doc["witnesses"].(map[string]any)["capture"].(map[string]any)
}

func scSetSpan(text string) func(map[string]any) {
	return func(doc map[string]any) {
		a := scAssessment(doc, "complete")
		a["required_spans"] = []any{map[string]any{"id": "selected", "text": text}}
	}
}

// scDerived judges the staged corpus and returns the findings of one member.
func scDerived(t *testing.T, dir, id string) string {
	t.Helper()
	result, err := corpora.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	for _, m := range result.Members {
		if m.ID == id {
			return strings.Join(m.Findings, "; ")
		}
	}
	t.Fatalf("member %s is not in the result", id)
	return ""
}

func TestSourceCoverageEachRuleChangesTheVerdict(t *testing.T) {
	cases := []struct {
		name   string
		member string
		mutate func(t *testing.T, dir string)
		want   string
	}{
		{"rule 1: a record whose bytes no longer match its digest is unbound", "complete",
			func(t *testing.T, dir string) {
				flipOneByte(t, filepath.Join(dir, "cases", "complete", "report.txt"))
			}, "derived not_established/artifact_unavailable_or_unbound"},
		{"rule 1: a capture that is absent is unbound", "complete",
			func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "cases", "complete", "source.html")); err != nil {
					t.Fatal(err)
				}
			}, "derived not_established/artifact_unavailable_or_unbound"},
		{"rule 2: a capture taken after the window is outside it", "complete",
			func(t *testing.T, dir string) {
				scEdit(t, filepath.Join(dir, "cases", "complete", "policy.json"), func(doc map[string]any) {
					scCapture(doc)["captured_at"] = "2019-06-27T12:00:00Z"
				})
			}, "derived not_established/witness_outside_source_window"},
		{"rule 3: a passage only a head script carries is not in the witness", "complete",
			func(t *testing.T, dir string) {
				scEdit(t, filepath.Join(dir, "cases", "complete", "policy.json"),
					scSetSpan("A hidden claim was never published."))
			}, "derived not_established/selected_span_not_in_witness"},
		{"rule 4: a bound record without the passage is contradicted", "complete",
			func(t *testing.T, dir string) {
				caseDir := filepath.Join(dir, "cases", "complete")
				shorter := []byte("The publisher described the initial incident.\n")
				if err := os.WriteFile(filepath.Join(caseDir, "report.txt"), shorter, 0o600); err != nil {
					t.Fatal(err)
				}
				scEdit(t, filepath.Join(caseDir, "case.json"), func(doc map[string]any) {
					doc["artifacts"].(map[string]any)["record"].(map[string]any)["sha256"] = scHex(shorter)
				})
				scEdit(t, filepath.Join(caseDir, "policy.json"), func(doc map[string]any) {
					scAssessment(doc, "complete")["record_sha256"] = scHex(shorter)
				})
			}, "derived contradicted/selected_span_missing_from_record"},
		{"rule 5: a passage both artifacts carry is supported", "middle-omission",
			func(t *testing.T, dir string) {
				scEdit(t, filepath.Join(dir, "cases", "middle-omission", "policy.json"), func(doc map[string]any) {
					a := scAssessment(doc, "middle-omission")
					a["required_spans"] = []any{map[string]any{
						"id": "selected", "text": "The publisher described the initial incident."}}
				})
			}, "derived supported/all_selected_spans_present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := scStage(t)
			tc.mutate(t, dir)
			if got := scDerived(t, dir, tc.member); !strings.Contains(got, tc.want) {
				t.Errorf("findings for %s: %q, want %q", tc.member, got, tc.want)
			}
		})
	}
}

func TestSourceCoverageUnreadableCasesAreFindings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, caseDir string)
		want   string
	}{
		{"case.json does not parse", func(t *testing.T, caseDir string) {
			if err := os.WriteFile(filepath.Join(caseDir, "case.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "case.json does not parse"},
		{"policy.json is absent", func(t *testing.T, caseDir string) {
			if err := os.Remove(filepath.Join(caseDir, "policy.json")); err != nil {
				t.Fatal(err)
			}
		}, "policy.json cannot be read"},
		{"no assessment for the case", func(t *testing.T, caseDir string) {
			scEdit(t, filepath.Join(caseDir, "policy.json"), func(doc map[string]any) {
				doc["assessments"] = map[string]any{}
			})
		}, "no assessment for case"},
		{"the named witness is undefined", func(t *testing.T, caseDir string) {
			scEdit(t, filepath.Join(caseDir, "policy.json"), func(doc map[string]any) {
				doc["witnesses"] = map[string]any{}
			})
		}, "defines none"},
		{"a timestamp does not parse", func(t *testing.T, caseDir string) {
			scEdit(t, filepath.Join(caseDir, "policy.json"), func(doc map[string]any) {
				scCapture(doc)["captured_at"] = "yesterday"
			})
		}, "does not parse"},
		{"the source format is not article text", func(t *testing.T, caseDir string) {
			scEdit(t, filepath.Join(caseDir, "policy.json"), func(doc map[string]any) {
				scCapture(doc)["source_format"] = "pdf_text/v1"
			})
		}, "is not html_article_text/v1"},
		{"an undeclared file sits in the member", func(t *testing.T, caseDir string) {
			if err := os.WriteFile(filepath.Join(caseDir, "extra.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "extra.txt is in the member and not in the manifest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := scStage(t)
			tc.mutate(t, filepath.Join(dir, "cases", "complete"))
			if got := scDerived(t, dir, "complete"); !strings.Contains(got, tc.want) {
				t.Errorf("findings: %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSourceCoverageCorpusLevelFindings(t *testing.T) {
	t.Run("a changed corpus digest is refused", func(t *testing.T) {
		dir := scStage(t)
		scEdit(t, filepath.Join(dir, corpora.ManifestName), func(doc map[string]any) {
			doc["corpusDigest"] = strings.Repeat("0", 64)
		})
		result, err := corpora.Judge(dir)
		if err != nil {
			t.Fatal(err)
		}
		if result.OK() || len(result.Findings) == 0 ||
			!strings.Contains(result.Findings[0], "does not match the recomputed") {
			t.Errorf("findings: %v", result.Findings)
		}
	})
	t.Run("a missing member directory is a member finding", func(t *testing.T) {
		dir := scStage(t)
		if err := os.RemoveAll(filepath.Join(dir, "cases", "complete")); err != nil {
			t.Fatal(err)
		}
		if got := scDerived(t, dir, "complete"); !strings.Contains(got, "cannot be read") {
			t.Errorf("findings: %q", got)
		}
	})
	t.Run("a manifest that does not parse is an error", func(t *testing.T) {
		dir := t.TempDir()
		manifest := []byte(`{"suite":"source-text-coverage/v1","vectors":{}}`)
		if err := os.WriteFile(filepath.Join(dir, corpora.ManifestName), manifest, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := corpora.Judge(dir); err == nil {
			t.Error("a manifest whose vectors are not a list was judged")
		}
	})
}
