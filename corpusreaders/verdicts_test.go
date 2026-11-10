package corpusreaders_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

var verdictCorpora = []string{
	"vectors-attenuated-delegation",
	"vectors-grant-use",
	"vectors-revocation-epoch",
	"vectors-durable-history",
	"vectors-approval-binding-v2",
	"vectors-decision-client-failure-modes",
}

// Every case's verdict, derived from record.json alone, equals what the
// manifest declares, and the lines come out in manifest order.
func TestVerdictLinesMatchManifest(t *testing.T) {
	for _, name := range verdictCorpora {
		t.Run(name, func(t *testing.T) {
			dir := corpusPath(name)
			raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json")) // #nosec G304 -- a test reading its own corpus
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Vectors []struct {
					ID       string `json:"id"`
					Expected struct {
						Decision string `json:"decision"`
						Reason   string `json:"reason"`
					} `json:"expected"`
				} `json:"vectors"`
			}
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			lines, err := corpusreaders.VerdictLines(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(lines) != len(manifest.Vectors) || len(lines) == 0 {
				t.Fatalf("got %d lines for %d vectors", len(lines), len(manifest.Vectors))
			}
			for i, vector := range manifest.Vectors {
				want := vector.ID + "\t" + vector.Expected.Decision + "\t" + vector.Expected.Reason
				if lines[i] != want {
					t.Errorf("line %d: got %q, want %q", i, lines[i], want)
				}
			}
		})
	}
}

func TestRecordVerdictRefusals(t *testing.T) {
	if _, err := corpusreaders.RecordVerdict("no-such/v1", []byte("{}")); err == nil {
		t.Error("an unknown suite was not refused")
	}
	if _, err := corpusreaders.GrantUseVerdict([]byte("[1]")); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("a non-object record was not refused: %v", err)
	}
	if _, err := corpusreaders.GrantUseVerdict([]byte("{")); err == nil {
		t.Error("an unparsable record was not refused")
	}
}

func TestVerdictLinesRefusesUnknownSuiteAndMissingManifest(t *testing.T) {
	dir := t.TempDir()
	if _, err := corpusreaders.VerdictLines(dir); err == nil {
		t.Error("a directory with no manifest was not refused")
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.json"), []byte(`{"suite":"nope/v1","vectors":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpusreaders.VerdictLines(dir); err == nil || !strings.Contains(err.Error(), "unknown suite") {
		t.Errorf("an unknown suite was not refused: %v", err)
	}
}
