package observedeffect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const invocationBindingProfile = "../interop/observed-invocation-binding-candidate"

// invocationBindingCandidates holds the new profile beside the immutable released
// corpus. It verifies fixture byte pins before using any expected outcome.
func invocationBindingCandidates(t *testing.T) ([]manifestVector, map[string]string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(invocationBindingProfile, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Vectors []struct {
			ID                        string `json:"id"`
			File                      string `json:"file"`
			SHA256                    string `json:"sha256"`
			ExpectedInvocationBinding string `json:"expectedInvocationBinding"`
			Expected                  struct {
				Verdict string   `json:"verdict"`
				Codes   []string `json:"codes"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Vectors) == 0 {
		t.Fatal("invocation-binding candidate profile is empty")
	}
	var vectors []manifestVector
	pins := map[string]string{}
	for _, row := range profile.Vectors {
		path := filepath.Join(invocationBindingProfile, row.File)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != row.SHA256 {
			t.Fatalf("%s: candidate fixture digest mismatch", row.ID)
		}
		relative, err := filepath.Rel(corpusDir, path)
		if err != nil {
			t.Fatal(err)
		}
		vector := manifestVector{ID: row.ID, Slug: row.ID, File: relative}
		vector.Expected.Verdict = row.Expected.Verdict
		vector.Expected.Codes = row.Expected.Codes
		vectors = append(vectors, vector)
		pins[row.ID] = row.ExpectedInvocationBinding
	}
	return vectors, pins
}

func TestInvocationBindingCandidateProfile(t *testing.T) {
	m := loadManifest(t)
	vectors, pins := invocationBindingCandidates(t)
	for _, vector := range vectors {
		t.Run(vector.ID, func(t *testing.T) {
			policy := testPolicy(t, m)
			policy.ExpectedInvocationBinding = pins[vector.ID]
			report := Verify(readVector(t, vector), policy)
			want := vector.Expected.Verdict + ":" + strings.Join(vector.Expected.Codes, ",")
			if outcome(report) != want {
				t.Fatalf("expected %s, got %s", want, outcome(report))
			}
		})
	}
}
