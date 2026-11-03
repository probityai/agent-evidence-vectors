package corpusreaders

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sigCovSource(t *testing.T, text string) any {
	t.Helper()
	value, err := sigCovDecode([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSignatureCoverageAgreesWithEveryMember(t *testing.T) {
	dir := filepath.Join("..", "corpora", "vectors-signature-coverage")
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := signatureCoverage{}.Judge(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	var manifest struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(result.Members) != len(manifest.Vectors) || len(result.Members) == 0 {
		t.Fatalf("judged %d members of %d", len(result.Members), len(manifest.Vectors))
	}
	for _, member := range result.Members {
		if len(member.Findings) != 0 {
			t.Errorf("%s: %v", member.ID, member.Findings)
		}
	}
}

func TestSignatureCoverageRepeatIsFoundAtEveryDepth(t *testing.T) {
	cases := map[string]bool{
		`{"entries":[["a",1],["a",2]]}`:                                  true,
		`{"entries":[["x",{"entries":[["a",1],["a",2]]}]]}`:              true,
		`{"entries":[["x",[{"entries":[["a",1],["b",2],["a",3]]}]]]}`:    true,
		`{"entries":[["a",1],["A",2]]}`:                                  false,
		`{"entries":[["x",{"entries":[["a",1]]}],["y",{"entries":[["a",2]]}]]}`: false,
	}
	for text, want := range cases {
		if got := sigCovRepeats(sigCovSource(t, text)); got != want {
			t.Errorf("%s: repeats=%v, want %v", text, got, want)
		}
	}
}

func TestSignatureCoverageComparisonKeepsTypesApart(t *testing.T) {
	number := sigCovSource(t, `1`)
	if sigCovSame(number, sigCovSource(t, `"1"`)) || sigCovSame(sigCovSource(t, `true`), number) {
		t.Error("a number compared equal to a string or a boolean")
	}
	if !sigCovSame(number, sigCovSource(t, `1.0`)) {
		t.Error("1 and 1.0 are one JSON number")
	}
}
