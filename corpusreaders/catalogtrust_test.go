package corpusreaders

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

const ctDir = "../corpora/vectors-catalog-trust-manifest"

// The Go reader is a second implementation of the profile: every member of the
// committed corpus reaches the verdict and reason its manifest declares.
func TestCatalogTrustCorpusIsClean(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(ctDir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	result, err := catalogTrust{}.Judge(ctDir, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Members) < 88 {
		t.Fatalf("judged %d members, the corpus holds at least 88", len(result.Members))
	}
	for _, m := range result.Members {
		for _, f := range m.Findings {
			t.Errorf("%s: %s", m.ID, f)
		}
	}
	for _, f := range result.Findings {
		t.Errorf("corpus: %s", f)
	}
}

func TestCatalogTrustNumberFormIsECMAScript(t *testing.T) {
	for value, want := range map[float64]string{1: "1", 0.5: "0.5", 1e-7: "1e-7",
		0.000001: "0.000001", -2.5e-10: "-2.5e-10", 123.456: "123.456", 100: "100",
		9007199254740991: "9007199254740991", 5e-324: "5e-324", 1e21: "1e+21"} {
		if got, err := ctNumberForm(value); err != nil || got != want {
			t.Errorf("%v: got %q (%v), want %q", value, got, err, want)
		}
	}
}

func TestCatalogTrustInstants(t *testing.T) {
	for text, want := range map[string]string{
		"2026-11-01T00:00:00Z":      "1793491200",
		"2026-11-01T01:00:00+01:00": "1793491200",
		"2026-11-01t00:00:00.5z":    "3586982401/2",
		"0000-02-29T00:00:00Z":      "-62162121600",
		"2026-11-01T23:59:60Z":      "1793577600",
	} {
		got := ctInstant(text)
		expected, _ := new(big.Rat).SetString(want)
		if got == nil || got.Cmp(expected) != 0 {
			t.Errorf("%s: got %v, want %s", text, got, want)
		}
	}
	for _, text := range []string{"2026-02-30T00:00:00Z", "2026-11-01T24:00:00Z",
		"2026-11-01T00:00:00", "1900-02-29T00:00:00Z", "2026-11-01T00:00:00+24:00",
		"٢٠٢٦-11-01T00:00:00Z"} {
		if got := ctInstant(text); got != nil {
			t.Errorf("%s: got %v, want no instant", text, got)
		}
	}
}

func TestCatalogTrustParserKeepsALoneSurrogateDistinct(t *testing.T) {
	value, err := ctParse([]byte(`{"a":"\ud800","b":"😀"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctCanonical(value); err == nil {
		t.Error("a lone surrogate has no RFC 8785 form, and the writer produced one")
	}
	if _, err := ctParse([]byte(`{"a":1,"a":2}`)); err != errCTDuplicate {
		t.Errorf("a repeated member: got %v", err)
	}
	if _, err := ctParse([]byte(`{"a":NaN}`)); err != errCTInvalid {
		t.Errorf("NaN: got %v", err)
	}
}
