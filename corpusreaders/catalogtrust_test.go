package corpusreaders

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
	if len(result.Members) < 115 {
		t.Fatalf("judged %d members, the corpus holds at least 115", len(result.Members))
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
		"2016-12-31T23:59:60Z":      "1483228800",
		"2016-12-31T18:59:60-05:00": "1483228800",
		"1972-06-30T23:59:60.5Z":    "157593601/2",
	} {
		got := ctInstant(text)
		expected, _ := new(big.Rat).SetString(want)
		if got == nil || got.Cmp(expected) != 0 {
			t.Errorf("%s: got %v, want %s", text, got, want)
		}
	}
	for _, text := range []string{"2026-02-30T00:00:00Z", "2026-11-01T24:00:00Z",
		"2026-11-01T00:00:00", "1900-02-29T00:00:00Z", "2026-11-01T00:00:00+24:00",
		"٢٠٢٦-11-01T00:00:00Z", "2026-11-01T23:59:60Z", "2026-11-01T00:00:60Z",
		"2016-12-31T23:59:60+01:00", "2016-12-30T23:59:60Z"} {
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

func TestCatalogTrustNestingIsBoundedBeforeParsing(t *testing.T) {
	open := func(n int) []byte {
		return append(bytes.Repeat([]byte("["), n), bytes.Repeat([]byte("]"), n)...)
	}
	if ctTooDeep(open(ctMaxNesting)) || !ctTooDeep(open(ctMaxNesting+1)) {
		t.Error("the limit is not exactly ctMaxNesting open arrays")
	}
	if ctTooDeep(append([]byte(`{"a": "`), append(bytes.Repeat([]byte("["), 100), `"}`...)...)) {
		t.Error("brackets inside a string were counted")
	}
	escaped := append([]byte(`["\\",`), open(ctMaxNesting)...)
	if !ctTooDeep(append(escaped, ']')) {
		t.Error("a string ending in an escaped backslash did not close")
	}
	if _, err := ctParse(open(100000)); err != errCTInvalid {
		t.Errorf("100000 open arrays: got %v", err)
	}
}

func TestCatalogTrustDSSEBase64TakesEitherAlphabet(t *testing.T) {
	for text, want := range map[string]string{"YWJj": "abc", "YWI=": "ab", "-_8=": "\xfb\xff",
		"+/8=": "\xfb\xff", "": ""} {
		if got, ok := ctDSSEDecode(text); !ok || string(got) != want {
			t.Errorf("%q: got %q %v", text, got, ok)
		}
	}
	for _, text := range []string{"YWI", "YW\nJj", "YW\r\nJj", "+_8=", "YWJj ", "YQ==YQ=="} {
		if _, ok := ctDSSEDecode(text); ok {
			t.Errorf("%q decoded", text)
		}
	}
}

func TestCatalogTrustOriginIsRFC6454(t *testing.T) {
	for url, want := range map[string]string{
		"https://publisher.example/a":      "https://publisher.example",
		"HTTPS://Publisher.Example:443/a":  "https://publisher.example",
		"https://publisher.example:/a":     "https://publisher.example",
		"https://publisher.example:8443/a": "", "http://publisher.example/a": "",
		"https://user@publisher.example/a": "", "https://publisher%2Eexample/a": "",
		"https://[::1]/a": "", "https:///a": ""} {
		if got := ctHTTPSOrigin(url); got != want {
			t.Errorf("%s: got %q, want %q", url, got, want)
		}
	}
}

func TestCatalogTrustContextIndexIsANonNegativeInteger(t *testing.T) {
	for value, want := range map[any]int{0.0: 0, 3.0: 3, 1.0: 1, -1.0: ctNoIndex, 0.5: ctNoIndex,
		true: ctNoIndex, "1": ctNoIndex, float64(1 << 40): ctNoIndex} {
		if got := ctIndexOf(map[string]any{"entry": value}, "entry"); got != want {
			t.Errorf("%v: got %d, want %d", value, got, want)
		}
	}
}

func TestCatalogTrustRootDIDWeb(t *testing.T) {
	long := "did:web:" + strings.Repeat("a", 63) + "." + strings.Repeat(strings.Repeat("b", 63)+".", 2)
	for did, want := range map[string]bool{
		"did:web:publisher.example": true, "did:web:xn--bcher-kva.example": true,
		"did:web:192.0.2.1": false, "did:web:agents.2026": false, "did:web:2026": false,
		long + strings.Repeat("c", 61): true, long + strings.Repeat("c", 62): false} {
		if got := ctRootDIDWeb(did); got != want {
			t.Errorf("%s: got %v, want %v", did, got, want)
		}
	}
}
