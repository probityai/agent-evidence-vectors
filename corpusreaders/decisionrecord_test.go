package corpusreaders

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const drecCorpusDir = "../corpora/vectors-decision-record"

// TestDecisionRecordCorpusBehaves: every member reaches the verdict, the first
// refusing dimension and every dimension status its manifest entry declares, each
// member naming a published case agrees with that case, and the counts, the corpus
// digest and the vendored published files hold.
func TestDecisionRecordCorpusBehaves(t *testing.T) {
	result, err := Judge(drecCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range result.Members {
		for _, f := range m.Findings {
			t.Errorf("%s: %s", m.ID, f)
		}
	}
	for _, f := range result.Findings {
		t.Errorf("corpus: %s", f)
	}
	counts := result.CountsByVerdict()
	if len(result.Members) < 100 || counts["accept"] == 0 || counts["reject"] == 0 {
		t.Fatalf("expected a corpus of accepting and refusing members, read %v", counts)
	}
}

// TestDecisionRecordRefusesAMalformedManifest: a manifest that does not parse is
// an error and never a verdict.
func TestDecisionRecordRefusesAMalformedManifest(t *testing.T) {
	if _, err := (decisionRecord{}).Judge(drecCorpusDir, []byte("{")); err == nil {
		t.Error("expected an error")
	}
}

// TestDecisionRecordFlagsAnEscapingOrUnreadableMember: a member path that leaves
// the corpus, or names no file, is a finding on that member, and a manifest that
// disagrees with its members is a finding on the corpus.
func TestDecisionRecordFlagsAnEscapingOrUnreadableMember(t *testing.T) {
	manifest := `{"counts":{"accept":9},"vectors":[` +
		`{"id":"escape","path":"../README.md","profile":"baseline","expected":{"verdict":"accept","code":null}},` +
		`{"id":"missing","path":"members/absent.json","profile":"baseline","expected":{"verdict":"accept","code":null}}]}`
	result, err := (decisionRecord{}).Judge(drecCorpusDir, []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Members) != 2 || result.Members[0].OK() || result.Members[1].OK() {
		t.Fatalf("both members should carry a finding: %+v", result.Members)
	}
	if len(result.Findings) == 0 {
		t.Fatal("a disagreeing manifest should carry corpus findings")
	}
}

// TestDecisionRecordAMemberJudgedOtherwiseIsNamed: a member whose declared verdict
// or dimension is not the one its bytes read to is named, and so is one whose
// declared profile is not the member's own.
func TestDecisionRecordAMemberJudgedOtherwiseIsNamed(t *testing.T) {
	root := t.TempDir()
	copyCorpus(t, drecCorpusDir, root)
	raw, err := os.ReadFile(filepath.Join(root, ManifestName)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), `"verdict": "accept"`, `"verdict": "reject"`, 1)
	text = strings.Replace(text, `"profile": "strict"`, `"profile": "baseline"`, 1)
	result, err := (decisionRecord{}).Judge(root, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, m := range result.Members {
		if !m.OK() {
			named++
		}
	}
	if named < 2 {
		t.Fatalf("expected the two altered members to be named, %d were", named)
	}
}

func copyCorpus(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o750)
		}
		body, readErr := os.ReadFile(path) // #nosec G304,G122 -- the repository's own corpus
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(filepath.Join(to, rel), body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDecisionRecordReadsJSONAsTheReferenceDoes: the strict reading refuses what
// parse_ijson refuses, keeps 1 and 1.0 apart, and the bounds reading reads an
// integer outside the exact range instead of refusing the document.
func TestDecisionRecordReadsJSONAsTheReferenceDoes(t *testing.T) {
	refused := map[string]string{
		`{"a":1,"a":2}`:         "duplicate-member",
		`{"a":1,"\u0061":2}`:    "duplicate-member",
		`[9007199254740993]`:    "unsafe-integer",
		`["\ud800"]`:            "lone-surrogate",
		`[0.10000000000000001]`: "value-not-representable",
		`[1e400]`:               "value-not-representable",
		`[NaN]`:                 "non-json-number",
		`[-Infinity]`:           "non-json-number",
		"\xef\xbb\xbf{}":        "not-utf8",
		`[01]`:                  "not-parseable",
		"[\"a\x01\"]":           "not-parseable",
		strings.Repeat("[", 129) + strings.Repeat("]", 129): "nesting-too-deep",
	}
	for text, code := range refused {
		_, err := drecParse([]byte(text), drecStrict)
		je, ok := err.(*drecJSONError)
		if !ok || je.Code != code {
			t.Errorf("%q: want %s, got %v", text, code, err)
		}
	}
	accepted, err := drecParse([]byte(`[1.10, 1, 1.0, true, "😀", -0]`), drecStrict)
	if err != nil {
		t.Fatal(err)
	}
	list := accepted.([]any)
	if drecSame(list[1], list[2]) || drecSame(list[1], list[3]) || !drecEq(list[1], list[3]) {
		t.Error("1, 1.0 and true are three values to the format and equal to Python's ==")
	}
	if list[4] != "\U0001F600" {
		t.Errorf("an escaped surrogate pair is one character, read %q", list[4])
	}
	bounds, err := drecParse([]byte(`[9007199254740993]`), drecBounds)
	if err != nil || drecJSONInteger(bounds.([]any)[0]) {
		t.Errorf("the bounds reading reads an unsafe integer and marks it: %v %v", bounds, err)
	}
	lenient, err := drecParse([]byte(`{"a":1,"a":2}`), drecLenient)
	if err != nil || !drecEq(lenient.(map[string]any)["a"], drecInt{n: big.NewInt(2)}) {
		t.Errorf("a member file keeps the last of a repeated member: %v %v", lenient, err)
	}
}

// TestDecisionRecordReadsTimesAsTheReferenceDoes: an instant needs an offset and a
// calendar date, and Python's "$" lets one final newline through.
func TestDecisionRecordReadsTimesAsTheReferenceDoes(t *testing.T) {
	for text, ok := range map[string]bool{
		"2026-10-01T09:00:00Z":        true,
		"2026-10-01T09:00:00Z\n":      true,
		"2026-10-01T09:00:00.5+02:00": true,
		"2026-10-01T09:00:00":         false,
		"2026-02-30T09:00:00Z":        false,
		"2026-10-01T24:00:00Z":        false,
		"2026-10-01T09:00:00+24:00":   false,
		"0000-01-01T00:00:00Z":        false,
	} {
		if got := drecReadInstant(text).ok(); got != ok {
			t.Errorf("%q: read as an instant %v, want %v", text, got, ok)
		}
	}
	a := drecReadInstant("2026-10-01T11:00:00+02:00")
	b := drecReadInstant("2026-10-01T09:00:00Z")
	if a.sec.Cmp(b.sec) != 0 {
		t.Error("one instant written in two offsets is one instant")
	}
}

// TestDecisionRecordRefusesAnUnknownProfile: a member naming a profile the format
// does not have is a finding, never a verdict.
func TestDecisionRecordRefusesAnUnknownProfile(t *testing.T) {
	if _, _, err := drecVerdict(&drecReport{dims: map[string]drecDim{}}, "lenient"); err == nil {
		t.Error("expected an unknown profile to be refused")
	}
}
