package aee

import (
	"slices"
	"testing"
)

// TestEmptyPredicateStatesAreOneInput pins the rule in spec/v1/statement.md
// at the API rather than only through the corpus: an absent `predicate`
// member, `"predicate": null` and `"predicate": {}` decode to the same empty
// predicate and Verify reports the identical verdict and codes for all three.
// Before the normalization an absent member failed ParseStatement, which Verify
// maps to a lone statement-malformed, while the other two spellings earned the
// codes the empty predicate actually fails on.
func TestEmptyPredicateStatesAreOneInput(t *testing.T) {
	head := `{"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"a","digest":{"sha256":"` +
		`d14fbbcd076c6bfe5e6aa52b169c0baf7f7044ea46fe279afd7629e92baac8fc"}}],` +
		`"predicateType":"` + PredicateType + `"`
	spellings := map[string]string{
		"absent": head + `}`,
		"null":   head + `,"predicate":null}`,
		"empty":  head + `,"predicate":{}}`,
	}

	var want *Report
	for name, doc := range spellings {
		s, err := ParseStatement([]byte(doc))
		if err != nil {
			t.Fatalf("%s: ParseStatement refused the statement: %v", name, err)
		}
		if s.Predicate == nil || s.Predicate.Raw == nil || len(s.Predicate.Raw) != 0 {
			t.Fatalf("%s: predicate did not decode to the empty object: %+v", name, s.Predicate)
		}
		got := Verify([]byte(doc), nil)
		if got.Verdict != VerdictInvalid {
			t.Fatalf("%s: verdict %q, want invalid (the empty predicate lacks every required member)", name, got.Verdict)
		}
		if want == nil {
			want = got
			continue
		}
		if !slices.Equal(got.Codes, want.Codes) || got.PrimaryCode != want.PrimaryCode {
			t.Fatalf("%s: codes %v (primary %q) differ from another spelling's %v (primary %q)",
				name, got.Codes, got.PrimaryCode, want.Codes, want.PrimaryCode)
		}
	}
	if len(want.Codes) < 2 {
		t.Fatalf("codes %v: the empty predicate should fail on the members it lacks, not on one parse error", want.Codes)
	}
}
