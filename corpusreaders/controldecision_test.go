package corpusreaders

import (
	"strings"
	"testing"
)

const cdCorpusDir = "../corpora/vectors-acs-decision-record"

// TestControlDecisionCorpusBehaves: every member reaches the verdict and the first
// refusal its manifest entry declares, and the manifest counts, digest and rule
// coverage hold.
func TestControlDecisionCorpusBehaves(t *testing.T) {
	result, err := Judge(cdCorpusDir)
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
	if len(result.Members) != 15 {
		t.Fatalf("expected 15 members, read %d", len(result.Members))
	}
}

// TestControlDecisionRefusesAMalformedManifest: a manifest that does not parse, or
// whose producer key is not an Ed25519 key, is an error and never a verdict.
func TestControlDecisionRefusesAMalformedManifest(t *testing.T) {
	for name, raw := range map[string]string{
		"not json": "{",
		"no key":   `{"keys":{"producer":{"publicKey":"zz"}}}`,
		"short":    `{"keys":{"producer":{"publicKey":"00"}}}`,
	} {
		if _, err := (controlDecision{}).Judge(cdCorpusDir, []byte(raw)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestControlDecisionFlagsAnEscapingOrUnreadableMember: a member path that leaves
// the corpus directory, or names no file, is a finding on that member, and a
// manifest that disagrees with its members is a finding on the corpus.
func TestControlDecisionFlagsAnEscapingOrUnreadableMember(t *testing.T) {
	key := strings.Repeat("00", 32)
	manifest := `{"predicateType":"x","keys":{"producer":{"publicKey":"` + key + `"}},"counts":{"accept":9},` +
		`"vectors":[` +
		`{"id":"escape","path":"../README.md","expected":{"verdict":"accept","code":null}},` +
		`{"id":"missing","path":"members/absent.json","expected":{"verdict":"accept","code":null}}]}`
	result, err := (controlDecision{}).Judge(cdCorpusDir, []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Members) != 2 || len(result.Members[0].Findings) == 0 || len(result.Members[1].Findings) == 0 {
		t.Fatalf("both members should carry a finding: %+v", result.Members)
	}
	if len(result.Findings) == 0 {
		t.Fatal("a disagreeing manifest should carry corpus findings")
	}
}

// TestControlDecisionRefusesMalformedMembers: a body that is not an object, has no
// envelope, or carries an envelope nobody signed is refused with the first rule that
// fails.
func TestControlDecisionRefusesMalformedMembers(t *testing.T) {
	m := &cdManifest{PredicateType: "x"}
	key := make([]byte, 32)
	for body, code := range map[string]string{
		`[]`:                             "statement-malformed",
		`{`:                              "statement-malformed",
		`{}`:                             "signature-invalid",
		`{"envelope":{"payload":"!!"}}`:  "signature-invalid",
		`{"envelope":{"signatures":[]}}`: "signature-invalid",
	} {
		verdict, got := cdDecide(m, key, []byte(body))
		if verdict != "reject" || got != code {
			t.Errorf("%s: got %s/%q, want reject/%q", body, verdict, got, code)
		}
	}
	if !cdKnownDecision("deny") || cdKnownDecision("other") || cdKnownDecision(3.0) {
		t.Error("cdKnownDecision should admit only the decisions the record defines")
	}
}
