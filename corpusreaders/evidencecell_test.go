package corpusreaders_test

// The incident-evidence-cell reader derives every decision from the record
// alone. Swapping the control's record for a denied member's must move the
// decision, and the reverse must restore it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const ecDir = "vectors-incident-evidence-cell"

func ecStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ecDir)
	copyTree(t, corpusPath(ecDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ecRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ecDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestEvidenceCellCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(ecDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestEvidenceCellEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"reject-statement-type-old", "reject-subject-empty",
		"reject-subject-digest-uppercase", "reject-predicate-type-other",
		"reject-predicate-type-foreign-host", "reject-predicate-not-object", "reject-value-and-not-addressed",
		"reject-neither-value-nor-not-addressed", "reject-value-empty-string",
		"reject-producer-http", "reject-issued-at-offset", "reject-registry-digest-short",
		"reject-extra-member", "reject-does-not-assert-empty", "reject-state-slash-form",
		"reject-state-es9", "reject-response-investigation", "reject-support-label-partial",
		"reject-empty-cell-supported", "reject-empty-cell-unsupported",
		"reject-disclaimer-paraphrased", "reject-disclaimer-absent"}
	for _, from := range denied {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := ecStage(t, "allow-investigation-supported", ecRead(t, from))
			if got := scDerived(t, dir, "allow-investigation-supported"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	dir := ecStage(t, "reject-empty-cell-supported", ecRead(t, "allow-investigation-supported"))
	if got := scDerived(t, dir, "reject-empty-cell-supported"); !strings.Contains(got, "derived allow/cell_recorded") {
		t.Fatalf("want a derived allow, got %q", got)
	}
}

func TestEvidenceCellMalformedShapesAreDenied(t *testing.T) {
	control := ecRead(t, "allow-investigation-supported")
	edits := map[string][2]string{
		"a statement that is not an object member": {`"_type": "https://in-toto.io/Statement/v1"`, `"_type": "https://in-toto.io/Statement/v1", "extra": 1`},
		"a subject that is not an object":          {`"subject": [`, `"subject": [7, `},
		"a cell member that is empty":              {`"table": "decision-table-1"`, `"table": ""`},
		"an impossible date":                       {`"2026-11-02T09:00:00Z"`, `"2026-02-30T09:00:00Z"`},
		"a sentence that is not text":              {`"doesNotAssert": [`, `"doesNotAssert": [1, `},
		"an empty-cell reason that is empty":       {`"value": "raise monitoring on the affected hosts"`, `"notAddressed": {"reason": ""}`},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(control, edit[0], edit[1], 1)
			if body == control {
				t.Fatal("the edit did not apply")
			}
			dir := ecStage(t, "allow-investigation-supported", body)
			if got := scDerived(t, dir, "allow-investigation-supported"); !strings.Contains(got, "_malformed") {
				t.Fatalf("want a malformed refusal, got %q", got)
			}
		})
	}
}

func TestEvidenceCellUnreadableInputsAreFindings(t *testing.T) {
	for body, want := range map[string]string{"{": "record.json does not parse", "[]": "not a JSON object"} {
		dir := ecStage(t, "allow-investigation-supported", body)
		if got := scDerived(t, dir, "allow-investigation-supported"); !strings.Contains(got, want) {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
}
