package aee_test

// A corpus manifest that declares no attack identifier is not an adversarial
// corpus, and a statement carrying one is malformed.
//
// These tests exist because the fault they cover is a TOTAL BYPASS of the
// substrate rather than a lie about a run. With zero declared attack
// identifiers there are zero rows; with zero rows there are zero basis:
// substrate rows; and with no substrate rows the predicate legally permits
// runEntropy, observationRecords and batchRoot all to be absent. Every
// structure that would have forced a substrate signature drops out, and
// coverage integrity compares an empty union of row attack ids against an
// empty union of manifest attack ids and passes vacuously. The statements
// built below therefore reached a valid verdict, a pass result and consumer
// admission with no substrate, no substrate key, no substrate run and every
// carried digest fabricated.
//
// The rule is phrased over attack identifiers and not over classes on
// purpose: a manifest carrying a real class name with an empty id array
// ({"classes":{"CO":[]}}) reads far more plausibly than an empty classes
// object, and only the id-counting phrasing closes both.

import (
	"encoding/json"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// Fabricated digests. Each is a syntactically canonical lowercase 64-hex
// string that commits to nothing at all -- which is exactly the point: a
// zero-attack statement never has to produce a pre-image for any of them.
const (
	fabricatedSubjectDigest   = "1111111111111111111111111111111111111111111111111111111111111111"
	fabricatedSubstrateDigest = "2222222222222222222222222222222222222222222222222222222222222222"
	fabricatedPolicyDigest    = "3333333333333333333333333333333333333333333333333333333333333333"
	fabricatedPostureDigest   = "4444444444444444444444444444444444444444444444444444444444444444"
)

func canonDigest(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return aee.SHA256Hex(canon)
}

// substrateFreeStatement builds a complete statement that carries the given
// corpus manifest and coverage bound and NO attackResults rows, no
// observationRecords, no batchRoot and no runEntropy. Everything the
// statement does carry is well-formed: the corpus and vocabulary digests are
// the ones the rail itself derives, so nothing below is found by a digest
// mismatch.
func substrateFreeStatement(t *testing.T, manifestClasses map[string]any, assessed []string, outOfScope map[string]string, result string) []byte {
	t.Helper()
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	manifest := map[string]any{"classes": manifestClasses}

	if assessed == nil {
		assessed = []string{}
	}
	if outOfScope == nil {
		outOfScope = map[string]string{}
	}

	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": aee.PredicateType,
		"subject": []any{
			map[string]any{"digest": map[string]any{"sha256": fabricatedSubjectDigest}, "name": "example-agent-bundle"},
		},
		"predicate": map[string]any{
			"attackResults": []any{},
			"coverage": map[string]any{
				"assessedClasses": assessed,
				"outOfScope":      outOfScope,
				"routedElsewhere": map[string]string{},
			},
			"issuedAt": "2026-01-01T00:00:00Z",
			"observationEnvironment": map[string]any{
				"catchPolicy":    map[string]any{"digest": map[string]any{"sha256": fabricatedPolicyDigest}},
				"corpus":         map[string]any{"digest": map[string]any{"sha256": canonDigest(t, manifest)}, "manifest": manifest, "name": "example-corpus", "uri": "pkg:example/corpus@1"},
				"networkPosture": map[string]any{"digest": map[string]any{"sha256": fabricatedPostureDigest}, "posture": "sinkhole"},
				"observationVocabulary": map[string]any{
					"caught": caught,
					"digest": map[string]any{"sha256": canonDigest(t, map[string]any{"caught": caught, "labels": labels})},
					"labels": labels,
				},
				"substrate": map[string]any{"digest": map[string]any{"sha256": fabricatedSubstrateDigest}, "name": "example-substrate"},
			},
			"result": result,
		},
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize statement: %v", err)
	}
	return canon
}

// TestZeroAttackManifestIsMalformed is the defect's regression pin. Before the
// fix both statements below verified VALID with result pass and were admitted
// under a consumer policy, with no substrate anywhere in them.
func TestZeroAttackManifestIsMalformed(t *testing.T) {
	cases := []struct {
		name     string
		classes  map[string]any
		assessed []string
	}{
		{
			"empty classes object",
			map[string]any{},
			nil,
		},
		{
			"a real class name declaring no attack ids",
			map[string]any{"CO": []string{}},
			[]string{"CO"},
		},
		{
			"several real class names, none declaring an attack id",
			map[string]any{"CO": []string{}, "XA": []string{}},
			[]string{"CO", "XA"},
		},
		{
			"a manifest with no classes member at all",
			nil,
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statement := substrateFreeStatement(t, tc.classes, tc.assessed, nil, "pass")
			r := aee.Verify(statement, pinnedPolicy())
			requireInvalid(t, r, aee.CodeCorpusManifestNoAttacks)
			if r.Admitted {
				t.Fatal("a malformed statement must never be admitted")
			}
		})
	}
}

// TestZeroAttackManifestRefusedAtEmit pins the producer seam: the emit gate
// refuses to sign what the verifier rejects, so a producer pipeline cannot
// mint a zero-attack statement either.
func TestZeroAttackManifestRefusedAtEmit(t *testing.T) {
	statement := substrateFreeStatement(t, map[string]any{"CO": []string{}}, []string{"CO"}, nil, "pass")
	if _, err := aee.VerifyForEmit(statement); err == nil {
		t.Fatal("emit seam signed a zero-attack manifest")
	}
}

// TestFullySkippedRunStaysValid is the control. A manifest that DOES declare
// an attack id, assessed nowhere and disclosed under outOfScope, is the
// honest fully-skipped run: it must stay valid and score degraded. The new
// rule counts attack identifiers, not rows, so it must not touch this case.
func TestFullySkippedRunStaysValid(t *testing.T) {
	statement := substrateFreeStatement(t,
		map[string]any{"CO": []string{"CO-1"}},
		nil,
		map[string]string{"CO": "not exercised in this run"},
		"degraded")
	r := aee.Verify(statement, pinnedPolicy())
	requireValid(t, r)
	if r.Result != "degraded" {
		t.Fatalf("expected degraded, got %q", r.Result)
	}
}

// TestFullySkippedRunWithoutDisclosureIsIncomplete is the other half of the
// control: dropping the outOfScope disclosure leaves the declared class
// unaccounted, which coverage integrity already catches. Keeping this
// assertion beside the one above shows the new rule did not take over a
// finding that coverage integrity owns.
func TestFullySkippedRunWithoutDisclosureIsIncomplete(t *testing.T) {
	statement := substrateFreeStatement(t,
		map[string]any{"CO": []string{"CO-1"}},
		nil,
		nil,
		"pass")
	r := aee.Verify(statement, pinnedPolicy())
	requireInvalid(t, r, aee.CodeCoverageIncomplete)
}
