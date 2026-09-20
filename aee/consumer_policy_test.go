package aee_test

// Consumer-policy stage tests: the anchor comparison
// (corpus-anchor-mismatch / substrate-anchor-mismatch on the report's
// consumer surface) and the Admitted conjunction — validity AND tier-policy
// satisfaction AND supplied-anchors-match. Throughout, the byte-pure facts
// (Verdict, Codes, Result, Tiers) must be unchanged by any policy input.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
	"github.com/probityai/agent-evidence-vectors/aeetest"
)

// carriedAnchors extracts the corpus and substrate digests a built statement
// carries, so the tests compare policy anchors against the exact wire values.
func carriedAnchors(t *testing.T, body []byte) (corpus, substrate string) {
	t.Helper()
	var stmt struct {
		Predicate struct {
			Env struct {
				Corpus struct {
					Digest map[string]string `json:"digest"`
				} `json:"corpus"`
				Substrate struct {
					Digest map[string]string `json:"digest"`
				} `json:"substrate"`
			} `json:"observationEnvironment"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	corpus = stmt.Predicate.Env.Corpus.Digest["sha256"]
	substrate = stmt.Predicate.Env.Substrate.Digest["sha256"]
	if corpus == "" || substrate == "" {
		t.Fatal("built statement carries no anchor digests")
	}
	return corpus, substrate
}

func hasPolicyCode(r *aee.Report, want aee.Code) bool {
	for _, c := range r.PolicyCodes {
		if c == want {
			return true
		}
	}
	return false
}

func TestAnchorsMatchMismatchUnsupplied(t *testing.T) {
	body := aeetest.Build(aeetest.Options{})
	corpus, substrate := carriedAnchors(t, body)
	keys := pinnedPolicy().SubstrateObservationKeys
	wrong := strings.Repeat("0", 64)

	cases := []struct {
		name      string
		policy    *aee.ConsumerPolicy
		wantCodes []aee.Code
		wantAdmit bool
	}{
		{"both anchors match", &aee.ConsumerPolicy{SubstrateObservationKeys: keys, ExpectedCorpusDigest: corpus, ExpectedSubstrateDigest: substrate}, nil, true},
		{"anchors unsupplied", &aee.ConsumerPolicy{SubstrateObservationKeys: keys}, nil, true},
		{"corpus mismatch", &aee.ConsumerPolicy{SubstrateObservationKeys: keys, ExpectedCorpusDigest: wrong, ExpectedSubstrateDigest: substrate}, []aee.Code{aee.CodeCorpusAnchorMismatch}, false},
		{"substrate mismatch", &aee.ConsumerPolicy{SubstrateObservationKeys: keys, ExpectedCorpusDigest: corpus, ExpectedSubstrateDigest: wrong}, []aee.Code{aee.CodeSubstrateAnchorMismatch}, false},
		{"both mismatch", &aee.ConsumerPolicy{SubstrateObservationKeys: keys, ExpectedCorpusDigest: wrong, ExpectedSubstrateDigest: wrong}, []aee.Code{aee.CodeCorpusAnchorMismatch, aee.CodeSubstrateAnchorMismatch}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := aee.Verify(body, tc.policy)
			// Byte-pure facts are untouched by any anchor input.
			requireValid(t, r)
			if r.Result != "fail" {
				t.Fatalf("result %q changed by consumer policy", r.Result)
			}
			if len(r.PolicyCodes) != len(tc.wantCodes) {
				t.Fatalf("policy codes %v, want %v", r.PolicyCodes, tc.wantCodes)
			}
			for _, c := range tc.wantCodes {
				if !hasPolicyCode(r, c) {
					t.Fatalf("policy codes %v missing %s", r.PolicyCodes, c)
				}
			}
			if r.Admitted != tc.wantAdmit {
				t.Fatalf("admitted = %t, want %t", r.Admitted, tc.wantAdmit)
			}
		})
	}
}

func TestAdmittedConjunctionTruthTable(t *testing.T) {
	substrateBody := aeetest.Build(aeetest.Options{})
	corpus, substrate := carriedAnchors(t, substrateBody)
	artifactBody := aeetest.BuildArtifactOnly()
	keys := pinnedPolicy().SubstrateObservationKeys
	wrong := strings.Repeat("0", 64)

	cases := []struct {
		name      string
		body      []byte
		policy    *aee.ConsumerPolicy
		wantAdmit bool
	}{
		// validity AND tier policy AND anchors all hold.
		{"substrate row attested, anchors match", substrateBody,
			&aee.ConsumerPolicy{SubstrateObservationKeys: keys, ExpectedCorpusDigest: corpus, ExpectedSubstrateDigest: substrate}, true},
		// tier policy fails: no named substrate key, substrate row present.
		{"substrate row, empty key set", substrateBody, &aee.ConsumerPolicy{}, false},
		// tier policy fails: nil policy is the same no-TOFU outcome.
		{"substrate row, nil policy", substrateBody, nil, false},
		// tier policy vacuously satisfied: no substrate rows, no keys named.
		{"artifact-only, empty policy", artifactBody, &aee.ConsumerPolicy{}, true},
		{"artifact-only, nil policy", artifactBody, nil, true},
		// anchors fail an otherwise fully satisfied conjunction.
		{"attested but corpus anchor mismatch", substrateBody,
			&aee.ConsumerPolicy{SubstrateObservationKeys: keys, ExpectedCorpusDigest: wrong}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := aee.Verify(tc.body, tc.policy)
			requireValid(t, r)
			if r.Admitted != tc.wantAdmit {
				t.Fatalf("admitted = %t, want %t (tiers %v, policy codes %v)",
					r.Admitted, tc.wantAdmit, r.Tiers, r.PolicyCodes)
			}
		})
	}
}

func TestInvalidStatementNeverAdmitted(t *testing.T) {
	// A recompute mismatch makes the statement invalid; no consumer input
	// can admit it, and the consumer-policy step never runs (no PolicyCodes).
	body := aeetest.Build(aeetest.Options{Result: "pass"})
	corpus, substrate := carriedAnchors(t, body)
	r := aee.Verify(body, &aee.ConsumerPolicy{
		SubstrateObservationKeys: pinnedPolicy().SubstrateObservationKeys,
		ExpectedCorpusDigest:     corpus,
		ExpectedSubstrateDigest:  substrate,
	})
	requireInvalid(t, r, aee.CodeResultRecomputeMismatch)
	if r.Admitted {
		t.Fatal("invalid statement reported admitted")
	}
	if r.PolicyCodes != nil {
		t.Fatalf("invalid statement carries policy codes %v", r.PolicyCodes)
	}
}
