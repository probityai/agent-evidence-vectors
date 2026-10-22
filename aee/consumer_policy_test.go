package aee_test

// Consumer-policy stage tests: every condition of the admission conjunction
// (admission.go), each perturbed alone away from a policy that admits.
// Throughout, the byte-pure facts (Verdict, Codes, Result, Tiers) must be
// unchanged by any policy input.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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

// subjectDigest reads subject[0].digest.sha256 from a built statement.
func subjectDigest(t *testing.T, body []byte) string {
	t.Helper()
	var stmt struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(body, &stmt); err != nil || len(stmt.Subject) == 0 {
		t.Fatalf("built statement carries no subject: %v", err)
	}
	return stmt.Subject[0].Digest["sha256"]
}

// admittingPolicy pins everything a clean built statement carries, so each
// case below perturbs exactly one knob away from admission.
func admittingPolicy(t *testing.T, body []byte) *aee.ConsumerPolicy {
	t.Helper()
	corpus, substrate := carriedAnchors(t, body)
	return &aee.ConsumerPolicy{
		SubstrateObservationKeys: pinnedPolicy().SubstrateObservationKeys,
		ExpectedCorpusDigest:     corpus,
		ExpectedSubstrateDigest:  substrate,
		ExpectedSubjectDigest:    subjectDigest(t, body),
		DemandedClasses:          []string{"XA"},
		AllowPublishedTestKeys:   true,
	}
}

func requirePolicyCodes(t *testing.T, r *aee.Report, want ...aee.Code) {
	t.Helper()
	if len(r.PolicyCodes) != len(want) {
		t.Fatalf("policy codes %v, want %v", r.PolicyCodes, want)
	}
	for _, c := range want {
		if !hasPolicyCode(r, c) {
			t.Fatalf("policy codes %v missing %s", r.PolicyCodes, c)
		}
	}
	if r.Admitted != (len(want) == 0) {
		t.Fatalf("admitted = %t with policy codes %v", r.Admitted, r.PolicyCodes)
	}
}

func TestAdmissionKnobByKnob(t *testing.T) {
	body := aeetest.Build(aeetest.Options{Clean: true})
	wrong := strings.Repeat("0", 64)
	yes, no := true, false
	cases := []struct {
		name   string
		change func(p *aee.ConsumerPolicy)
		want   []aee.Code
	}{
		{"every pin supplied and matching", func(*aee.ConsumerPolicy) {}, nil},
		{"corpus mismatch", func(p *aee.ConsumerPolicy) { p.ExpectedCorpusDigest = wrong }, []aee.Code{aee.CodeCorpusAnchorMismatch}},
		{"substrate mismatch", func(p *aee.ConsumerPolicy) { p.ExpectedSubstrateDigest = wrong }, []aee.Code{aee.CodeSubstrateAnchorMismatch}},
		{"subject mismatch", func(p *aee.ConsumerPolicy) { p.ExpectedSubjectDigest = wrong }, []aee.Code{aee.CodeSubjectAnchorMismatch}},
		{"anchors unpinned", func(p *aee.ConsumerPolicy) {
			p.ExpectedCorpusDigest, p.ExpectedSubstrateDigest, p.ExpectedSubjectDigest = "", "", ""
		}, []aee.Code{aee.CodeCorpusAnchorUnpinned, aee.CodeSubstrateAnchorUnpinned, aee.CodeSubjectAnchorUnpinned}},
		{"anchors unpinned and declined", func(p *aee.ConsumerPolicy) {
			p.ExpectedCorpusDigest, p.ExpectedSubstrateDigest, p.ExpectedSubjectDigest = "", "", ""
			p.AllowUnpinnedAnchors = true
		}, nil},
		{"a decline never excuses a mismatch", func(p *aee.ConsumerPolicy) {
			p.ExpectedCorpusDigest = wrong
			p.AllowUnpinnedAnchors = true
		}, []aee.Code{aee.CodeCorpusAnchorMismatch}},
		{"scope unpinned", func(p *aee.ConsumerPolicy) { p.DemandedClasses = nil }, []aee.Code{aee.CodeScopeUnpinned}},
		{"scope declined", func(p *aee.ConsumerPolicy) { p.DemandedClasses, p.AllowUnpinnedScope = nil, true }, nil},
		{"a class the run did not assess", func(p *aee.ConsumerPolicy) { p.DemandedClasses = []string{"XA", "XZ"} }, []aee.Code{aee.CodeDemandedClassUnassessed}},
		{"no observation key", func(p *aee.ConsumerPolicy) { p.SubstrateObservationKeys = nil }, []aee.Code{aee.CodeSubstrateRowUnattested}},
		{"a published test key, not declined", func(p *aee.ConsumerPolicy) { p.AllowPublishedTestKeys = false }, []aee.Code{aee.CodePublishedTestKey}},
		{"a threshold naming degraded", func(p *aee.ConsumerPolicy) { p.AcceptedResults = []string{"pass", "degraded"} }, []aee.Code{aee.CodeAcceptedResultsMalformed}},
		{"a widened threshold with the row rule unsaid", func(p *aee.ConsumerPolicy) {
			p.AcceptedResults = []string{"pass_indirect", "pass"}
		}, []aee.Code{aee.CodeRowGateUndeclared}},
		{"a widened threshold keeping the row rule", func(p *aee.ConsumerPolicy) {
			p.AcceptedResults, p.AdmitUninterceptedCleanRows = []string{"pass", "pass_indirect"}, &no
		}, nil},
		{"the row rule declined under pass only", func(p *aee.ConsumerPolicy) { p.AdmitUninterceptedCleanRows = &yes }, []aee.Code{aee.CodeRowGateDeclineUnreachable}},
		{"a lag bound the run meets", func(p *aee.ConsumerPolicy) { p.MaxIssuanceLag = 2 * time.Minute }, nil},
		{"a lag bound the run misses", func(p *aee.ConsumerPolicy) { p.MaxIssuanceLag = 30 * time.Second }, []aee.Code{aee.CodeIssuanceLagExceeded}},
		{"an age bound, clock pinned inside it", func(p *aee.ConsumerPolicy) {
			p.MaxEvidenceAge = time.Hour
			p.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
		}, nil},
		{"an age bound, clock pinned past it", func(p *aee.ConsumerPolicy) {
			p.MaxEvidenceAge = time.Hour
			p.Now = func() time.Time { return time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC) }
		}, []aee.Code{aee.CodeEvidenceAgeExceeded}},
		{"a lag bound with no key to verify an arming record", func(p *aee.ConsumerPolicy) {
			p.MaxIssuanceLag, p.SubstrateObservationKeys = 24*time.Hour, nil
		}, []aee.Code{aee.CodeSubstrateRowUnattested, aee.CodeObservedInstantAbsent}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := admittingPolicy(t, body)
			tc.change(policy)
			r := aee.Verify(body, policy)
			requireValid(t, r)
			if r.Result != "pass" {
				t.Fatalf("result %q changed by consumer policy", r.Result)
			}
			requirePolicyCodes(t, r, tc.want...)
		})
	}
}

func TestNothingPinnedIsNeverAdmitted(t *testing.T) {
	// A nil policy and an empty one are the same consumer: one that pinned
	// nothing. The command this package backs used to exit 0 for it.
	for _, body := range [][]byte{aeetest.Build(aeetest.Options{Clean: true}), aeetest.BuildArtifactOnly()} {
		for _, policy := range []*aee.ConsumerPolicy{nil, {}} {
			r := aee.Verify(body, policy)
			requireValid(t, r)
			if r.Admitted {
				t.Fatalf("admitted with nothing pinned: tiers %v, codes %v", r.Tiers, r.PolicyCodes)
			}
			for _, c := range []aee.Code{aee.CodeCorpusAnchorUnpinned, aee.CodeSubjectAnchorUnpinned, aee.CodeScopeUnpinned} {
				if !hasPolicyCode(r, c) {
					t.Fatalf("policy codes %v missing %s", r.PolicyCodes, c)
				}
			}
		}
	}
}

func TestArtifactEvidenceIsNotAdmittedVacuously(t *testing.T) {
	// No substrate row means the tier half holds vacuously. That used to be
	// enough: an artifact-only statement, every row the producer's own
	// account, was admitted under any key set.
	body := aeetest.BuildArtifactOnly()
	policy := admittingPolicy(t, body)
	policy.DemandedClasses = nil
	policy.AllowUnpinnedScope = true
	r := aee.Verify(body, policy)
	requireValid(t, r)
	if r.Admitted {
		t.Fatalf("artifact-only statement admitted: result %s, codes %v", r.Result, r.PolicyCodes)
	}
}

func TestFailResultIsNotAdmitted(t *testing.T) {
	body := aeetest.Build(aeetest.Options{})
	policy := admittingPolicy(t, body)
	r := aee.Verify(body, policy)
	requireValid(t, r)
	if r.Result != "fail" {
		t.Fatalf("built statement result %q, want fail", r.Result)
	}
	requirePolicyCodes(t, r, aee.CodeResultNotAccepted)
}

func TestReportSaysWhatNoObserverBound(t *testing.T) {
	body := aeetest.Build(aeetest.Options{Clean: true})
	r := aee.Verify(body, admittingPolicy(t, body))
	if len(r.ArmedAt) != 1 || r.ArmedAt[0] != aeetest.ArmedAt {
		t.Fatalf("armedAt %v, want [%s]", r.ArmedAt, aeetest.ArmedAt)
	}
	joined := strings.Join(r.ProducerAsserted, " ")
	for _, want := range []string{"predicate.issuedAt", "predicate.observationEnvironment.corpus.name"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("producerAsserted %v lacks %s", r.ProducerAsserted, want)
		}
	}
	for _, bound := range []string{"subject[0].digest", ".digest.sha256", "corpus.manifest", "networkPosture"} {
		if strings.Contains(joined, bound) {
			t.Fatalf("producerAsserted %v lists %s, which an observer binds", r.ProducerAsserted, bound)
		}
	}
	// Without a key no arming record verifies, so no instant is credited.
	if r := aee.Verify(body, nil); len(r.ArmedAt) != 0 {
		t.Fatalf("armedAt %v credited with no pinned key", r.ArmedAt)
	}
}

func TestParseConsumerPolicy(t *testing.T) {
	pub := strings.Repeat("ab", 32)
	good := `{"substrateObservationKeys":[{"keyid":"k","publicKeyHex":"` + pub + `"}],` +
		`"expectedCorpusDigest":"c","expectedSubstrateDigest":"s","expectedSubjectDigest":"x",` +
		`"allowUnpinnedAnchors":true,"demandedClasses":["XA"],"allowUnpinnedScope":true,` +
		`"acceptedResults":["pass"],"admitUninterceptedCleanRows":false,` +
		`"maxIssuanceLagSeconds":60,"maxEvidenceAgeSeconds":3600,"allowPublishedTestKeys":true}`
	p, err := aee.ParseConsumerPolicy([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SubstrateObservationKeys) != 1 || p.ExpectedSubjectDigest != "x" || !p.AllowUnpinnedAnchors ||
		p.AdmitUninterceptedCleanRows == nil || *p.AdmitUninterceptedCleanRows ||
		p.MaxIssuanceLag != time.Minute || p.MaxEvidenceAge != time.Hour || !p.AllowPublishedTestKeys {
		t.Fatalf("parsed %+v", p)
	}
	for _, bad := range []string{
		"{", `{"expectedSubjectDigests":"x"}`, `{"substrateObservationKeys":[{"publicKeyHex":"zz"}]}`,
		`{"maxIssuanceLagSeconds":-1}`, `{"maxEvidenceAgeSeconds":0}`, `{"maxIssuanceLagSeconds":"1h"}`,
	} {
		if _, err := aee.ParseConsumerPolicy([]byte(bad)); err == nil {
			t.Fatalf("policy %s parsed", bad)
		}
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
