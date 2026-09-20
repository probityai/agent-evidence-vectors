package aee_test

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
	"github.com/probityai/agent-evidence-vectors/aeetest"
)

func pinnedPolicy() *aee.ConsumerPolicy {
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	return &aee.ConsumerPolicy{SubstrateObservationKeys: []ed25519.PublicKey{pub}}
}

func requireValid(t *testing.T, r *aee.Report) {
	t.Helper()
	if r.Verdict != aee.VerdictValid {
		t.Fatalf("expected valid, got %s codes=%v", r.Verdict, r.Codes)
	}
}

func requireInvalid(t *testing.T, r *aee.Report, want aee.Code) {
	t.Helper()
	if r.Verdict != aee.VerdictInvalid {
		t.Fatalf("expected invalid(%s), got valid result=%s tiers=%v", want, r.Result, r.Tiers)
	}
	found := false
	for _, c := range r.Codes {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected code %s, got %v", want, r.Codes)
	}
	// Behavior assertion: an invalid verdict emits no result and no tiers.
	if r.Result != "" || r.Tiers != nil {
		t.Fatalf("invalid report leaked result=%q tiers=%v", r.Result, r.Tiers)
	}
}

func TestCaughtSubstrateValid(t *testing.T) {
	b := aeetest.Build(aeetest.Options{})
	r := aee.Verify(b, pinnedPolicy())
	requireValid(t, r)
	if r.Result != "fail" {
		t.Fatalf("expected result fail, got %q", r.Result)
	}
	if len(r.Tiers) != 1 || r.Tiers[0] != aee.TierAttested {
		t.Fatalf("expected [attested], got %v", r.Tiers)
	}
}

func TestNoPolicyMeansUnattestedNeverInferred(t *testing.T) {
	b := aeetest.Build(aeetest.Options{})
	r := aee.Verify(b, nil)
	requireValid(t, r)
	if r.Tiers[0] != aee.TierUnattested {
		t.Fatalf("no-TOFU violated: tier %v without any pinned key", r.Tiers)
	}
}

func TestWrongSignerIsUnattestedNotInvalid(t *testing.T) {
	b := aeetest.Build(aeetest.Options{SignerRole: aeetest.RoleWrongSigner})
	r := aee.Verify(b, pinnedPolicy())
	requireValid(t, r) // signature failure is a tier outcome, never a validity code
	if r.Tiers[0] != aee.TierUnattested {
		t.Fatalf("expected unattested under wrong signer, got %v", r.Tiers)
	}
}

func TestCleanSubstrateValidPass(t *testing.T) {
	b := aeetest.Build(aeetest.Options{Clean: true})
	r := aee.Verify(b, pinnedPolicy())
	requireValid(t, r)
	if r.Result != "pass" {
		t.Fatalf("expected pass, got %q", r.Result)
	}
	if r.Tiers[0] != aee.TierAttested {
		t.Fatalf("expected attested clean row, got %v", r.Tiers)
	}
}

func TestArtifactOnlyValidDeclared(t *testing.T) {
	b := aeetest.BuildArtifactOnly()
	r := aee.Verify(b, pinnedPolicy())
	requireValid(t, r)
	if r.Tiers[0] != aee.TierDeclared {
		t.Fatalf("expected declared, got %v", r.Tiers)
	}
}

func TestTierNeverAltersResult(t *testing.T) {
	b := aeetest.Build(aeetest.Options{Clean: true})
	with := aee.Verify(b, pinnedPolicy())
	without := aee.Verify(b, nil)
	if with.Result != without.Result {
		t.Fatalf("tier altered result: %q vs %q", with.Result, without.Result)
	}
}

func TestMethodInflationInvalid(t *testing.T) {
	b := aeetest.Build(aeetest.Options{RecordMethod: "reconstructed"})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeMethodCapExceeded)
}

func TestRowMethodAbsentFailClosedSubstrate(t *testing.T) {
	b := aeetest.Build(aeetest.Options{RowMethod: "ABSENT"})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeFailClosedSubstrateRow)
}

func TestRowMethodUnknownFailClosedSubstrate(t *testing.T) {
	b := aeetest.Build(aeetest.Options{RowMethod: "inferred"})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeFailClosedSubstrateRow)
}

func TestResultRecomputeMismatch(t *testing.T) {
	b := aeetest.Build(aeetest.Options{Result: "pass"}) // caught row recomputes fail
	requireInvalid(t, aee.Verify(b, nil), aee.CodeResultRecomputeMismatch)
}

func TestResultVocabulary(t *testing.T) {
	b := aeetest.Build(aeetest.Options{Result: "PASS"})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeResultVocabulary)
}

func TestBatchRootTamper(t *testing.T) {
	b := aeetest.Build(aeetest.Options{TamperBatchRoot: true})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeBatchRootMismatch)
}

func TestVocabularyDigestTamper(t *testing.T) {
	b := aeetest.Build(aeetest.Options{TamperVocabularyDigest: true})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeVocabularyDigestMismatch)
}

func TestRunEntropyMissing(t *testing.T) {
	b := aeetest.Build(aeetest.Options{DropRunEntropy: true})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeRunEntropyMissing)
}

func TestCoverageIncomplete(t *testing.T) {
	b := aeetest.Build(aeetest.Options{ExtraManifestAttack: true})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeCoverageIncomplete)
}

func TestWrongPredicateTypeFailClosed(t *testing.T) {
	b := aeetest.Build(aeetest.Options{PredicateType: "https://in-toto.io/attestation/adversarial-execution-evidence/v0.5"})
	requireInvalid(t, aee.Verify(b, nil), aee.CodePredicateTypeUnsupported)
}

func TestArmedAtAfterIssuedAtCoversNothing(t *testing.T) {
	b := aeetest.Build(aeetest.Options{Clean: true, ArmedAtOverride: "2026-01-01T00:01:00Z"})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeArmingCoversNothing)
}

func TestSealedStillArmedFalseCoversNothing(t *testing.T) {
	b := aeetest.Build(aeetest.Options{Clean: true, SealedStillArmedFalse: true})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeSealedCoversNothing)
}

// Emit seam: the attestor MUST error, never sign, on gate-0, gate-1, and
// recompute faults (the widened attestor-refuses behavior assertion).
func TestVerifyForEmitRefusals(t *testing.T) {
	cases := map[string][]byte{
		"method-inflation":   aeetest.Build(aeetest.Options{RecordMethod: "reconstructed"}),
		"vocabulary-digest":  aeetest.Build(aeetest.Options{TamperVocabularyDigest: true}),
		"coverage-integrity": aeetest.Build(aeetest.Options{ExtraManifestAttack: true}),
		"recompute-mismatch": aeetest.Build(aeetest.Options{Result: "pass"}),
		"batch-root":         aeetest.Build(aeetest.Options{TamperBatchRoot: true}),
	}
	for name, body := range cases {
		if _, err := aee.VerifyForEmit(body); err == nil {
			t.Errorf("%s: emit seam signed a statement the suite rejects", name)
		}
	}
	if _, err := aee.VerifyForEmit(aeetest.Build(aeetest.Options{})); err != nil {
		t.Errorf("emit seam refused a valid statement: %v", err)
	}
}

func TestCheckRecordSignaturesProducerQA(t *testing.T) {
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)

	// A correctly signed statement passes the gates and the producer-QA check.
	ctx, err := aee.VerifyForEmit(aeetest.Build(aeetest.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.CheckRecordSignatures([]ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("producer QA rejected a correctly signed statement: %v", err)
	}

	// A wrong-signer statement is still gate-valid (signatures are not a GATE 1
	// check), so it seals a context, but the producer-QA signature check fails.
	ctx2, err := aee.VerifyForEmit(aeetest.Build(aeetest.Options{SignerRole: aeetest.RoleWrongSigner}))
	if err != nil {
		t.Fatalf("wrong-signer statement should be gate-valid: %v", err)
	}
	if err := ctx2.CheckRecordSignatures([]ed25519.PublicKey{pub}); err == nil {
		t.Fatal("producer QA accepted a wrong-signer statement")
	}
}

// Structural mutations applied to the JSON directly (no rederive needed).
func mutate(t *testing.T, b []byte, f func(statement map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func predicate(m map[string]any) map[string]any { return m["predicate"].(map[string]any) }

func TestSnakeCaseSpellingRejected(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		predicate(m)["does_not_assert"] = []any{"example"}
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeMemberSpelling)
}

func TestSecondSubjectSubstrateCardinality(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		subj := m["subject"].([]any)
		m["subject"] = append(subj, map[string]any{"digest": map[string]any{"sha256": strings.Repeat("ab", 32)}, "name": "second"})
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeSubjectCardinality)
}

func TestRefOutOfRange(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		rows := predicate(m)["attackResults"].([]any)
		rows[0].(map[string]any)["observationRefs"] = []any{0, 7}
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeRefOutOfRange)
}

func TestRefNonIntegerMalformed(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		rows := predicate(m)["attackResults"].([]any)
		rows[0].(map[string]any)["observationRefs"] = []any{0, 1.5}
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeRefMalformed)
}

func TestRefNegativeMalformed(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		rows := predicate(m)["attackResults"].([]any)
		rows[0].(map[string]any)["observationRefs"] = []any{0, -1}
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeRefMalformed)
}

func TestRefsEmptyCompound(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		rows := predicate(m)["attackResults"].([]any)
		rows[0].(map[string]any)["observationRefs"] = []any{}
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeRefsEmpty)
}

func TestRecordsAbsentPrecedence(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		delete(predicate(m), "observationRecords")
		delete(predicate(m), "batchRoot")
	})
	r := aee.Verify(b, nil)
	requireInvalid(t, r, aee.CodeRecordsAbsent)
	// Registry precedence pin 2: ref-out-of-range is reserved for
	// statements where records exist.
	for _, c := range r.Codes {
		if c == aee.CodeRefOutOfRange {
			t.Fatalf("ref-out-of-range emitted while records absent: %v", r.Codes)
		}
	}
}

func TestBatchRootOrphaned(t *testing.T) {
	b := mutate(t, aeetest.BuildArtifactOnly(), func(m map[string]any) {
		predicate(m)["batchRoot"] = strings.Repeat("ab", 32)
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeBatchRootOrphaned)
}

func TestStatementTypeUnsupported(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		m["_type"] = "https://in-toto.io/Statement/v0.1"
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeStatementTypeUnsupported)
}

func TestIssuedAtMalformed(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		predicate(m)["issuedAt"] = "yesterday"
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeIssuedAtMalformed)
}

func TestUppercaseEntropyDigestNotCanonical(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		env := predicate(m)["observationEnvironment"].(map[string]any)
		re := env["runEntropy"].(map[string]any)["digest"].(map[string]any)
		re["sha256"] = strings.ToUpper(re["sha256"].(string))
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeDigestNotCanonical)
}

func TestCleanRowLayerNotNone(t *testing.T) {
	b := mutate(t, aeetest.Build(aeetest.Options{Clean: true}), func(m map[string]any) {
		rows := predicate(m)["attackResults"].([]any)
		rows[0].(map[string]any)["actualLayer"] = "policy.egress_sinkhole"
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeCleanRowLayerNotNone)
}

func TestReconstructedRowWithoutExaminationUncovered(t *testing.T) {
	// A method: reconstructed row must reference at least one examination
	// record; the built statement's only record is an interception, so the
	// class-match requirement is unmet. (The unknown-kind sole-cover case is
	// exercised by the vector suite's dedicated vector.)
	b := mutate(t, aeetest.Build(aeetest.Options{}), func(m map[string]any) {
		rows := predicate(m)["attackResults"].([]any)
		rows[0].(map[string]any)["method"] = "reconstructed"
	})
	requireInvalid(t, aee.Verify(b, nil), aee.CodeReconstructedRowUncovered)
}
