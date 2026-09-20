package aee

import (
	"fmt"
	"strings"
	"time"
)

// Report is the outcome of a full verification run.
//
// Behavior contract (mirrors the conformance suite's behavior assertions):
// an invalid report carries NO Result and NO Tiers — a consumer must never
// see a result it is forbidden to consume (spec:req-fields-these-requirements-consumption-preconditions-optional@0d960383b00e82b9).
type Report struct {
	// Verdict is "valid" or "invalid".
	Verdict string `json:"verdict"`
	// Codes lists every detected failure code in pinned detection order;
	// empty when valid.
	Codes []Code `json:"codes,omitempty"`
	// PrimaryCode is Codes[0] — the deterministic primary code ("" when
	// valid). Conformance compares the primary code for set membership;
	// code ORDER beyond the primary is never part of the contract.
	PrimaryCode Code `json:"primaryCode,omitempty"`
	// Result is the carried (and recompute-confirmed) result; only set when
	// valid.
	Result string `json:"result,omitempty"`
	// Tiers is the derived per-row evidence tier column, in attackResults
	// order; only set when valid.
	Tiers []Tier `json:"tiers,omitempty"`
	// PolicyCodes lists consumer-policy findings (the anchor comparison) for
	// a VALID statement under the supplied policy. They are consumer-relative
	// admission facts, never validity codes: Verdict, Codes, Result, and
	// Tiers are byte-pure and unchanged by them.
	PolicyCodes []Code `json:"policyCodes,omitempty"`
	// Admitted is the single consumer-facing admission result: validity AND
	// tier-policy satisfaction (every basis: substrate row the consumer
	// credits derives attested; vacuously satisfied when the statement
	// carries no substrate rows) AND every supplied anchor matching. A
	// consumer with no substrate observation keys derives unattested for
	// every substrate row (no TOFU), so such a statement is never admitted
	// under that policy.
	Admitted bool `json:"admitted"`
}

// The two verdicts a Report can carry.
const (
	VerdictValid   = "valid"
	VerdictInvalid = "invalid"
)

// EvalContext is a statement that has passed GATE 0 + GATE 1 + recompute
// equality, with the single expensive record derivation (base64 + PAE + Merkle
// + JCS over every record) memoized. Every field is unexported, so an external
// package cannot construct a usable one: the only way to obtain a populated
// context is Evaluate. Any function that takes an *EvalContext is therefore
// guaranteed a validated statement and never has to (nor can it accidentally
// skip) re-running the gates. This collapses what were three independent
// recomputations -- one in GATE 1, one in DeriveTiers, one in
// CheckRecordSignatures -- into one, which removes the permanent risk that the
// three drift apart.
type EvalContext struct {
	s        *Statement
	states   []recordState
	binding  string
	issuedAt time.Time
	result   string
}

// Statement returns the parsed, validated statement backing the context.
func (ctx *EvalContext) Statement() *Statement { return ctx.s }

// Result returns the carried, recompute-confirmed result.
func (ctx *EvalContext) Result() string { return ctx.result }

// Evaluate runs the shared consumer/producer precondition once -- GATE 0
// (well-formedness) + GATE 1 (coverage validity) + recompute equality -- and
// returns a sealed context on success. On a gate/recompute failure it returns a
// nil context and the failure codes (primary first). On a parse failure it
// returns an error. Exactly one of {ctx non-nil} / {codes non-empty} / {err
// non-nil} holds.
func Evaluate(statementJSON []byte) (*EvalContext, []Code, error) {
	s, err := ParseStatement(statementJSON)
	if err != nil {
		return nil, nil, err
	}
	if codes := Gate0(s); len(codes) > 0 {
		return nil, codes, nil
	}
	states, binding, issuedAt, codes := gate1WithContext(s)
	if len(codes) > 0 {
		return nil, codes, nil
	}
	if got := Recompute(s.Predicate); got != s.Predicate.Result {
		return nil, []Code{CodeResultRecomputeMismatch}, nil
	}
	return &EvalContext{s: s, states: states, binding: binding, issuedAt: issuedAt, result: s.Predicate.Result}, nil, nil
}

// Verify runs the full consumer pipeline over one in-toto statement:
//
//	GATE 0 (statement well-formedness)
//	GATE 1 (coverage validity — consumption precondition)
//	recompute equality (carried result == pure recompute)
//	GATE 2 (evidence tier, per the given consumer policy)
//	consumer-policy step (anchor comparison; Admitted conjunction)
//
// The gates run in that order and the pipeline stops at the first failing
// gate: a statement that fails GATE 0 is invalid regardless of anything a
// later gate might have said, and neither Result nor Tiers is ever derived
// for an invalid statement. The consumer-policy step never alters the
// byte-pure facts: an anchor mismatch fails Admitted, never validity.
func Verify(statementJSON []byte, policy *ConsumerPolicy) *Report {
	ctx, codes, err := Evaluate(statementJSON)
	if err != nil {
		return &Report{Verdict: VerdictInvalid, Codes: []Code{CodeStatementMalformed}, PrimaryCode: CodeStatementMalformed}
	}
	if len(codes) > 0 {
		return invalidReport(codes)
	}
	tiers := ctx.DeriveTiers(policy)
	policyCodes := anchorPolicyCodes(ctx, policy)
	return &Report{
		Verdict:     VerdictValid,
		Result:      ctx.result,
		Tiers:       tiers,
		PolicyCodes: policyCodes,
		Admitted:    tierPolicySatisfied(ctx, tiers) && len(policyCodes) == 0,
	}
}

// tierPolicySatisfied reports whether every basis: substrate row derived
// attested under the consumer's policy. Artifact rows (and rows fail-closed
// on basis) are declared and never gate admission; a statement with no
// substrate rows satisfies the tier policy vacuously, under any key set.
func tierPolicySatisfied(ctx *EvalContext, tiers []Tier) bool {
	rows := ctx.s.Predicate.Rows
	for i := range rows {
		if rows[i].IsSubstrate() && tiers[i] != TierAttested {
			return false
		}
	}
	return true
}

// anchorPolicyCodes compares the supplied expected anchors against the
// carried observationEnvironment digests. An empty expected digest is
// unsupplied and compares nothing. The comparison is deliberately not a
// validity gate: it runs only on a valid statement and its findings live on
// the consumer surface (Report.PolicyCodes), feeding Admitted alone.
func anchorPolicyCodes(ctx *EvalContext, policy *ConsumerPolicy) []Code {
	if policy == nil {
		return nil
	}
	env := ctx.s.Predicate.Env
	var codes []Code
	if policy.ExpectedCorpusDigest != "" && policy.ExpectedCorpusDigest != env.Corpus.Sha256() {
		codes = appendCode(codes, CodeCorpusAnchorMismatch)
	}
	if policy.ExpectedSubstrateDigest != "" && policy.ExpectedSubstrateDigest != env.Substrate.Sha256() {
		codes = appendCode(codes, CodeSubstrateAnchorMismatch)
	}
	return codes
}

// VerifyForEmit is the producer-side seam: GATE 0 + GATE 1 + recompute
// equality, with no tier (the tier is trust-relative and consumer-derived by
// definition; it never runs at emit). It returns the sealed context so the
// producer-QA signature check can reuse the memoized derivation instead of
// re-deriving it. A non-nil error means the statement MUST NOT be signed.
func VerifyForEmit(statementJSON []byte) (*EvalContext, error) {
	ctx, codes, err := Evaluate(statementJSON)
	if err != nil {
		return nil, fmt.Errorf("statement does not parse: %w", err)
	}
	if len(codes) > 0 {
		return nil, fmt.Errorf("statement fails GATE 0/1 or recompute: %s", joinCodes(codes))
	}
	return ctx, nil
}

func invalidReport(codes []Code) *Report {
	return &Report{Verdict: VerdictInvalid, Codes: codes, PrimaryCode: codes[0]}
}

func joinCodes(codes []Code) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}
