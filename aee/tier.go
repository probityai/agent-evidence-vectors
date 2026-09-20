package aee

// GATE 2 — the per-row evidence tier (spec:req-fields-there-second-use-these-three@260bfd9c41c35939). Trust-relative and
// derived, never carried: {declared | unattested | attested} given the
// consumer's key policy. The tier is total and deterministic given that
// policy; it never alters result.
//
// No TOFU: a consumer with no policy-pinned substrate root MUST treat every
// basis: substrate row as unattested and MUST NOT infer the substrate root
// from the predicate (spec:req-fields-there-second-use-these-three@260bfd9c41c35939). A record's keyid is an unauthenticated
// lookup hint and never the check itself (spec:req-verification-consumer-pin-out-band-set@263aa86dc614e465): verification below
// tries every policy-named key and never reads keyid.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Tier is a derived per-row evidence tier.
type Tier string

// The three tiers. Consumer policy MAY subdivide attested into stricter
// refinements; a refinement refines, never reorders, and tier names
// beginning with "aee" are reserved (spec:req-fields-closure-against-producer-consumer-obligation@eae11109144a622f).
const (
	TierDeclared   Tier = "declared"
	TierUnattested Tier = "unattested"
	TierAttested   Tier = "attested"
)

// ConsumerPolicy is the consumer's out-of-band expectation set: the
// substrate observation keys (GATE 2's input) and the expected corpus and
// substrate anchors compared at the consumer-policy step after GATE 2.
// Nothing in it is ever read from the predicate.
type ConsumerPolicy struct {
	SubstrateObservationKeys []ed25519.PublicKey

	// ExpectedCorpusDigest is the corpus digest the consumer expects for the
	// deployment it is admitting into (lowercase 64-hex sha256). Empty means
	// unsupplied: no comparison is made and the corpus anchor never fails
	// admission. When supplied, inequality with
	// observationEnvironment.corpus.digest.sha256 fails admission, never
	// validity: an anchor-mismatched attestation is valid evidence about the
	// wrong context.
	ExpectedCorpusDigest string

	// ExpectedSubstrateDigest is the substrate digest the consumer expects,
	// with the same semantics against
	// observationEnvironment.substrate.digest.sha256.
	ExpectedSubstrateDigest string
}

// DeriveTiers derives the per-row tier column for a statement that has
// already passed GATE 0 and GATE 1. Row order matches attackResults order.
//
//   - a basis: artifact row is declared; a row fail-closed on basis sits at
//     the bottom of both orderings (spec:req-fields-attribution-axis-acquires-such-reader@dded35f82974eac5) and is reported declared —
//     it can strengthen nothing;
//   - a basis: substrate row is attested when every covering record's
//     signature verifies against a policy-named key, unattested otherwise.
func (ctx *EvalContext) DeriveTiers(policy *ConsumerPolicy) []Tier {
	p := ctx.s.Predicate
	tiers := make([]Tier, len(p.Rows))

	for i := range p.Rows {
		row := &p.Rows[i]
		if !row.IsSubstrate() {
			tiers[i] = TierDeclared
			continue
		}
		if policy == nil || len(policy.SubstrateObservationKeys) == 0 {
			tiers[i] = TierUnattested
			continue
		}
		rowCodes, covering := checkSubstrateRow(p, row, ctx.states, ctx.binding, ctx.issuedAt)
		if len(rowCodes) > 0 {
			// Unreachable on a validated context; fail-closed if reached.
			tiers[i] = TierUnattested
			continue
		}
		tiers[i] = TierAttested
		for _, idx := range covering {
			if !recordVerifies(&ctx.states[idx], p.Records[idx].Signatures, policy.SubstrateObservationKeys) {
				tiers[i] = TierUnattested
				break
			}
		}
	}
	return tiers
}

// recordVerifies reports whether at least one of the record's signatures
// verifies over its DSSE PAE bytes against at least one policy-named key.
func recordVerifies(state *recordState, sigs []RecordSignature, keys []ed25519.PublicKey) bool {
	if state.decodeErr {
		return false
	}
	for _, sig := range sigs {
		sigBytes, err := base64.StdEncoding.Strict().DecodeString(sig.Sig)
		if err != nil {
			continue
		}
		for _, key := range keys {
			if ed25519.Verify(key, state.pae, sigBytes) {
				return true
			}
		}
	}
	return false
}

// CheckRecordSignatures is the producer-QA check the attestor exposes
// behind an explicit flag: it verifies that every substrate row's covering
// records carry a signature verifying under the given keys. It derives NO
// tier — the tier is a consumer derivation by definition — and its failure
// is a producer pipeline error, never a validity code.
func (ctx *EvalContext) CheckRecordSignatures(keys []ed25519.PublicKey) error {
	p := ctx.s.Predicate
	if !hasSubstrateRows(p) {
		return nil
	}
	// The context is sealed by Evaluate, so the statement-level record codes
	// (undecodable / batch-root / duplicate) are already known empty -- the
	// prior free function discarded them from a fresh checkRecordsStatementLevel
	// call, which a consumer invoking it directly (without GATE 1) could exploit
	// to sign over unvalidated records. That path no longer exists.
	for i := range p.Rows {
		row := &p.Rows[i]
		if !row.IsSubstrate() {
			continue
		}
		rowCodes, covering := checkSubstrateRow(p, row, ctx.states, ctx.binding, ctx.issuedAt)
		if len(rowCodes) > 0 {
			return fmt.Errorf("row %d (%s) is not gate-1 valid: %v", i, row.AttackID, rowCodes)
		}
		for _, idx := range covering {
			if !recordVerifies(&ctx.states[idx], p.Records[idx].Signatures, keys) {
				return fmt.Errorf("row %d (%s): covering record %d does not verify under the expected key", i, row.AttackID, idx)
			}
		}
	}
	return nil
}
