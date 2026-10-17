package aee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// The admission conjunction.
//
// Validity and the tier column are facts about the carried bytes and the
// consumer's keys. ADMITTED is the answer a relying party acts on, and it is
// the one this package used to report on too little. With no policy at all the
// CLI exited 0 and printed "result":"pass" while every row was unattested; with
// the observation key alone it admitted a statement whose subject had been
// renamed and redated after the run, and one whose result was "fail". The
// specification already said what an admission decision needs: the consumer
// pins the corpus and the substrate it expects, pins the classes it demands or
// declines the demand by name, credits a substrate row only under a key it
// pinned, and bounds time against a substrate-signed instant rather than
// issuedAt. This file implements that conjunction, with the same knobs and the
// same absent-input defaults agent-evidence-admission's rails take, so a policy
// pinned for an offline check and for a cluster means the same thing.

// PublishedTestKeyRoles are the roles whose Ed25519 seed this repository
// publishes, SHA-256("in-toto-aee-test-key/<role>/v1"), so that every vector
// is reproducible. Anyone can sign with them, which is the point for a
// conformance suite and the opposite of the point for an admission decision:
// a record that verifies under one says only that someone ran the recipe.
var PublishedTestKeyRoles = []string{
	"substrate-observation-test", "wrong-signer-test", "statement-test", "no-pae-verify",
}

// isPublishedTestKey reports whether pub is the public half of a published
// test seed.
func isPublishedTestKey(pub ed25519.PublicKey) bool {
	for _, role := range PublishedTestKeyRoles {
		seed := sha256.Sum256([]byte("in-toto-aee-test-key/" + role + "/v1"))
		if ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey).Equal(pub) {
			return true
		}
	}
	return false
}

// The two admissible thresholds over fail < degraded < pass_indirect < pass.
// A threshold is not a free set of tokens: a list naming "degraded", or only
// "pass_indirect", is a typo rather than a policy, and it refuses loudly.
var (
	thresholdPass     = []string{ResultPass}
	thresholdIndirect = []string{ResultPass, ResultPassIndirect}
)

// admissionCodes returns every policy code the consumer's policy raises against
// a VALID statement, in a fixed order. An empty result is admission.
func admissionCodes(ctx *EvalContext, tiers []Tier, policy *ConsumerPolicy, armed []time.Time) []Code {
	if policy == nil {
		policy = &ConsumerPolicy{}
	}
	var codes []Code
	if !tierPolicySatisfied(ctx, tiers) || !sealsVerify(ctx, policy) {
		codes = appendCode(codes, CodeSubstrateRowUnattested)
	}
	if !policy.AllowPublishedTestKeys {
		for _, key := range policy.SubstrateObservationKeys {
			if isPublishedTestKey(key) {
				codes = appendCode(codes, CodePublishedTestKey)
				break
			}
		}
	}
	codes = append(codes, anchorPolicyCodes(ctx, policy)...)
	codes = append(codes, scopePolicyCodes(ctx, policy)...)
	codes = append(codes, thresholdPolicyCodes(ctx, policy)...)
	codes = append(codes, timePolicyCodes(ctx, policy, armed)...)
	return codes
}

// sealsVerify reports whether every sealed record of a statement carrying a
// basis: substrate row verifies under a pinned key. A row's tier reads only the
// records the row resolves, and a caught row resolves interception records, so
// a seal no row references would otherwise carry any signature bytes at all.
// The seal is the producer's closing statement of what the observer saw; it is
// checked in every case, never because of what the rows contain.
func sealsVerify(ctx *EvalContext, policy *ConsumerPolicy) bool {
	p := ctx.s.Predicate
	if !hasSubstrateRows(p) {
		return true
	}
	if policy == nil || len(policy.SubstrateObservationKeys) == 0 {
		return false
	}
	kinds := recordKinds(p, ctx.states)
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		if !recordVerifies(&ctx.states[i], p.Records[i].Signatures, policy.SubstrateObservationKeys) {
			return false
		}
	}
	return true
}

// anchorPolicyCodes compares the three pins against the carried digests. A pin
// the consumer did not supply fails admission, unless the consumer declined the
// pins by name, and the decline excuses an ABSENT pin only: a mismatched pin is
// refused whatever the decline says. The subject pin is compared against
// subject[0].digest.sha256, the one subject value the observer's records bind;
// the subject's name, uri and any other digest algorithm are never compared,
// because a producer holding only the envelope key rewrites them freely.
func anchorPolicyCodes(ctx *EvalContext, policy *ConsumerPolicy) []Code {
	env := ctx.s.Predicate.Env
	subject := ""
	if len(ctx.s.Subject) > 0 {
		subject = ctx.s.Subject[0].Digest["sha256"]
	}
	pins := []struct {
		expected, carried  string
		unpinned, mismatch Code
	}{
		{policy.ExpectedCorpusDigest, env.Corpus.Sha256(), CodeCorpusAnchorUnpinned, CodeCorpusAnchorMismatch},
		{policy.ExpectedSubstrateDigest, env.Substrate.Sha256(), CodeSubstrateAnchorUnpinned, CodeSubstrateAnchorMismatch},
		{policy.ExpectedSubjectDigest, subject, CodeSubjectAnchorUnpinned, CodeSubjectAnchorMismatch},
	}
	var codes []Code
	for _, pin := range pins {
		switch {
		case pin.expected == "" && !policy.AllowUnpinnedAnchors:
			codes = appendCode(codes, pin.unpinned)
		case pin.expected != "" && pin.expected != pin.carried:
			codes = appendCode(codes, pin.mismatch)
		}
	}
	return codes
}

// scopePolicyCodes holds the demanded-class obligation. The deciding fact is
// the consumer's: a withdrawn class is byte-identical to an honest run with no
// coverage of it, so only the consumer's demand can refuse it.
func scopePolicyCodes(ctx *EvalContext, policy *ConsumerPolicy) []Code {
	if len(policy.DemandedClasses) == 0 {
		if policy.AllowUnpinnedScope {
			return nil
		}
		return []Code{CodeScopeUnpinned}
	}
	assessed := map[string]bool{}
	if ctx.s.Predicate.Coverage != nil {
		for _, c := range ctx.s.Predicate.Coverage.AssessedClasses {
			assessed[c] = true
		}
	}
	for _, c := range policy.DemandedClasses {
		if !assessed[c] {
			return []Code{CodeDemandedClassUnassessed}
		}
	}
	return nil
}

// thresholdPolicyCodes holds the result threshold and the clean-row rule
// together, because the specification ties them: "a policy relaxed to admit
// pass_indirect MUST keep the rule". A widened threshold must say what it
// requires of a row, and declining the row rule under a pass-only threshold
// changes nothing, so both of those pairings refuse by name rather than
// resolve silently in either direction.
func thresholdPolicyCodes(ctx *EvalContext, policy *ConsumerPolicy) []Code {
	threshold := thresholdPass
	if policy.AcceptedResults != nil {
		threshold = policy.AcceptedResults
	}
	var codes []Code
	relaxed := sameTokens(threshold, thresholdIndirect)
	if !relaxed && !sameTokens(threshold, thresholdPass) {
		return []Code{CodeAcceptedResultsMalformed}
	}
	declared := policy.AdmitUninterceptedCleanRows != nil
	declined := declared && *policy.AdmitUninterceptedCleanRows
	switch {
	case relaxed && !declared:
		codes = appendCode(codes, CodeRowGateUndeclared)
	case declined && !relaxed:
		codes = appendCode(codes, CodeRowGateDeclineUnreachable)
	}
	if (!declined || !relaxed) && cleanRowUnintercepted(ctx) {
		codes = appendCode(codes, CodeCleanRowUnintercepted)
	}
	if !containsToken(threshold, ctx.result) {
		codes = appendCode(codes, CodeResultNotAccepted)
	}
	return codes
}

// cleanRowUnintercepted reports whether some clean row -- a containment label
// the vocabulary lists and does not list as caught -- is anything other than a
// live substrate interception. Such a row is a "nothing happened" claim the
// producer assembled rather than one an observer watched happen.
func cleanRowUnintercepted(ctx *EvalContext) bool {
	p := ctx.s.Predicate
	labels, caught := map[string]bool{}, map[string]bool{}
	if p.Env != nil && p.Env.Vocabulary != nil {
		for _, l := range p.Env.Vocabulary.Labels {
			labels[l] = true
		}
		for _, c := range p.Env.Vocabulary.Caught {
			caught[c] = true
		}
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		if !labels[row.ContainmentObserved] || caught[row.ContainmentObserved] {
			continue
		}
		if !row.IsSubstrate() || row.Method == nil || *row.Method != MethodIntercepted {
			return true
		}
	}
	return false
}

// timePolicyCodes bounds when the run happened against the armedAt instants of
// arming records that verify under a pinned key. issuedAt is read only as the
// far end of the issuance lag, which is the one comparison it can enter: the
// producer can move it, and only upward, so the lag bound is the rewrite turned
// into a rule. A bounded consumer handed no verified arming record refuses,
// because that statement carries no instant an observer signed.
func timePolicyCodes(ctx *EvalContext, policy *ConsumerPolicy, armed []time.Time) []Code {
	if policy.MaxIssuanceLag <= 0 && policy.MaxEvidenceAge <= 0 {
		return nil
	}
	if len(armed) == 0 {
		return []Code{CodeObservedInstantAbsent}
	}
	var codes []Code
	now := time.Now
	if policy.Now != nil {
		now = policy.Now
	}
	for _, at := range armed {
		if policy.MaxIssuanceLag > 0 && ctx.issuedAt.Sub(at) > policy.MaxIssuanceLag {
			codes = appendCode(codes, CodeIssuanceLagExceeded)
		}
		if policy.MaxEvidenceAge > 0 && now().Sub(at) > policy.MaxEvidenceAge {
			codes = appendCode(codes, CodeEvidenceAgeExceeded)
		}
	}
	return codes
}

// verifiedArmedAt returns the armedAt of every arming record that verifies
// under a pinned key and commits to this statement's run binding, sorted. A
// record that does not verify carries no instant this consumer can credit.
func verifiedArmedAt(ctx *EvalContext, policy *ConsumerPolicy) []time.Time {
	if policy == nil || len(policy.SubstrateObservationKeys) == 0 {
		return nil
	}
	p := ctx.s.Predicate
	kinds := recordKinds(p, ctx.states)
	var out []time.Time
	for i := range p.Records {
		if kinds[i] != KindArming {
			continue
		}
		if !recordVerifies(&ctx.states[i], p.Records[i].Signatures, policy.SubstrateObservationKeys) {
			continue
		}
		obj := payloadObject(&ctx.states[i])
		if obj == nil {
			continue
		}
		if binding, ok := objString(obj, memberRunBinding); !ok || binding != ctx.binding {
			continue
		}
		raw, ok := objString(obj, memberArmedAt)
		if !ok {
			continue
		}
		if at, err := parseTimestamp(raw); err == nil {
			out = append(out, at)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Before(out[b]) })
	return out
}

func sameTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, t := range a {
		if seen[t] {
			return false
		}
		seen[t] = true
	}
	for _, t := range b {
		if !seen[t] {
			return false
		}
	}
	return true
}

func containsToken(set []string, t string) bool {
	for _, s := range set {
		if s == t {
			return true
		}
	}
	return false
}

// policyDocument is the consumer policy as a JSON document: the shape the
// admission corpus publishes, AEE_CONSUMER_POLICY points at, and -keys has
// always read (a document carrying only substrateObservationKeys is a policy
// that pins nothing else).
type policyDocument struct {
	SubstrateObservationKeys []struct {
		KeyID        string `json:"keyid"`
		PublicKeyHex string `json:"publicKeyHex"`
	} `json:"substrateObservationKeys"`
	ExpectedCorpusDigest        string   `json:"expectedCorpusDigest"`
	ExpectedSubstrateDigest     string   `json:"expectedSubstrateDigest"`
	ExpectedSubjectDigest       string   `json:"expectedSubjectDigest"`
	AllowUnpinnedAnchors        bool     `json:"allowUnpinnedAnchors"`
	DemandedClasses             []string `json:"demandedClasses"`
	AllowUnpinnedScope          bool     `json:"allowUnpinnedScope"`
	AcceptedResults             []string `json:"acceptedResults"`
	AdmitUninterceptedCleanRows *bool    `json:"admitUninterceptedCleanRows"`
	MaxIssuanceLagSeconds       *float64 `json:"maxIssuanceLagSeconds"`
	MaxEvidenceAgeSeconds       *float64 `json:"maxEvidenceAgeSeconds"`
	AllowPublishedTestKeys      bool     `json:"allowPublishedTestKeys"`
}

// ParseConsumerPolicy reads a consumer policy document. An unknown member is
// refused rather than ignored, because a misspelt pin that parses as absent is
// a pin that silently stopped being enforced. So is a key that is not 32 bytes
// of hex and a time bound that is not a positive number of seconds.
func ParseConsumerPolicy(raw []byte) (*ConsumerPolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc policyDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("consumer policy does not parse: %w", err)
	}
	policy := &ConsumerPolicy{
		ExpectedCorpusDigest:        doc.ExpectedCorpusDigest,
		ExpectedSubstrateDigest:     doc.ExpectedSubstrateDigest,
		ExpectedSubjectDigest:       doc.ExpectedSubjectDigest,
		AllowUnpinnedAnchors:        doc.AllowUnpinnedAnchors,
		DemandedClasses:             doc.DemandedClasses,
		AllowUnpinnedScope:          doc.AllowUnpinnedScope,
		AcceptedResults:             doc.AcceptedResults,
		AdmitUninterceptedCleanRows: doc.AdmitUninterceptedCleanRows,
		AllowPublishedTestKeys:      doc.AllowPublishedTestKeys,
	}
	for _, k := range doc.SubstrateObservationKeys {
		pub, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: publicKeyHex must be %d hex-encoded bytes", k.KeyID, ed25519.PublicKeySize)
		}
		policy.SubstrateObservationKeys = append(policy.SubstrateObservationKeys, ed25519.PublicKey(pub))
	}
	for name, v := range map[string]*float64{"maxIssuanceLagSeconds": doc.MaxIssuanceLagSeconds, "maxEvidenceAgeSeconds": doc.MaxEvidenceAgeSeconds} {
		if v != nil && *v <= 0 {
			return nil, fmt.Errorf("%s must be a positive number of seconds, got %v", name, *v)
		}
	}
	if doc.MaxIssuanceLagSeconds != nil {
		policy.MaxIssuanceLag = time.Duration(*doc.MaxIssuanceLagSeconds * float64(time.Second))
	}
	if doc.MaxEvidenceAgeSeconds != nil {
		policy.MaxEvidenceAge = time.Duration(*doc.MaxEvidenceAgeSeconds * float64(time.Second))
	}
	return policy, nil
}

// boundMembers names, per observationEnvironment member, the members an
// observer's records bind through the run binding or a digest-integrity check.
// networkPosture is absent because the version-2 binding digests the whole
// carried object. Everything else in these objects is the producer's.
var boundMembers = map[string]map[string]bool{
	"catchPolicy":           {"digest": true},
	"corpus":                {"digest": true, "manifest": true},
	"runEntropy":            {"digest": true},
	"substrate":             {"digest": true},
	"observationVocabulary": {"digest": true, "labels": true, "caught": true},
}

// producerAsserted lists the members of a statement no observer signature
// binds, as dotted paths, sorted. It reads the statement's own bytes because
// the parsed Subject keeps only the name and the digest, and a uri or an
// annotation is exactly as unbound as the name.
func producerAsserted(statementJSON []byte) []string {
	var st struct {
		Subject   []map[string]json.RawMessage `json:"subject"`
		Predicate struct {
			IssuedAt json.RawMessage                       `json:"issuedAt"`
			Env      map[string]map[string]json.RawMessage `json:"observationEnvironment"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(statementJSON, &st); err != nil {
		return nil
	}
	var out []string
	if len(st.Subject) > 0 {
		out = append(out, unboundIn("subject[0]", st.Subject[0], map[string]bool{"digest": true})...)
	}
	if st.Predicate.IssuedAt != nil {
		out = append(out, "predicate.issuedAt")
	}
	for member, bound := range boundMembers {
		if obj, ok := st.Predicate.Env[member]; ok {
			out = append(out, unboundIn("predicate.observationEnvironment."+member, obj, bound)...)
		}
	}
	sort.Strings(out)
	return out
}

// unboundIn lists obj's members outside bound, and every digest algorithm but
// sha256 when digest is bound, since only the sha256 value enters a binding.
func unboundIn(prefix string, obj map[string]json.RawMessage, bound map[string]bool) []string {
	var out []string
	for name, raw := range obj {
		if !bound[name] {
			out = append(out, prefix+"."+name)
			continue
		}
		if name != "digest" {
			continue
		}
		var algs map[string]json.RawMessage
		if json.Unmarshal(raw, &algs) != nil {
			continue
		}
		for alg := range algs {
			if alg != "sha256" {
				out = append(out, prefix+".digest."+alg)
			}
		}
	}
	return out
}
