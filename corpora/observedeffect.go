package corpora

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/probityai/agent-evidence-vectors/observedeffect"
)

func init() { register(observedEffect{}) }

// observedEffect judges vectors-observed-effect/ by replaying every member through
// the Go rail in observedeffect.
//
// Before this reader the corpus was judged by nothing this binary runs: aee-verify
// exited 2 on the directory with "no reader in this binary judges it", which is the
// correct refusal and not a result. Its Python reference verifier ran in CI and
// nowhere else, so a consumer holding the release binary could not check the
// corpus at all, and the two rails could not be compared member by member.
type observedEffect struct{}

func (observedEffect) Suite() string { return "observed-effect-conformance" }

type observedEffectManifest struct {
	PredicateType string            `json:"predicateType"`
	PredicateSpec string            `json:"predicateSpec"`
	Counts        map[string]int    `json:"counts"`
	Conditions    map[string]string `json:"conditions"`
	EmptyTree     map[string]string `json:"emptyTree"`
	CorpusDigest  string            `json:"corpusDigest"`
	Keys          struct {
		Observer struct {
			PublicKey string `json:"publicKey"`
		} `json:"observer"`
	} `json:"keys"`
	Vectors []observedEffectVector `json:"vectors"`
}

type observedEffectVector struct {
	ID         string   `json:"id"`
	Slug       string   `json:"slug"`
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	Parent     string   `json:"parent"`
	Conditions []string `json:"conditions"`
	Expected   struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
	Readings []struct {
		Verdict string `json:"verdict"`
	} `json:"readings"`
}

// narratedBlob is the one blob this corpus's read rows point at, restated here
// rather than imported from the generator or read from a file.
//
// The range-preimage rule binds blob length and both offsets, and a verifier that
// does not hold the blob cannot check it. So this reader holds it, and states it
// itself: a reader that took the bytes from the thing it is judging would agree
// with the corpus by construction. If the corpus ever narrates different bytes,
// the digest check below says so rather than the rule quietly going unexercised.
var narratedBlob = bytes.Repeat([]byte("port: 8080\nmode: strict\n"), 8)

func (o observedEffect) Judge(dir string, raw []byte) (*Result, error) {
	var m observedEffectManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	if len(m.Vectors) == 0 {
		return nil, fmt.Errorf("%s/MANIFEST.json carries no vectors", dir)
	}
	policy, err := o.policy(dir, m)
	if err != nil {
		return nil, err
	}
	result := &Result{}
	for _, v := range m.Vectors {
		result.Members = append(result.Members, o.judgeMember(dir, v, policy))
	}
	result.Findings = append(result.Findings, o.corpusFindings(dir, m, policy)...)
	return result, nil
}

// policy is what a consumer brings: the predicate type read out of the document
// that defines it, the observer key the manifest publishes as the anchored one, and
// the blob this reader holds.
func (o observedEffect) policy(dir string, m observedEffectManifest) (observedeffect.Policy, error) {
	spec := m.PredicateSpec
	if spec == "" {
		return observedeffect.Policy{}, fmt.Errorf(
			"%s/MANIFEST.json names no predicateSpec, so the predicate type cannot be read "+
				"out of the document that defines it", dir)
	}
	predicateType, err := observedeffect.PredicateTypeFromSpec(filepath.Join(dir, "..", spec))
	if err != nil {
		return observedeffect.Policy{}, err
	}
	return observedeffect.Policy{
		PredicateType:        predicateType,
		ObserverPublicKeyHex: m.Keys.Observer.PublicKey,
		Blobs:                map[string][]byte{sha(narratedBlob): narratedBlob},
	}, nil
}

func (o observedEffect) judgeMember(dir string, v observedEffectVector, policy observedeffect.Policy) Member {
	member := Member{ID: v.ID, Kind: v.Kind}
	if v.File == "" {
		member.Findings = append(member.Findings, "MANIFEST row declares no file")
		return member
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		member.Findings = append(member.Findings, "vector body missing: "+err.Error())
		return member
	}
	// The identifier is the first 16 hex characters of the member's own bytes, so
	// an edited vector cannot keep its name.
	if want := "v" + sha(body)[:16]; want != v.ID {
		member.Findings = append(member.Findings, fmt.Sprintf(
			"file bytes hash to %s and the manifest calls this member %s", want, v.ID))
	}
	report := observedeffect.Verify(body, policy)
	switch v.Kind {
	case "accept", "reject":
		o.checkDeclared(v, report, &member)
	case "indeterminate":
		o.checkIndeterminate(v, report, &member)
	default:
		member.Findings = append(member.Findings, fmt.Sprintf(
			"MANIFEST lists this member under kind %q, which this reader does not replay. "+
				"A kind nobody taught the reader about is refused by name rather than "+
				"replayed as an accept.", v.Kind))
	}
	return member
}

func (o observedEffect) checkDeclared(v observedEffectVector, report *observedeffect.Report, out *Member) {
	if report.Verdict != v.Expected.Verdict {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"%s: expected %s, got %s %v", v.Slug, v.Expected.Verdict, report.Verdict, report.Codes))
		return
	}
	if len(v.Expected.Codes) > 0 && !sameStrings(report.Codes, v.Expected.Codes) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"%s: expected codes %v, got %v", v.Slug, v.Expected.Codes, report.Codes))
		return
	}
	// The vocabulary's prohibition -- a voluntary record may never be read as
	// evidence of independent observation -- was asserted here and could not fail.
	// Verify sets IndependentlyObserved to `derivedTier == "authoritative"`, so
	// `IndependentlyObserved && DerivedTier != "authoritative"` was a
	// contradiction: a guard in the shape of the central prohibition, reporting a
	// clean member in the same words a working guard would. It is gone, and the
	// invariant is asserted where it can fail instead, over every member, in
	// TestTheObservedBitIsTheRecomputedTier.
}

func (o observedEffect) checkIndeterminate(v observedEffectVector, report *observedeffect.Report, out *Member) {
	if len(v.Readings) == 0 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"%s: declared indeterminate and names no readings, so no answer can be wrong", v.Slug))
		return
	}
	allowed := make([]string, 0, len(v.Readings))
	for _, reading := range v.Readings {
		allowed = append(allowed, reading.Verdict)
		if reading.Verdict == report.Verdict {
			return
		}
	}
	sort.Strings(allowed)
	out.Findings = append(out.Findings, fmt.Sprintf(
		"%s: this rail took the reading %q, which is outside the declared set %v",
		v.Slug, report.Verdict, allowed))
}

// corpusFindings are the claims that belong to no single member.
func (o observedEffect) corpusFindings(dir string, m observedEffectManifest, policy observedeffect.Policy) []string {
	var findings []string
	if m.PredicateType != policy.PredicateType {
		findings = append(findings, fmt.Sprintf(
			"the manifest's predicateType is not the Type URI %s states", m.PredicateSpec))
	}
	for algorithm, declared := range m.EmptyTree {
		computed, known := observedeffect.EmptyTree(algorithm)
		if !known {
			findings = append(findings, fmt.Sprintf(
				"the manifest declares an empty-tree constant for %s and this rail knows none", algorithm))
			continue
		}
		if declared != computed {
			findings = append(findings, fmt.Sprintf(
				"the manifest's %s empty-tree constant is not the one this rail holds", algorithm))
		}
	}
	// The blob this reader states has to be the blob the corpus narrates, or the
	// range-preimage rule ran against nothing and reported a pass.
	if !blobIsNamed(dir, m, sha(narratedBlob)) {
		findings = append(findings, "the blob this reader reconstructs is named by no read row, "+
			"so the range-preimage rule was not exercised")
	}
	findings = append(findings, o.checkTwins(m)...)
	findings = append(findings, o.checkParents(m)...)
	measured := map[string]int{}
	for _, v := range m.Vectors {
		measured[v.Kind]++
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		findings = append(findings, bad)
	}
	ids, files := make([]string, 0, len(m.Vectors)), make([]string, 0, len(m.Vectors))
	for _, v := range m.Vectors {
		ids, files = append(ids, v.ID), append(files, v.File)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		findings = append(findings, "corpus digest could not be computed: "+err.Error())
	} else if m.CorpusDigest != digest {
		findings = append(findings, fmt.Sprintf(
			"corpusDigest %s does not recompute (%s)", short(m.CorpusDigest), short(digest)))
	}
	return findings
}

// blobIsNamed asks whether any member's payload actually names this digest.
//
// The first version of this function looked for the string "oe-range-preimage" in
// the manifest's condition lists and returned true if a member declared it. That
// is a check on a label, not on the bytes: the corpus could narrate a different
// blob, the range-preimage rule would skip every row for want of the blob, and this
// function would still have said the rule was exercised. It decodes the payloads
// now, which is the only place the digest appears.
func blobIsNamed(dir string, m observedEffectManifest, digest string) bool {
	for _, v := range m.Vectors {
		body, err := readIn(dir, v.File)
		if err != nil {
			continue
		}
		var envelope struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			continue
		}
		if bytes.Contains(payload, []byte(digest)) {
			return true
		}
	}
	return false
}

// checkTwins is what makes a corpus of refusals scoreable: every condition a
// reject member carries must also be carried by a member that has to be ACCEPTED.
// Without it a verifier that refuses everything scores full marks.
func (o observedEffect) checkTwins(m observedEffectManifest) []string {
	accepted, rejected, indeterminate := map[string]bool{}, map[string]bool{}, map[string]bool{}
	buckets := map[string]map[string]bool{
		"accept": accepted, "reject": rejected, "indeterminate": indeterminate,
	}
	for _, v := range m.Vectors {
		bucket, known := buckets[v.Kind]
		if !known {
			continue
		}
		for _, condition := range v.Conditions {
			bucket[condition] = true
		}
	}
	var findings []string
	for _, condition := range orphanTwins(accepted, rejected) {
		// A condition carried only by an indeterminate member is exempt by
		// construction: the predicate states no rule for it, so there is no
		// implementation for a refuse-everything strategy to skip.
		if indeterminate[condition] {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"condition %s is exercised only by reject members, so refusing everything "+
				"scores full marks on it", condition))
	}
	exercised := map[string]bool{}
	for _, bucket := range buckets {
		for condition := range bucket {
			exercised[condition] = true
		}
	}
	for _, condition := range declaredMinusUsed(m.Conditions, exercised) {
		findings = append(findings, fmt.Sprintf(
			"condition %s is declared and no member exercises it", condition))
	}
	for _, condition := range sortedKeys(exercised) {
		if _, declared := m.Conditions[condition]; !declared {
			findings = append(findings, fmt.Sprintf(
				"condition %s is used by a member and not declared", condition))
		}
	}
	for _, condition := range sortedKeys(m.Conditions) {
		if accepted[condition] && !rejected[condition] && !indeterminate[condition] {
			findings = append(findings, fmt.Sprintf(
				"condition %s has no reject member, so a verifier that implements nothing "+
					"for it scores full marks", condition))
		}
	}
	return findings
}

// checkParents holds every reject member to the accept member it is one mutation
// from. A reject vector with no parent is a refusal nobody can reproduce.
func (o observedEffect) checkParents(m observedEffectManifest) []string {
	ids := map[string]bool{}
	for _, v := range m.Vectors {
		ids[v.ID] = true
	}
	var findings []string
	for _, v := range m.Vectors {
		if v.Kind != "reject" {
			continue
		}
		switch {
		case v.Parent == "":
			findings = append(findings, v.ID+": a reject member names no parent")
		case !ids[v.Parent]:
			findings = append(findings, fmt.Sprintf(
				"%s: parent %s is not a member", v.ID, v.Parent))
		}
	}
	return findings
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
