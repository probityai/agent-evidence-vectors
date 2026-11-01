package corpora

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(aeeCorpus{}) }

// aeeCorpus judges vectors/, the AEE predicate corpus, by replaying every
// member through aee.Verify.
//
// It runs in BARE CONFORMANCE-REPLAY mode: no consumer key policy is supplied,
// which is the column a stranger can reproduce without holding any of our keys.
// Under it every substrate row derives unattested and no row may reach attested
// (there is no trust on first use), so the tierWithoutKey column the corpus
// pins is checkable here and the pinned-key column is not. The pinned-key
// column is exercised by aee/vectors_test.go, which holds the test key.
type aeeCorpus struct{}

func (aeeCorpus) Suite() string { return "adversarial-execution-evidence-conformance" }

type aeeManifest struct {
	PredicateType string         `json:"predicateType"`
	Counts        map[string]int `json:"counts"`
	Vectors       []aeeVector    `json:"vectors"`
	Index         []aeeVector    `json:"index"`
}

type aeeVector struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Expected struct {
		Codes          []string          `json:"codes"`
		Result         string            `json:"result"`
		TierWithoutKey []string          `json:"tierWithoutKey"`
		Family         string            `json:"family"`
		Readings       map[string]string `json:"readings"`
	} `json:"expected"`
}

func (a aeeCorpus) Judge(dir string, raw []byte) (*Result, error) {
	var m aeeManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	vectors := m.Vectors
	if len(vectors) == 0 {
		vectors = m.Index
	}
	if len(vectors) == 0 {
		return nil, fmt.Errorf("%s/MANIFEST.json carries no vectors under \"vectors\" or \"index\"", dir)
	}
	result := &Result{}
	// The primary code this rail reports per indeterminate member, collected as
	// the members run and asserted family-wide afterwards. The per-member check
	// can only ask whether the answer is one somebody declared; whether the
	// answers hang together is a property of several of them at once.
	answers := map[string]string{}
	seen := map[string]bool{}

	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate id")
		}
		seen[v.ID] = true
		if v.File == "" {
			member.Findings = append(member.Findings, "MANIFEST row declares no file")
			result.Members = append(result.Members, member)
			continue
		}
		body, err := readIn(dir, v.File)
		if err != nil {
			member.Findings = append(member.Findings, "vector body missing: "+err.Error())
			result.Members = append(result.Members, member)
			continue
		}
		switch v.Kind {
		case "accept":
			a.checkAccept(body, v, &member)
		case "reject":
			a.checkReject(body, v, &member)
		case "indeterminate":
			answers[v.ID] = a.checkIndeterminate(body, v, &member)
		default:
			member.Findings = append(member.Findings, fmt.Sprintf(
				"MANIFEST lists this member under kind %q, which this reader does not replay. "+
					"A kind nobody taught the reader about is refused by name rather than "+
					"replayed as an accept.", v.Kind))
		}
		result.Members = append(result.Members, member)
	}

	result.Findings = append(result.Findings, a.checkFamilyCoherence(vectors, answers)...)
	measured := map[string]int{}
	for _, v := range vectors {
		measured[v.Kind]++
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	return result, nil
}

// verifyBare runs the verifier with no consumer policy at all, which is the
// column a third party can reproduce.
func verifyBare(body []byte) *aee.Report {
	defer func() { _ = recover() }()
	return aee.Verify(body, nil)
}

func (aeeCorpus) checkAccept(body []byte, v aeeVector, out *Member) {
	report := verifyBare(body)
	if report == nil {
		out.Findings = append(out.Findings, "the verifier panicked on this member")
		return
	}
	if report.Verdict != aee.VerdictValid {
		out.Findings = append(out.Findings, fmt.Sprintf("expected valid, got invalid %v", report.Codes))
		return
	}
	if v.Expected.Result != "" && report.Result != v.Expected.Result {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"result %q want %q", report.Result, v.Expected.Result))
	}
	if want := v.Expected.TierWithoutKey; len(want) > 0 {
		if len(report.Tiers) != len(want) {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"tier count %d want %d (%v)", len(report.Tiers), len(want), report.Tiers))
		} else {
			for i := range want {
				if string(report.Tiers[i]) != want[i] {
					out.Findings = append(out.Findings, fmt.Sprintf(
						"tier[%d]=%s want %s", i, report.Tiers[i], want[i]))
				}
			}
		}
	}
	// Tier soundness with no pinned keys: no row may reach attested, whatever
	// the suite pins. Trust on first use is exactly the thing a consumer with no
	// key policy must not be granted.
	for i, tier := range report.Tiers {
		if tier == aee.TierAttested {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"tier[%d] is attested with no key policy at all, which is trust on first use", i))
		}
	}
}

func (aeeCorpus) checkReject(body []byte, v aeeVector, out *Member) {
	report := verifyBare(body)
	if report == nil {
		out.Findings = append(out.Findings, "the verifier panicked on this member")
		return
	}
	if report.Verdict != aee.VerdictInvalid {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"expected invalid(%v), got valid (result %q)", v.Expected.Codes, report.Result))
		return
	}
	if len(v.Expected.Codes) > 0 && !containsCode(v.Expected.Codes, string(report.PrimaryCode)) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"primary code %s not in expected set %v (all: %v)",
			report.PrimaryCode, v.Expected.Codes, report.Codes))
	}
	if report.Result != "" || report.Tiers != nil {
		out.Findings = append(out.Findings, "invalid verdict leaked result/tiers")
	}
}

// checkIndeterminate replays a member the specification settles the verdict for
// and not the condition. What is required is that the rail have A reading and
// keep to it; the reading is compared family-wide afterwards.
func (aeeCorpus) checkIndeterminate(body []byte, v aeeVector, out *Member) string {
	if len(v.Expected.Readings) < 2 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares %d reading(s); a family with fewer than two is a reject vector",
			len(v.Expected.Readings)))
		return ""
	}
	report := verifyBare(body)
	if report == nil {
		out.Findings = append(out.Findings, "the verifier panicked on this member")
		return ""
	}
	if report.Verdict != aee.VerdictInvalid {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"expected invalid, got valid (result %q)", report.Result))
		return ""
	}
	if report.Result != "" || report.Tiers != nil {
		out.Findings = append(out.Findings, "invalid verdict leaked result/tiers")
	}
	predicted := false
	for _, want := range v.Expected.Readings {
		if want == string(report.PrimaryCode) {
			predicted = true
		}
	}
	if !predicted {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"primary code %s is predicted by no declared reading (all codes: %v). An "+
				"undeclared reading is added to the family by name, never by widening the set",
			report.PrimaryCode, report.Codes))
	}
	return string(report.PrimaryCode)
}

// checkFamilyCoherence asserts one declared reading explains every member of
// each family. Either answer is admissible; answering two members under
// different readings is not, because the reported condition is then a function
// of incidental structure rather than of a policy the rail applies.
func (aeeCorpus) checkFamilyCoherence(vectors []aeeVector, answers map[string]string) []string {
	families := map[string][]aeeVector{}
	for _, v := range vectors {
		if v.Kind == "indeterminate" && v.Expected.Family != "" {
			families[v.Expected.Family] = append(families[v.Expected.Family], v)
		}
	}
	var findings []string
	for _, family := range sortedKeys(families) {
		members := families[family]
		matched := false
		for reading := range members[0].Expected.Readings {
			all := true
			for _, m := range members {
				if m.Expected.Readings[reading] != answers[m.ID] {
					all = false
				}
			}
			if all {
				matched = true
			}
		}
		if matched {
			continue
		}
		got := make([]string, 0, len(members))
		for _, m := range members {
			got = append(got, m.ID+" -> "+answers[m.ID])
		}
		sort.Strings(got)
		findings = append(findings, fmt.Sprintf(
			"family %s: no declared reading explains this rail's answers (%s)",
			family, strings.Join(got, ", ")))
	}
	return findings
}

func containsCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
