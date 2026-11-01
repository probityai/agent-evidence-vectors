package corpora

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(admission{}) }

// admission judges vectors-admission/: the admission answer a verifier reports
// for an Adversarial Execution Evidence statement under a consumer's policy.
//
// Every member is a statement and a policy. The reader runs the pair through
// aee.Verify and requires the admission answer and the policy codes the
// manifest declares. It also holds the corpus to itself: the digest over the
// files on disk, the counts, every condition cited and every cited condition
// carried by at least one admitted and one refused member (a condition only
// refusals exercise is satisfied by a verifier that refuses everything), and
// every condition's quotation still present in the file it rests on.
type admission struct{}

func (admission) Suite() string { return "adversarial-execution-evidence-admission" }

type admissionVector struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	Policy     string   `json:"policy"`
	Conditions []string `json:"conditions"`
	Expected   struct {
		Admitted    *bool    `json:"admitted"`
		PolicyCodes []string `json:"policyCodes"`
	} `json:"expected"`
}

type admissionCondition struct {
	File  string `json:"file"`
	Quote string `json:"quote"`
}

type admissionManifest struct {
	Conditions   map[string]admissionCondition `json:"conditions"`
	Counts       map[string]int                `json:"counts"`
	CorpusDigest string                        `json:"corpusDigest"`
	Vectors      []admissionVector             `json:"vectors"`
}

var admissionWhitespace = regexp.MustCompile(`\s+`)

func (admission) Judge(dir string, raw []byte) (*Result, error) {
	var m admissionManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", filepath.Join(dir, ManifestName), err)
	}
	res := &Result{}
	for _, v := range m.Vectors {
		res.Members = append(res.Members, Member{ID: v.ID, Kind: v.Kind, Findings: judgeAdmissionMember(dir, v)})
	}
	res.Findings = append(res.Findings, admissionCorpusFindings(dir, &m)...)
	return res, nil
}

func judgeAdmissionMember(dir string, v admissionVector) []string {
	statement, err := os.ReadFile(filepath.Join(dir, v.File)) // #nosec G304,G703 -- a path the manifest names inside the corpus
	if err != nil {
		return []string{fmt.Sprintf("statement unreadable: %v", err)}
	}
	policyBytes, err := os.ReadFile(filepath.Join(dir, v.Policy)) // #nosec G304,G703 -- a path the manifest names inside the corpus
	if err != nil {
		return []string{fmt.Sprintf("policy unreadable: %v", err)}
	}
	policy, err := aee.ParseConsumerPolicy(policyBytes)
	if err != nil {
		return []string{fmt.Sprintf("policy refused: %v", err)}
	}
	if v.Expected.Admitted == nil {
		return []string{"the manifest declares no expected admission answer"}
	}
	var findings []string
	if want := *v.Expected.Admitted; (v.Kind == "accept") != want {
		findings = append(findings, fmt.Sprintf("kind %q disagrees with expected admitted=%t", v.Kind, want))
	}
	r := aee.Verify(statement, policy)
	if r.Verdict != aee.VerdictValid {
		findings = append(findings, fmt.Sprintf("statement is %s (%v); every member of this corpus is a valid statement", r.Verdict, r.Codes))
		return findings
	}
	if r.Admitted != *v.Expected.Admitted {
		findings = append(findings, fmt.Sprintf("admitted=%t, the manifest declares %t (policy codes %v)", r.Admitted, *v.Expected.Admitted, r.PolicyCodes))
	}
	got := make([]string, 0, len(r.PolicyCodes))
	for _, c := range r.PolicyCodes {
		got = append(got, string(c))
	}
	sort.Strings(got)
	want := append([]string(nil), v.Expected.PolicyCodes...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		findings = append(findings, fmt.Sprintf("policy codes %v, the manifest declares %v", got, want))
	}
	return findings
}

func admissionCorpusFindings(dir string, m *admissionManifest) []string {
	var findings []string
	counts := map[string]int{}
	hasher := sha256.New()
	ordered := append([]admissionVector(nil), m.Vectors...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, v := range ordered {
		counts[v.Kind]++
		for _, rel := range []string{v.File, v.Policy} {
			b, err := os.ReadFile(filepath.Join(dir, rel)) // #nosec G304,G703 -- a path the manifest names inside the corpus
			if err != nil {
				findings = append(findings, fmt.Sprintf("%s is named by member %s and unreadable: %v", rel, v.ID, err))
				continue
			}
			hasher.Write(b)
		}
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != m.CorpusDigest {
		findings = append(findings, fmt.Sprintf("corpus digest over the files on disk is %s, the manifest publishes %s", got, m.CorpusDigest))
	}
	for kind, n := range counts {
		if m.Counts[kind] != n {
			findings = append(findings, fmt.Sprintf("counts[%s] is %d, the members carry %d", kind, m.Counts[kind], n))
		}
	}
	for kind := range m.Counts {
		if counts[kind] == 0 {
			findings = append(findings, fmt.Sprintf("counts declares kind %s that no member carries", kind))
		}
	}
	return append(findings, admissionConditionFindings(dir, m)...)
}

func admissionConditionFindings(dir string, m *admissionManifest) []string {
	var findings []string
	byKind := map[string]map[string]bool{}
	for _, v := range m.Vectors {
		for _, c := range v.Conditions {
			if _, ok := m.Conditions[c]; !ok {
				findings = append(findings, fmt.Sprintf("member %s cites condition %s, which the manifest does not define", v.ID, c))
			}
			if byKind[c] == nil {
				byKind[c] = map[string]bool{}
			}
			byKind[c][v.Kind] = true
		}
	}
	names := make([]string, 0, len(m.Conditions))
	for name := range m.Conditions {
		names = append(names, name)
	}
	sort.Strings(names)
	root := filepath.Dir(filepath.Clean(dir))
	for _, name := range names {
		if !byKind[name]["accept"] || !byKind[name]["reject"] {
			findings = append(findings, fmt.Sprintf("condition %s is not carried by both an admitted and a refused member", name))
		}
		cond := m.Conditions[name]
		text, err := os.ReadFile(filepath.Join(root, cond.File)) // #nosec G304,G703 -- a repository path the manifest names
		if err != nil {
			findings = append(findings, fmt.Sprintf("condition %s rests on %s, which cannot be read: %v", name, cond.File, err))
			continue
		}
		body := admissionWhitespace.ReplaceAllString(string(text), " ")
		if !strings.Contains(body, admissionWhitespace.ReplaceAllString(cond.Quote, " ")) {
			findings = append(findings, fmt.Sprintf("condition %s quotes a sentence %s no longer carries", name, cond.File))
		}
	}
	return findings
}
