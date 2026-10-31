package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// A rule corpus is a manifest of single-record cases, each judged by an ordered
// list of rules: the first rule that fires names the refusal, and a record no
// rule fires on is accepted. The Python readers in packaging/agent_evidence_vectors
// apply the same rules in the same order; the manifest carries the answer both
// must reach, and a rejected member names the accepted twin it differs from.
type rlRule struct {
	code  string
	fires func(record any) bool
}

type ruleCorpus struct {
	suite  string
	accept string
	rules  []rlRule
}

func (c ruleCorpus) Suite() string { return c.suite }

type rlExpected struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type rlVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected rlExpected        `json:"expected"`
	Twin     string            `json:"twin"`
}

func (c ruleCorpus) decide(record any) rlExpected {
	for _, rule := range c.rules {
		if rule.fires(record) {
			return rlExpected{Decision: "rejected", Reason: rule.code}
		}
	}
	return rlExpected{Decision: "accepted", Reason: c.accept}
}

func (c ruleCorpus) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	accepted := map[string]bool{}
	var vectors []rlVector
	for _, entry := range manifest.Vectors {
		var v rlVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		accepted[v.ID] = v.Expected.Decision == "accepted"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = c.judgeMember(filepath.Join(dir, v.Path), v)
		if v.Expected.Decision == "rejected" && !accepted[v.Twin] {
			member.Findings = append(member.Findings, "a rejected member must name an accepted twin")
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (c ruleCorpus) judgeMember(caseDir string, v rlVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, "case.json cannot be read: "+err.Error())
	}
	record, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "case.json does not parse: "+err.Error())
	}
	if got := c.decide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// rlGet walks a dotted path through nested objects and returns nil when any
// step is missing or is not an object, as the Python readers' _get does.
func rlGet(record any, path string) any {
	node := record
	for _, part := range strings.Split(path, ".") {
		object, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		next, present := object[part]
		if !present {
			return nil
		}
		node = next
	}
	return node
}

func rlStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func rlInt(v any) int64 {
	if n, ok := v.(json.Number); ok {
		i, _ := n.Int64()
		return i
	}
	return 0
}

func rlList(v any) []any {
	l, _ := v.([]any)
	return l
}

func rlMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func rlTrue(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

// rlDigest is the SHA-256 of the value in the compact, sorted, ASCII form the
// Python readers' digest_of takes.
func rlDigest(v any) string {
	compact, err := pythonCompactJSON(v)
	if err != nil {
		return ""
	}
	return sha(compact)
}

func rlStringSet(v any) map[string]bool {
	set := map[string]bool{}
	for _, item := range rlList(v) {
		set[rlStr(item)] = true
	}
	return set
}

func rlSubset(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
