package corpusreaders

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func init() { register(mcpAuthz{}) }

// mcpAuthz judges that corpora/vectors-mcp-authz/ is intact. It does not judge
// the observations: a member's verdict and finding codes are the answer a
// verifier under test must give, and this corpus is run against that verifier
// through the external-verifier contract (`--verifier`). The reader checks what
// a verifier cannot: every member file is the one the manifest names, each
// member's answer is well formed (an accept is valid with no codes, a reject is
// invalid with at least one), every observation is marked synthetic, and the
// counts and corpus digest agree with the tree.
type mcpAuthz struct{}

func (mcpAuthz) Suite() string { return "mcp-authz-observation/v1" }

type mcpAuthzManifest struct {
	Suite        string          `json:"suite"`
	Counts       map[string]int  `json:"counts"`
	CorpusDigest string          `json:"corpusDigest"`
	Vectors      []mcpAuthzEntry `json:"vectors"`
}

type mcpAuthzEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Expected struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
}

func (r mcpAuthz) Judge(dir string, raw []byte) (*Result, error) {
	var m mcpAuthzManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, e := range m.Vectors {
		member := Member{ID: e.ID, Kind: e.Kind}
		if seen[e.ID] {
			member.Findings = append(member.Findings, "duplicate id")
		}
		seen[e.ID] = true
		if _, known := measured[e.Kind]; known {
			measured[e.Kind]++
		}
		r.judgeMember(dir, e, &member)
		result.Members = append(result.Members, member)
	}
	sort.Slice(result.Members, func(i, j int) bool { return result.Members[i].ID < result.Members[j].ID })
	ids, files := make([]string, len(m.Vectors)), make([]string, len(m.Vectors))
	for i, e := range m.Vectors {
		ids[i], files[i] = e.ID, e.File
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the observations on disk")
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	return result, nil
}

func (mcpAuthz) judgeMember(dir string, e mcpAuthzEntry, out *Member) {
	switch {
	case e.Kind == "accept" && e.Expected.Verdict == "valid" && len(e.Expected.Codes) == 0:
	case e.Kind == "reject" && e.Expected.Verdict == "invalid" && len(e.Expected.Codes) > 0:
	default:
		out.Findings = append(out.Findings,
			"the declared answer does not fit the kind: an accept is valid with no codes, a reject is invalid with codes")
	}
	if !strings.HasPrefix(e.File, "observations/") || strings.Contains(e.File, "..") {
		out.Findings = append(out.Findings, "the member file is not under observations/")
		return
	}
	body, err := readIn(dir, e.File)
	if err != nil {
		out.Findings = append(out.Findings, "the member file is missing")
		return
	}
	if sha(body) != e.SHA256 {
		out.Findings = append(out.Findings, "declared sha256 does not recompute from the file")
	}
	var obs struct {
		CaseID  string `json:"case_id"`
		Fixture struct {
			Synthetic bool `json:"synthetic"`
		} `json:"fixture"`
	}
	if err := json.Unmarshal(body, &obs); err != nil {
		out.Findings = append(out.Findings, "the observation does not parse: "+err.Error())
		return
	}
	if !obs.Fixture.Synthetic {
		out.Findings = append(out.Findings, "the observation is not marked synthetic")
	}
	if obs.CaseID != "vectors-mcp-authz-"+e.ID {
		out.Findings = append(out.Findings, "the observation names another case")
	}
}
