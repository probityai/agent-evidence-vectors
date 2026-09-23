package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
)

func init() { register(mcpResponsePhase{}) }

// mcpResponsePhase judges vectors-mcp-response-phase/. Two jobs, and the second
// is the one that matters: the ordinary corpus check, and then the criterion RUN
// against every member. The criterion is what a conformant response-phase policy
// must produce for a member's operation -- the policy is invoked on the
// completion, and its decision decides what the caller receives -- computed here
// from the member's own bytes and compared with what the member declares.
//
// An accept member must declare the conformant outcome. A reject member must
// declare a DIFFERENT outcome, on exactly one axis, and that axis is the defect
// it encodes: a policy never invoked on an error frame (policyInvoked), or a
// caller left with the wrong completion (callerReceives).
type mcpResponsePhase struct{}

func (mcpResponsePhase) Suite() string { return "mcp-response-phase-interception" }

type mrpManifest struct {
	Criterion    string                     `json:"criterion"`
	SpecVendored string                     `json:"specVendored"`
	SpecDigest   string                     `json:"specDigest"`
	Conditions   map[string]json.RawMessage `json:"conditions"`
	Counts       map[string]int             `json:"counts"`
	CorpusDigest string                     `json:"corpusDigest"`
	Vectors      []mrpVector                `json:"vectors"`
}

type mrpVector struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	File       string      `json:"file"`
	Conditions []string    `json:"conditions"`
	Expected   mrpExpected `json:"expected"`
}

// mrpExpected is a member's declaration on the two axes. PolicyInvoked is a
// pointer so "declares nothing" is distinct from "declares false", which is the
// defect an error-frame reject member encodes.
type mrpExpected struct {
	PolicyInvoked  *bool           `json:"policyInvoked"`
	CallerReceives json.RawMessage `json:"callerReceives"`
}

// mrpOperation is a member's operation file: the request, the upstream
// completion, and the response-phase policy applied to it.
type mrpOperation struct {
	Event              string          `json:"event"`
	Phase              string          `json:"phase"`
	Request            json.RawMessage `json:"request"`
	UpstreamCompletion json.RawMessage `json:"upstreamCompletion"`
	Policy             mrpPolicy       `json:"policy"`
}

type mrpPolicy struct {
	Decision string          `json:"decision"`
	Error    json.RawMessage `json:"error"`
	With     json.RawMessage `json:"with"`
}

func (m mcpResponsePhase) Judge(dir string, raw []byte) (*Result, error) {
	var manifest mrpManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	accepted, rejected, used := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ids, files := make([]string, 0, len(manifest.Vectors)), make([]string, 0, len(manifest.Vectors))

	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.File)
		for _, c := range v.Conditions {
			used[c] = true
			switch v.Kind {
			case "accept":
				accepted[c] = true
			case "reject":
				rejected[c] = true
			}
		}
		m.judgeMember(dir, &manifest, v, &member)
		result.Members = append(result.Members, member)
	}

	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		result.Findings = append(result.Findings, fmt.Sprintf(
			"conditions that reject and never accept: %v. A gateway that refuses "+
				"or drops every response would score full marks on them.", orphan))
	}
	if idle := declaredMinusUsed(manifest.Conditions, used); len(idle) > 0 {
		result.Findings = append(result.Findings,
			fmt.Sprintf("conditions declared and carried by no member: %v", idle))
	}
	// The criterion document sits above the corpus directory.
	if !existsIn(filepath.Dir(dir), manifest.Criterion) {
		result.Findings = append(result.Findings, fmt.Sprintf(
			"the manifest names the criterion at %s and no such file is there, so the "+
				"corpus measures a rule nobody can read", manifest.Criterion))
	}
	// The vendored specification whose gap the criterion fills must still hash to
	// its pinned digest, so the corpus certifies against text somebody published.
	if bad := checkVendored(dir, manifest.SpecVendored, manifest.SpecDigest, "specification"); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, v := range manifest.Vectors {
		if _, k := measured[v.Kind]; k {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != manifest.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the operation files on disk")
	}
	return result, nil
}

func (m mcpResponsePhase) judgeMember(dir string, manifest *mrpManifest, v mrpVector, out *Member) {
	if v.Kind != "accept" && v.Kind != "reject" {
		out.Findings = append(out.Findings, fmt.Sprintf("declares kind %q", v.Kind))
	}
	if len(v.Conditions) == 0 {
		out.Findings = append(out.Findings, "cites no condition")
		return
	}
	for _, condition := range v.Conditions {
		if _, defined := manifest.Conditions[condition]; !defined {
			out.Findings = append(out.Findings, "cites condition "+condition+" the manifest does not define")
		}
	}
	if !existsIn(dir, v.File) {
		out.Findings = append(out.Findings, "the manifest names an operation file that does not exist")
		return
	}
	if v.Expected.PolicyInvoked == nil {
		out.Findings = append(out.Findings, "declares no expectation on policyInvoked")
		return
	}
	if len(v.Expected.CallerReceives) == 0 {
		out.Findings = append(out.Findings, "declares no expectation on callerReceives")
		return
	}
	m.checkAgainstCriterion(dir, v, out)
}

// checkAgainstCriterion runs the criterion. This is the check the prose cannot
// do: it computes what a conformant response phase must produce for the member's
// operation and compares it with what the member declares.
func (mcpResponsePhase) checkAgainstCriterion(dir string, v mrpVector, out *Member) {
	body, err := readIn(dir, v.File)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	var op mrpOperation
	if err := json.Unmarshal(body, &op); err != nil {
		out.Findings = append(out.Findings, "the operation does not parse: "+err.Error())
		return
	}
	if op.Phase != "response" {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"operation declares phase %q; this corpus is about the response phase", op.Phase))
	}

	// The identifier is a digest over the member's kind, its conditions and the
	// operation itself, so an edit to the operation without regenerating leaves a
	// name describing bytes that are no longer there.
	checkMrpIdentity(body, v, out)

	conformantReceives, cerr := conformantReceives(op)
	if cerr != "" {
		out.Findings = append(out.Findings, cerr)
		return
	}
	declaredReceives, derr := canonicalJSON(v.Expected.CallerReceives)
	if derr != "" {
		out.Findings = append(out.Findings, "callerReceives does not parse: "+derr)
		return
	}

	// The two axes, computed against the criterion. A conformant policy is always
	// invoked, so invokedAgrees is true exactly when the member declares it true.
	invokedAgrees := *v.Expected.PolicyInvoked
	receivesAgrees := declaredReceives == conformantReceives
	agreeing := 0
	if invokedAgrees {
		agreeing++
	}
	if receivesAgrees {
		agreeing++
	}

	switch v.Kind {
	case "accept":
		if !invokedAgrees {
			out.Findings = append(out.Findings,
				"is an accept member declaring policyInvoked=false; a conformant policy is always invoked")
		}
		if !receivesAgrees {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"is an accept member whose callerReceives is not what the policy applied to the "+
					"completion yields. declared %s, criterion %s", declaredReceives, conformantReceives))
		}
	case "reject":
		// A reject member encodes the defect on exactly one axis: it must differ
		// from the conformant outcome, and on only one axis, or it cannot tell a
		// reader which rule caught it.
		if agreeing == 2 {
			out.Findings = append(out.Findings,
				"is a reject member declaring the conformant outcome on both axes, so it encodes no defect")
		} else if agreeing == 0 {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"is a reject member failing both axes at once, so it cannot tell you which rule "+
					"caught it. declared policyInvoked=%t callerReceives=%s, criterion policyInvoked=true "+
					"callerReceives=%s", *v.Expected.PolicyInvoked, declaredReceives, conformantReceives))
		}
	}
}

// conformantReceives computes the completion a conformant response phase leaves
// the caller with, given the operation. It is the criterion for the
// callerReceives axis, restated from docs/mcp-response-phase.md.
func conformantReceives(op mrpOperation) (string, string) {
	switch op.Policy.Decision {
	case "pass":
		return canonicalJSON(op.UpstreamCompletion)
	case "fail":
		var e struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(op.Policy.Error, &e); err != nil {
			return "", "policy.error does not parse: " + err.Error()
		}
		completion := map[string]any{
			"kind":  "error",
			"error": map[string]any{"code": e.Code, "message": e.Message},
		}
		return canonicalValue(completion)
	case "replace":
		return canonicalJSON(op.Policy.With)
	default:
		return "", fmt.Sprintf("policy declares an unknown decision %q", op.Policy.Decision)
	}
}

// checkMrpIdentity recomputes the member's name from its kind, its conditions
// and the operation's own value.
func checkMrpIdentity(body []byte, v mrpVector, out *Member) {
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return
	}
	conditions := make([]any, 0, len(v.Conditions))
	for _, c := range v.Conditions {
		conditions = append(conditions, c)
	}
	payload, err := pythonCompactJSON(map[string]any{
		"kind": v.Kind, "conditions": conditions, "operation": value,
	})
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	if idFromBytes(payload) != v.ID {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}
}

// canonicalJSON returns a stable string form of raw JSON, so two completions are
// compared by value rather than by byte order.
func canonicalJSON(raw json.RawMessage) (string, string) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err.Error()
	}
	return canonicalValue(value)
}

func canonicalValue(value any) (string, string) {
	out, err := json.Marshal(sortValue(value))
	if err != nil {
		return "", err.Error()
	}
	return string(out), ""
}

// sortValue rewrites a decoded JSON value so json.Marshal emits object keys in a
// stable order. Marshal already sorts map[string]any keys, so this is here only
// to make the intent explicit and to guard against a future non-map container.
func sortValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		next := make(map[string]any, len(typed))
		for _, k := range keys {
			next[k] = sortValue(typed[k])
		}
		return next
	case []any:
		next := make([]any, len(typed))
		for i, item := range typed {
			next[i] = sortValue(item)
		}
		return next
	default:
		return value
	}
}
