package corpora

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"time"
)

func init() { register(delegatorRight{}) }

// delegatorRight judges vectors-delegator-right/. Each member is one record of
// a delegated request with the grant chain behind it, the entitlements the
// delegating principals held, and the scope removals that took effect at the
// source. The reader derives each member's decision with the checks the Python
// reader applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the delegator-right contract: contract_id_unknown;
//  3. the record has the fields and types the contract names and every time
//     parses: malformed_record;
//  4. the request is inside the last grant's scope and each scope is inside
//     the one before it: delegate_exceeds_delegator;
//  5. every grantor that is not a root held an entitlement to delegate the
//     requested operation when it issued its grant: delegator_not_entitled;
//  6. no such entitlement ended a propagation limit or more before the
//     decision: delegation_right_removed;
//  7. no grant had the operation removed at the source a propagation limit or
//     more before the decision: ancestor_scope_removed.
type delegatorRight struct{}

const drContractID = "https://probityai.github.io/agent-evidence-vectors/contract/delegator-right/v1"

func (delegatorRight) Suite() string { return "delegator-right/v1" }

type drVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

func (delegatorRight) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v drVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = drJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func drJudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record map[string]any
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	got := drDecide(record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type drRight struct {
	principal, operation string
	from                 time.Time
	until                *time.Time
}

type drNarrowing struct {
	operation string
	at        time.Time
}

type drHop struct {
	grantor    string
	issued     time.Time
	scope      []string
	narrowings []drNarrowing
}

type drParsed struct {
	decided   time.Time
	limit     time.Duration
	operation string
	chain     []drHop
	rights    []drRight
	roots     []string
}

// drDecide mirrors the Python reader: the contract checks, then the structural
// check, then the four rights checks in order.
func drDecide(record map[string]any) scDecision {
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != drContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	p, ok := drParse(record)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	checks := []struct {
		reason string
		fails  bool
	}{
		{"delegate_exceeds_delegator", drExceeds(p)},
		{"delegator_not_entitled", drNotEntitled(p)},
		{"delegation_right_removed", drRightRemoved(p)},
		{"ancestor_scope_removed", drScopeRemoved(p)},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "entitled"}
}

func drText(m map[string]any, key string) (string, bool) {
	value, ok := m[key].(string)
	return value, ok
}

func drTime(m map[string]any, key string) (time.Time, bool) {
	text, ok := drText(m, key)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, text)
	return parsed, err == nil
}

func drTexts(value any) ([]string, bool) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func drParse(record map[string]any) (drParsed, bool) {
	var p drParsed
	var ok bool
	if p.decided, ok = drTime(record, "decisionTime"); !ok {
		return p, false
	}
	seconds, isNumber := record["propagationLimitSeconds"].(float64)
	if !isNumber || seconds < 0 || seconds != math.Trunc(seconds) {
		return p, false
	}
	p.limit = time.Duration(seconds) * time.Second
	request, isMap := record["request"].(map[string]any)
	if !isMap {
		return p, false
	}
	if p.operation, ok = drText(request, "operation"); !ok {
		return p, false
	}
	if p.roots, ok = drTexts(record["roots"]); !ok {
		return p, false
	}
	chain, isList := record["chain"].([]any)
	if !isList || len(chain) == 0 {
		return p, false
	}
	for _, item := range chain {
		hop, ok := drParseHop(item)
		if !ok {
			return p, false
		}
		p.chain = append(p.chain, hop)
	}
	rights, isList := record["rights"].([]any)
	if !isList {
		return p, false
	}
	for _, item := range rights {
		right, ok := drParseRight(item)
		if !ok {
			return p, false
		}
		p.rights = append(p.rights, right)
	}
	return p, true
}

func drParseHop(item any) (drHop, bool) {
	var hop drHop
	m, isMap := item.(map[string]any)
	if !isMap {
		return hop, false
	}
	for _, name := range []string{"grantId", "grantee", "expiresAt"} {
		if _, ok := drText(m, name); !ok {
			return hop, false
		}
	}
	var ok bool
	if hop.grantor, ok = drText(m, "grantor"); !ok {
		return hop, false
	}
	if _, ok = drTime(m, "expiresAt"); !ok {
		return hop, false
	}
	if hop.issued, ok = drTime(m, "issuedAt"); !ok {
		return hop, false
	}
	if hop.scope, ok = drTexts(m["scope"]); !ok {
		return hop, false
	}
	list, isList := m["narrowings"].([]any)
	if !isList {
		return hop, false
	}
	for _, entry := range list {
		n, isMap := entry.(map[string]any)
		if !isMap {
			return hop, false
		}
		var narrowing drNarrowing
		if narrowing.operation, ok = drText(n, "operation"); !ok {
			return hop, false
		}
		if narrowing.at, ok = drTime(n, "effectiveAt"); !ok {
			return hop, false
		}
		hop.narrowings = append(hop.narrowings, narrowing)
	}
	return hop, true
}

func drParseRight(item any) (drRight, bool) {
	var right drRight
	m, isMap := item.(map[string]any)
	if !isMap {
		return right, false
	}
	var ok bool
	if right.principal, ok = drText(m, "principal"); !ok {
		return right, false
	}
	if right.operation, ok = drText(m, "operation"); !ok {
		return right, false
	}
	if right.from, ok = drTime(m, "from"); !ok {
		return right, false
	}
	if m["until"] != nil {
		until, ok := drTime(m, "until")
		if !ok {
			return right, false
		}
		right.until = &until
	}
	return right, true
}

func drExceeds(p drParsed) bool {
	if !slices.Contains(p.chain[len(p.chain)-1].scope, p.operation) {
		return true
	}
	for i := 1; i < len(p.chain); i++ {
		for _, operation := range p.chain[i].scope {
			if !slices.Contains(p.chain[i-1].scope, operation) {
				return true
			}
		}
	}
	return false
}

func drDelegating(p drParsed) []drHop {
	var hops []drHop
	for _, hop := range p.chain {
		if !slices.Contains(p.roots, hop.grantor) {
			hops = append(hops, hop)
		}
	}
	return hops
}

// drEntitlement is the entitlement that covered the grantor when the grant was issued.
func drEntitlement(p drParsed, hop drHop) *drRight {
	for _, right := range p.rights {
		if right.principal != hop.grantor || right.operation != p.operation {
			continue
		}
		if !right.from.After(hop.issued) && (right.until == nil || hop.issued.Before(*right.until)) {
			return &right
		}
	}
	return nil
}

func drReached(p drParsed, effective time.Time) bool {
	return !effective.Add(p.limit).After(p.decided)
}

func drNotEntitled(p drParsed) bool {
	return slices.ContainsFunc(drDelegating(p), func(hop drHop) bool { return drEntitlement(p, hop) == nil })
}

func drRightRemoved(p drParsed) bool {
	return slices.ContainsFunc(drDelegating(p), func(hop drHop) bool {
		right := drEntitlement(p, hop)
		return right != nil && right.until != nil && drReached(p, *right.until)
	})
}

func drScopeRemoved(p drParsed) bool {
	for _, hop := range p.chain {
		for _, n := range hop.narrowings {
			if n.operation == p.operation && drReached(p, n.at) {
				return true
			}
		}
	}
	return false
}
