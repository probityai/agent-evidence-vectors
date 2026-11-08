package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

func init() { register(attenuatedDelegation{}) }

// attenuatedDelegation judges corpora/vectors-attenuated-delegation/. Each
// member is one record of a capability carried across execution hops (child
// workflows, sub-agents, agent-to-agent calls, tool-to-tool calls) and
// presented at the end. The reader recomputes every grant digest and derives
// each member's decision with the checks the Python reader applies, in the
// same order, naming the first one that fails:
//
//  1. contract_id_missing; 2. contract_id_unknown; 3. malformed_record;
//  4. chain_unlinked: a parentDigest is not the recomputed digest of the
//     grant before it, or the root names a grant on the chain;
//  5. root_untrusted: the root names a parent, its issuer is not trusted, or
//     another key handed it over;
//  6. issuer_not_parent_holder; 7. hop_kind_not_permitted; 8. depth_exceeded;
//  9. tool_widened; 10. constraint_widened; 11. lifetime_extended;
//  12. caveat_dropped; 13. uses_raised; 14. presenter_not_holder;
//  15. presentation_outside_leaf.
type attenuatedDelegation struct{}

const attnContractID = "https://probityai.github.io/agent-evidence-vectors/contract/attenuated-delegation/v1"

const attnSafeInteger = int64(1)<<53 - 1

var (
	attnInstant   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	attnDigestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	attnHopKinds  = []string{"child-workflow", "sub-agent", "a2a", "tool"}
	attnGrantText = []string{"grantId", "issuer", "holder", "notBefore", "expiresAt"}
)

func (attenuatedDelegation) Suite() string { return "attenuated-delegation/v1" }

func (attenuatedDelegation) Judge(dir string, raw []byte) (*Result, error) {
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
		member.Findings = attnJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func attnJudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read: "+err.Error())
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "record.json does not parse: "+err.Error())
	}
	record, isMap := value.(map[string]any)
	if !isMap {
		return append(findings, "record.json does not parse: not an object")
	}
	if got := attnDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// attnValue is one argument value: a string or a safe integer.
type attnValue struct {
	isInt bool
	i     int64
	s     string
}

type attnConstraint struct {
	kind   string
	values []attnValue
	lo, hi int64
	prefix string
}

type attnGrant struct {
	digest, parent           string
	issuer, holder           string
	tools, caveats, hopKinds []string
	constraints              map[string]map[string]attnConstraint
	closedWorld              bool
	maxUses, depth, maxDepth int64
	notBefore, expiresAt     time.Time
}

type attnHop struct {
	kind, presentedBy string
	grant             attnGrant
}

type attnParsed struct {
	hops      []attnHop
	roots     []string
	presenter string
	tool      string
	args      map[string]attnValue
	at        time.Time
}

func attnDecide(record map[string]any) scDecision {
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != attnContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	p, ok := attnParse(record)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	checks := []struct {
		reason string
		fails  func(attnParsed) bool
	}{
		{"chain_unlinked", attnUnlinked},
		{"root_untrusted", attnRootUntrusted},
		{"issuer_not_parent_holder", attnIssuerWrong},
		{"hop_kind_not_permitted", attnKindNotPermitted},
		{"depth_exceeded", attnDepthExceeded},
		{"tool_widened", attnToolWidened},
		{"constraint_widened", attnConstraintWidened},
		{"lifetime_extended", attnLifetimeExtended},
		{"caveat_dropped", attnCaveatDropped},
		{"uses_raised", attnUsesRaised},
		{"presenter_not_holder", func(p attnParsed) bool { return p.presenter != p.hops[len(p.hops)-1].grant.holder }},
		{"presentation_outside_leaf", attnOutsideLeaf},
	}
	for _, check := range checks {
		if check.fails(p) {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "attenuated"}
}

func attnInt(value any) (int64, bool) {
	n, isNumber := value.(json.Number)
	if !isNumber {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil || i > attnSafeInteger || i < -attnSafeInteger {
		return 0, false
	}
	return i, true
}

func attnScalar(value any) (attnValue, bool) {
	if s, isText := value.(string); isText {
		return attnValue{s: s}, true
	}
	i, ok := attnInt(value)
	return attnValue{isInt: true, i: i}, ok
}

func attnWhen(value any) (time.Time, bool) {
	text, isText := value.(string)
	if !isText || !attnInstant.MatchString(text) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, text)
	return parsed, err == nil
}

// attnTexts is a list of distinct strings, non-empty when nonempty is set.
func attnTexts(value any, nonempty bool) ([]string, bool) {
	list, isList := value.([]any)
	if !isList || (nonempty && len(list) == 0) {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, isText := item.(string)
		if !isText || slices.Contains(out, text) {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func attnParseConstraint(value any) (attnConstraint, bool) {
	m, isMap := value.(map[string]any)
	if !isMap || len(m) != 1 {
		return attnConstraint{}, false
	}
	for kind, bound := range m {
		c := attnConstraint{kind: kind}
		switch kind {
		case "exact":
			v, ok := attnScalar(bound)
			c.values = []attnValue{v}
			return c, ok
		case "oneOf":
			list, isList := bound.([]any)
			if !isList || len(list) == 0 {
				return c, false
			}
			for _, item := range list {
				v, ok := attnScalar(item)
				if !ok || slices.Contains(c.values, v) {
					return c, false
				}
				c.values = append(c.values, v)
			}
			return c, true
		case "range":
			list, isList := bound.([]any)
			if !isList || len(list) != 2 {
				return c, false
			}
			lo, okLo := attnInt(list[0])
			hi, okHi := attnInt(list[1])
			c.lo, c.hi = lo, hi
			return c, okLo && okHi && lo <= hi
		case "prefix":
			text, isText := bound.(string)
			c.prefix = text
			return c, isText
		}
	}
	return attnConstraint{}, false
}

func attnParseConstraints(value any, tools []string) (map[string]map[string]attnConstraint, bool) {
	table, isMap := value.(map[string]any)
	if !isMap {
		return nil, false
	}
	out := map[string]map[string]attnConstraint{}
	for tool, argsValue := range table {
		args, isArgs := argsValue.(map[string]any)
		if !isArgs || !slices.Contains(tools, tool) {
			return nil, false
		}
		out[tool] = map[string]attnConstraint{}
		for arg, raw := range args {
			c, ok := attnParseConstraint(raw)
			if !ok {
				return nil, false
			}
			out[tool][arg] = c
		}
	}
	return out, true
}

func attnParseGrant(value any) (attnGrant, bool) {
	var g attnGrant
	m, isMap := value.(map[string]any)
	if !isMap {
		return g, false
	}
	for _, name := range attnGrantText {
		if _, isText := m[name].(string); !isText {
			return g, false
		}
	}
	g.issuer, g.holder = m["issuer"].(string), m["holder"].(string)
	parent, present := m["parentDigest"]
	if !present {
		return g, false
	}
	if parent != nil {
		text, isText := parent.(string)
		if !isText || !attnDigestRe.MatchString(text) {
			return g, false
		}
		g.parent = text
	}
	var ok, okC, okK bool
	g.tools, ok = attnTexts(m["tools"], true)
	g.caveats, okC = attnTexts(m["caveats"], false)
	g.hopKinds, okK = attnTexts(m["hopKinds"], false)
	if !ok || !okC || !okK || !attnSubset(g.hopKinds, attnHopKinds) {
		return g, false
	}
	if g.closedWorld, ok = m["closedWorld"].(bool); !ok {
		return g, false
	}
	var okD, okM, okU bool
	g.depth, okD = attnInt(m["depth"])
	g.maxDepth, okM = attnInt(m["maxDepth"])
	g.maxUses, okU = attnInt(m["maxUses"])
	if !okD || !okM || !okU || g.depth < 0 || g.maxDepth < 0 || g.maxUses < 1 {
		return g, false
	}
	if g.constraints, ok = attnParseConstraints(m["constraints"], g.tools); !ok {
		return g, false
	}
	var okN, okE bool
	g.notBefore, okN = attnWhen(m["notBefore"])
	g.expiresAt, okE = attnWhen(m["expiresAt"])
	if !okN || !okE || !g.notBefore.Before(g.expiresAt) {
		return g, false
	}
	bytes, err := jcsSHA256Bytes(value)
	if err != nil {
		return g, false
	}
	g.digest = "sha256:" + sha(bytes)
	return g, true
}

func attnParseHop(value any, index int) (attnHop, bool) {
	var hop attnHop
	m, isMap := value.(map[string]any)
	if !isMap {
		return hop, false
	}
	var ok bool
	if hop.presentedBy, ok = m["presentedBy"].(string); !ok {
		return hop, false
	}
	if hop.kind, ok = m["hopKind"].(string); !ok {
		return hop, false
	}
	if (index == 0) != (hop.kind == "root") || (index > 0 && !slices.Contains(attnHopKinds, hop.kind)) {
		return hop, false
	}
	hop.grant, ok = attnParseGrant(m["grant"])
	return hop, ok
}

func attnParse(record map[string]any) (attnParsed, bool) {
	var p attnParsed
	var ok bool
	if p.roots, ok = attnTexts(record["trustedRoots"], true); !ok {
		return p, false
	}
	presentation, isMap := record["presentation"].(map[string]any)
	if !isMap {
		return p, false
	}
	if p.presenter, ok = presentation["presenterKeyId"].(string); !ok {
		return p, false
	}
	if p.tool, ok = presentation["tool"].(string); !ok {
		return p, false
	}
	args, isArgs := presentation["args"].(map[string]any)
	if !isArgs {
		return p, false
	}
	p.args = map[string]attnValue{}
	for name, raw := range args {
		if p.args[name], ok = attnScalar(raw); !ok {
			return p, false
		}
	}
	if p.at, ok = attnWhen(presentation["at"]); !ok {
		return p, false
	}
	hops, isList := record["hops"].([]any)
	if !isList || len(hops) == 0 {
		return p, false
	}
	for i, item := range hops {
		hop, ok := attnParseHop(item, i)
		if !ok {
			return p, false
		}
		p.hops = append(p.hops, hop)
	}
	return p, true
}

func attnSubset(inner, outer []string) bool {
	for _, item := range inner {
		if !slices.Contains(outer, item) {
			return false
		}
	}
	return true
}

// attnPairs calls fails on each (parent, child) pair and reports whether any failed.
func attnPairs(p attnParsed, fails func(parent, child attnHop) bool) bool {
	for i := 1; i < len(p.hops); i++ {
		if fails(p.hops[i-1], p.hops[i]) {
			return true
		}
	}
	return false
}

func attnUnlinked(p attnParsed) bool {
	var digests []string
	for _, hop := range p.hops {
		if slices.Contains(digests, hop.grant.digest) {
			return true
		}
		digests = append(digests, hop.grant.digest)
	}
	if p.hops[0].grant.parent != "" && slices.Contains(digests, p.hops[0].grant.parent) {
		return true
	}
	for i := 1; i < len(p.hops); i++ {
		if p.hops[i].grant.parent != digests[i-1] {
			return true
		}
	}
	return false
}

func attnRootUntrusted(p attnParsed) bool {
	root := p.hops[0]
	return root.grant.parent != "" || !slices.Contains(p.roots, root.grant.issuer) ||
		root.presentedBy != root.grant.issuer
}

func attnIssuerWrong(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool {
		return child.grant.issuer != parent.grant.holder || child.presentedBy != parent.grant.holder
	})
}

func attnKindNotPermitted(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool {
		return !slices.Contains(parent.grant.hopKinds, child.kind) ||
			!attnSubset(child.grant.hopKinds, parent.grant.hopKinds)
	})
}

func attnDepthExceeded(p attnParsed) bool {
	if p.hops[0].grant.depth != 0 {
		return true
	}
	limit := p.hops[0].grant.maxDepth
	for i, hop := range p.hops {
		limit = min(limit, hop.grant.maxDepth)
		if hop.grant.depth > limit {
			return true
		}
		if i > 0 {
			parent := p.hops[i-1].grant
			if hop.grant.depth != parent.depth+1 || hop.grant.maxDepth > parent.maxDepth {
				return true
			}
		}
	}
	return false
}

func attnToolWidened(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool { return !attnSubset(child.grant.tools, parent.grant.tools) })
}

func attnAdmits(c attnConstraint, v attnValue) bool {
	switch c.kind {
	case "exact", "oneOf":
		return slices.Contains(c.values, v)
	case "range":
		return v.isInt && c.lo <= v.i && v.i <= c.hi
	default:
		return !v.isInt && strings.HasPrefix(v.s, c.prefix)
	}
}

// attnWithin reports whether every value child admits, parent admits too.
func attnWithin(child, parent attnConstraint) bool {
	switch child.kind {
	case "exact", "oneOf":
		for _, v := range child.values {
			if !attnAdmits(parent, v) {
				return false
			}
		}
		return true
	case "range":
		switch parent.kind {
		case "range":
			return parent.lo <= child.lo && child.hi <= parent.hi
		case "exact", "oneOf":
			if child.hi-child.lo+1 > int64(len(parent.values)) {
				return false
			}
			for v := child.lo; v <= child.hi; v++ {
				if !attnAdmits(parent, attnValue{isInt: true, i: v}) {
					return false
				}
			}
			return true
		}
		return false
	default:
		return parent.kind == "prefix" && strings.HasPrefix(child.prefix, parent.prefix)
	}
}

func attnToolWidens(parent, child attnGrant, tool string) bool {
	held, given := parent.constraints[tool], child.constraints[tool]
	for arg, bound := range held {
		c, present := given[arg]
		if !present || !attnWithin(c, bound) {
			return true
		}
	}
	if parent.closedWorld {
		for arg := range given {
			if _, named := held[arg]; !named {
				return true
			}
		}
	}
	return false
}

func attnConstraintWidened(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool {
		if parent.grant.closedWorld && !child.grant.closedWorld {
			return true
		}
		return slices.ContainsFunc(child.grant.tools, func(tool string) bool {
			return attnToolWidens(parent.grant, child.grant, tool)
		})
	})
}

func attnLifetimeExtended(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool {
		return child.grant.notBefore.Before(parent.grant.notBefore) ||
			child.grant.expiresAt.After(parent.grant.expiresAt)
	})
}

func attnCaveatDropped(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool { return !attnSubset(parent.grant.caveats, child.grant.caveats) })
}

func attnUsesRaised(p attnParsed) bool {
	return attnPairs(p, func(parent, child attnHop) bool { return child.grant.maxUses > parent.grant.maxUses })
}

func attnOutsideLeaf(p attnParsed) bool {
	leaf := p.hops[len(p.hops)-1].grant
	if !slices.Contains(leaf.tools, p.tool) {
		return true
	}
	bounds := leaf.constraints[p.tool]
	for arg, bound := range bounds {
		v, present := p.args[arg]
		if !present || !attnAdmits(bound, v) {
			return true
		}
	}
	if leaf.closedWorld {
		for arg := range p.args {
			if _, named := bounds[arg]; !named {
				return true
			}
		}
	}
	return p.at.Before(leaf.notBefore) || !p.at.Before(leaf.expiresAt)
}
