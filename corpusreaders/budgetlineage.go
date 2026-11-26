package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/probityai/agent-evidence-vectors/internal/identifiers"
)

func init() { register(budgetLineage{}) }

// budgetLineage judges corpora/vectors-budget-lineage/. Each member is one
// principal's delegation tree: the grants, the delegates' acceptances, the
// budgets the tree may spend from, the depth limit, and every charge the
// accounting authority booked for the agents the grants name, whatever budget
// each charge names. The reader applies the checks the Python reader applies,
// in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the budget-lineage contract: contract_id_unknown;
//  3. every field has its contract type: malformed_record;
//  4. every grant is accepted by its delegate and every acceptance names a
//     grant: delegation_unilateral;
//  5. every delegator is the principal or a member when it grants:
//     delegation_detached;
//  6. no member deeper than maxDepth was admitted a charge:
//     depth_limit_exceeded;
//  7. no carve is larger than the budget its delegator holds:
//     carve_exceeds_parent;
//  8. no member is charged against a budget outside the lineage while it is
//     a member: charge_outside_lineage;
//  9. the lineage's charges stay inside the principal's limit and every
//     carve's limit: lineage_overspend.
//
// The reader also recomputes each member's retained principal, budget,
// agents and charged units.
type budgetLineage struct{}

var blContractID = identifiers.Identifier("agent-evidence-observer/contract/budget-lineage/v1")

func (budgetLineage) Suite() string { return "budget-lineage/v1" }

type blRetained struct {
	Agents       []string `json:"agents"`
	Budget       string   `json:"budget"`
	ChargedUnits *int64   `json:"chargedUnits"`
	Principal    string   `json:"principal"`
}

type blVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained blRetained        `json:"retained"`
}

type blGrant struct {
	id, delegator, delegate string
	issued                  time.Time
	revoked                 *time.Time
	carveID                 string
	carveLimit              int64
	hasCarve                bool
}

type blAcceptance struct {
	id, delegate string
	accepted     time.Time
}

type blCharge struct {
	agent, budget, decision, outcome string
	units                            int64
	at                               time.Time
}

type blRecord struct {
	principal   string
	budgetID    string
	limit       int64
	maxDepth    int64
	grants      []blGrant
	acceptances []blAcceptance
	ledger      []blCharge
}

func (budgetLineage) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v blVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = blJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func blJudgeMember(caseDir string, v blVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, fmt.Sprintf("record.json cannot be read: %v", err))
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, fmt.Sprintf("record.json does not parse: %v", err))
	}
	raw, ok := value.(map[string]any)
	if !ok {
		return append(findings, "record.json is not an object")
	}
	if kept := blRetain(raw); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := blDecide(raw); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func blName(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok && s != ""
}

func blCount(value any) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil && i >= 0
}

func blInt(value any) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func blWhen(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok || !strings.HasSuffix(s, "Z") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func blParseGrant(value any) (blGrant, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return blGrant{}, false
	}
	var g blGrant
	var okID, okFrom, okTo, okIssued bool
	g.id, okID = blName(m["grantId"])
	g.delegator, okFrom = blName(m["delegator"])
	g.delegate, okTo = blName(m["delegate"])
	g.issued, okIssued = blWhen(m["issuedAt"])
	if !okID || !okFrom || !okTo || !okIssued {
		return g, false
	}
	if revoked, present := m["revokedAt"]; present && revoked != nil {
		t, okRevoked := blWhen(revoked)
		if !okRevoked {
			return g, false
		}
		g.revoked = &t
	}
	if carve, present := m["carve"]; present && carve != nil {
		c, okCarve := carve.(map[string]any)
		if !okCarve {
			return g, false
		}
		var okCID, okLimit bool
		g.carveID, okCID = blName(c["id"])
		g.carveLimit, okLimit = blCount(c["limit"])
		if !okCID || !okLimit {
			return g, false
		}
		g.hasCarve = true
	}
	return g, true
}

func blParseAcceptance(value any) (blAcceptance, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return blAcceptance{}, false
	}
	var a blAcceptance
	var okID, okTo, okAt bool
	a.id, okID = blName(m["grantId"])
	a.delegate, okTo = blName(m["delegate"])
	a.accepted, okAt = blWhen(m["acceptedAt"])
	return a, okID && okTo && okAt
}

func blParseCharge(value any) (blCharge, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return blCharge{}, false
	}
	var c blCharge
	_, okReq := blName(m["requestId"])
	var okAgent, okBudget, okUnits, okAt bool
	c.agent, okAgent = blName(m["agent"])
	c.budget, okBudget = blName(m["budget"])
	c.units, okUnits = blCount(m["units"])
	c.at, okAt = blWhen(m["at"])
	c.decision, _ = m["decision"].(string)
	c.outcome, _ = m["outcome"].(string)
	okDecision := c.decision == "admitted" || c.decision == "refused"
	okOutcome := c.outcome == "committed" || c.outcome == "released" || c.outcome == "unknown" || c.outcome == "none"
	return c, okReq && okAgent && okBudget && okUnits && okAt && okDecision && okOutcome
}

// blParse returns the typed record, or false when any field lacks its contract type.
func blParse(raw map[string]any) (blRecord, bool) {
	var r blRecord
	var okPrincipal bool
	r.principal, okPrincipal = blName(raw["principal"])
	budget, okBudget := raw["budget"].(map[string]any)
	if !okPrincipal || !okBudget {
		return r, false
	}
	var okBID, okLimit, okDepth bool
	r.budgetID, okBID = blName(budget["id"])
	r.limit, okLimit = blCount(budget["limit"])
	r.maxDepth, okDepth = blCount(raw["maxDepth"])
	grants, okG := raw["delegations"].([]any)
	accepts, okA := raw["acceptances"].([]any)
	ledger, okL := raw["ledger"].([]any)
	if !okBID || !okLimit || !okDepth || r.maxDepth < 1 || !okG || !okA || !okL {
		return r, false
	}
	for _, item := range grants {
		g, ok := blParseGrant(item)
		if !ok {
			return r, false
		}
		r.grants = append(r.grants, g)
	}
	for _, item := range accepts {
		a, ok := blParseAcceptance(item)
		if !ok {
			return r, false
		}
		r.acceptances = append(r.acceptances, a)
	}
	for _, item := range ledger {
		c, ok := blParseCharge(item)
		if !ok {
			return r, false
		}
		r.ledger = append(r.ledger, c)
	}
	return r, true
}

func blCharged(c blCharge) bool {
	return c.decision == "admitted" && (c.outcome == "committed" || c.outcome == "unknown")
}

func blActive(g blGrant, at time.Time) bool {
	return !g.issued.After(at) && (g.revoked == nil || at.Before(*g.revoked))
}

// blDepth is the agent's depth below the principal at the instant, or -1 when it is not a member.
func blDepth(r blRecord, agent string, at time.Time, seen map[string]bool) int64 {
	if agent == r.principal {
		return 0
	}
	if seen[agent] {
		return -1
	}
	next := map[string]bool{agent: true}
	for k := range seen {
		next[k] = true
	}
	best := int64(-1)
	for _, g := range r.grants {
		if g.delegate != agent || !blActive(g, at) {
			continue
		}
		if parent := blDepth(r, g.delegator, at, next); parent >= 0 && (best < 0 || parent+1 < best) {
			best = parent + 1
		}
	}
	return best
}

func blLineage(r blRecord) map[string]bool {
	set := map[string]bool{r.budgetID: true}
	for _, g := range r.grants {
		if g.hasCarve {
			set[g.carveID] = true
		}
	}
	return set
}

func blChargedUnits(r blRecord) int64 {
	lineage := blLineage(r)
	total := int64(0)
	for _, c := range r.ledger {
		if blCharged(c) && lineage[c.budget] {
			total += c.units
		}
	}
	return total
}

// blRetain mirrors the Python reader's retained fields, including a null
// chargedUnits when the delegations or ledger cannot be read as a lineage.
func blRetain(raw map[string]any) blRetained {
	kept := blRetained{Agents: []string{}}
	kept.Principal, _ = raw["principal"].(string)
	if budget, ok := raw["budget"].(map[string]any); ok {
		kept.Budget, _ = budget["id"].(string)
	}
	agents := map[string]bool{}
	if ledger, ok := raw["ledger"].([]any); ok {
		for _, item := range ledger {
			if m, isMap := item.(map[string]any); isMap {
				agents[fmt.Sprint(blPyString(m["agent"]))] = true
			}
		}
	}
	for agent := range agents {
		kept.Agents = append(kept.Agents, agent)
	}
	sort.Strings(kept.Agents)
	kept.ChargedUnits = blLooseChargedUnits(raw)
	return kept
}

// blPyString renders a value as Python's str() does for the values a record carries.
func blPyString(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

// blLooseChargedUnits sums charged units the way the Python reader does before
// any type check runs, returning nil where the Python reader raises.
func blLooseChargedUnits(raw map[string]any) *int64 {
	lineage, ok := blLooseLineage(raw)
	if !ok {
		return nil
	}
	ledger, ok := raw["ledger"].([]any)
	if !ok {
		return nil
	}
	total := int64(0)
	for _, item := range ledger {
		units, counted, ok := blChargedEntry(item, lineage)
		if !ok {
			return nil
		}
		if counted {
			total += units
		}
	}
	return &total
}

// blLooseLineage is the set of budget ids in the root budget's lineage: the root and
// every carve a delegation names. False when the record is not that shape.
func blLooseLineage(raw map[string]any) (map[string]bool, bool) {
	budget, ok := raw["budget"].(map[string]any)
	if !ok {
		return nil, false
	}
	root, ok := budget["id"].(string)
	if !ok {
		return nil, false
	}
	lineage := map[string]bool{root: true}
	grants, ok := raw["delegations"].([]any)
	if !ok {
		return nil, false
	}
	for _, item := range grants {
		g, isMap := item.(map[string]any)
		if !isMap {
			return nil, false
		}
		carve, present := g["carve"]
		if !present || carve == nil {
			continue
		}
		c, isCarve := carve.(map[string]any)
		if !isCarve {
			return nil, false
		}
		id, hasID := c["id"].(string)
		if !hasID {
			return nil, false
		}
		lineage[id] = true
	}
	return lineage, true
}

// blChargedEntry reads one ledger entry: its units, whether they are charged to
// the lineage (admitted, then committed or unknown, against a lineage budget),
// and false when the entry is not that shape.
func blChargedEntry(item any, lineage map[string]bool) (int64, bool, bool) {
	m, isMap := item.(map[string]any)
	if !isMap {
		return 0, false, false
	}
	decision, okD := m["decision"].(string)
	outcome, okO := m["outcome"].(string)
	if !okD || !okO {
		return 0, false, false
	}
	if decision != "admitted" || (outcome != "committed" && outcome != "unknown") {
		return 0, false, true
	}
	b, okB := m["budget"].(string)
	if !okB {
		return 0, false, false
	}
	if !lineage[b] {
		return 0, false, true
	}
	units, okU := blInt(m["units"])
	if !okU {
		return 0, false, false
	}
	return units, true, true
}

func blDecide(raw map[string]any) scDecision {
	if _, present := raw["contractId"]; !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id, _ := raw["contractId"].(string); identifiers.CanonicalIdentifier(id) != blContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	r, ok := blParse(raw)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	checks := []struct {
		reason string
		fails  func() bool
	}{
		{"delegation_unilateral", func() bool { return blUnilateral(r) }},
		{"delegation_detached", func() bool { return blDetached(r) }},
		{"depth_limit_exceeded", func() bool { return blTooDeep(r) }},
		{"carve_exceeds_parent", func() bool { return blCarveWider(r) }},
		{"charge_outside_lineage", func() bool { return blOutside(r) }},
		{"lineage_overspend", func() bool { return blOverspend(r) }},
	}
	for _, check := range checks {
		if check.fails() {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "lineage_held"}
}

func blUnilateral(r blRecord) bool {
	type key struct{ id, delegate string }
	grants := map[key]time.Time{}
	for _, g := range r.grants {
		grants[key{g.id, g.delegate}] = g.issued
	}
	accepted := map[key]time.Time{}
	for _, a := range r.acceptances {
		accepted[key{a.id, a.delegate}] = a.accepted
	}
	if len(grants) != len(accepted) {
		return true
	}
	for k, issued := range grants {
		at, ok := accepted[k]
		if !ok || at.Before(issued) {
			return true
		}
	}
	return false
}

func blDetached(r blRecord) bool {
	for _, g := range r.grants {
		if blDepth(r, g.delegator, g.issued, map[string]bool{}) < 0 {
			return true
		}
	}
	return false
}

func blTooDeep(r blRecord) bool {
	for _, c := range r.ledger {
		if c.decision != "admitted" {
			continue
		}
		if d := blDepth(r, c.agent, c.at, map[string]bool{}); d >= 0 && d > r.maxDepth {
			return true
		}
	}
	return false
}

func blHolding(r blRecord, agent string, seen map[string]bool) int64 {
	if agent == r.principal || seen[agent] {
		return r.limit
	}
	for _, g := range r.grants {
		if g.delegate != agent {
			continue
		}
		if g.hasCarve {
			return g.carveLimit
		}
		next := map[string]bool{agent: true}
		for k := range seen {
			next[k] = true
		}
		return blHolding(r, g.delegator, next)
	}
	return r.limit
}

func blCarveWider(r blRecord) bool {
	for _, g := range r.grants {
		if g.hasCarve && g.carveLimit > blHolding(r, g.delegator, map[string]bool{}) {
			return true
		}
	}
	return false
}

func blOutside(r blRecord) bool {
	lineage := blLineage(r)
	for _, c := range r.ledger {
		if !blCharged(c) || lineage[c.budget] || c.agent == r.principal {
			continue
		}
		if blDepth(r, c.agent, c.at, map[string]bool{}) >= 0 {
			return true
		}
	}
	return false
}

func blOverspend(r blRecord) bool {
	if blChargedUnits(r) > r.limit {
		return true
	}
	for _, g := range r.grants {
		if !g.hasCarve {
			continue
		}
		spent := int64(0)
		for _, c := range r.ledger {
			if blCharged(c) && c.budget == g.carveID {
				spent += c.units
			}
		}
		if spent > g.carveLimit {
			return true
		}
	}
	return false
}
