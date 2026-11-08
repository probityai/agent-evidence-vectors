package corpusreaders

import (
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

func init() { register(approvalBindingV2{}) }

// approvalBindingV2 judges corpora/vectors-approval-binding-v2/. Each member is
// one record of a proposed tool call, its approval policy, every decision
// received for it, the execution that relied on some of them, the consumption
// ledger the authority read and the witness log. The reader derives each
// member's decision with the checks the Python reader applies, in the same
// order, recomputing every digest it relies on, and names the first one that
// fails. The order is ab2Checks.
type approvalBindingV2 struct{}

const ab2ContractID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v2"

var (
	ab2DigestForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	ab2Status     = map[string]string{"applied": "spent", "failed": "returned", "uncertain": "held"}
)

func (approvalBindingV2) Suite() string { return "approval-binding/v2" }

func (approvalBindingV2) Judge(dir string, raw []byte) (*Result, error) {
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
		member.Findings = ab2JudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ab2JudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read: "+err.Error())
	}
	record, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "record.json does not parse: "+err.Error())
	}
	got := ab2Decide(record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// ab2Digest is sha256: and the hex SHA-256 of the value's JCS bytes.
func ab2Digest(value any) (string, bool) {
	data, err := pythonCompactJSONOpts(value, pyEncodeOpts{EnsureASCII: false})
	if err != nil {
		return "", false
	}
	return "sha256:" + sha(data), true
}

func ab2Must(value any) string {
	d, _ := ab2Digest(value)
	return d
}

// Typed views of a JSON value decoded with json.Number.

func ab2Obj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func ab2Str(m map[string]any, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok && s != ""
}

func ab2Int(v any, floor int64) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, ok := new(big.Int).SetString(n.String(), 10)
	if !ok || !i.IsInt64() || i.Int64() < floor {
		return 0, false
	}
	return i.Int64(), true
}

func ab2Strs(v any, nonempty bool) ([]string, bool) {
	list, ok := v.([]any)
	if !ok || (nonempty && len(list) == 0) {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func ab2Time(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || !strings.HasSuffix(s, "Z") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func ab2Texts(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := ab2Str(m, k); !ok {
			return false
		}
	}
	return true
}

func ab2DigestOK(m map[string]any, key string) bool {
	s, ok := m[key].(string)
	return ok && ab2DigestForm.MatchString(s)
}

func ab2HasFloat(v any) bool {
	switch x := v.(type) {
	case json.Number:
		return strings.ContainsAny(x.String(), ".eE")
	case map[string]any:
		for _, item := range x {
			if ab2HasFloat(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if ab2HasFloat(item) {
				return true
			}
		}
	}
	return false
}

type ab2Approval struct {
	id, proposal, call, tool, claimed, key string
	principal                              *string
	decision, argsDigest, historyDigest    string
	issued, expires                        time.Time
}

type ab2Delegation struct {
	issuer      string
	add, remove []string
	quorum      *int64
}

type ab2Witness struct {
	kind, digest string
	at           time.Time
}

type ab2Ledger struct{ approval, call string }

type ab2Record struct {
	proposalID, proposer, call, tool string
	argsShown, modelResponse         any
	calls                            [][2]string
	historyClaim                     string
	proposed                         time.Time
	quorum, timeout                  int64
	approvers                        []string
	keys                             map[string]string
	delegations                      []ab2Delegation
	rejectVetoes                     bool
	conflicts                        [][]string
	authority                        string
	approvals                        []ab2Approval
	relied                           []ab2Approval
	exec                             map[string]any
	execCall, execTool, execHistory  string
	argsExecuted                     any
	transforms                       [][3]string
	consumedBy, outcome, status      string
	consumed, dispatched             time.Time
	ledger                           []ab2Ledger
	ledgerRead                       bool
	witness                          []ab2Witness
	witnessPresent                   bool
}

func ab2ParseProposal(r *ab2Record, v any) bool {
	p, ok := ab2Obj(v)
	if !ok || !ab2Texts(p, "proposalId", "proposer", "toolCallId", "tool") {
		return false
	}
	r.proposalID, r.proposer, r.call, r.tool = p["proposalId"].(string), p["proposer"].(string),
		p["toolCallId"].(string), p["tool"].(string)
	if _, ok := ab2Obj(p["argsShown"]); !ok {
		return false
	}
	r.argsShown = p["argsShown"]
	response, ok := ab2Obj(p["modelResponse"])
	if !ok {
		return false
	}
	r.modelResponse = response
	calls, ok := response["toolCalls"].([]any)
	if !ok {
		return false
	}
	for _, item := range calls {
		c, ok := ab2Obj(item)
		if !ok || !ab2Texts(c, "toolCallId", "tool") {
			return false
		}
		if _, ok := ab2Obj(c["args"]); !ok {
			return false
		}
		r.calls = append(r.calls, [2]string{c["toolCallId"].(string), c["tool"].(string)})
	}
	if !ab2DigestOK(p, "historyDigest") {
		return false
	}
	r.historyClaim = p["historyDigest"].(string)
	r.proposed, ok = ab2Time(p["proposedAt"])
	return ok
}

func ab2ParsePolicy(r *ab2Record, v any) bool {
	p, ok := ab2Obj(v)
	if !ok {
		return false
	}
	if r.quorum, ok = ab2Int(p["quorum"], 1); !ok {
		return false
	}
	if r.approvers, ok = ab2Strs(p["approvers"], true); !ok {
		return false
	}
	keys, ok := ab2Obj(p["approverKeys"])
	if !ok {
		return false
	}
	r.keys = map[string]string{}
	for name, value := range keys {
		s, ok := value.(string)
		if !ok || s == "" {
			return false
		}
		r.keys[name] = s
	}
	delegations, ok := p["delegations"].([]any)
	if !ok {
		return false
	}
	for _, item := range delegations {
		d, ok := ab2ParseDelegation(item)
		if !ok {
			return false
		}
		r.delegations = append(r.delegations, d)
	}
	if r.timeout, ok = ab2Int(p["timeoutSeconds"], 1); !ok {
		return false
	}
	if r.rejectVetoes, ok = p["rejectVetoes"].(bool); !ok {
		return false
	}
	sod, ok := ab2Obj(p["separationOfDuties"])
	if !ok {
		return false
	}
	conflicts, ok := sod["conflicts"].([]any)
	if !ok {
		return false
	}
	for _, item := range conflicts {
		pair, ok := ab2Strs(item, false)
		if !ok || len(pair) != 2 {
			return false
		}
		r.conflicts = append(r.conflicts, pair)
	}
	r.authority, ok = ab2Str(p, "authorityKeyId")
	return ok
}

func ab2ParseDelegation(item any) (ab2Delegation, bool) {
	var d ab2Delegation
	m, ok := ab2Obj(item)
	if !ok || !ab2Texts(m, "delegationId", "issuer") {
		return d, false
	}
	d.issuer = m["issuer"].(string)
	if d.add, ok = ab2Strs(m["add"], false); !ok {
		return d, false
	}
	if d.remove, ok = ab2Strs(m["remove"], false); !ok {
		return d, false
	}
	if q, present := m["quorum"]; present && q != nil {
		n, ok := ab2Int(q, 1)
		if !ok {
			return d, false
		}
		d.quorum = &n
	} else if !present {
		return d, false
	}
	return d, true
}

func ab2ParseApproval(item any) (ab2Approval, bool) {
	var a ab2Approval
	m, ok := ab2Obj(item)
	names := []string{"approvalId", "proposalId", "toolCallId", "tool", "approverClaimed", "keyId"}
	if !ok || !ab2Texts(m, names...) {
		return a, false
	}
	a.id, a.proposal, a.call, a.tool = m["approvalId"].(string), m["proposalId"].(string),
		m["toolCallId"].(string), m["tool"].(string)
	a.claimed, a.key = m["approverClaimed"].(string), m["keyId"].(string)
	if value, present := m["authenticatedPrincipal"]; present && value != nil {
		s, ok := value.(string)
		if !ok || s == "" {
			return a, false
		}
		a.principal = &s
	}
	a.decision, _ = m["decision"].(string)
	if a.decision != "approve" && a.decision != "reject" {
		return a, false
	}
	if !ab2DigestOK(m, "argsDigest") || !ab2DigestOK(m, "historyDigest") {
		return a, false
	}
	a.argsDigest, a.historyDigest = m["argsDigest"].(string), m["historyDigest"].(string)
	if a.issued, ok = ab2Time(m["issuedAt"]); !ok {
		return a, false
	}
	a.expires, ok = ab2Time(m["expiresAt"])
	return a, ok
}

func ab2ParseExecution(r *ab2Record, v any) ([]string, bool) {
	e, ok := ab2Obj(v)
	if !ok || !ab2Texts(e, "executionId", "toolCallId", "tool", "consumedBy") {
		return nil, false
	}
	r.exec = e
	r.execCall, r.execTool, r.consumedBy = e["toolCallId"].(string), e["tool"].(string),
		e["consumedBy"].(string)
	if !ab2DigestOK(e, "historyDigest") {
		return nil, false
	}
	r.execHistory = e["historyDigest"].(string)
	if _, ok := ab2Obj(e["argsExecuted"]); !ok {
		return nil, false
	}
	r.argsExecuted = e["argsExecuted"]
	transforms, ok := e["transforms"].([]any)
	if !ok {
		return nil, false
	}
	for _, item := range transforms {
		t, ok := ab2Obj(item)
		kind, _ := t["kind"].(string)
		if !ok || !slices.Contains([]string{"override_args", "editedArgs", "after_tool_validate", "none"}, kind) ||
			!ab2DigestOK(t, "beforeDigest") || !ab2DigestOK(t, "afterDigest") {
			return nil, false
		}
		r.transforms = append(r.transforms, [3]string{kind, t["beforeDigest"].(string), t["afterDigest"].(string)})
	}
	ids, ok := ab2Strs(e["approvalIds"], false)
	if !ok {
		return nil, false
	}
	r.outcome, _ = e["outcome"].(string)
	r.status, _ = e["approvalStatus"].(string)
	if _, known := ab2Status[r.outcome]; !known || !slices.Contains([]string{"spent", "returned", "held"}, r.status) {
		return nil, false
	}
	if r.consumed, ok = ab2Time(e["consumedAt"]); !ok {
		return nil, false
	}
	r.dispatched, ok = ab2Time(e["dispatchedAt"])
	return ids, ok
}

func ab2ParseLedger(r *ab2Record, v any) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		m, ok := ab2Obj(item)
		if !ok || !ab2Texts(m, "approvalId", "toolCallId", "executionId") {
			return false
		}
		if _, ok := ab2Time(m["consumedAt"]); !ok {
			return false
		}
		r.ledger = append(r.ledger, ab2Ledger{m["approvalId"].(string), m["toolCallId"].(string)})
	}
	return true
}

func ab2ParseWitness(r *ab2Record, v any) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	kinds := []string{"grant", "permit", "effect", "srl", "approval"}
	for index, item := range list {
		m, ok := ab2Obj(item)
		if !ok {
			return false
		}
		seq, ok := ab2Int(m["seq"], 1)
		kind, _ := m["kind"].(string)
		if !ok || seq != int64(index+1) || !slices.Contains(kinds, kind) || !ab2DigestOK(m, "digest") {
			return false
		}
		at, ok := ab2Time(m["at"])
		if !ok {
			return false
		}
		r.witness = append(r.witness, ab2Witness{kind, m["digest"].(string), at})
	}
	return true
}

func ab2Parse(record map[string]any) (*ab2Record, bool) {
	r := &ab2Record{}
	if ab2HasFloat(record) || !ab2ParseProposal(r, record["proposal"]) || !ab2ParsePolicy(r, record["policy"]) {
		return nil, false
	}
	approvals, ok := record["approvals"].([]any)
	if !ok {
		return nil, false
	}
	byID := map[string]ab2Approval{}
	for _, item := range approvals {
		a, ok := ab2ParseApproval(item)
		if !ok {
			return nil, false
		}
		if _, seen := byID[a.id]; seen {
			return nil, false
		}
		byID[a.id] = a
		r.approvals = append(r.approvals, a)
	}
	ids, ok := ab2ParseExecution(r, record["execution"])
	if !ok {
		return nil, false
	}
	for _, id := range ids {
		a, present := byID[id]
		if !present {
			return nil, false
		}
		r.relied = append(r.relied, a)
	}
	if value, present := record["ledger"]; present {
		r.ledgerRead = true
		if !ab2ParseLedger(r, value) {
			return nil, false
		}
	}
	if value, present := record["witness"]; present {
		r.witnessPresent = true
		if !ab2ParseWitness(r, value) {
			return nil, false
		}
	}
	return r, true
}

// ab2Decide mirrors the Python reader: the contract checks, the structural
// check, then every binding check in order.
func ab2Decide(value any) scDecision {
	record, ok := ab2Obj(value)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != ab2ContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	r, ok := ab2Parse(record)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	for _, check := range ab2Checks {
		if check.fails(r) {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "quorum_bound"}
}

type ab2Check struct {
	reason string
	fails  func(*ab2Record) bool
}

func ab2Any(r *ab2Record, f func(ab2Approval) bool) bool { return slices.ContainsFunc(r.relied, f) }

var ab2Checks = []ab2Check{
	{"consumption_not_checked", func(r *ab2Record) bool { return !r.ledgerRead }},
	{"approver_delegation_widened", func(r *ab2Record) bool {
		return slices.ContainsFunc(r.delegations, r.widens)
	}},
	{"approval_not_for_call", ab2NotForCall},
	{"approver_unauthenticated", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return a.principal == nil })
	}},
	{"approver_claim_mismatch", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return a.claimed != *a.principal })
	}},
	{"approver_key_not_bound", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return r.keys[*a.principal] != a.key })
	}},
	{"approver_ineligible", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return r.seat(*a.principal) == "" })
	}},
	{"approver_is_proposer", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return r.seat(*a.principal) == r.proposer || *a.principal == r.proposer })
	}},
	{"approver_counted_twice", ab2CountedTwice},
	{"approvers_conflicted", ab2Conflicted},
	{"approval_not_granted", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return a.decision != "approve" })
	}},
	{"approval_vetoed", ab2Vetoed},
	{"quorum_not_met", func(r *ab2Record) bool { return int64(len(r.relied)) < r.effectiveQuorum() }},
	{"approval_not_for_bytes", func(r *ab2Record) bool {
		shown := ab2Must(r.argsShown)
		return ab2Any(r, func(a ab2Approval) bool { return a.argsDigest != shown })
	}},
	{"args_changed_after_approval", func(r *ab2Record) bool {
		executed := ab2Must(r.argsExecuted)
		return ab2Any(r, func(a ab2Approval) bool { return a.argsDigest != executed })
	}},
	{"transforms_unaccounted", ab2TransformsUnaccounted},
	{"history_digest_mismatch", func(r *ab2Record) bool {
		history := ab2Must(r.modelResponse)
		return r.historyClaim != history || r.execHistory != history ||
			ab2Any(r, func(a ab2Approval) bool { return a.historyDigest != history })
	}},
	{"approval_expired", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return !r.dispatched.Before(a.expires) })
	}},
	{"approval_postdates_consumption", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool { return a.issued.After(r.consumed) })
	}},
	{"timeout_not_fail_closed", ab2TimedOut},
	{"approval_replayed", func(r *ab2Record) bool {
		return ab2Any(r, func(a ab2Approval) bool {
			return slices.ContainsFunc(r.ledger, func(l ab2Ledger) bool { return l.approval == a.id })
		})
	}},
	{"call_already_executed", func(r *ab2Record) bool {
		return slices.ContainsFunc(r.ledger, func(l ab2Ledger) bool { return l.call == r.execCall })
	}},
	{"consumption_not_by_authority", func(r *ab2Record) bool { return r.consumedBy != r.authority }},
	{"consumption_not_witnessed", ab2NotWitnessed},
	{"consumed_after_dispatch", ab2AfterDispatch},
	{"outcome_misrecorded", func(r *ab2Record) bool { return ab2Status[r.outcome] != r.status }},
}

func (r *ab2Record) widens(d ab2Delegation) bool {
	lowered := d.quorum != nil && *d.quorum < r.quorum
	return len(d.remove) > 0 || lowered || !slices.Contains(r.approvers, d.issuer)
}

// seat is the seat a principal's approval counts for, or "" when it holds none.
func (r *ab2Record) seat(principal string) string {
	if slices.Contains(r.approvers, principal) {
		return principal
	}
	for _, d := range r.delegations {
		if !r.widens(d) && slices.Contains(d.add, principal) {
			return d.issuer
		}
	}
	return ""
}

func (r *ab2Record) effectiveQuorum() int64 {
	q := r.quorum
	for _, d := range r.delegations {
		if !r.widens(d) && d.quorum != nil && *d.quorum > q {
			q = *d.quorum
		}
	}
	return q
}

func ab2NotForCall(r *ab2Record) bool {
	if ab2Any(r, func(a ab2Approval) bool { return a.proposal != r.proposalID || a.call != r.call || a.tool != r.tool }) {
		return true
	}
	if r.execCall != r.call || r.execTool != r.tool {
		return true
	}
	return !slices.Contains(r.calls, [2]string{r.call, r.tool})
}

func ab2CountedTwice(r *ab2Record) bool {
	seen := map[string]bool{}
	for _, a := range r.relied {
		seat := r.seat(*a.principal)
		if seen[seat] {
			return true
		}
		seen[seat] = true
	}
	return false
}

func ab2Conflicted(r *ab2Record) bool {
	seats := map[string]bool{}
	for _, a := range r.relied {
		seats[r.seat(*a.principal)] = true
	}
	return slices.ContainsFunc(r.conflicts, func(pair []string) bool { return seats[pair[0]] && seats[pair[1]] })
}

func ab2Vetoed(r *ab2Record) bool {
	if !r.rejectVetoes {
		return false
	}
	return slices.ContainsFunc(r.approvals, func(a ab2Approval) bool {
		return a.decision == "reject" && a.principal != nil && a.claimed == *a.principal &&
			r.keys[*a.principal] == a.key && r.seat(*a.principal) != "" &&
			a.proposal == r.proposalID && !a.issued.After(r.consumed)
	})
}

func ab2TransformsUnaccounted(r *ab2Record) bool {
	current := ab2Must(r.argsShown)
	for _, t := range r.transforms {
		if t[1] != current || (t[0] == "none" && t[2] != t[1]) {
			return true
		}
		current = t[2]
	}
	return current != ab2Must(r.argsExecuted)
}

func ab2TimedOut(r *ab2Record) bool {
	needed := r.effectiveQuorum()
	if int64(len(r.relied)) < needed {
		return false
	}
	issued := make([]time.Time, 0, len(r.relied))
	for _, a := range r.relied {
		issued = append(issued, a.issued)
	}
	sort.Slice(issued, func(i, j int) bool { return issued[i].Before(issued[j]) })
	closes := r.proposed.Add(time.Duration(r.timeout) * time.Second)
	return !issued[needed-1].Before(closes)
}

// ab2Consumption is the digest the witness records for one consumption.
func ab2Consumption(r *ab2Record, approvalID string) string {
	return ab2Must(map[string]any{"approvalId": approvalID, "consumedAt": r.exec["consumedAt"],
		"consumedBy": r.consumedBy, "executionId": r.exec["executionId"]})
}

func ab2NotWitnessed(r *ab2Record) bool {
	if !r.witnessPresent {
		return true
	}
	return ab2Any(r, func(a ab2Approval) bool {
		want := ab2Consumption(r, a.id)
		return !slices.ContainsFunc(r.witness, func(w ab2Witness) bool { return w.kind == "approval" && w.digest == want })
	})
}

func ab2AfterDispatch(r *ab2Record) bool {
	if r.consumed.After(r.dispatched) {
		return true
	}
	return ab2Any(r, func(a ab2Approval) bool {
		want := ab2Consumption(r, a.id)
		return slices.ContainsFunc(r.witness, func(w ab2Witness) bool {
			return w.kind == "approval" && w.digest == want && w.at.After(r.dispatched)
		})
	})
}
