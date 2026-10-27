package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
)

func init() { register(aggregateAccounting{}) }

// aggregateAccounting judges vectors-aggregate-accounting/. Each member is the
// decision log of an accounting authority for one budget shared by a principal
// and its delegation subtrees. The reader derives each member's decision with
// the checks the Python reader applies, in the same order, and names the first
// one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the aggregate-accounting contract: contract_id_unknown;
//  3. every decision names its principal, subtree, budget and action:
//     accounting_identity_missing;
//  4. no request is admitted after an answer past the latency bound:
//     latency_bound_admitted;
//  5. an admitted reservation of unknown outcome is still charged:
//     unknown_outcome_not_charged;
//  6. the units charged do not exceed the budget: aggregate_overspend;
//  7. no request was refused for budget that fitted beside everything admitted:
//     fitting_request_refused;
//  8. the retained counts equal the counts the decisions give:
//     effect_counts_disagree.
//
// The reader also recomputes each member's retained principal, subtrees,
// budget, actions and counts.
type aggregateAccounting struct{}

const aaContractID = "https://probityai.github.io/agent-evidence-observer/contract/aggregate-accounting/v1"

func (aggregateAccounting) Suite() string { return "aggregate-accounting/v1" }

type aaCounts struct {
	Admitted       int `json:"admitted"`
	Refused        int `json:"refused"`
	Held           int `json:"held"`
	ChargedUnits   int `json:"chargedUnits"`
	RemainingUnits int `json:"remainingUnits"`
}

type aaRetained struct {
	Actions   []string `json:"actions"`
	Budget    string   `json:"budget"`
	Counts    aaCounts `json:"counts"`
	Principal string   `json:"principal"`
	Subtrees  []string `json:"subtrees"`
}

type aaVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained aaRetained        `json:"retained"`
}

type aaDecision struct {
	Action    string `json:"action"`
	Budget    string `json:"budget"`
	Charged   bool   `json:"charged"`
	Decision  string `json:"decision"`
	Latency   int    `json:"latencyMs"`
	Outcome   string `json:"outcome"`
	Principal string `json:"principal"`
	Reason    string `json:"reason"`
	Subtree   string `json:"subtree"`
	Units     int    `json:"units"`
}

type aaRecord struct {
	ContractID *string `json:"contractId"`
	Principal  string  `json:"principal"`
	Budget     struct {
		ID              string `json:"id"`
		RemainingBefore int    `json:"remainingBefore"`
	} `json:"budget"`
	LatencyBound int          `json:"latencyBoundMs"`
	Decisions    []aaDecision `json:"decisions"`
	EffectCounts aaCounts     `json:"effectCounts"`
}

func (aggregateAccounting) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v aaVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = aaJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func aaJudgeMember(caseDir string, v aaVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record aaRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if kept := aaRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the decisions give something other than the manifest declares")
	}
	got := aaDecide(record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func aaIsCharged(d aaDecision) bool {
	return d.Decision == "admitted" && (d.Outcome == "committed" || d.Outcome == "unknown")
}

func aaChargedUnits(r aaRecord) int {
	total := 0
	for _, d := range r.Decisions {
		if aaIsCharged(d) {
			total += d.Units
		}
	}
	return total
}

func aaCounting(r aaRecord) aaCounts {
	var c aaCounts
	for _, d := range r.Decisions {
		switch d.Decision {
		case "admitted":
			c.Admitted++
		case "refused":
			c.Refused++
		case "held":
			c.Held++
		}
	}
	c.ChargedUnits = aaChargedUnits(r)
	c.RemainingUnits = r.Budget.RemainingBefore - c.ChargedUnits
	return c
}

func aaSorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func aaRetain(r aaRecord) aaRetained {
	actions, subtrees := map[string]bool{}, map[string]bool{}
	for _, d := range r.Decisions {
		actions[d.Action] = true
		subtrees[d.Subtree] = true
	}
	return aaRetained{Actions: aaSorted(actions), Budget: r.Budget.ID, Counts: aaCounting(r),
		Principal: r.Principal, Subtrees: aaSorted(subtrees)}
}

func aaDecide(r aaRecord) scDecision {
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", r.ContractID == nil},
		{"contract_id_unknown", r.ContractID != nil && *r.ContractID != aaContractID},
		{"accounting_identity_missing", aaIdentityMissing(r)},
		{"latency_bound_admitted", aaLatencyAdmitted(r)},
		{"unknown_outcome_not_charged", aaUnknownReleased(r)},
		{"aggregate_overspend", aaChargedUnits(r) > r.Budget.RemainingBefore},
		{"fitting_request_refused", aaFittingRefused(r)},
		{"effect_counts_disagree", r.EffectCounts != aaCounting(r)},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "aggregate_held"}
}

func aaIdentityMissing(r aaRecord) bool {
	for _, d := range r.Decisions {
		if d.Principal == "" || d.Subtree == "" || d.Budget == "" || d.Action == "" {
			return true
		}
	}
	return false
}

func aaLatencyAdmitted(r aaRecord) bool {
	for _, d := range r.Decisions {
		if d.Decision == "admitted" && d.Latency > r.LatencyBound {
			return true
		}
	}
	return false
}

func aaUnknownReleased(r aaRecord) bool {
	for _, d := range r.Decisions {
		if d.Decision == "admitted" && d.Outcome == "unknown" && !d.Charged {
			return true
		}
	}
	return false
}

func aaFittingRefused(r aaRecord) bool {
	room := r.Budget.RemainingBefore - aaChargedUnits(r)
	for _, d := range r.Decisions {
		if d.Decision == "refused" && d.Reason == "budget" && d.Units <= room {
			return true
		}
	}
	return false
}
