package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

func init() { register(monitorCoverage{}) }

// monitorCoverage judges corpora/vectors-monitor-coverage/. Each member is one
// monitor's verdict over one window: the monitor, its vantage and the channels
// it reads, the window, the collector-side coverage count, the effect another
// source observed, the verdict with its decision and effective-action counts,
// and an optional claim drawn from it. The reader derives each member's
// decision with the checks the Python reader applies, in the same order:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. window_invalid: the window ends after it starts;
//  4. coverage_counts_invalid: counts are non-negative, collected plus dropped
//     is at most expected, effective actions are at most decisions;
//  5. coverage_self_reported: a clean verdict rests on a collector count;
//  6. clean_with_incomplete_coverage: a clean verdict has every expected event
//     collected and none dropped;
//  7. clean_outside_vantage: a clean verdict covers the effect's channel;
//  8. clean_contradicts_observed_effect: a clean verdict does not stand beside
//     an effect in the window on a channel read with complete coverage;
//  9. defence_effect_without_effective_actions: a claim that the defence
//     reduced harm rests on at least one effective action.
type monitorCoverage struct{}

const mcContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/monitor-coverage"

func (monitorCoverage) Suite() string { return "monitor-coverage/v1" }

type mcRetained struct {
	Complete         bool   `json:"complete"`
	Decisions        int    `json:"decisions"`
	EffectiveActions int    `json:"effectiveActions"`
	Monitor          string `json:"monitor"`
	Result           string `json:"result"`
}

type mcVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained mcRetained        `json:"retained"`
}

type mcRecord struct {
	ContractID json.RawMessage `json:"contractId"`
	Coverage   struct {
		Basis     string `json:"basis"`
		Collected int    `json:"collected"`
		Dropped   int    `json:"dropped"`
		Expected  int    `json:"expected"`
	} `json:"coverage"`
	Monitor struct {
		Channels []string `json:"channels"`
		ID       string   `json:"id"`
	} `json:"monitor"`
	Verdict struct {
		Decisions        int    `json:"decisions"`
		EffectiveActions int    `json:"effectiveActions"`
		Result           string `json:"result"`
	} `json:"verdict"`
	Window struct {
		End   string `json:"end"`
		Start string `json:"start"`
	} `json:"window"`
	Effect *struct {
		At      string `json:"at"`
		Channel string `json:"channel"`
	} `json:"effect"`
	Claim *struct {
		Kind string `json:"kind"`
	} `json:"claim"`
}

func (monitorCoverage) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v mcVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = mcJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func mcJudgeMember(caseDir string, v mcVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record mcRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	stamps := []string{record.Window.Start, record.Window.End}
	if record.Effect != nil {
		stamps = append(stamps, record.Effect.At)
	}
	for _, stamp := range stamps {
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			return append(findings, fmt.Sprintf("record.json carries a timestamp that is not RFC 3339: %q", stamp))
		}
	}
	if kept := mcRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := mcDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func mcComplete(r mcRecord) bool {
	return r.Coverage.Collected == r.Coverage.Expected && r.Coverage.Dropped == 0
}

func mcRetain(r mcRecord) mcRetained {
	return mcRetained{Complete: mcComplete(r), Decisions: r.Verdict.Decisions,
		EffectiveActions: r.Verdict.EffectiveActions, Monitor: r.Monitor.ID, Result: r.Verdict.Result}
}

func mcCountsInvalid(r mcRecord) bool {
	c, v := r.Coverage, r.Verdict
	for _, n := range []int{c.Expected, c.Collected, c.Dropped, v.Decisions, v.EffectiveActions} {
		if n < 0 {
			return true
		}
	}
	return c.Collected+c.Dropped > c.Expected || v.EffectiveActions > v.Decisions
}

func mcDecide(r mcRecord) scDecision {
	var contract string
	known := len(r.ContractID) > 0 && json.Unmarshal(r.ContractID, &contract) == nil && contract == mcContractID
	clean := r.Verdict.Result == "clean"
	at := func(stamp string) time.Time { t, _ := time.Parse(time.RFC3339, stamp); return t }
	start, end := at(r.Window.Start), at(r.Window.End)
	read := r.Effect != nil && slices.Contains(r.Monitor.Channels, r.Effect.Channel)
	inWindow := r.Effect != nil && !at(r.Effect.At).Before(start) && at(r.Effect.At).Before(end)
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", len(r.ContractID) == 0},
		{"contract_id_unknown", len(r.ContractID) > 0 && !known},
		{"window_invalid", !end.After(start)},
		{"coverage_counts_invalid", mcCountsInvalid(r)},
		{"coverage_self_reported", clean && r.Coverage.Basis != "collector_count"},
		{"clean_with_incomplete_coverage", clean && !mcComplete(r)},
		{"clean_outside_vantage", clean && r.Effect != nil && !read},
		{"clean_contradicts_observed_effect", clean && read && mcComplete(r) && inWindow},
		{"defence_effect_without_effective_actions", r.Claim != nil &&
			r.Claim.Kind == "defence_reduced_harm" && r.Verdict.EffectiveActions == 0},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "verdict_supported"}
}
