package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

func init() { register(approvalBinding{}) }

// approvalBinding judges vectors-approval-binding/. Each member is one record
// of an approval presented for a use and the payload bytes of the use. The
// reader derives each member's decision with the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the approval-binding contract: contract_id_unknown;
//  3. no other presented approval shares the identifier with different
//     content: approval_id_ambiguous;
//  4. the identifier was not consumed already: approval_replayed;
//  5. the approval's keyId is the approver's trusted key: key_not_bound;
//  6. the use's principal is the approval's principal: principal_mismatch;
//  7. the use's event and phase are the approved ones: event_phase_mismatch;
//  8. the used tool, target and bytes are the approved ones: payload_mismatch;
//  9. usedAt is inside the approval's validity window:
//     approval_outside_validity;
//  10. the policy release lookup answered: comparison_unavailable;
//  11. the release was served at the decision time, allowing the grace period:
//     release_not_served_at_decision.
type approvalBinding struct{}

const abContractID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1"

func (approvalBinding) Suite() string { return "approval-binding/v1" }

type abVector struct {
	ID         string            `json:"id"`
	Path       string            `json:"path"`
	Files      map[string]string `json:"files"`
	Expected   scDecision        `json:"expected"`
	UseMatches bool              `json:"useMatchesApproval"`
}

type abRecord struct {
	ContractID   *string           `json:"contractId"`
	DecisionTime string            `json:"decisionTime"`
	Approval     map[string]any    `json:"approval"`
	Presented    []map[string]any  `json:"presentedApprovals"`
	Consumed     []string          `json:"consumedApprovalIds"`
	TrustedKeys  map[string]string `json:"trustedKeys"`
	Use          map[string]string `json:"use"`
	Release      struct {
		FirstServedAt string  `json:"firstServedAt"`
		LastServedAt  string  `json:"lastServedAt"`
		GraceSeconds  float64 `json:"graceSeconds"`
		Lookup        string  `json:"lookup"`
	} `json:"policyRelease"`
}

func (approvalBinding) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v abVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = abJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func abJudgeMember(caseDir string, v abVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record abRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	used, err := readIn(caseDir, record.Use["payloadFile"])
	if err != nil {
		return append(findings, fmt.Sprintf("%s cannot be read: %v", record.Use["payloadFile"], err))
	}
	matches := abMatches(record, used)
	if matches != v.UseMatches {
		findings = append(findings, fmt.Sprintf(
			"use matches approval: %t, the manifest declares %t", matches, v.UseMatches))
	}
	got, err := abDecide(record, matches)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func abField(r abRecord, key string) string {
	value, _ := r.Approval[key].(string)
	return value
}

func abMatches(r abRecord, used []byte) bool {
	return r.Use["tool"] == abField(r, "tool") && r.Use["target"] == abField(r, "target") &&
		sha(used) == abField(r, "payloadSha256")
}

func abAmbiguous(r abRecord) bool {
	return slices.ContainsFunc(r.Presented, func(other map[string]any) bool {
		return other["approvalId"] == r.Approval["approvalId"] && !reflect.DeepEqual(other, r.Approval)
	})
}

func abDecide(r abRecord, matches bool) (scDecision, error) {
	var clock atdClock
	decided := clock.at(r.DecisionTime)
	usedAt := clock.at(r.Use["usedAt"])
	issued, expires := clock.at(abField(r, "issuedAt")), clock.at(abField(r, "expiresAt"))
	first, last := clock.at(r.Release.FirstServedAt), clock.at(r.Release.LastServedAt)
	grace := time.Duration(r.Release.GraceSeconds) * time.Second
	key, known := r.TrustedKeys[abField(r, "approver")]
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", r.ContractID == nil},
		{"contract_id_unknown", r.ContractID != nil && *r.ContractID != abContractID},
		{"approval_id_ambiguous", abAmbiguous(r)},
		{"approval_replayed", slices.Contains(r.Consumed, abField(r, "approvalId"))},
		{"key_not_bound", !known || key != abField(r, "keyId")},
		{"principal_mismatch", r.Use["principal"] != abField(r, "principal")},
		{"event_phase_mismatch", r.Use["event"] != abField(r, "event") || r.Use["phase"] != abField(r, "phase")},
		{"payload_mismatch", !matches},
		{"approval_outside_validity", usedAt.Before(issued) || !usedAt.Before(expires)},
		{"comparison_unavailable", r.Release.Lookup != "ok"},
		{"release_not_served_at_decision", decided.Before(first) || decided.After(last.Add(grace))},
	}
	if clock.err != nil {
		return scDecision{}, clock.err
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}, nil
		}
	}
	return scDecision{"allow", "bound"}, nil
}
