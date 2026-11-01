package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"time"
)

func init() { register(completionConfirmation{}) }

// completionConfirmation judges vectors-completion-confirmation/. Each member
// is one record of a task, the authorization decision for it, the agent's claim
// about its outcome and the confirmation the claim rests on (or none). The
// reader derives each member's decision with the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the completion-confirmation contract: contract_id_unknown;
//  3. the record has the fields and types the contract names and every time
//     parses: malformed_record;
//  4. the claim is not "complete": allow, no_completion_claimed;
//  5. a confirmation is present: completion_unconfirmed;
//  6. the confirmation names the task, authorization, operation, resource and
//     arguments: confirmation_not_bound;
//  7. the observer is not the claimant and the key is the observer's trusted
//     key: confirmation_self_reported;
//  8. the confirmation identifier was not consumed: confirmation_reused;
//  9. observedAt is between the authorization and the decision:
//     confirmation_outside_window;
//  10. the confirmed outcome is not unresolved: outcome_unresolved;
//  11. the confirmed outcome is not absent: outcome_contradicts_claim.
type completionConfirmation struct{}

const ccContractID = "https://probityai.github.io/agent-evidence-vectors/contract/completion-confirmation/v1"

func (completionConfirmation) Suite() string { return "completion-confirmation/v1" }

type ccVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

func (completionConfirmation) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ccVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ccJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ccJudgeMember(caseDir string, v ccVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record map[string]any
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	got := ccDecide(record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type ccConfirmation struct {
	id, authorizationID, taskID, operation, resource, args, observedBy, keyID, outcome string
	observedAt                                                                         time.Time
}

type ccParsed struct {
	decided, authorizedAt             time.Time
	taskID, operation, resource, args string
	authorizationID, authTaskID       string
	status, claimedBy                 string
	confirmation                      *ccConfirmation
	observers                         map[string]any
	consumed                          []any
}

func ccDecide(record map[string]any) scDecision {
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != ccContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	p, ok := ccParse(record)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	if p.status != "complete" {
		return scDecision{"allow", "no_completion_claimed"}
	}
	c := p.confirmation
	if c == nil {
		return scDecision{"deny", "completion_unconfirmed"}
	}
	checks := []struct {
		reason string
		fails  bool
	}{
		{"confirmation_not_bound", !ccBound(p, c)},
		{"confirmation_self_reported", c.observedBy == p.claimedBy || p.observers[c.observedBy] != c.keyID},
		{"confirmation_reused", slices.Contains(p.consumed, any(c.id))},
		{"confirmation_outside_window", c.observedAt.Before(p.authorizedAt) || c.observedAt.After(p.decided)},
		{"outcome_unresolved", c.outcome == "unresolved"},
		{"outcome_contradicts_claim", c.outcome == "absent"},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "confirmed"}
}

func ccBound(p ccParsed, c *ccConfirmation) bool {
	return c.taskID == p.taskID && p.taskID == p.authTaskID && c.authorizationID == p.authorizationID &&
		c.operation == p.operation && c.resource == p.resource && c.args == p.args
}

func ccTexts(value any, names ...string) (map[string]string, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		text, ok := m[name].(string)
		if !ok {
			return nil, false
		}
		out[name] = text
	}
	return out, true
}

func ccInstant(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func ccParse(record map[string]any) (ccParsed, bool) {
	var p ccParsed
	decision, ok := record["decisionTime"].(string)
	if !ok {
		return p, false
	}
	task, ok1 := ccTexts(record["task"], "taskId", "operation", "resource", "argsSha256")
	auth, ok2 := ccTexts(record["authorization"], "authorizationId", "taskId", "decidedAt")
	claim, ok3 := ccTexts(record["claim"], "status", "claimedBy", "claimedAt")
	observers, ok4 := record["trustedObservers"].(map[string]any)
	consumed, ok5 := record["consumedConfirmationIds"].([]any)
	_, ok6 := record["confirmation"]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !slices.Contains([]string{"complete", "unresolved", "failed"}, claim["status"]) {
		return p, false
	}
	p.taskID, p.operation, p.resource, p.args = task["taskId"], task["operation"], task["resource"], task["argsSha256"]
	p.authorizationID, p.authTaskID = auth["authorizationId"], auth["taskId"]
	p.status, p.claimedBy = claim["status"], claim["claimedBy"]
	p.observers, p.consumed = observers, consumed
	if p.decided, ok = ccInstant(decision); !ok {
		return p, false
	}
	if p.authorizedAt, ok = ccInstant(auth["decidedAt"]); !ok {
		return p, false
	}
	if _, ok = ccInstant(claim["claimedAt"]); !ok {
		return p, false
	}
	if record["confirmation"] == nil {
		return p, true
	}
	return ccParseConfirmation(p, record["confirmation"])
}

func ccParseConfirmation(p ccParsed, value any) (ccParsed, bool) {
	t, ok := ccTexts(value, "confirmationId", "authorizationId", "taskId", "operation", "resource",
		"argsSha256", "observedBy", "keyId", "observedAt", "outcome")
	if !ok || !slices.Contains([]string{"committed", "unresolved", "absent"}, t["outcome"]) {
		return p, false
	}
	observed, ok := ccInstant(t["observedAt"])
	if !ok {
		return p, false
	}
	p.confirmation = &ccConfirmation{
		id: t["confirmationId"], authorizationID: t["authorizationId"], taskID: t["taskId"],
		operation: t["operation"], resource: t["resource"], args: t["argsSha256"],
		observedBy: t["observedBy"], keyID: t["keyId"], outcome: t["outcome"], observedAt: observed,
	}
	return p, true
}
