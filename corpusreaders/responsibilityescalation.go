package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

func init() { register(responsibilityEscalation{}) }

// responsibilityEscalation judges corpora/vectors-responsibility-escalation/.
// Each member is one synthetic record of a hiring agent's decision and the
// escalation of that decision to a designated human role. The reader derives
// each member's outcome with the checks the Python reader applies, in the same
// order:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. referral_not_evidenced; 4. event_after_evaluation_instant;
//  5. reference_unavailable: the authority reference did not resolve;
//  6. reference_inconsistent: the resolved version is neither the one in force at
//     the read instant nor the current one;
//  7. current_record_resolved_not_decision_time: the current record came back in
//     place of the version in force at the read instant;
//  8. authority_not_held_at_read_instant;
//  9. receipt_not_evidenced; 10. escalation_unanswered: no acknowledgement;
//  11. acknowledged_outside_designated_role;
//  12. authority_narrowed_before_acknowledgement;
//  13. acceptance_not_evidenced; 14. accepted_outside_designated_role;
//  15. closure_not_evidenced, 16. closed_outside_designated_role and
//  17. closed_late, each only where the record requires closure.
//
// A record that passes every check is established.
type responsibilityEscalation struct{}

const resContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/responsibility-escalation"

func (responsibilityEscalation) Suite() string { return "responsibility-escalation/v1" }

type resRetained struct {
	Evidenced string `json:"evidenced"`
	InForce   string `json:"inForce"`
	ReadAt    string `json:"readAt"`
}

type resVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained resRetained       `json:"retained"`
}

type resVersion struct {
	EffectiveFrom string `json:"effectiveFrom"`
	Holds         bool   `json:"holds"`
	ID            string `json:"id"`
}

type resSlot struct {
	At        string `json:"at"`
	By        string `json:"by"`
	Evidenced bool   `json:"evidenced"`
}

type resRecord struct {
	ContractID *string `json:"contractId"`
	Decision   struct {
		At string `json:"at"`
	} `json:"decision"`
	Authority struct {
		ReadAt     string `json:"readAt"`
		Resolution struct {
			Returned *string `json:"returned"`
			Status   string  `json:"status"`
		} `json:"resolution"`
		Versions []resVersion `json:"versions"`
	} `json:"authority"`
	Escalation struct {
		Closure struct {
			DueBy    *string `json:"dueBy"`
			Required bool    `json:"required"`
		} `json:"closure"`
		DesignatedRole string             `json:"designatedRole"`
		Slots          map[string]resSlot `json:"slots"`
	} `json:"escalation"`
	EvaluatedAt string `json:"evaluatedAt"`
}

var resSlotOrder = []string{"referral", "receipt", "acknowledgement", "acceptance", "closure"}

func (responsibilityEscalation) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v resVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = resJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func resJudgeMember(caseDir string, v resVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record resRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if kept := resRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	got, err := resDecide(record)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func resInstant(text string) (time.Time, error) { return time.Parse("2006-01-02T15:04:05Z", text) }

func (r resRecord) evidenced(name string) bool { return r.Escalation.Slots[name].Evidenced }

// readInstant is the decision instant, or the referral instant when the record reads there.
func (r resRecord) readInstant() string {
	if r.Authority.ReadAt == "referral" {
		return r.Escalation.Slots["referral"].At
	}
	return r.Decision.At
}

// inForce is the last version of the authority record effective at the instant.
func (r resRecord) inForce(when string) (*resVersion, error) {
	if when == "" {
		return nil, nil
	}
	at, err := resInstant(when)
	if err != nil {
		return nil, err
	}
	var found *resVersion
	for i := range r.Authority.Versions {
		from, err := resInstant(r.Authority.Versions[i].EffectiveFrom)
		if err != nil {
			return nil, err
		}
		if !from.After(at) {
			found = &r.Authority.Versions[i]
		}
	}
	return found, nil
}

func resRetain(r resRecord) resRetained {
	held, _ := r.inForce(r.readInstant())
	id, readAt := "none", "decision"
	if held != nil {
		id = held.ID
	}
	if r.Authority.ReadAt != "" {
		readAt = r.Authority.ReadAt
	}
	var kept []string
	for _, name := range resSlotOrder {
		if r.evidenced(name) {
			kept = append(kept, name)
		}
	}
	evidenced := "none"
	if len(kept) > 0 {
		evidenced = strings.Join(kept, "+")
	}
	return resRetained{Evidenced: evidenced, InForce: id, ReadAt: readAt}
}

func resDecide(r resRecord) (scDecision, error) {
	held, err := r.inForce(r.readInstant())
	if err != nil {
		return scDecision{}, err
	}
	checks, err := resChecks(r, held)
	if err != nil {
		return scDecision{}, err
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{check.outcome, check.reason}, nil
		}
	}
	reason := "authority_held_at_decision_time"
	switch {
	case r.Escalation.Closure.Required:
		reason = "closed_as_accepted"
	case r.Authority.ReadAt == "referral":
		reason = "authority_held_at_referral_instant"
	}
	return scDecision{"established", reason}, nil
}

type resCheck struct {
	reason  string
	outcome string
	fails   bool
}

func resAfterEvaluation(r resRecord) (bool, error) {
	evaluated, err := resInstant(r.EvaluatedAt)
	if err != nil {
		return false, err
	}
	times := []string{r.Decision.At}
	for _, name := range resSlotOrder {
		if r.evidenced(name) {
			times = append(times, r.Escalation.Slots[name].At)
		}
	}
	for _, text := range times {
		at, err := resInstant(text)
		if err != nil {
			return false, err
		}
		if at.After(evaluated) {
			return true, nil
		}
	}
	return false, nil
}

func resClosedLate(r resRecord) (bool, error) {
	if r.Escalation.Closure.DueBy == nil || !r.evidenced("closure") {
		return false, nil
	}
	due, err := resInstant(*r.Escalation.Closure.DueBy)
	if err != nil {
		return false, err
	}
	at, err := resInstant(r.Escalation.Slots["closure"].At)
	if err != nil {
		return false, err
	}
	return at.After(due), nil
}

// resChecks is the ordered check table, first failure wins.
func resChecks(r resRecord, held *resVersion) ([]resCheck, error) {
	after, err := resAfterEvaluation(r)
	if err != nil {
		return nil, err
	}
	atAck, err := r.inForce(r.Escalation.Slots["acknowledgement"].At)
	if err != nil {
		return nil, err
	}
	late, err := resClosedLate(r)
	if err != nil {
		return nil, err
	}
	var current *resVersion
	known := map[string]bool{}
	for i := range r.Authority.Versions {
		known[r.Authority.Versions[i].ID] = true
		current = &r.Authority.Versions[i]
	}
	returned, heldID, currentID := "", "", ""
	if r.Authority.Resolution.Returned != nil {
		returned = *r.Authority.Resolution.Returned
	}
	if held != nil {
		heldID = held.ID
	}
	if current != nil {
		currentID = current.ID
	}
	role := r.Escalation.DesignatedRole
	required := r.Escalation.Closure.Required
	return []resCheck{
		{"contract_id_missing", "not_established", r.ContractID == nil},
		{"contract_id_unknown", "not_established", r.ContractID != nil && *r.ContractID != resContractID},
		{"referral_not_evidenced", "not_established", !r.evidenced("referral")},
		{"event_after_evaluation_instant", "not_established", after},
		{"reference_unavailable", "not_established", r.Authority.Resolution.Status != "resolved"},
		{"reference_inconsistent", "not_established",
			!known[returned] || (returned != heldID && returned != currentID)},
		{"current_record_resolved_not_decision_time", "not_established", returned != heldID && returned == currentID},
		{"authority_not_held_at_read_instant", "not_established", held == nil || !held.Holds},
		{"receipt_not_evidenced", "partial", !r.evidenced("receipt")},
		{"escalation_unanswered", "unresolved", !r.evidenced("acknowledgement")},
		{"acknowledged_outside_designated_role", "partial", r.Escalation.Slots["acknowledgement"].By != role},
		{"authority_narrowed_before_acknowledgement", "partial", atAck == nil || !atAck.Holds},
		{"acceptance_not_evidenced", "partial", !r.evidenced("acceptance")},
		{"accepted_outside_designated_role", "partial", r.Escalation.Slots["acceptance"].By != role},
		{"closure_not_evidenced", "partial", required && !r.evidenced("closure")},
		{"closed_outside_designated_role", "partial", required && r.Escalation.Slots["closure"].By != role},
		{"closed_late", "partial", required && late},
	}, nil
}
