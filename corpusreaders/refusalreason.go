package corpusreaders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
)

func init() { register(refusalReason{}) }

// refusalReason judges corpora/vectors-refusal-reason-priority/. Each member is
// one attestation response and the facts it answered over, anchored to
// draft-li-rttp-iqa-addressing-02 sections 6.1, 7.2, 8.1 and 8.2. The reader
// derives each member's decision with the checks the Python reader applies, in
// the same order:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. reason_member_absent: the response carries a reason member;
//  4. reason_outside_closed_set: the reason is null or one of the five values;
//  5. answer_outside_both_boundary_readings: at the lease instant the answer
//     is a permit or evidence_expired;
//  6. refusal_without_condition: no value is emitted when no condition applies;
//  7. condition_ignored: a permit is not emitted while a condition applies;
//  8. later_value_emitted: the value emitted is the first applicable one;
//  9. observation_backfilled: the observation member is null when the relied-on
//     observation is absent or not fresh;
//  10. evidence_renewed_by_diagnostic_read: a diagnostic read does not move the
//     grant's expiry.
//
// A record that passes all ten is conformant, except at the lease instant,
// where an undeclared boundary or a declaration that contradicts the answer is
// ambiguous: the draft leaves both open.
type refusalReason struct{}

const rsnContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/refusal-reason-priority"

func (refusalReason) Suite() string { return "refusal-reason-priority/v1" }

type rsnRetained struct {
	Emitted string `json:"emitted"`
	Owed    string `json:"owed"`
}

type rsnVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained rsnRetained       `json:"retained"`
}

type rsnRecord struct {
	ContractID json.RawMessage `json:"contractId"`
	Facts      struct {
		Authority          string    `json:"authority"`
		BindingMismatch    bool      `json:"bindingMismatch"`
		EvidenceExpired    bool      `json:"evidenceExpired"`
		OperationPermitted *bool     `json:"operationPermitted"`
		GrantExpiresAtMs   int64     `json:"grantExpiresAtMs"`
		DiagnosticRead     *struct{} `json:"diagnosticRead"`
		ReliedOn           *struct {
			Fresh   bool `json:"fresh"`
			Present bool `json:"present"`
		} `json:"reliedOnObservation"`
		LeaseInstant *struct {
			Declared *string `json:"declaredBoundary"`
		} `json:"leaseInstant"`
	} `json:"facts"`
	Response struct {
		Reason   json.RawMessage `json:"reason"`
		GrantRef struct {
			ExpiresAtMs *int64 `json:"expiresAtMs"`
			Observation *int64 `json:"observationAsOfMs"`
		} `json:"grantRef"`
	} `json:"response"`
}

var rsnFive = []string{"evidence_binding_mismatch", "evidence_expired", "authority_not_determined",
	"authority_revoked", "operation_not_permitted"}

func (refusalReason) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v rsnVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = rsnJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func rsnJudgeMember(caseDir string, v rsnVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record rsnRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if kept := rsnRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := rsnDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// rsnReason reads the reason member: absent, null, or the string it carries.
func rsnReason(r rsnRecord) (value string, present, null bool) {
	if len(r.Response.Reason) == 0 {
		return "", false, false
	}
	if bytes.Equal(bytes.TrimSpace(r.Response.Reason), []byte("null")) {
		return "", true, true
	}
	var text string
	if err := json.Unmarshal(r.Response.Reason, &text); err != nil {
		return string(r.Response.Reason), true, false
	}
	return text, true, false
}

func rsnApplicable(r rsnRecord) []string {
	f := r.Facts
	var found []string
	if f.BindingMismatch {
		found = append(found, "evidence_binding_mismatch")
	}
	if f.EvidenceExpired {
		found = append(found, "evidence_expired")
	}
	if f.Authority == "unreachable" || f.Authority == "staleObservation" {
		found = append(found, "authority_not_determined")
	}
	if f.Authority == "revoked" {
		found = append(found, "authority_revoked")
	}
	if f.OperationPermitted != nil && !*f.OperationPermitted {
		found = append(found, "operation_not_permitted")
	}
	return found
}

func rsnLeaseOnly(r rsnRecord) bool { return r.Facts.LeaseInstant != nil && len(rsnApplicable(r)) == 0 }

// rsnOwed lists what the draft licenses as the reason, with "null" for a permit.
func rsnOwed(r rsnRecord) []string {
	if rsnLeaseOnly(r) {
		return []string{"evidence_expired", "null"}
	}
	if found := rsnApplicable(r); len(found) > 0 {
		return []string{found[0]}
	}
	return []string{"null"}
}

func rsnEmitted(r rsnRecord) string {
	value, present, null := rsnReason(r)
	switch {
	case !present:
		return "absent"
	case null:
		return "null"
	}
	return value
}

func rsnRetain(r rsnRecord) rsnRetained {
	owed := rsnOwed(r)
	sort.Strings(owed)
	return rsnRetained{Emitted: rsnEmitted(r), Owed: strings.Join(owed, "|")}
}

func rsnRelyFresh(r rsnRecord) bool {
	return r.Facts.ReliedOn != nil && r.Facts.ReliedOn.Present && r.Facts.ReliedOn.Fresh
}

// rsnBackfilled: a stale or absent relied-on observation with a non-null member.
func rsnBackfilled(r rsnRecord) bool {
	return r.Facts.ReliedOn != nil && !rsnRelyFresh(r) && r.Response.GrantRef.Observation != nil
}

// rsnRenewed: a diagnostic read after stale evidence with the expiry moved later.
func rsnRenewed(r rsnRecord) bool {
	return r.Facts.DiagnosticRead != nil && !rsnRelyFresh(r) &&
		r.Response.GrantRef.ExpiresAtMs != nil && *r.Response.GrantRef.ExpiresAtMs > r.Facts.GrantExpiresAtMs
}

func rsnDecide(r rsnRecord) scDecision {
	var contract string
	known := len(r.ContractID) > 0 && json.Unmarshal(r.ContractID, &contract) == nil && contract == rsnContractID
	emitted := rsnEmitted(r)
	owed := rsnOwed(r)
	leaseOnly := rsnLeaseOnly(r)
	wrong := !leaseOnly && !slices.Contains(owed, emitted)
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", len(r.ContractID) == 0},
		{"contract_id_unknown", len(r.ContractID) > 0 && !known},
		{"reason_member_absent", emitted == "absent"},
		{"reason_outside_closed_set", emitted != "absent" && emitted != "null" && !slices.Contains(rsnFive, emitted)},
		{"answer_outside_both_boundary_readings", leaseOnly && emitted != "null" && emitted != "evidence_expired"},
		{"refusal_without_condition", wrong && len(owed) == 1 && owed[0] == "null" && emitted != "null"},
		{"condition_ignored", wrong && emitted == "null"},
		{"later_value_emitted", wrong && emitted != "null" && !(len(owed) == 1 && owed[0] == "null")},
		{"observation_backfilled", rsnBackfilled(r)},
		{"evidence_renewed_by_diagnostic_read", rsnRenewed(r)},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"nonconformant", check.reason}
		}
	}
	if leaseOnly {
		declared := r.Facts.LeaseInstant.Declared
		if declared == nil {
			return scDecision{"ambiguous", "boundary_undeclared"}
		}
		owes := "evidence_expired"
		if *declared == "inclusive" {
			owes = "null"
		}
		if emitted != owes {
			return scDecision{"ambiguous", "declaration_contradicts_use"}
		}
	}
	return scDecision{"conformant", "response_follows_source"}
}
