package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
)

func init() { register(physicalCompletion{}) }

// physicalCompletion judges corpora/vectors-physical-completion/. Each member
// is one presentation (a receipt, any controller outcome, any transport
// acknowledgement, any physical-observation artifact and the verifier's trust
// configuration) and the result a verifier reported for the
// PHYSICAL_COMPLETION intent, anchored to draft-noa-scitt-ai-agent-receipt-01
// Sections 1.5, 2 and 8.1 to 8.4. The reader applies the checks the Python
// reader applies, in the same order, and names the first that fails:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. result_member_absent: the result answers the intent;
//  4. proven_without_policy: no unqualified proof (Section 8.2);
//  5. result_outside_vocabulary: the value is one of the closed set;
//  6. untokenised_result_as_profile_token: CONFLICT is not presented as the
//     draft's vocabulary (Section 1.5);
//  7. completion_from_receipt and 8. completion_from_controller_report: no
//     completion without an observation (Section 8.1);
//  9. negative_without_observation: NOT_SATISFIED only when a presented
//     observation says the criterion was not met (Section 8.3);
//  10. absence_not_reported_as_not_provided: with no observation, the result
//     is NOT_PROVIDED (Section 8.3).
//
// A record that passes all ten and breaks one of the corpus's proposal rules
// for the artifacts Section 1.5 leaves undefined is ambiguous; otherwise it is
// conformant.
type physicalCompletion struct{}

const (
	pcContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/physical-completion"
	pcProfile    = "draft-noa-scitt-ai-agent-receipt-01"
)

func (physicalCompletion) Suite() string { return "physical-completion/v1" }

type pcRetained struct {
	Owed     string `json:"owed"`
	Reported string `json:"reported"`
}

type pcVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained pcRetained        `json:"retained"`
}

type pcObservation struct {
	Authenticated      bool    `json:"authenticated"`
	BoundToAction      bool    `json:"boundToAction"`
	Witness            *string `json:"witness"`
	CriterionFixedAtMs int64   `json:"criterionFixedAtMs"`
	ObservedAtMs       int64   `json:"observedAtMs"`
	WindowEndMs        int64   `json:"windowEndMs"`
	CriterionMet       *bool   `json:"criterionMet"`
}

type pcRecord struct {
	ContractID json.RawMessage `json:"contractId"`
	Presented  struct {
		Receipt struct {
			DispatchedAtMs int64 `json:"dispatchedAtMs"`
		} `json:"receipt"`
		Trust struct {
			Trusted []string `json:"witnessesTrustedForPurpose"`
		} `json:"trust"`
		Controller *struct {
			Status string `json:"status"`
		} `json:"controllerOutcome"`
		Observation *pcObservation `json:"observation"`
	} `json:"presented"`
	Result struct {
		PhysicalCompletion *string `json:"physicalCompletion"`
		TrustConfiguration string  `json:"trustConfiguration"`
		Vocabulary         string  `json:"vocabulary"`
		Claims             []struct {
			Source string `json:"source"`
		} `json:"claims"`
	} `json:"result"`
}

var pcClosed = []string{"NOT_CLAIMED", "NOT_PROVIDED", "NOT_APPLICABLE", "INDETERMINATE",
	"PROVEN_TO_POLICY", "NOT_SATISFIED", "CONFLICT"}

func (physicalCompletion) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v pcVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = pcJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func pcJudgeMember(caseDir string, v pcVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record pcRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if kept := pcRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := pcDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// pcProposal names the proposal rule that decides the presentation and the
// results it owes; the first matching condition decides.
func pcProposal(r pcRecord) (string, []string) {
	o := r.Presented.Observation
	switch {
	case o == nil:
		return "absence_reported_as_not_claimed", []string{"NOT_PROVIDED"}
	case !o.Authenticated:
		return "observation_unauthenticated", []string{"NOT_PROVIDED"}
	case !o.BoundToAction:
		return "observation_unbound", []string{"NOT_PROVIDED"}
	case o.Witness == nil || *o.Witness == "":
		return "witness_unidentified", []string{"INDETERMINATE"}
	case !slices.Contains(r.Presented.Trust.Trusted, *o.Witness):
		return "witness_untrusted", []string{"INDETERMINATE"}
	}
	dispatched := r.Presented.Receipt.DispatchedAtMs
	if o.CriterionFixedAtMs >= dispatched {
		return "criterion_not_prefixed", []string{"INDETERMINATE"}
	}
	if o.ObservedAtMs < dispatched || o.ObservedAtMs > o.WindowEndMs {
		return "observation_outside_window", []string{"INDETERMINATE"}
	}
	met := o.CriterionMet != nil && *o.CriterionMet
	if c := r.Presented.Controller; c != nil && (c.Status == "succeeded") != met {
		return "conflict_erased", []string{"CONFLICT"}
	}
	if met {
		return "observation_outcome_not_reported", []string{"PROVEN_TO_POLICY"}
	}
	return "observation_outcome_not_reported", []string{"NOT_SATISFIED"}
}

func pcReported(r pcRecord) string {
	if r.Result.PhysicalCompletion == nil {
		return "absent"
	}
	return *r.Result.PhysicalCompletion
}

func pcRetain(r pcRecord) pcRetained {
	_, owed := pcProposal(r)
	sort.Strings(owed)
	return pcRetained{Owed: strings.Join(owed, "|"), Reported: pcReported(r)}
}

type pcCheck struct {
	reason string
	fails  bool
}

// pcChecks is the ordered table of the profile's rules, first failure wins.
func pcChecks(r pcRecord) []pcCheck {
	var contract string
	known := len(r.ContractID) > 0 && json.Unmarshal(r.ContractID, &contract) == nil && contract == pcContractID
	reported := pcReported(r)
	observed := r.Presented.Observation != nil
	controller := r.Presented.Controller != nil
	unmet := observed && r.Presented.Observation.CriterionMet != nil && !*r.Presented.Observation.CriterionMet
	proven := reported == "PROVEN_TO_POLICY"
	unqualified := reported == "PROVEN" || reported == "PHYSICAL_COMPLETION_PROVEN" ||
		(proven && r.Result.TrustConfiguration == "")
	return []pcCheck{
		{"contract_id_missing", len(r.ContractID) == 0},
		{"contract_id_unknown", len(r.ContractID) > 0 && !known},
		{"result_member_absent", reported == "absent"},
		{"proven_without_policy", unqualified},
		{"result_outside_vocabulary", !slices.Contains(pcClosed, reported)},
		{"untokenised_result_as_profile_token", reported == "CONFLICT" && r.Result.Vocabulary == pcProfile},
		{"completion_from_receipt", proven && !observed && !controller},
		{"completion_from_controller_report", proven && !observed && controller},
		{"negative_without_observation", reported == "NOT_SATISFIED" && !unmet},
		{"absence_not_reported_as_not_provided", !observed && reported != "NOT_PROVIDED" && reported != "NOT_CLAIMED"},
	}
}

func pcDecide(r pcRecord) scDecision {
	for _, check := range pcChecks(r) {
		if check.fails {
			return scDecision{"nonconformant", check.reason}
		}
	}
	rule, owed := pcProposal(r)
	reported := pcReported(r)
	if !slices.Contains(owed, reported) {
		return scDecision{"ambiguous", rule}
	}
	if reported == "CONFLICT" {
		sources := map[string]bool{}
		for _, claim := range r.Result.Claims {
			sources[claim.Source] = true
		}
		if len(sources) != 2 || !sources["controller"] || !sources["witness"] {
			return scDecision{"ambiguous", "conflict_drops_a_claim"}
		}
	}
	return scDecision{"conformant", "result_follows_presentation"}
}
