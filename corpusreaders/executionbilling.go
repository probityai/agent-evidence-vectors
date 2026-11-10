package corpusreaders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
)

func init() { register(executionBilling{}) }

// executionBilling judges corpora/vectors-execution-billing-finality/. Each
// member is one runtime's observation of one scenario against its spend
// ledger: the scenario, and the attempt's state after the reservation, after
// every step, after the steps, after a reopen in a fresh process, after every
// probe and after a final reopen. Every state carries the execution outcome,
// the billing finality and the dispatch state side by side. The reader derives
// each member's decision with the checks the Python reader applies, in the
// same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the execution-billing-finality contract:
//     contract_id_unknown;
//  3. the scenario, every state and every action have their shape, every
//     amount is an integer and every flag a boolean: record_malformed;
//  4. every state carries dispatchState, one of RESERVED, POSSIBLE and
//     NOT_DISPATCHED: dispatch_state_missing;
//  5. externalEffect is NOT_EVALUATED and every claim boundary is declared:
//     claim_boundary_dropped;
//  6. the state read after each reopen is the state written before it:
//     reopen_changed_state;
//  7. an execution outcome other than UNKNOWN follows an accepted observation
//     of it, or a non-dispatch proof: execution_outcome_without_observation;
//  8. while billing is not final, the reservation less the known spend is
//     still held: held_released_before_final_billing;
//  9. a dispatch is allowed only from a reserved attempt whose billing is
//     unknown: same_attempt_redispatched;
//  10. once billing is final or in conflict, the dispatch state is no longer
//     RESERVED: dispatch_state_reserved_after_billing;
//  11. a replayed invoice event is not new and does not finalize again:
//     invoice_replay_refinalized.
//
// The reader also recomputes each member's retained scenario, axes and
// dispatch states.
type executionBilling struct{}

const ebContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/execution-billing-finality"

func (executionBilling) Suite() string { return "execution-billing-finality/v1" }

var (
	ebInteger    = regexp.MustCompile(`^-?[0-9]+$`)
	ebExecution  = map[string]bool{"UNKNOWN": true, "SUCCEEDED": true, "FAILED": true, "NOT_DISPATCHED": true}
	ebBilling    = map[string]bool{"UNKNOWN": true, "FINAL": true, "CONFLICT": true}
	ebDispatch   = map[string]bool{"RESERVED": true, "POSSIBLE": true, "NOT_DISPATCHED": true}
	ebExceptions = map[string]bool{"AdmissionDenied": true, "ConfigurationConflict": true,
		"EvidenceConflict": true, "EvidenceValidationError": true, "UnknownAttempt": true}
	ebCommands = map[string]bool{"cost": true, "dispatch": true, "invoice": true,
		"non_dispatch": true, "outcome": true, "reserve": true, "unknown": true}
	ebReturnKeys = map[string]bool{"dispatchAllowed": true, "newEvent": true,
		"newlyFinalized": true, "newlyReserved": true, "stateChanged": true}
	ebMoney      = []string{"availableMicroUsd", "heldMicroUsd", "knownSpendMicroUsd"}
	ebStateKeys  = map[string]bool{"availableMicroUsd": true, "heldMicroUsd": true, "knownSpendMicroUsd": true, "frozen": true, "unbounded": true, "billingFinality": true, "executionOutcome": true, "dispatchState": true}
	ebBoundaries = []string{"external_effect_established", "invoice_authenticity", "production_durability", "upstream_acceptance"}
	ebStates     = []string{"initial", "observed", "reopened", "end", "endReopened"}
)

type ebVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained json.RawMessage   `json:"retained"`
}

type ebObj = map[string]any

type ebAction struct {
	step, action, before ebObj
}

func (executionBilling) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ebVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ebJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ebDecode(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return value, nil
}

func ebJudgeMember(caseDir string, v ebVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	raw, err := os.ReadFile(filepath.Join(caseDir, "record.json")) // #nosec G304 -- a member of the corpus under judgement
	if err != nil {
		return append(findings, err.Error())
	}
	parsed, parseErr := ebDecode(raw)
	record, isObject := parsed.(ebObj)
	got := scDecision{Decision: "deny", Reason: "record_malformed"}
	if parseErr == nil && isObject {
		got = ebDecide(record)
		if !ebMalformed(record) {
			declared, err := ebDecode(v.Retained)
			if err != nil || !reflect.DeepEqual(declared, ebRetain(record)) {
				findings = append(findings, "retained fields: the record gives something other than the manifest declares")
			}
		}
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func ebDecide(r ebObj) scDecision {
	checks := []struct {
		name string
		fail func(ebObj) bool
	}{
		{"contract_id_missing", func(r ebObj) bool { _, ok := r["contractId"]; return !ok }},
		{"contract_id_unknown", func(r ebObj) bool { return r["contractId"] != ebContractID }},
		{"record_malformed", ebMalformed},
		{"dispatch_state_missing", ebDispatchStateMissing},
		{"claim_boundary_dropped", ebBoundaryDropped},
		{"reopen_changed_state", ebReopenChanged},
		{"execution_outcome_without_observation", ebOutcomeUnobserved},
		{"held_released_before_final_billing", ebHeldReleased},
		{"same_attempt_redispatched", ebRedispatched},
		{"dispatch_state_reserved_after_billing", ebReservedAfterBilling},
		{"invoice_replay_refinalized", ebReplayRefinalized},
	}
	for _, c := range checks {
		if c.fail(r) {
			return scDecision{Decision: "deny", Reason: c.name}
		}
	}
	return scDecision{Decision: "allow", Reason: "finality_held"}
}

func ebIsMoney(v any) bool {
	n, ok := v.(json.Number)
	if !ok || !ebInteger.MatchString(string(n)) {
		return false
	}
	value, ok := new(big.Int).SetString(string(n), 10)
	return ok && value.Sign() >= 0
}

func ebString(v any) string {
	s, _ := v.(string)
	return s
}

func ebStateShapeOK(v any) bool {
	state, ok := v.(ebObj)
	if !ok {
		return false
	}
	for key := range state {
		if !ebStateKeys[key] {
			return false
		}
	}
	for _, key := range ebMoney {
		if !ebIsMoney(state[key]) {
			return false
		}
	}
	for _, key := range []string{"frozen", "unbounded"} {
		if _, ok := state[key].(bool); !ok {
			return false
		}
	}
	outcome, okOutcome := state["executionOutcome"].(string)
	billing, okBilling := state["billingFinality"].(string)
	return okOutcome && okBilling && ebExecution[outcome] && ebBilling[billing]
}

func ebStepOK(v any) bool {
	step, ok := v.(ebObj)
	if !ok {
		return false
	}
	for _, key := range []string{"expected", "expect_return", "raises"} {
		if _, present := step[key]; present {
			return false
		}
	}
	cmd, ok := step["cmd"].(string)
	return ok && ebCommands[cmd]
}

func ebActionOK(v any) bool {
	action, ok := v.(ebObj)
	if !ok || len(action) != 3 {
		return false
	}
	exception, hasException := action["exception"]
	returned, okReturn := action["return"].(ebObj)
	state, hasState := action["state"]
	if !hasException || !okReturn || !hasState {
		return false
	}
	if exception != nil && !ebExceptions[ebString(exception)] {
		return false
	}
	for key, value := range returned {
		if _, isBool := value.(bool); !ebReturnKeys[key] || !isBool {
			return false
		}
	}
	return ebStateShapeOK(state)
}

func ebScenarioOK(r ebObj) bool {
	scenario, ok := r["scenario"].(ebObj)
	if !ok || len(scenario) != 4 {
		return false
	}
	if _, ok := scenario["id"].(string); !ok || !ebIsMoney(scenario["budget"]) {
		return false
	}
	for _, key := range []string{"probes", "steps"} {
		items, ok := scenario[key].([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if !ebStepOK(item) {
				return false
			}
		}
	}
	return true
}

func ebMalformed(r ebObj) bool {
	if !ebScenarioOK(r) {
		return true
	}
	scenario := r["scenario"].(ebObj)
	for _, key := range []string{"steps", "probes"} {
		items, ok := r[key].([]any)
		if !ok || len(items) != len(scenario[key].([]any)) {
			return true
		}
		for _, item := range items {
			if !ebActionOK(item) {
				return true
			}
		}
	}
	for _, key := range ebStates {
		if !ebStateShapeOK(r[key]) {
			return true
		}
	}
	return false
}

func ebActionList(r ebObj, key string) []ebObj {
	var out []ebObj
	for _, item := range r[key].([]any) {
		out = append(out, item.(ebObj))
	}
	return out
}

// ebAllStates lists every state in the order the run produced them; it reads
// a record ebMalformed has passed.
func ebAllStates(r ebObj) []ebObj {
	out := []ebObj{r["initial"].(ebObj)}
	for _, a := range ebActionList(r, "steps") {
		out = append(out, a["state"].(ebObj))
	}
	out = append(out, r["observed"].(ebObj), r["reopened"].(ebObj))
	for _, a := range ebActionList(r, "probes") {
		out = append(out, a["state"].(ebObj))
	}
	return append(out, r["end"].(ebObj), r["endReopened"].(ebObj))
}

func ebActions(r ebObj) []ebAction {
	var out []ebAction
	scenario := r["scenario"].(ebObj)
	for _, phase := range []struct{ key, start string }{{"steps", "initial"}, {"probes", "reopened"}} {
		before := r[phase.start].(ebObj)
		steps := scenario[phase.key].([]any)
		for i, action := range ebActionList(r, phase.key) {
			out = append(out, ebAction{step: steps[i].(ebObj), action: action, before: before})
			before = action["state"].(ebObj)
		}
	}
	return out
}

func ebDispatchStateMissing(r ebObj) bool {
	for _, state := range ebAllStates(r) {
		if !ebDispatch[ebString(state["dispatchState"])] {
			return true
		}
	}
	return false
}

func ebBoundaryDropped(r ebObj) bool {
	if r["externalEffect"] != "NOT_EVALUATED" {
		return true
	}
	claims, ok := r["mustNotClaim"].([]any)
	if !ok || len(claims) != len(ebBoundaries) {
		return true
	}
	seen := map[string]bool{}
	for _, claim := range claims {
		seen[ebString(claim)] = true
		if _, isString := claim.(string); !isString {
			return true
		}
	}
	for _, boundary := range ebBoundaries {
		if !seen[boundary] {
			return true
		}
	}
	return false
}

func ebReopenChanged(r ebObj) bool {
	return !reflect.DeepEqual(r["reopened"], r["observed"]) || !reflect.DeepEqual(r["endReopened"], r["end"])
}

func ebOutcomeUnobserved(r ebObj) bool {
	if r["initial"].(ebObj)["executionOutcome"] != "UNKNOWN" {
		return true
	}
	observed := map[string]bool{"UNKNOWN": true}
	for _, a := range ebActions(r) {
		accepted := a.action["exception"] == nil
		switch {
		case accepted && a.step["cmd"] == "outcome":
			if value, ok := a.step["value"].(string); ok {
				observed[value] = true
			}
		case accepted && a.step["cmd"] == "non_dispatch":
			observed["NOT_DISPATCHED"] = true
		}
		if !observed[ebString(a.action["state"].(ebObj)["executionOutcome"])] {
			return true
		}
	}
	for _, state := range ebAllStates(r) {
		if !observed[ebString(state["executionOutcome"])] {
			return true
		}
	}
	return false
}

func ebInt(v any) *big.Int {
	value, _ := new(big.Int).SetString(string(v.(json.Number)), 10) // validated by ebMalformed
	return value
}

func ebHeldReleased(r ebObj) bool {
	reserved := ebInt(r["initial"].(ebObj)["heldMicroUsd"])
	for _, state := range ebAllStates(r) {
		if state["billingFinality"] != "UNKNOWN" {
			continue
		}
		want := new(big.Int).Sub(reserved, ebInt(state["knownSpendMicroUsd"]))
		if want.Sign() < 0 {
			want.SetInt64(0)
		}
		if ebInt(state["heldMicroUsd"]).Cmp(want) != 0 {
			return true
		}
	}
	return false
}

func ebRedispatched(r ebObj) bool {
	for _, a := range ebActions(r) {
		attempt, named := a.step["attempt"]
		if a.step["cmd"] != "dispatch" || (named && attempt != "A") {
			continue
		}
		allowed, _ := a.action["return"].(ebObj)["dispatchAllowed"].(bool)
		if allowed && (a.before["dispatchState"] != "RESERVED" || a.before["billingFinality"] != "UNKNOWN") {
			return true
		}
	}
	return false
}

func ebReservedAfterBilling(r ebObj) bool {
	for _, state := range ebAllStates(r) {
		if state["billingFinality"] != "UNKNOWN" && state["dispatchState"] == "RESERVED" {
			return true
		}
	}
	return false
}

func ebReplayRefinalized(r ebObj) bool {
	accepted := map[string]bool{}
	for _, a := range ebActions(r) {
		event, hasEvent := a.step["event"]
		if a.step["cmd"] != "invoice" || !hasEvent {
			continue
		}
		key, _ := json.Marshal([]any{event, a.step["amount"]})
		returned := a.action["return"].(ebObj)
		if accepted[string(key)] && (returned["newEvent"] != false || returned["newlyFinalized"] != false) {
			return true
		}
		if a.action["exception"] == nil {
			accepted[string(key)] = true
		}
	}
	return false
}

func ebRetain(r ebObj) any {
	observed, end := r["observed"].(ebObj), r["end"].(ebObj)
	return map[string]any{
		"billingFinality":    observed["billingFinality"],
		"dispatchState":      observed["dispatchState"],
		"endDispatchState":   end["dispatchState"],
		"executionOutcome":   observed["executionOutcome"],
		"heldMicroUsd":       observed["heldMicroUsd"],
		"knownSpendMicroUsd": observed["knownSpendMicroUsd"],
		"scenario":           r["scenario"].(ebObj)["id"],
	}
}
