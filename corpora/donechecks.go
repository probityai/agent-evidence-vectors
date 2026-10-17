package corpora

import (
	"path/filepath"
	"strings"
)

// The three checks a done verdict rests on, and how they combine. This file mirrors
// packaging/agent_evidence_vectors/donechecks.py; spec/predicates/done-receipt.md
// states the rules.

const (
	donePROTECTED  = "protected_paths/v1"
	doneACCEPTANCE = "acceptance_observed/v1"
	doneTOOLS      = "tool_claim_match/v1"
)

var (
	doneClaimTypes = []string{donePROTECTED, doneACCEPTANCE, doneTOOLS}
	doneFileNames  = map[string]string{donePROTECTED: "protected-paths",
		doneACCEPTANCE: "acceptance", doneTOOLS: "tool-claims"}
	doneToolTypes = []string{"write", "create", "rename", "link", "unlink", "truncate", "chmod", "exec"}
	doneMutateSet = []string{"write", "create", "rename", "link", "unlink", "truncate", "chmod"}
	// doneContradictions maps a claim status to the reason a contradicted check names.
	doneContradictions = map[string]string{"unmatched": "tool_claim_unmatched",
		"precedes_last_edit": "tool_claim_precedes_last_edit", "exit_mismatch": "tool_claim_exit_mismatch"}
	doneGraderNames    = map[string]bool{"sitecustomize.py": true, "usercustomize.py": true, "reward.json": true, "reward.txt": true}
	doneGraderSegments = map[string]bool{"site-packages": true, "dist-packages": true, "verifier": true}
)

// doneVerdict is a check's result: decision, reason, vantage and, once decided, scope.
type doneVerdict = map[string]any

func doneBase(caseID, claimType string) doneVerdict {
	return doneVerdict{"case_id": caseID, "claim_type": claimType, "vantage": "unestablished"}
}

func doneDecided(base doneVerdict, decision, reason string, pairs ...[2]doneObject) doneVerdict {
	out := doneVerdict{}
	for k, v := range base {
		out[k] = v
	}
	out["decision"], out["reason"] = decision, reason
	if decision != "not_established" {
		out["vantage"], out["witness_scope"] = "independent", doneScopeOf(pairs...)
	}
	return out
}

func doneHasAll(visible any, required []string) bool {
	have := map[string]bool{}
	for _, item := range visible.([]any) {
		if name, ok := item.(string); ok {
			have[name] = true
		}
	}
	for _, name := range required {
		if !have[name] {
			return false
		}
	}
	return true
}

func doneIsProtectedEvent(entries []doneObject, event doneObject) bool {
	hit := func(name string) bool {
		for _, entry := range entries {
			if doneProtects(entry, name) {
				return true
			}
		}
		return false
	}
	kind, _ := event["type"].(string)
	if !doneMutations[kind] {
		return false
	}
	path, _ := event["path"].(string)
	if hit(path) {
		return true
	}
	target, ok := event["target"].(string)
	return ok && hit(target)
}

func doneChanged(entries []doneObject, files doneObject) bool {
	for _, entry := range entries {
		path, _ := entry["path"].(string)
		want, _ := entry["sha256"].(string)
		var now string
		if entry["kind"] == "file" {
			now, _ = files[path].(string)
		} else {
			selected := map[string]string{}
			for name, digest := range files {
				if name != path && doneProtects(entry, name) {
					selected[name], _ = digest.(string)
				}
			}
			now = doneTreeDigest(selected)
		}
		if now != want {
			return true
		}
	}
	return false
}

func doneContextOK(record doneObject, caseID, invocation string, scope doneObject) bool {
	if record["claim_id"] != caseID || record["invocation_id"] != invocation {
		return false
	}
	return scope == nil || doneEqual(record["scope"], scope)
}

func doneEvents2(record doneObject) []doneObject {
	list, _ := record["events"].([]any)
	out := make([]doneObject, 0, len(list))
	for _, item := range list {
		out = append(out, item.(doneObject))
	}
	return out
}

func doneProtectedEntries(contract doneObject) []doneObject {
	list, _ := contract["protected_paths"].([]any)
	out := make([]doneObject, 0, len(list))
	for _, item := range list {
		out = append(out, item.(doneObject))
	}
	return out
}

func doneAssessmentStrings(assessment doneObject) (string, string, error) {
	invocation, err := doneText(assessment["invocation_id"], "policy_invocation_id")
	if err != nil {
		return "", "", err
	}
	party, err := doneText(assessment["observed_party"], "policy_observed_party")
	return invocation, party, err
}

// doneSettle is the bounded absence rule over file mutation (event_absence/v2, profiled).
func doneSettle(base doneVerdict, observed, capability []byte, caseID, invocation string,
	scope doneObject, obsPin doneObject, party string, entries []doneObject,
	parsed *doneObject) (doneVerdict, error) {
	if observed == nil {
		return doneDecided(base, "not_established", "observation_unavailable_or_unbound"), nil
	}
	record, err := doneObservation(observed)
	if err != nil {
		return nil, err
	}
	*parsed = record
	if !doneContextOK(record, caseID, invocation, scope) {
		return doneDecided(base, "not_established", "observation_context_mismatch"), nil
	}
	var manifest doneObject
	if capability != nil {
		if manifest, err = doneCapability(capability); err != nil {
			return nil, err
		}
	}
	if !doneIndependent(record, obsPin, party) {
		return doneDecided(base, "not_established", "observation_vantage_unestablished"), nil
	}
	for _, event := range doneEvents2(record) {
		if doneIsProtectedEvent(entries, event) {
			return doneDecided(base, "contradicted", "event_observed"), nil
		}
	}
	if manifest == nil {
		return doneDecided(base, "not_established", "capability_unavailable_or_unbound"), nil
	}
	if manifest["claim_id"] != caseID || manifest["invocation_id"] != invocation || manifest["producer"] != record["producer"] {
		return doneDecided(base, "not_established", "capability_context_mismatch"), nil
	}
	if !doneHasAll(manifest["visible_event_types"], doneMutateSet) {
		return doneDecided(base, "not_established", "field_visibility_unestablished"), nil
	}
	if record["coverage"] != "complete" {
		return doneDecided(base, "not_established", "observation_coverage_unestablished"), nil
	}
	return doneDecided(base, "supported", "absence_within_covered_scope"), nil
}

func doneProtectedPaths(caseValue, policyValue any, root string) (doneVerdict, error) {
	caseID, assessment, caseDoc, policy, err := doneStart(caseValue, policyValue, donePROTECTED,
		[]string{"claim_type", "invocation_id", "scope", "observed_party", "contract_witness",
			"capability_witness", "observation_witness", "tree_witness"})
	if err != nil {
		return nil, err
	}
	invocation, party, err := doneAssessmentStrings(assessment)
	if err != nil {
		return nil, err
	}
	scope, err := doneScope(assessment["scope"], "policy")
	if err != nil {
		return nil, err
	}
	bound, err := doneBind(caseDoc, policy, assessment, root, []string{"contract", "capability", "observation", "tree"},
		map[string]bool{"observation": true, "tree": true})
	if err != nil {
		return nil, err
	}
	base := doneBase(caseID, donePROTECTED)
	if bound["contract"].data == nil {
		return doneDecided(base, "not_established", "contract_unavailable_or_unbound"), nil
	}
	contract, err := doneContract(bound["contract"].data)
	if err != nil {
		return nil, err
	}
	entries := doneProtectedEntries(contract)
	var tree doneObject
	if bound["tree"].data != nil {
		if tree, err = doneTree(bound["tree"].data); err != nil {
			return nil, err
		}
	}
	var parsed doneObject
	settled, err := doneSettle(base, bound["observation"].data, bound["capability"].data, caseID,
		invocation, scope, bound["observation"].pin, party, entries, &parsed)
	if err != nil {
		return nil, err
	}
	obsPair := [2]doneObject{parsed, bound["observation"].pin}
	if settled["decision"] == "contradicted" {
		return doneDecided(base, "contradicted", "protected_path_mutated", obsPair), nil
	}
	treeMet := false
	if tree != nil && doneContextOK(tree, caseID, invocation, nil) && doneIndependent(tree, bound["tree"].pin, party) {
		files, _ := tree["files"].(doneObject)
		if doneChanged(entries, files) {
			return doneDecided(base, "contradicted", "protected_path_digest_changed", [2]doneObject{tree, bound["tree"].pin}), nil
		}
		treeMet = true
	}
	if settled["decision"] == "not_established" {
		return doneDecided(base, "not_established", settled["reason"].(string)), nil
	}
	if !treeMet {
		return doneDecided(base, "not_established", "final_tree_unestablished"), nil
	}
	return doneDecided(base, "supported", "protected_paths_untouched", obsPair, [2]doneObject{tree, bound["tree"].pin}), nil
}

func doneCompare(acceptance []any, results []any) (string, []int64) {
	byID := map[string]doneObject{}
	for _, item := range results {
		entry := item.(doneObject)
		byID[entry["id"].(string)] = entry
	}
	var exits []int64
	for _, item := range acceptance {
		command := item.(doneObject)
		id := command["id"].(string)
		found, ok := byID[id]
		if !ok {
			return "acceptance_result_missing", exits
		}
		delete(byID, id)
		if !doneEqual(found["argv"], command["argv"]) {
			return "acceptance_argv_mismatch", exits
		}
		code, _ := doneInteger(found["exit"])
		exits = append(exits, code)
	}
	if len(byID) > 0 {
		return "acceptance_result_unexpected", exits
	}
	return "", exits
}

func doneAcceptanceObserved(caseValue, policyValue any, root string) (doneVerdict, error) {
	caseID, assessment, caseDoc, policy, err := doneStart(caseValue, policyValue, doneACCEPTANCE,
		[]string{"claim_type", "invocation_id", "observed_party", "contract_witness", "tree_witness", "grade_witness"})
	if err != nil {
		return nil, err
	}
	invocation, party, err := doneAssessmentStrings(assessment)
	if err != nil {
		return nil, err
	}
	bound, err := doneBind(caseDoc, policy, assessment, root, []string{"contract", "tree", "grade"},
		map[string]bool{"tree": true, "grade": true})
	if err != nil {
		return nil, err
	}
	base := doneBase(caseID, doneACCEPTANCE)
	var contract, tree, grade doneObject
	if data := bound["contract"].data; data != nil {
		if contract, err = doneContract(data); err != nil {
			return nil, err
		}
	}
	if data := bound["tree"].data; data != nil {
		if tree, err = doneTree(data); err != nil {
			return nil, err
		}
	}
	if data := bound["grade"].data; data != nil {
		if grade, err = doneGrade(data); err != nil {
			return nil, err
		}
	}
	treePair := [2]doneObject{tree, bound["tree"].pin}
	gradePair := [2]doneObject{grade, bound["grade"].pin}
	switch {
	case contract == nil:
		return doneDecided(base, "not_established", "contract_unavailable_or_unbound"), nil
	case tree == nil || !doneContextOK(tree, caseID, invocation, nil) || !doneIndependent(tree, bound["tree"].pin, party):
		return doneDecided(base, "not_established", "final_tree_unestablished"), nil
	case grade == nil:
		return doneDecided(base, "not_established", "grade_unavailable_or_unbound"), nil
	case !doneContextOK(grade, caseID, invocation, nil):
		return doneDecided(base, "not_established", "grade_context_mismatch"), nil
	case !doneIndependent(grade, bound["grade"].pin, party):
		return doneDecided(base, "not_established", "grade_vantage_unestablished"), nil
	case grade["contract_sha256"] != bound["contract"].pin["consumer_pinned_sha256"]:
		return doneDecided(base, "not_established", "grade_contract_mismatch"), nil
	case grade["tree_sha256"] != tree["tree_sha256"]:
		return doneDecided(base, "not_established", "grade_tree_unbound"), nil
	}
	problem, exits := doneCompare(contract["acceptance"].([]any), grade["results"].([]any))
	if problem != "" {
		return doneDecided(base, "not_established", problem), nil
	}
	for _, code := range exits {
		if code != 0 {
			return doneDecided(base, "contradicted", "acceptance_failed_in_verifier", treePair, gradePair), nil
		}
	}
	killed, _ := doneInteger(contract["adequacy"].(doneObject)["killed"])
	if killed <= 0 {
		return doneDecided(base, "not_established", "contract_adequacy_zero"), nil
	}
	return doneDecided(base, "supported", "acceptance_passed_in_verifier", treePair, gradePair), nil
}

func doneClaimStatus(claim doneObject, events []doneObject) string {
	var candidates []doneObject
	for _, event := range events {
		if event["type"] == "exec" && doneEqual(event["argv"], claim["argv"]) {
			candidates = append(candidates, event)
		}
	}
	own := map[string]bool{}
	for _, event := range candidates {
		if origin, ok := event["origin"].(string); ok {
			own[origin] = true
		} else {
			own[event["id"].(string)] = true
		}
	}
	lastEdit := int64(-1)
	for _, event := range events {
		if kind, _ := event["type"].(string); !doneMutations[kind] {
			continue
		}
		origin, hasOrigin := event["origin"].(string)
		if hasOrigin && own[origin] {
			continue
		}
		if step, _ := doneInteger(event["step"]); step > lastEdit {
			lastEdit = step
		}
	}
	var fresh []doneObject
	for _, event := range candidates {
		if step, _ := doneInteger(event["step"]); step > lastEdit {
			fresh = append(fresh, event)
		}
	}
	switch {
	case len(candidates) == 0:
		return "unmatched"
	case len(fresh) == 0:
		return "precedes_last_edit"
	}
	want, hasExit := claim["exit"]
	if !hasExit {
		return "matched"
	}
	unseen := false
	for _, event := range fresh {
		got, ok := event["exit"]
		if !ok {
			unseen = true
		} else if doneEqual(got, want) {
			return "matched"
		}
	}
	if unseen {
		return "exit_unobserved"
	}
	return "exit_mismatch"
}

func doneToolClaimMatch(caseValue, policyValue any, root string) (doneVerdict, error) {
	caseID, assessment, caseDoc, policy, err := doneStart(caseValue, policyValue, doneTOOLS,
		[]string{"claim_type", "invocation_id", "scope", "observed_party", "claims_witness",
			"capability_witness", "observation_witness"})
	if err != nil {
		return nil, err
	}
	invocation, party, err := doneAssessmentStrings(assessment)
	if err != nil {
		return nil, err
	}
	scope, err := doneScope(assessment["scope"], "policy")
	if err != nil {
		return nil, err
	}
	bound, err := doneBind(caseDoc, policy, assessment, root, []string{"claims", "capability", "observation"},
		map[string]bool{"observation": true})
	if err != nil {
		return nil, err
	}
	base := doneBase(caseID, doneTOOLS)
	var claimed, record, manifest doneObject
	if data := bound["claims"].data; data != nil {
		if claimed, err = doneClaims(data); err != nil {
			return nil, err
		}
	}
	if data := bound["observation"].data; data != nil {
		if record, err = doneObservation(data); err != nil {
			return nil, err
		}
	}
	if data := bound["capability"].data; data != nil {
		if manifest, err = doneCapability(data); err != nil {
			return nil, err
		}
	}
	obsPin := bound["observation"].pin
	switch {
	case claimed == nil:
		return doneDecided(base, "not_established", "claims_unavailable_or_unbound"), nil
	case !doneContextOK(claimed, caseID, invocation, nil):
		return doneDecided(base, "not_established", "claims_context_mismatch"), nil
	case record == nil:
		return doneDecided(base, "not_established", "observation_unavailable_or_unbound"), nil
	case !doneContextOK(record, caseID, invocation, scope):
		return doneDecided(base, "not_established", "observation_context_mismatch"), nil
	case !doneIndependent(record, obsPin, party):
		return doneDecided(base, "not_established", "observation_vantage_unestablished"), nil
	}
	events := doneEvents2(record)
	var unsettled []string
	for _, item := range claimed["claims"].([]any) {
		if status := doneClaimStatus(item.(doneObject), events); status != "matched" {
			unsettled = append(unsettled, status)
		}
	}
	switch {
	case manifest == nil:
		return doneDecided(base, "not_established", "capability_unavailable_or_unbound"), nil
	case manifest["claim_id"] != caseID || manifest["invocation_id"] != invocation || manifest["producer"] != record["producer"]:
		return doneDecided(base, "not_established", "capability_context_mismatch"), nil
	case !doneHasAll(manifest["visible_event_types"], doneToolTypes):
		return doneDecided(base, "not_established", "field_visibility_unestablished"), nil
	case record["coverage"] != "complete":
		return doneDecided(base, "not_established", "observation_coverage_unestablished"), nil
	}
	pair := [2]doneObject{record, obsPin}
	for _, status := range unsettled {
		if reason, ok := doneContradictions[status]; ok {
			return doneDecided(base, "contradicted", reason, pair), nil
		}
	}
	if len(unsettled) > 0 {
		return doneDecided(base, "not_established", "tool_exit_unobserved"), nil
	}
	return doneDecided(base, "supported", "tool_claims_matched", pair), nil
}

// doneRunCheck reads a member's case and policy for one check and returns its verdict.
func doneRunCheck(claimType, member string) (doneVerdict, error) {
	name := doneFileNames[claimType]
	caseBytes, err := doneMemberFile(member, name+".case.json", "case_unreadable")
	if err != nil {
		return nil, err
	}
	policyBytes, err := doneMemberFile(member, name+".policy.json", "policy_unreadable")
	if err != nil {
		return nil, err
	}
	if caseBytes == nil || policyBytes == nil {
		return nil, refuse("case_missing")
	}
	caseValue, err := doneStrictJSON(caseBytes, "case")
	if err != nil {
		return nil, err
	}
	policyValue, err := doneStrictJSON(policyBytes, "policy")
	if err != nil {
		return nil, err
	}
	switch claimType {
	case donePROTECTED:
		return doneProtectedPaths(caseValue, policyValue, member)
	case doneACCEPTANCE:
		return doneAcceptanceObserved(caseValue, policyValue, member)
	}
	return doneToolClaimMatch(caseValue, policyValue, member)
}

// doneProjection is the fields a corpus member declares about a verdict.
func doneProjection(verdict doneVerdict) map[string]any {
	out := map[string]any{}
	for _, key := range []string{"decision", "reason", "vantage", "witness_scope"} {
		if v, ok := verdict[key]; ok {
			out[key] = v
		}
	}
	return out
}

func doneGraderPath(name string) bool {
	parts := strings.Split(name, "/")
	last := parts[len(parts)-1]
	if doneGraderNames[last] || strings.HasSuffix(last, ".pth") {
		return true
	}
	for _, part := range parts {
		if doneGraderSegments[part] {
			return true
		}
	}
	return false
}

func doneGraderEffect(effects []any) bool {
	for _, item := range effects {
		effect, _ := item.(doneObject)
		paths, _ := effect["paths"].([]any)
		for _, p := range paths {
			if text, ok := p.(string); ok && doneGraderPath(filepath.ToSlash(text)) {
				return true
			}
		}
	}
	return false
}

// doneCombine is one done verdict from the three checks and the effects outside the workspace.
func doneCombine(checks []doneVerdict, effects []any) map[string]any {
	var contradicting doneVerdict
	settled, notEstablished := 0, doneVerdict(nil)
	for _, check := range checks {
		switch check["decision"] {
		case "contradicted":
			if contradicting == nil {
				contradicting = check
			}
		case "not_established":
			if notEstablished == nil {
				notEstablished = check
			}
		}
		if check["decision"] != "not_established" {
			settled++
		}
	}
	var decision, reason string
	switch {
	case contradicting != nil:
		decision, reason = "contradicted", contradicting["reason"].(string)
	case doneGraderEffect(effects):
		decision, reason = "contradicted", "external_effect_on_grader_path"
	case settled == len(checks):
		decision, reason = "supported", "done_checks_supported"
	default:
		decision, reason = "not_established", notEstablished["reason"].(string)
	}
	out := map[string]any{"decision": decision, "reason": reason, "vantage": "unestablished"}
	if decision != "not_established" {
		out["vantage"] = "independent"
		external := settled > 0
		for _, check := range checks {
			if check["decision"] != "not_established" && check["witness_scope"] != "EXTERNAL" {
				external = false
			}
		}
		out["witness_scope"] = "PEER"
		if external {
			out["witness_scope"] = "EXTERNAL"
		}
	}
	return out
}
