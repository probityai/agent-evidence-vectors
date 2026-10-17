package corpora

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
)

// The done-contract and done-receipt corpora, and the three that build on them.
//
// Five corpora share one reader because they share one question: given the records
// of a coding agent's run, what does an outside verifier conclude? A member is a
// directory of records; the manifest declares what the reader derives, and the reader
// recomputes it. The Python reader is packaging/agent_evidence_vectors/donerun.py and
// the two must print the same findings.

const (
	doneContractSuite = "done-contract/v1"
	doneReceiptSuite  = "done-receipt/v1"
	doneSpoofedSuite  = "spoofed-tool-output/v1"
	doneTamperSuite   = "test-tampering/v1"
	doneGraderSuite   = "grader-isolation/v1"

	doneURI          = "https://w3id.org/agent-evidence/predicate/v1/"
	doneContractType = doneURI + "done-contract"
	doneReceiptType  = doneURI + "done-receipt"
	doneStatement    = "https://in-toto.io/Statement/v1"
	doneReceiptShape = "probity-done-receipt/v1"
)

func init() {
	for _, suite := range []string{doneContractSuite, doneReceiptSuite, doneSpoofedSuite, doneTamperSuite, doneGraderSuite} {
		register(doneReader{suite})
	}
}

type doneReader struct{ suite string }

func (r doneReader) Suite() string { return r.suite }

var (
	doneCoreRoles   = []string{"contract", "tree", "observation", "capability", "grade", "claims"}
	doneLaunchRoles = []string{"launch", "launch_receipt"}
	doneStopActions = map[string]bool{"continue": true, "replan": true, "escalate": true, "stop": true}
	doneRoleFiles   = map[string]string{"contract": "contract.json", "tree": "tree.json",
		"observation": "observation.json", "capability": "capability.json", "grade": "grade.json",
		"claims": "claims.json", "launch": "launch.json", "launch_receipt": "launch-receipt.json"}
	doneLaunchFields = []string{"schema_version", "backend", "image", "image_id", "runtime_version",
		"strace_version", "container_argv", "trace_expression", "tracer_flags", "tracer_uid_separated",
		"agent_argv", "agent_uid", "env", "network", "container_workspace", "start_tarball_sha256",
		"observer_source_sha256", "timeout_seconds"}
	doneLaunchReceiptFields = []string{"schema_version", "claim_id", "invocation_id", "producer",
		"witnessScope", "launch_sha256", "trace_expression", "watch_list", "start_tarball_sha256",
		"tree_sha256", "coverage", "container_exit", "agent_exit", "timed_out", "transcript_sha256",
		"trace_sha256", "observation_sha256", "capability_sha256", "sensors", "doesNotAssert"}
)

// doneInvalid is a receipt or statement that disagrees with the records it names.
type doneInvalid struct{ code string }

func (e *doneInvalid) Error() string { return e.code }

func invalid(code string) error { return &doneInvalid{code} }

func doneEqual(a, b any) bool { return reflect.DeepEqual(a, b) }

// --- statements -----------------------------------------------------------------------------

func doneStatementOf(data []byte, expectedType, prefix string) (doneObject, error) {
	value, err := doneStrictJSON(data, prefix)
	if err == nil {
		var statement doneObject
		statement, err = doneFields(value, prefix, []string{"_type", "subject", "predicateType", "predicate"})
		if err == nil {
			return doneStatementChecks(statement, expectedType, prefix)
		}
	}
	return nil, invalid(err.(*doneError).code)
}

func doneStatementChecks(statement doneObject, expectedType, prefix string) (doneObject, error) {
	if statement["_type"] != doneStatement {
		return nil, invalid(prefix + "_type_wrong")
	}
	if statement["predicateType"] != expectedType {
		return nil, invalid(prefix + "_predicate_type_wrong")
	}
	subject, ok := statement["subject"].([]any)
	if !ok || len(subject) != 1 {
		return nil, invalid(prefix + "_subject_malformed")
	}
	entry, ok := subject[0].(doneObject)
	if !ok || len(entry) != 2 {
		return nil, invalid(prefix + "_subject_malformed")
	}
	name, _ := entry["name"].(string)
	digest, _ := entry["digest"].(doneObject)
	value, _ := digest["sha256"].(string)
	if name == "" || len(digest) != 1 || !doneHex64.MatchString(value) {
		return nil, invalid(prefix + "_subject_malformed")
	}
	return statement, nil
}

func doneSubjectDigest(statement doneObject) string {
	entry := statement["subject"].([]any)[0].(doneObject)
	return entry["digest"].(doneObject)["sha256"].(string)
}

func doneJudgeContract(member string) (map[string]any, error) {
	statementBytes, err := doneMemberFile(member, "statement.json", "member_unreadable")
	if err != nil {
		return nil, err
	}
	contractBytes, err := doneMemberFile(member, "contract.json", "member_unreadable")
	if err != nil {
		return nil, err
	}
	if statementBytes == nil || contractBytes == nil {
		return nil, refuse("member_incomplete")
	}
	verdict := func(code string) (map[string]any, error) {
		return map[string]any{"verdict": "invalid", "code": code}, nil
	}
	statement, err := doneStatementOf(statementBytes, doneContractType, "statement")
	if err != nil {
		return verdict(err.Error())
	}
	record, err := doneContract(contractBytes)
	if err != nil {
		return verdict(err.Error())
	}
	if doneSubjectDigest(statement) != sha(contractBytes) {
		return verdict("statement_subject_unbound")
	}
	if !doneEqual(statement["predicate"], record) {
		return verdict("statement_predicate_differs")
	}
	return map[string]any{"verdict": "valid"}, nil
}

// --- launch records ----------------------------------------------------------------------------

func doneLaunch(data []byte) error {
	value, err := doneStrictJSON(data, "launch")
	if err != nil {
		return err
	}
	record, err := doneFields(value, "launch", doneLaunchFields)
	if err != nil {
		return err
	}
	if record["schema_version"] != "probity-launch/v1" {
		return refuse("launch_schema_unsupported")
	}
	if _, err = doneChoice(record["backend"], "launch_backend", "docker", "apptainer"); err != nil {
		return err
	}
	for _, key := range []string{"image", "image_id", "runtime_version", "strace_version", "trace_expression", "container_workspace"} {
		if _, err = doneText(record[key], "launch_"+key); err != nil {
			return err
		}
	}
	for _, key := range []string{"container_argv", "tracer_flags", "agent_argv"} {
		if _, err = doneArgv(record[key], "launch_"+key); err != nil {
			return err
		}
	}
	_, uidSeparated := record["tracer_uid_separated"].(bool)
	_, network := record["network"].(bool)
	_, uid := doneInteger(record["agent_uid"])
	_, timeout := doneInteger(record["timeout_seconds"])
	_, env := record["env"].(doneObject)
	if !uidSeparated || !network || !uid || !timeout || !env {
		return refuse("launch_types")
	}
	for _, key := range []string{"start_tarball_sha256", "observer_source_sha256"} {
		if _, err = doneDigest(record[key], "launch_digest_malformed"); err != nil {
			return err
		}
	}
	return nil
}

func doneEffect(item any) error {
	effect, err := doneFields(item, "launch_receipt_effect", []string{"type", "time"}, "paths", "address")
	if err != nil {
		return err
	}
	if _, err = doneText(effect["type"], "launch_receipt_effect"); err != nil {
		return err
	}
	if _, err = doneInstantOf(effect["time"], "launch_receipt_effect"); err != nil {
		return err
	}
	paths, hasPaths := effect["paths"]
	address, hasAddress := effect["address"]
	if hasPaths == hasAddress {
		return refuse("launch_receipt_effect")
	}
	if hasPaths {
		list, ok := paths.([]any)
		if !ok || len(list) == 0 {
			return refuse("launch_receipt_effect")
		}
		for _, p := range list {
			if text, ok := p.(string); !ok || text == "" {
				return refuse("launch_receipt_effect")
			}
		}
	}
	if hasAddress {
		_, err = doneText(address, "launch_receipt_effect")
	}
	return err
}

func doneSensors(value any) (doneObject, error) {
	found, err := doneFields(value, "launch_receipt_sensors", []string{"s1_inotify", "s2_strace", "s3_tree", "join", "external_effects"})
	if err != nil {
		return nil, err
	}
	_, a := found["s1_inotify"].(doneObject)
	strace, b := found["s2_strace"].(doneObject)
	_, c := found["join"].(doneObject)
	if !a || !b || !c {
		return nil, refuse("launch_receipt_sensors")
	}
	if _, err = doneChoice(strace["tracer"], "launch_receipt_sensors", "complete", "lost"); err != nil {
		return nil, err
	}
	tree, err := doneFields(found["s3_tree"], "launch_receipt_sensors", []string{"tree_sha256"}, "files", "symlinks", "special")
	if err != nil {
		return nil, err
	}
	if _, err = doneDigest(tree["tree_sha256"], "launch_receipt_sensors"); err != nil {
		return nil, err
	}
	effects, ok := found["external_effects"].([]any)
	if !ok {
		return nil, refuse("launch_receipt_sensors")
	}
	for _, item := range effects {
		if err = doneEffect(item); err != nil {
			return nil, err
		}
	}
	return found, nil
}

func doneLaunchReceipt(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "launch_receipt")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "launch_receipt", doneLaunchReceiptFields)
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-launch-receipt/v1" {
		return nil, refuse("launch_receipt_schema_unsupported")
	}
	for _, key := range []string{"claim_id", "invocation_id", "producer"} {
		if _, err = doneText(record[key], "launch_receipt_"+key); err != nil {
			return nil, err
		}
	}
	if _, err = doneChoice(record["witnessScope"], "launch_receipt_witness_scope", "PEER", "EXTERNAL"); err != nil {
		return nil, err
	}
	if _, err = doneChoice(record["coverage"], "launch_receipt_coverage", "complete", "incomplete", "unknown"); err != nil {
		return nil, err
	}
	for _, key := range []string{"launch_sha256", "start_tarball_sha256", "tree_sha256", "transcript_sha256", "trace_sha256", "observation_sha256", "capability_sha256"} {
		if _, err = doneDigest(record[key], "launch_receipt_digest_malformed"); err != nil {
			return nil, err
		}
	}
	_, timedOut := record["timed_out"].(bool)
	_, watch := record["watch_list"].([]any)
	if !timedOut || !watch {
		return nil, refuse("launch_receipt_types")
	}
	for _, key := range []string{"container_exit", "agent_exit"} {
		if v := record[key]; v != nil {
			if _, ok := doneInteger(v); !ok {
				return nil, refuse("launch_receipt_types")
			}
		}
	}
	sensors, err := doneSensors(record["sensors"])
	if err != nil {
		return nil, err
	}
	record["sensors"] = sensors
	return record, nil
}

func doneExternalEffects(member string) ([]any, error) {
	data, err := doneMemberFile(member, doneRoleFiles["launch_receipt"], "member_unreadable")
	if err != nil || data == nil {
		return []any{}, err
	}
	record, err := doneLaunchReceipt(data)
	if err != nil {
		return nil, err
	}
	return record["sensors"].(doneObject)["external_effects"].([]any), nil
}

// --- the done-receipt statement ---------------------------------------------------------------------

func donePredicate(statement doneObject) (doneObject, error) {
	predicate, err := doneFields(statement["predicate"], "receipt_predicate",
		[]string{"schema_version", "claim_id", "invocation_id", "records", "checks", "verdict", "external_effects", "verifier"},
		"policy", "verifier_isolation", "stop_decision")
	if err != nil {
		return nil, invalid(err.(*doneError).code)
	}
	if predicate["schema_version"] != doneReceiptShape {
		return nil, invalid("receipt_schema_unsupported")
	}
	for _, key := range []string{"claim_id", "invocation_id"} {
		if text, ok := predicate[key].(string); !ok || text == "" {
			return nil, invalid("receipt_predicate_malformed")
		}
	}
	verifier, ok := predicate["verifier"].(doneObject)
	identity, _ := verifier["id"].(string)
	if !ok || len(verifier) != 1 || !doneVerifierID.MatchString(identity) {
		return nil, invalid("receipt_verifier_malformed")
	}
	if policy, present := predicate["policy"]; present {
		table, ok := policy.(doneObject)
		digest, _ := table["table_sha256"].(string)
		if !ok || len(table) != 1 || !doneHex64.MatchString(digest) {
			return nil, invalid("receipt_predicate_malformed")
		}
	}
	return predicate, doneOptionalBlocks(predicate)
}

func doneOptionalBlocks(predicate doneObject) error {
	if report, present := predicate["verifier_isolation"]; present {
		object, ok := report.(doneObject)
		if _, text := object["contract_sha256"].(string); !ok || !text {
			return invalid("receipt_isolation_malformed")
		}
	}
	if stop, present := predicate["stop_decision"]; present {
		object, ok := stop.(doneObject)
		action, _ := object["action"].(string)
		reason, _ := object["reason"].(string)
		if !ok || len(object) != 2 || !doneStopActions[action] || reason == "" {
			return invalid("receipt_stop_decision_malformed")
		}
	}
	return nil
}

func doneRecordDigests(records any) (map[string]string, error) {
	object, ok := records.(doneObject)
	digests := map[string]string{}
	if ok {
		for role, item := range object {
			entry, isObject := item.(doneObject)
			value, _ := entry["sha256"].(string)
			if !isObject || len(entry) != 1 || !doneHex64.MatchString(value) {
				ok = false
				break
			}
			digests[role] = value
		}
	}
	core := len(digests) == len(doneCoreRoles)
	full := len(digests) == len(doneCoreRoles)+len(doneLaunchRoles)
	if ok && (core || full) {
		for _, role := range doneCoreRoles {
			if _, present := digests[role]; !present {
				ok = false
			}
		}
		for _, role := range doneLaunchRoles {
			if _, present := digests[role]; present != full {
				ok = false
			}
		}
	} else {
		ok = false
	}
	if !ok {
		return nil, invalid("receipt_records_shape")
	}
	return digests, nil
}

func doneReadRoles(member string, digests map[string]string) (map[string][]byte, error) {
	data := map[string][]byte{}
	roles := make([]string, 0, len(digests))
	for role := range digests {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		found, err := doneMemberFile(member, doneRoleFiles[role], "member_unreadable")
		if err != nil {
			return nil, err
		}
		if found == nil {
			return nil, invalid("receipt_record_missing")
		}
		if sha(found) != digests[role] {
			return nil, invalid("receipt_record_digest_mismatch")
		}
		data[role] = found
	}
	return data, nil
}

func doneSensorsLost(sensors doneObject) bool {
	inotify, _ := sensors["s1_inotify"].(doneObject)
	strace, _ := sensors["s2_strace"].(doneObject)
	join, _ := sensors["join"].(doneObject)
	truthy := func(v any) bool {
		switch t := v.(type) {
		case nil:
			return false
		case bool:
			return t
		case string:
			return t != ""
		case []any:
			return len(t) > 0
		case json.Number:
			return t.String() != "0"
		}
		return true
	}
	return strace["tracer"] == "lost" || truthy(inotify["overflow"]) || truthy(inotify["watch_failures"]) ||
		truthy(strace["escapes"]) || truthy(strace["unresolved"]) || truthy(strace["unparsed_lines"]) ||
		truthy(join["unattributed"])
}

func doneLaunchBound(data map[string][]byte, tree, observation doneObject, claimID, invocation string) error {
	if err := doneLaunch(data["launch"]); err != nil {
		return err
	}
	launched, err := doneLaunchReceipt(data["launch_receipt"])
	if err != nil {
		return err
	}
	sensors := launched["sensors"].(doneObject)
	switch {
	case launched["claim_id"] != claimID || launched["invocation_id"] != invocation:
		return invalid("receipt_launch_context_mismatch")
	case launched["launch_sha256"] != sha(data["launch"]):
		return invalid("receipt_launch_digest_unbound")
	}
	for _, role := range []string{"observation", "capability", "tree"} {
		if launched[role+"_sha256"] != sha(data[role]) {
			return invalid("receipt_launch_records_unbound")
		}
	}
	switch {
	case sensors["s3_tree"].(doneObject)["tree_sha256"] != tree["tree_sha256"]:
		return invalid("receipt_launch_tree_unbound")
	case launched["witnessScope"] != tree["witness_scope"] || launched["witnessScope"] != observation["witness_scope"]:
		return invalid("receipt_launch_scope_differs")
	case launched["coverage"] != observation["coverage"]:
		return invalid("receipt_launch_coverage_differs")
	case doneSensorsLost(sensors) && observation["coverage"] == "complete":
		return invalid("receipt_launch_coverage_overstated")
	}
	return nil
}

func doneRecomputed(member string) ([]doneVerdict, error) {
	out := make([]doneVerdict, 0, len(doneClaimTypes))
	for _, claimType := range doneClaimTypes {
		verdict, err := doneRunCheck(claimType, member)
		if err != nil {
			return nil, err
		}
		out = append(out, verdict)
	}
	return out, nil
}

func doneCompareChecks(carried any, computed []doneVerdict) error {
	list, ok := carried.([]any)
	if !ok {
		return invalid("receipt_predicate_malformed")
	}
	expected := make([]any, 0, len(computed))
	for _, item := range computed {
		row := map[string]any{"claim_type": item["claim_type"]}
		for k, v := range doneProjection(item) {
			row[k] = v
		}
		expected = append(expected, row)
	}
	if !doneEqual(normalize(list), normalize(expected)) {
		return invalid("receipt_check_not_recomputed")
	}
	return nil
}

// normalize re-encodes a value so decoded and constructed JSON compare alike.
func normalize(value any) any {
	raw, _ := json.Marshal(value)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// doneReceiptPrelude reads the receipt statement, its predicate, the record digests it lists
// and the records those digests name. Every error it returns is reported as a receipt verdict.
func doneReceiptPrelude(member string, data []byte) (statement, predicate doneObject, raw map[string][]byte, err error) {
	if statement, err = doneStatementOf(data, doneReceiptType, "receipt"); err != nil {
		return nil, nil, nil, err
	}
	if predicate, err = donePredicate(statement); err != nil {
		return nil, nil, nil, err
	}
	digests, err := doneRecordDigests(predicate["records"])
	if err != nil {
		return nil, nil, nil, err
	}
	if report, present := predicate["verifier_isolation"]; present &&
		report.(doneObject)["contract_sha256"] != digests["contract"] {
		return nil, nil, nil, invalid("receipt_isolation_contract_differs")
	}
	if raw, err = doneReadRoles(member, digests); err != nil {
		return nil, nil, nil, err
	}
	return statement, predicate, raw, nil
}

func doneJudgeReceipt(member string) (map[string]any, error) {
	data, err := doneMemberFile(member, "receipt.json", "member_unreadable")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, refuse("member_incomplete")
	}
	out := map[string]any{}
	fail := func(err error) (map[string]any, error) {
		var bad *doneInvalid
		if errors.As(err, &bad) {
			out["receipt"] = map[string]any{"verdict": "invalid", "code": bad.code}
			return out, nil
		}
		return nil, err
	}
	statement, predicate, raw, err := doneReceiptPrelude(member, data)
	if err != nil {
		return fail(err)
	}
	tree, err := doneTree(raw["tree"])
	if err != nil {
		return nil, err
	}
	observation, err := doneObservation(raw["observation"])
	if err != nil {
		return nil, err
	}
	if doneSubjectDigest(statement) != tree["tree_sha256"] {
		return fail(invalid("receipt_subject_unbound"))
	}
	if _, present := raw["launch"]; present {
		if err = doneLaunchBound(raw, tree, observation, predicate["claim_id"].(string), predicate["invocation_id"].(string)); err != nil {
			return fail(err)
		}
	}
	effects, err := doneExternalEffects(member)
	if err != nil {
		return nil, err
	}
	if !doneEqual(normalize(predicate["external_effects"]), normalize(effects)) {
		return fail(invalid("receipt_external_effects_differ"))
	}
	computed, err := doneRecomputed(member)
	if err != nil {
		return nil, err
	}
	rows := map[string]any{}
	for _, item := range computed {
		rows[item["claim_type"].(string)] = doneProjection(item)
	}
	out["checks"], out["done"] = rows, doneCombine(computed, effects)
	if err = doneCompareChecks(predicate["checks"], computed); err != nil {
		return fail(err)
	}
	if !doneEqual(normalize(predicate["verdict"]), normalize(out["done"])) {
		return fail(invalid("receipt_verdict_not_derived"))
	}
	out["receipt"] = map[string]any{"verdict": "valid"}
	return out, nil
}

// --- one member --------------------------------------------------------------------------------

func doneJudgeChecks(member string, declared []string) (map[string]any, error) {
	results := map[string]doneVerdict{}
	rows := map[string]any{}
	for _, claimType := range declared {
		verdict, err := doneRunCheck(claimType, member)
		if err != nil {
			return nil, err
		}
		results[claimType] = verdict
		rows[claimType] = doneProjection(verdict)
	}
	out := map[string]any{"checks": rows}
	if len(declared) == len(doneClaimTypes) {
		ordered := make([]doneVerdict, 0, len(doneClaimTypes))
		for _, claimType := range doneClaimTypes {
			ordered = append(ordered, results[claimType])
		}
		effects, err := doneExternalEffects(member)
		if err != nil {
			return nil, err
		}
		out["done"] = doneCombine(ordered, effects)
	}
	return out, nil
}

func doneJudgeMember(suite, member string, declared []string) map[string]any {
	var out map[string]any
	var err error
	switch {
	case suite == doneContractSuite:
		var verdict map[string]any
		if verdict, err = doneJudgeContract(member); err == nil {
			out = map[string]any{"contract": verdict}
		}
	case doneExists(member, "receipt.json"):
		out, err = doneJudgeReceipt(member)
	default:
		out, err = doneJudgeChecks(member, declared)
	}
	var refused *doneError
	if errors.As(err, &refused) {
		return map[string]any{"refused": refused.code}
	}
	if err != nil {
		return map[string]any{"refused": "member_unreadable"}
	}
	return out
}

func doneExists(dir, name string) bool { return existsIn(dir, name) }

// --- corpus ------------------------------------------------------------------------------------

type doneVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Kind     string            `json:"kind"`
	Files    map[string]string `json:"files"`
	Checks   []string          `json:"checks"`
	Expected map[string]any    `json:"expected"`
}

func (r doneReader) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v doneVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Kind}
		member.Findings = r.judgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (r doneReader) judgeMember(caseDir string, v doneVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	got := doneJudgeMember(r.suite, caseDir, v.Checks)
	if !doneEqual(normalize(got), normalize(v.Expected)) {
		declared, _ := json.Marshal(v.Expected)
		derived, _ := json.Marshal(got)
		findings = append(findings, fmt.Sprintf("derived %s, the manifest declares %s", derived, declared))
	}
	return findings
}
