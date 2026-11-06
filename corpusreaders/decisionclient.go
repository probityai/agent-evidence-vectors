package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

func init() { register(decisionClient{}) }

// decisionClient judges corpora/vectors-decision-client-failure-modes/. Each
// member is one decision client's record of one decision: the request it asked
// about, its configured mode and timeout, the facts of its exchange with the
// decision point (reached or not, timed out or not, the HTTP status, whether the
// body was a JSON object and the verdict it carried), the condition it recorded,
// the decision it took with its basis, and whether the action was performed. The
// reader derives each member's decision with the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the decision-client-failure-modes contract:
//     contract_id_unknown;
//  3. every required member is present with a value from its vocabulary, and a
//     reply that arrived carries a status while one that did not carries none:
//     record_malformed;
//  4. the recorded condition is the one the exchange facts give:
//     condition_misclassified;
//  5. a fault condition is recorded on a fallback basis:
//     fault_recorded_as_policy;
//  6. a fault condition never allows the action: fault_allowed;
//  7. on a readable verdict the decision follows it on a policy basis: allow
//     allows, block and halt deny: verdict_not_followed;
//  8. a halt verdict is recorded as halted, and nothing else is:
//     halt_not_honoured;
//  9. an action the client denied was not performed: effect_on_deny.
//
// The condition the exchange gives: unreachable when the point was not reached,
// timeout when no reply came inside the timeout, unauthorized on HTTP 401 or
// 403, http-error on any other status outside 200-299, unparseable-body when the
// body is not a JSON object, missing-verdict when it carries no verdict member,
// unknown-verdict when the verdict is not allow, block or halt, and ok
// otherwise. Every condition but ok is a fault.
//
// The reader also recomputes each member's retained action, condition, mode,
// outcome and performed flag.
type decisionClient struct{}

const dcContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/decision-client-failure-modes"

func (decisionClient) Suite() string { return "decision-client-failure-modes/v1" }

type dcRetained struct {
	Action    string `json:"action"`
	Condition string `json:"condition"`
	Mode      string `json:"mode"`
	Outcome   string `json:"outcome"`
	Performed bool   `json:"performed"`
}

type dcVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained dcRetained        `json:"retained"`
}

func (decisionClient) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v dcVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = dcJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func dcJudgeMember(caseDir string, v dcVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, fmt.Sprintf("record.json cannot be read: %v", err))
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, fmt.Sprintf("record.json does not parse: %v", err))
	}
	record, isObject := value.(map[string]any)
	if !isObject {
		return append(findings, "record.json is not a JSON object")
	}
	if kept, ok := dcRetain(record); !ok || kept != v.Retained {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := dcDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// dcObject returns the member key of m when it is a JSON object.
func dcObject(m map[string]any, key string) (map[string]any, bool) {
	value, ok := m[key].(map[string]any)
	return value, ok
}

func dcString(m map[string]any, key string) (string, bool) {
	value, ok := m[key].(string)
	return value, ok
}

func dcBool(m map[string]any, key string) (bool, bool) {
	value, ok := m[key].(bool)
	return value, ok
}

// dcInt reads an integer the way Python's json module does: a number written
// without a fraction or an exponent.
func dcInt(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(number.String(), ".eE") {
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil
}

func dcPositive(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Float64()
	return err == nil && parsed > 0
}

func dcOneOf(value string, ok bool, allowed ...string) bool {
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// dcParts returns the record's five required objects, or false when one is
// absent or not an object.
func dcParts(r map[string]any) (request, client, exchange, decision, effect map[string]any, ok bool) {
	var okR, okC, okX, okD, okE bool
	request, okR = dcObject(r, "request")
	client, okC = dcObject(r, "client")
	exchange, okX = dcObject(r, "exchange")
	decision, okD = dcObject(r, "decision")
	effect, okE = dcObject(r, "effect")
	return request, client, exchange, decision, effect, okR && okC && okX && okD && okE
}

func dcMalformed(r map[string]any) bool {
	request, client, exchange, decision, effect, ok := dcParts(r)
	if !ok {
		return true
	}
	action, okAction := dcString(request, "action")
	digest, okDigest := dcString(request, "argsDigest")
	mode, okMode := dcString(client, "mode")
	_, okReached := dcBool(exchange, "reached")
	_, okTimedOut := dcBool(exchange, "timedOut")
	_, okBody := dcBool(exchange, "bodyIsJsonObject")
	status, hasStatus := exchange["httpStatus"]
	_, statusIsInt := dcInt(status)
	verdictValue, hasVerdict := exchange["verdict"]
	_, verdictIsString := verdictValue.(string)
	outcome, okOutcome := dcString(decision, "outcome")
	basis, okBasis := dcString(decision, "basis")
	condition, okCondition := dcString(decision, "condition")
	_, okHalted := dcBool(decision, "halted")
	_, okPerformed := dcBool(effect, "performed")
	timeout, hasTimeout := client["timeoutMillis"]
	checks := []bool{
		okAction && action != "",
		okDigest && strings.HasPrefix(digest, "sha256:"),
		dcOneOf(mode, okMode, "default", "strict"),
		hasTimeout && dcPositive(timeout),
		okReached, okTimedOut,
		hasStatus && (status == nil || statusIsInt),
		okBody,
		!hasVerdict || verdictIsString,
		dcOneOf(outcome, okOutcome, "allow", "deny"),
		dcOneOf(basis, okBasis, "policy", "fallback"),
		dcOneOf(condition, okCondition, "ok", "unreachable", "timeout", "unauthorized",
			"http-error", "unparseable-body", "missing-verdict", "unknown-verdict"),
		okHalted, okPerformed,
	}
	for _, check := range checks {
		if !check {
			return true
		}
	}
	// A reply that arrived carries a status; one that did not carries none.
	reached, _ := dcBool(exchange, "reached")
	timedOut, _ := dcBool(exchange, "timedOut")
	return (reached && !timedOut) != (status != nil)
}

// dcCondition is the condition the exchange facts give, in the contract's
// order. It is false when a fact it needs is absent or of the wrong type.
func dcCondition(exchange map[string]any) (string, bool) {
	reached, ok := dcBool(exchange, "reached")
	if !ok {
		return "", false
	}
	if !reached {
		return "unreachable", true
	}
	timedOut, ok := dcBool(exchange, "timedOut")
	if !ok {
		return "", false
	}
	if timedOut {
		return "timeout", true
	}
	status, ok := dcInt(exchange["httpStatus"])
	if !ok {
		return "", false
	}
	switch {
	case status == 401 || status == 403:
		return "unauthorized", true
	case status < 200 || status > 299:
		return "http-error", true
	}
	parsed, ok := dcBool(exchange, "bodyIsJsonObject")
	if !ok {
		return "", false
	}
	if !parsed {
		return "unparseable-body", true
	}
	verdictValue, present := exchange["verdict"]
	if !present {
		return "missing-verdict", true
	}
	verdict, _ := verdictValue.(string)
	if !dcOneOf(verdict, true, "allow", "block", "halt") {
		return "unknown-verdict", true
	}
	return "ok", true
}

func dcRetain(r map[string]any) (dcRetained, bool) {
	request, client, exchange, decision, effect, ok := dcParts(r)
	if !ok {
		return dcRetained{}, false
	}
	action, okAction := dcString(request, "action")
	condition, okCondition := dcCondition(exchange)
	mode, okMode := dcString(client, "mode")
	outcome, okOutcome := dcString(decision, "outcome")
	performed, okPerformed := dcBool(effect, "performed")
	return dcRetained{Action: action, Condition: condition, Mode: mode, Outcome: outcome,
		Performed: performed}, okAction && okCondition && okMode && okOutcome && okPerformed
}

func dcDecide(r map[string]any) scDecision {
	contract, hasContract := r["contractId"]
	if !hasContract {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id, ok := contract.(string); !ok || id != dcContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	if dcMalformed(r) {
		return scDecision{"deny", "record_malformed"}
	}
	// Well formed from here on: every member below is present and typed.
	_, _, exchange, decision, effect, _ := dcParts(r)
	condition, _ := dcString(decision, "condition")
	outcome, _ := dcString(decision, "outcome")
	basis, _ := dcString(decision, "basis")
	halted, _ := dcBool(decision, "halted")
	performed, _ := dcBool(effect, "performed")
	verdict, _ := exchange["verdict"].(string)
	derived, _ := dcCondition(exchange)
	fault := condition != "ok"
	wanted := "deny"
	if verdict == "allow" {
		wanted = "allow"
	}
	halt := condition == "ok" && verdict == "halt"
	checks := []struct {
		reason string
		fails  bool
	}{
		{"condition_misclassified", condition != derived},
		{"fault_recorded_as_policy", fault && basis != "fallback"},
		{"fault_allowed", fault && outcome != "deny"},
		{"verdict_not_followed", !fault && (outcome != wanted || basis != "policy")},
		{"halt_not_honoured", halted != halt},
		{"effect_on_deny", outcome == "deny" && performed},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "decision_sound"}
}
