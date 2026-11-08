package corpusreaders

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

func init() { register(durableHistory{}) }

// durableHistory judges corpora/vectors-durable-history/. Each member is one
// record: what the operator exported of a durable workflow run, and the permits
// and effects witnessed at execution time outside the operator's worker. The
// reader derives each member's decision with the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the durable-history contract: contract_id_unknown;
//  3. the record has the fields and types the contract names: malformed_record;
//  4. the witnessed run was not reset before a witnessed event, and no fork of it
//     is offered in its place: history_reset;
//  5. the export holds the witnessed run: witnessed_run_missing_from_history;
//  6. every run's event ids run 1..n, it opens with its one start event, and
//     each activity is scheduled once and closed at most once, after its
//     schedule: event_sequence_broken;
//  7. every encrypted payload of a witnessed activity is the witnessed
//     ciphertext: encrypted_payload_differs_from_witnessed;
//  8. each permitted activity is scheduled with the permitted tool, call and
//     arguments: history_args_differ_from_permitted;
//  9. the model's recorded request is the witnessed one:
//     model_request_differs_from_witnessed;
//  10. each recorded result is the witnessed one:
//     history_result_differs_from_witnessed;
//  11. every permit names the measured tool code: tool_code_changed;
//  12. every completed attempt of a gated tool has a permit: activity_unwitnessed;
//  13. every permitted activity, and every applied effect's completion, is in
//     the history: witnessed_effect_missing;
//  14. no Update id is accepted twice: update_applied_twice;
//  15. no uncertain attempt is recorded as completed unless the system of record
//     settled it as applied: lost_reply_settled_without_evidence.
type durableHistory struct{}

const (
	dhContractID = "https://probityai.github.io/agent-evidence-vectors/contract/durable-history/v1"
	dhPlain      = "json/plain"
	dhEncrypted  = "binary/encrypted"
	dhModel      = "model_request"
	dhTool       = "tool:"
	dhStarted    = "WorkflowExecutionStarted"
	dhScheduled  = "ActivityTaskScheduled"
	dhCompleted  = "ActivityTaskCompleted"
	dhTimedOut   = "ActivityTaskTimedOut"
	dhUpdate     = "WorkflowExecutionUpdateAccepted"
	dhReset      = "WorkflowExecutionReset"
	dhUncertain  = "uncertain"
	dhApplied    = "applied"
)

var dhDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (durableHistory) Suite() string { return "durable-history/v1" }

func (durableHistory) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v drVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = dhJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func dhJudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read: "+err.Error())
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "record.json does not parse: "+err.Error())
	}
	record, isMap := value.(map[string]any)
	if !isMap {
		return append(findings, "record.json is not an object")
	}
	got := dhDecide(record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// ------------------------------------------------------------- the parsed record

type dhPayload struct {
	encrypted bool
	data      any
	cipher    []byte
}

type dhCall struct {
	callID, tool string
	args         any
}

type dhEvent struct {
	id                       int64
	kind                     string
	activityID, activityType string
	input, result            *dhPayload
	scheduledAt, attempt     int64
	updateID                 string
	resetPoint               int64
	inputCall                *dhCall
	toolCalls                []dhCall
}

type dhRun struct {
	events               []*dhEvent
	workflowID, runID    string
	hasReset             bool
	resetBase            string
	resetPoint           int64
	scheduled            map[string]*dhEvent
	closes               map[string][]*dhEvent
	modelResultsReadable bool
}

type dhPermit struct {
	permitID, callID, activityID, tool, modelActivityID string
	argsDigest, modelArgsDigest, toolCodeDigest         string
	inputCipher, modelCipher                            *string
	attempt                                             int64
}

type dhSettlement struct {
	source, outcome string
	resultDigest    *string
}

type dhEffect struct {
	permitID, outcome          string
	resultDigest, resultCipher *string
	settlement                 *dhSettlement
}

type dhRecord struct {
	runs                  []*dhRun
	workflowID, runID     string
	expectedCode          string
	gated                 []string
	permits               []dhPermit
	effects               []dhEffect
}

// dhDecide mirrors the Python reader: the contract checks, then the structural
// check, then the history checks in order.
func dhDecide(record map[string]any) scDecision {
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != dhContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	p, ok := dhParse(record)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	checks := []struct {
		reason string
		fails  func(*dhRecord) bool
	}{
		{"history_reset", dhResetFails},
		{"witnessed_run_missing_from_history", func(r *dhRecord) bool { return len(r.copies()) == 0 }},
		{"event_sequence_broken", func(r *dhRecord) bool { return slices.ContainsFunc(r.runs, dhSequenceBroken) }},
		{"encrypted_payload_differs_from_witnessed", dhEncryptedDiffers},
		{"history_args_differ_from_permitted", dhArgsDiffer},
		{"model_request_differs_from_witnessed", dhModelDiffers},
		{"history_result_differs_from_witnessed", dhResultDiffers},
		{"tool_code_changed", dhCodeChanged},
		{"activity_unwitnessed", dhUnwitnessed},
		{"witnessed_effect_missing", dhEffectMissing},
		{"update_applied_twice", dhUpdateTwice},
		{"lost_reply_settled_without_evidence", dhLostReply},
	}
	for _, check := range checks {
		if check.fails(p) {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "consistent"}
}

// ------------------------------------------------------------- value helpers

func dhText(m map[string]any, key string) (string, bool) {
	value, ok := m[key].(string)
	return value, ok && value != ""
}

func dhInt(value any, low int64) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	parsed, ok := new(big.Int).SetString(n.String(), 10)
	if !ok || !parsed.IsInt64() || parsed.Int64() < low {
		return 0, false
	}
	return parsed.Int64(), true
}

func dhIsDigest(value any) bool {
	text, ok := value.(string)
	return ok && dhDigestPattern.MatchString(text)
}

func dhIsTime(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339, text)
	return err == nil
}

// dhOptionalDigest reads a member that is absent or a digest.
func dhOptionalDigest(m map[string]any, key string) (*string, bool) {
	value, present := m[key]
	if !present {
		return nil, true
	}
	if !dhIsDigest(value) {
		return nil, false
	}
	text := value.(string)
	return &text, true
}

// dhNullableDigest reads a member that is absent, null or a digest.
func dhNullableDigest(m map[string]any, key string) (*string, bool) {
	if m[key] == nil {
		return nil, true
	}
	return dhOptionalDigest(m, key)
}

func dhValueDigest(value any) (string, bool) {
	body, err := pythonCompactJSONOpts(value, pyEncodeOpts{EnsureASCII: false})
	if err != nil {
		return "", false
	}
	return "sha256:" + sha(body), true
}

// dhDigestIs reports whether value's digest is want; an unencodable value never is.
func dhDigestIs(value any, want *string) bool {
	got, ok := dhValueDigest(value)
	return ok && want != nil && got == *want
}

// ------------------------------------------------------------- structure

func dhParsePayload(value any) (*dhPayload, bool) {
	m, isMap := value.(map[string]any)
	if !isMap {
		return nil, false
	}
	data, present := m["data"]
	if !present {
		return nil, false
	}
	switch m["encoding"] {
	case dhPlain:
		return &dhPayload{data: data}, true
	case dhEncrypted:
		if _, ok := dhText(m, "keyId"); !ok {
			return nil, false
		}
		text, isText := data.(string)
		if !isText {
			return nil, false
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil {
			return nil, false
		}
		return &dhPayload{encrypted: true, data: data, cipher: raw}, true
	}
	return nil, false
}

func dhParseCall(value any) (dhCall, bool) {
	m, isMap := value.(map[string]any)
	if !isMap {
		return dhCall{}, false
	}
	call, okCall := dhText(m, "callId")
	tool, okTool := dhText(m, "tool")
	_, isArgs := m["args"].(map[string]any)
	return dhCall{callID: call, tool: tool, args: m["args"]}, okCall && okTool && isArgs
}

func dhParseScheduled(e *dhEvent, attrs map[string]any) bool {
	var okID, okType, okInput bool
	e.activityID, okID = dhText(attrs, "activityId")
	e.activityType, okType = dhText(attrs, "activityType")
	e.input, okInput = dhParsePayload(attrs["input"])
	if !okID || !okType || !okInput {
		return false
	}
	if e.input.encrypted || !strings.HasPrefix(e.activityType, dhTool) {
		return true
	}
	data, isMap := e.input.data.(map[string]any)
	if !isMap {
		return false
	}
	call, okCall := dhText(data, "callId")
	if _, isArgs := data["args"].(map[string]any); !okCall || !isArgs {
		return false
	}
	e.inputCall = &dhCall{callID: call, args: data["args"]}
	return true
}

func dhParseClose(e *dhEvent, attrs map[string]any) bool {
	var okAt, okAttempt bool
	e.scheduledAt, okAt = dhInt(attrs["scheduledEventId"], 1)
	e.attempt, okAttempt = dhInt(attrs["attempt"], 1)
	if !okAt || !okAttempt {
		return false
	}
	if e.kind == dhTimedOut {
		return true
	}
	var okResult bool
	e.result, okResult = dhParsePayload(attrs["result"])
	return okResult
}

func dhParseAttributes(e *dhEvent, attrs map[string]any) bool {
	var ok bool
	switch e.kind {
	case dhStarted:
		return dhStartedOK(attrs)
	case dhScheduled:
		return dhParseScheduled(e, attrs)
	case dhCompleted, dhTimedOut:
		return dhParseClose(e, attrs)
	case dhUpdate:
		e.updateID, ok = dhText(attrs, "updateId")
		return ok
	case dhReset:
		_, okRun := dhText(attrs, "newRunId")
		e.resetPoint, ok = dhInt(attrs["resetEventId"], 1)
		return okRun && ok
	}
	return true
}

func dhStartedOK(attrs map[string]any) bool {
	_, okWorkflow := dhText(attrs, "workflowId")
	_, okRun := dhText(attrs, "runId")
	if !okWorkflow || !okRun {
		return false
	}
	if attrs["resetFrom"] == nil {
		return true
	}
	reset, isMap := attrs["resetFrom"].(map[string]any)
	if !isMap {
		return false
	}
	_, okBase := dhText(reset, "baseRunId")
	_, okPoint := dhInt(reset["resetEventId"], 1)
	return okBase && okPoint
}

func dhParseEvent(value any) (*dhEvent, map[string]any, bool) {
	m, isMap := value.(map[string]any)
	if !isMap {
		return nil, nil, false
	}
	e := &dhEvent{}
	var okID, okKind bool
	e.id, okID = dhInt(m["eventId"], 0)
	e.kind, okKind = dhText(m, "eventType")
	attrs, isAttrs := m["attributes"].(map[string]any)
	if !okID || !okKind || !isAttrs {
		return nil, nil, false
	}
	return e, attrs, dhParseAttributes(e, attrs)
}

func dhParseRun(value any) (*dhRun, bool) {
	list, isList := value.([]any)
	if !isList || len(list) == 0 {
		return nil, false
	}
	run := &dhRun{scheduled: map[string]*dhEvent{}, closes: map[string][]*dhEvent{}}
	var startAttrs map[string]any
	for _, item := range list {
		e, attrs, ok := dhParseEvent(item)
		if !ok {
			return nil, false
		}
		if e.kind == dhStarted && startAttrs == nil {
			startAttrs = attrs
		}
		run.events = append(run.events, e)
	}
	if startAttrs == nil {
		return nil, false
	}
	run.workflowID, _ = dhText(startAttrs, "workflowId")
	run.runID, _ = dhText(startAttrs, "runId")
	if reset, isMap := startAttrs["resetFrom"].(map[string]any); isMap {
		run.hasReset = true
		run.resetBase, _ = dhText(reset, "baseRunId")
		run.resetPoint, _ = dhInt(reset["resetEventId"], 1)
	}
	run.index()
	return run, run.modelResultsReadable
}

// index mirrors the Python Run: activities by id, closes by the activity their
// schedule names, and each plain model response's tool calls.
func (run *dhRun) index() {
	kinds := map[int64]string{}
	for _, e := range run.events {
		if e.kind == dhScheduled {
			run.scheduled[e.activityID] = e
			kinds[e.id] = e.activityType
		}
	}
	byEvent := map[int64]string{}
	for activity, e := range run.scheduled {
		byEvent[e.id] = activity
	}
	run.modelResultsReadable = true
	for _, e := range run.events {
		if e.kind != dhCompleted && e.kind != dhTimedOut {
			continue
		}
		if activity, found := byEvent[e.scheduledAt]; found {
			run.closes[activity] = append(run.closes[activity], e)
		}
		if e.kind == dhCompleted && kinds[e.scheduledAt] == dhModel && !e.result.encrypted {
			run.modelResultsReadable = run.modelResultsReadable && dhReadToolCalls(e)
		}
	}
}

func dhReadToolCalls(e *dhEvent) bool {
	data, isMap := e.result.data.(map[string]any)
	if !isMap {
		return false
	}
	calls, isList := data["toolCalls"].([]any)
	if !isList {
		return false
	}
	e.toolCalls = []dhCall{}
	for _, item := range calls {
		call, ok := dhParseCall(item)
		if !ok {
			return false
		}
		e.toolCalls = append(e.toolCalls, call)
	}
	return true
}

func dhParseExport(value any) ([]*dhRun, bool) {
	m, isMap := value.(map[string]any)
	if !isMap {
		return nil, false
	}
	var histories []any
	switch m["source"] {
	case "workflow-show":
		if _, isList := m["events"].([]any); !isList {
			return nil, false
		}
		histories = []any{m["events"]}
	case "cloud-export":
		items, isList := m["items"].([]any)
		if !isList {
			return nil, false
		}
		for _, item := range items {
			entry, isEntry := item.(map[string]any)
			history, isHistory := entry["history"].(map[string]any)
			if !isEntry || !isHistory {
				return nil, false
			}
			if _, isList := history["events"].([]any); !isList {
				return nil, false
			}
			histories = append(histories, history["events"])
		}
	default:
		return nil, false
	}
	var runs []*dhRun
	for _, history := range histories {
		run, ok := dhParseRun(history)
		if !ok {
			return nil, false
		}
		runs = append(runs, run)
	}
	return runs, true
}

func dhSrlOK(m map[string]any) bool {
	if m["srl"] == nil {
		return true
	}
	srl, isMap := m["srl"].(map[string]any)
	if !isMap {
		return false
	}
	_, okEpoch := dhInt(srl["epoch"], 0)
	return okEpoch && dhIsDigest(srl["digest"])
}

func dhParsePermit(value any) (dhPermit, bool) {
	var p dhPermit
	m, isMap := value.(map[string]any)
	if !isMap {
		return p, false
	}
	texts := map[string]*string{"permitId": &p.permitID, "callId": &p.callID, "activityId": &p.activityID,
		"tool": &p.tool, "modelActivityId": &p.modelActivityID}
	for _, name := range []string{"workflowId", "runId", "authorityKeyId"} {
		texts[name] = new(string)
	}
	for name, into := range texts {
		var ok bool
		if *into, ok = dhText(m, name); !ok {
			return p, false
		}
	}
	digests := map[string]*string{"argsDigest": &p.argsDigest, "modelArgsDigest": &p.modelArgsDigest,
		"toolCodeDigest": &p.toolCodeDigest, "grantDigest": new(string)}
	for name, into := range digests {
		if !dhIsDigest(m[name]) {
			return p, false
		}
		*into = m[name].(string)
	}
	var okInput, okModel, okAttempt bool
	p.inputCipher, okInput = dhOptionalDigest(m, "inputCiphertextDigest")
	p.modelCipher, okModel = dhOptionalDigest(m, "modelResponseCiphertextDigest")
	p.attempt, okAttempt = dhInt(m["attempt"], 1)
	if !okInput || !okModel || !okAttempt || !dhApprovalsOK(m["approvalIds"]) {
		return p, false
	}
	return p, dhIsTime(m["issuedAt"]) && dhIsTime(m["expiresAt"]) && dhSrlOK(m)
}

func dhApprovalsOK(value any) bool {
	if value == nil {
		return true
	}
	list, isList := value.([]any)
	if !isList {
		return false
	}
	for _, item := range list {
		if text, ok := item.(string); !ok || text == "" {
			return false
		}
	}
	return true
}

func dhParseSettlement(value any) (*dhSettlement, bool) {
	m, isMap := value.(map[string]any)
	if !isMap {
		return nil, false
	}
	s := &dhSettlement{}
	var okSource, okObserver, okResult bool
	s.source, okSource = dhText(m, "source")
	outcome, _ := m["outcome"].(string)
	s.outcome = outcome
	_, okObserver = dhText(m, "observerKeyId")
	s.resultDigest, okResult = dhNullableDigest(m, "resultDigest")
	okOutcome := outcome == dhApplied || outcome == "not-applied"
	return s, okSource && okOutcome && dhIsTime(m["settledAt"]) && okObserver && okResult
}

func dhParseEffect(value any) (dhEffect, map[string]string, bool) {
	var e dhEffect
	m, isMap := value.(map[string]any)
	if !isMap {
		return e, nil, false
	}
	texts := map[string]string{}
	for _, name := range []string{"effectId", "permitId", "workflowId", "runId", "callId", "observerKeyId"} {
		text, ok := dhText(m, name)
		if !ok {
			return e, nil, false
		}
		texts[name] = text
	}
	if !dhIsDigest(m["grantDigest"]) || !dhIsDigest(m["argsDigest"]) {
		return e, nil, false
	}
	texts["argsDigest"] = m["argsDigest"].(string)
	e.permitID = texts["permitId"]
	var okResult, okCipher bool
	e.resultDigest, okResult = dhOptionalDigest(m, "resultDigest")
	e.resultCipher, okCipher = dhOptionalDigest(m, "resultCiphertextDigest")
	e.outcome, _ = m["outcome"].(string)
	known := e.outcome == dhApplied || e.outcome == "not-applied" || e.outcome == dhUncertain
	if !okResult || !okCipher || !known || !dhIsTime(m["observedAt"]) {
		return e, nil, false
	}
	if settlement, present := m["settlement"]; present {
		var ok bool
		e.settlement, ok = dhParseSettlement(settlement)
		if !ok || e.outcome != dhUncertain {
			return e, nil, false
		}
	}
	return e, texts, dhSrlOK(m)
}

func dhParseWitnessed(value any, r *dhRecord) bool {
	m, isMap := value.(map[string]any)
	if !isMap {
		return false
	}
	var okWorkflow, okRun bool
	r.workflowID, okWorkflow = dhText(m, "workflowId")
	r.runID, okRun = dhText(m, "runId")
	tools, isTools := m["gatedTools"].([]any)
	permits, isPermits := m["permits"].([]any)
	effects, isEffects := m["effects"].([]any)
	if !okWorkflow || !okRun || !dhIsDigest(m["expectedToolCodeDigest"]) || !isTools || len(tools) == 0 ||
		!isPermits || len(permits) == 0 || !isEffects {
		return false
	}
	r.expectedCode = m["expectedToolCodeDigest"].(string)
	for _, item := range tools {
		text, ok := item.(string)
		if !ok || text == "" {
			return false
		}
		r.gated = append(r.gated, text)
	}
	return dhParseWitnessRecords(permits, effects, r)
}

func dhParseWitnessRecords(permits, effects []any, r *dhRecord) bool {
	runs := map[string][2]string{}
	for _, item := range permits {
		p, ok := dhParsePermit(item)
		if !ok {
			return false
		}
		raw := item.(map[string]any)
		runs[p.permitID] = [2]string{raw["workflowId"].(string), raw["runId"].(string)}
		r.permits = append(r.permits, p)
	}
	var effectTexts []map[string]string
	for _, item := range effects {
		e, texts, ok := dhParseEffect(item)
		if !ok {
			return false
		}
		r.effects = append(r.effects, e)
		effectTexts = append(effectTexts, texts)
	}
	return dhWitnessHolds(r, runs, effectTexts)
}

// dhWitnessHolds mirrors the Python _witness_holds: permits and effects belong
// to the witnessed run and to each other.
func dhWitnessHolds(r *dhRecord, runs map[string][2]string, effectTexts []map[string]string) bool {
	want := [2]string{r.workflowID, r.runID}
	attempts := map[string]bool{}
	for _, p := range r.permits {
		attempts[fmt.Sprintf("%s\x00%d", p.activityID, p.attempt)] = true
		if runs[p.permitID] != want {
			return false
		}
	}
	if len(runs) != len(r.permits) || len(attempts) != len(r.permits) {
		return false
	}
	seen := map[string]bool{}
	for _, texts := range effectTexts {
		seen[texts["permitId"]] = true
		p := r.permit(texts["permitId"])
		if p == nil || [2]string{texts["workflowId"], texts["runId"]} != want {
			return false
		}
		if texts["callId"] != p.callID || texts["argsDigest"] != p.argsDigest {
			return false
		}
	}
	return len(seen) == len(r.effects)
}

func dhParse(record map[string]any) (*dhRecord, bool) {
	r := &dhRecord{}
	exports, isList := record["exports"].([]any)
	if !isList {
		return nil, false
	}
	for _, export := range exports {
		runs, ok := dhParseExport(export)
		if !ok {
			return nil, false
		}
		r.runs = append(r.runs, runs...)
	}
	return r, dhParseWitnessed(record["witnessed"], r)
}

// ------------------------------------------------------------- record views

func (r *dhRecord) copies() []*dhRun {
	var out []*dhRun
	for _, run := range r.runs {
		if run.workflowID == r.workflowID && run.runID == r.runID {
			out = append(out, run)
		}
	}
	return out
}

func (r *dhRecord) permit(id string) *dhPermit {
	for i := range r.permits {
		if r.permits[i].permitID == id {
			return &r.permits[i]
		}
	}
	return nil
}

func (r *dhRecord) effectOf(p dhPermit) *dhEffect {
	for i := range r.effects {
		if r.effects[i].permitID == p.permitID {
			return &r.effects[i]
		}
	}
	return nil
}

// anyPair reports whether fails holds for some copy of the witnessed run and permit.
func (r *dhRecord) anyPair(fails func(*dhRun, dhPermit) bool) bool {
	for _, run := range r.copies() {
		for _, p := range r.permits {
			if fails(run, p) {
				return true
			}
		}
	}
	return false
}

// completion is the completed event of an activity, for one attempt when attempt > 0.
func (run *dhRun) completion(activity string, attempt int64) *dhEvent {
	for _, e := range run.closes[activity] {
		if e.kind == dhCompleted && (attempt == 0 || e.attempt == attempt) {
			return e
		}
	}
	return nil
}

func dhResultOf(e *dhEvent) *dhPayload {
	if e == nil {
		return nil
	}
	return e.result
}

// ------------------------------------------------------------- the checks

func dhWitnessedLast(r *dhRecord, run *dhRun) int64 {
	activities := map[string]bool{}
	for _, p := range r.permits {
		activities[p.activityID] = true
		activities[p.modelActivityID] = true
	}
	var last int64
	for activity := range activities {
		scheduled, found := run.scheduled[activity]
		if !found {
			continue
		}
		last = max(last, scheduled.id)
		for _, e := range run.closes[activity] {
			last = max(last, e.id)
		}
	}
	return last
}

func dhResetFails(r *dhRecord) bool {
	var forks []int64
	for _, run := range r.runs {
		if run.hasReset && run.workflowID == r.workflowID && run.resetBase == r.runID {
			forks = append(forks, run.resetPoint)
		}
	}
	copies := r.copies()
	if len(copies) == 0 {
		return len(forks) > 0
	}
	for _, run := range copies {
		points := slices.Clone(forks)
		for _, e := range run.events {
			if e.kind == dhReset {
				points = append(points, e.resetPoint)
			}
		}
		last := dhWitnessedLast(r, run)
		if slices.ContainsFunc(points, func(point int64) bool { return point < last }) {
			return true
		}
	}
	return false
}

func dhSequenceBroken(run *dhRun) bool {
	started, scheduled := 0, 0
	for i, e := range run.events {
		if e.id != int64(i+1) {
			return true
		}
		switch e.kind {
		case dhStarted:
			started++
		case dhScheduled:
			scheduled++
		}
	}
	if run.events[0].kind != dhStarted || started != 1 || len(run.scheduled) != scheduled {
		return true
	}
	scheduledAt := map[int64]bool{}
	for _, e := range run.scheduled {
		scheduledAt[e.id] = true
	}
	for _, e := range run.events {
		if (e.kind == dhCompleted || e.kind == dhTimedOut) && (!scheduledAt[e.scheduledAt] || e.scheduledAt >= e.id) {
			return true
		}
	}
	for _, closes := range run.closes {
		if len(closes) > 1 {
			return true
		}
	}
	return false
}

func dhCipherDiffers(payload *dhPayload, witnessed *string) bool {
	if payload == nil {
		return false
	}
	if !payload.encrypted {
		return witnessed != nil
	}
	return witnessed == nil || *witnessed != "sha256:"+sha(payload.cipher)
}

func dhEncryptedDiffers(r *dhRecord) bool {
	return r.anyPair(func(run *dhRun, p dhPermit) bool {
		if scheduled := run.scheduled[p.activityID]; scheduled != nil && dhCipherDiffers(scheduled.input, p.inputCipher) {
			return true
		}
		if dhCipherDiffers(dhResultOf(run.completion(p.modelActivityID, 0)), p.modelCipher) {
			return true
		}
		e := r.effectOf(p)
		return e != nil && dhCipherDiffers(dhResultOf(run.completion(p.activityID, p.attempt)), e.resultCipher)
	})
}

func dhArgsDiffer(r *dhRecord) bool {
	return r.anyPair(func(run *dhRun, p dhPermit) bool {
		scheduled := run.scheduled[p.activityID]
		if scheduled == nil {
			return false
		}
		if scheduled.activityType != dhTool+p.tool {
			return true
		}
		if scheduled.input.encrypted {
			return false
		}
		call := scheduled.inputCall
		return call.callID != p.callID || !dhDigestIs(call.args, &p.argsDigest)
	})
}

func dhModelDiffers(r *dhRecord) bool {
	return r.anyPair(func(run *dhRun, p dhPermit) bool {
		scheduled := run.scheduled[p.modelActivityID]
		response := run.completion(p.modelActivityID, 0)
		if scheduled == nil || scheduled.activityType != dhModel || response == nil {
			return true
		}
		if response.result.encrypted {
			return false
		}
		var calls []dhCall
		for _, call := range response.toolCalls {
			if call.callID == p.callID {
				calls = append(calls, call)
			}
		}
		if len(calls) != 1 || calls[0].tool != p.tool {
			return true
		}
		return !dhDigestIs(calls[0].args, &p.modelArgsDigest)
	})
}

func dhSettledAsApplied(e *dhEffect) bool {
	return e.settlement != nil && e.settlement.source == "system-of-record" && e.settlement.outcome == dhApplied
}

// dhWitnessedResult is whether an attempt's result is judged here, and its digest.
func dhWitnessedResult(e *dhEffect) (bool, *string) {
	switch {
	case e == nil:
		return true, nil
	case e.outcome != dhUncertain:
		return true, e.resultDigest
	case dhSettledAsApplied(e):
		return true, e.settlement.resultDigest
	}
	return false, nil
}

func dhResultDiffers(r *dhRecord) bool {
	return r.anyPair(func(run *dhRun, p dhPermit) bool {
		result := dhResultOf(run.completion(p.activityID, p.attempt))
		if result == nil || result.encrypted {
			return false
		}
		judged, witnessed := dhWitnessedResult(r.effectOf(p))
		return judged && !dhDigestIs(result.data, witnessed)
	})
}

func dhCodeChanged(r *dhRecord) bool {
	return slices.ContainsFunc(r.permits, func(p dhPermit) bool { return p.toolCodeDigest != r.expectedCode })
}

func dhUnwitnessed(r *dhRecord) bool {
	permitted := map[string]bool{}
	for _, p := range r.permits {
		permitted[fmt.Sprintf("%s\x00%d", p.activityID, p.attempt)] = true
	}
	for _, run := range r.copies() {
		for activity, scheduled := range run.scheduled {
			if !strings.HasPrefix(scheduled.activityType, dhTool) ||
				!slices.Contains(r.gated, strings.TrimPrefix(scheduled.activityType, dhTool)) {
				continue
			}
			for _, e := range run.closes[activity] {
				if e.kind == dhCompleted && !permitted[fmt.Sprintf("%s\x00%d", activity, e.attempt)] {
					return true
				}
			}
		}
	}
	return false
}

func dhEffectMissing(r *dhRecord) bool {
	return r.anyPair(func(run *dhRun, p dhPermit) bool {
		if run.scheduled[p.activityID] == nil {
			return true
		}
		e := r.effectOf(p)
		return e != nil && e.outcome == dhApplied && run.completion(p.activityID, p.attempt) == nil
	})
}

func dhUpdateTwice(r *dhRecord) bool {
	for _, run := range r.copies() {
		seen := map[string]bool{}
		for _, e := range run.events {
			if e.kind != dhUpdate {
				continue
			}
			if seen[e.updateID] {
				return true
			}
			seen[e.updateID] = true
		}
	}
	return false
}

func dhLostReply(r *dhRecord) bool {
	return r.anyPair(func(run *dhRun, p dhPermit) bool {
		e := r.effectOf(p)
		if e == nil || e.outcome != dhUncertain || dhSettledAsApplied(e) {
			return false
		}
		return run.completion(p.activityID, p.attempt) != nil
	})
}
