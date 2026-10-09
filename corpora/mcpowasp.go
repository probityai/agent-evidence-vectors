package corpora

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() { register(mcpOWASP{}) }

// mcpOWASP judges vectors-mcp-owasp/. Each member is the observation one
// acceptance test of a draft MCP verification requirement (MCPVS-1 to
// MCPVS-12) produced. The requirement the record names selects a rule, and the
// rule decides whether the observed behaviour passes that acceptance test.
// Every requirement carries one member that must be accepted and one that must
// be rejected, and the rejected member differs from its accepting twin in
// exactly one observation field. The threat identifiers (MCPTM-1 to MCPTM-10)
// are reached through the requirements their registry row names.
//
// The rules restate packaging/agent_evidence_vectors/mcpowasp.py. They are
// written twice on purpose: one rule run by both rails would agree with itself.
type mcpOWASP struct{}

func (mcpOWASP) Suite() string { return "owasp-mcp-verification-draft" }

type moEntry struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Record     string   `json:"record"`
	Conditions []string `json:"conditions"`
	Twin       string   `json:"twin"`
}

type moManifest struct {
	Registry     string         `json:"registry"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []moEntry      `json:"vectors"`
}

type moRegistry struct {
	Requirements []struct {
		ID string `json:"id"`
	} `json:"requirements"`
	Threats []struct {
		ID       string   `json:"id"`
		TestedBy []string `json:"testedBy"`
	} `json:"threats"`
}

var moIdentifier = regexp.MustCompile(`^(MCPVS|MCPTM)-([1-9][0-9]*)$`)

type moRule func(o map[string]any) string

var moRules = map[string]moRule{
	"MCPVS-1":  moToolPin,
	"MCPVS-2":  moPinSurvivesRestart,
	"MCPVS-3":  moCredentialIsolation,
	"MCPVS-4":  moSessionScope,
	"MCPVS-5":  moNoShellInterpolation,
	"MCPVS-6":  moContentIsData,
	"MCPVS-7":  moServerIdentity,
	"MCPVS-8":  moCallRecord,
	"MCPVS-9":  moTamperEvident,
	"MCPVS-10": moUntrustedWorkspace,
	"MCPVS-11": moEndUserAttribution,
	"MCPVS-12": moDeclaredArgumentsOnly,
}

const moNotRun = ", so the test was not run"

func moStr(v any) string {
	s, _ := v.(string)
	return s
}

func moStrs(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

func moHas(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func moObj(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func moInt(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(n.String())
	return i, err == nil
}

func moToolPin(o map[string]any) string {
	approved, served := moStr(o["approvedDigest"]), moStr(o["servedDigest"])
	if approved == "" || approved == served {
		return "the served definition does not differ from the approved one" + moNotRun
	}
	if o["clientDecision"] != "refused" {
		return "the client accepted a tool whose definition digest differs from the approved one"
	}
	reported := moStrs(o["reportedDigests"])
	if !moHas(reported, approved) || !moHas(reported, served) {
		return "the refusal does not report both digests"
	}
	return ""
}

func moPinSurvivesRestart(o map[string]any) string {
	approved, served := moStr(o["approvedDigest"]), moStr(o["servedDigest"])
	if approved == "" || approved == served {
		return "the served definition does not differ from the approved one" + moNotRun
	}
	connections, ok := o["connections"].([]any)
	if !ok || len(connections) == 0 {
		return "no connection was observed"
	}
	restarted := false
	for _, c := range connections {
		if m, ok := moObj(c); ok && m["afterRestart"] == true {
			restarted = true
		}
	}
	if !restarted {
		return "no connection after a restart was observed" + moNotRun
	}
	for i, c := range connections {
		m, ok := moObj(c)
		if !ok || m["decision"] != "refused" {
			return fmt.Sprintf("connection %d accepted the altered definition", i+1)
		}
	}
	return ""
}

func moFlatten(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case map[string]any:
		var out []string
		for _, k := range sortedKeys(t) {
			out = append(out, moFlatten(t[k])...)
		}
		return out
	case []any:
		var out []string
		for _, item := range t {
			out = append(out, moFlatten(item)...)
		}
		return out
	}
	return nil
}

func moContainsAny(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

func moCredentialIsolation(o map[string]any) string {
	tokens, ok := moObj(o["tokens"])
	called := moStr(o["calledServer"])
	if _, present := tokens[called]; !ok || len(tokens) < 2 || !present {
		return "fewer than two servers with distinct tokens" + moNotRun
	}
	headers, arguments := moFlatten(o["receivedHeaders"]), moFlatten(o["receivedArguments"])
	for _, server := range sortedKeys(tokens) {
		token := moStr(tokens[server])
		if server != called && moContainsAny(headers, token) {
			return fmt.Sprintf("the token issued for server %s reached server %s in a header", server, called)
		}
		if moContainsAny(arguments, token) {
			return fmt.Sprintf("the token issued for server %s was placed in a tool argument", server)
		}
	}
	return ""
}

func moSessionScope(o map[string]any) string {
	required, ok := o["callRequires"].(string)
	if !ok || moHas(moStrs(o["sessionScopes"]), required) {
		return "the call does not require a scope outside the session" + moNotRun
	}
	if !moHas(moStrs(o["grantedAcrossSessions"]), required) {
		return "the required scope was never granted in any session" + moNotRun
	}
	if o["decision"] != "refused" {
		return "a call was authorized against a scope granted in another session"
	}
	return ""
}

func moNoShellInterpolation(o map[string]any) string {
	sent := moStrs(o["payloads"])
	for _, p := range []string{"; id", "$(id)", "`id`"} {
		if !moHas(sent, p) {
			return "not every injection token was sent" + moNotRun
		}
	}
	for _, where := range []string{"spawnedProcesses", "auditRecordProcesses"} {
		processes, ok := o[where].([]any)
		if !ok {
			return where + " was not observed"
		}
		for _, argv := range processes {
			if list, ok := argv.([]any); ok && len(list) > 0 && list[0] == "id" {
				return "the injected command ran, as observed in " + where
			}
		}
	}
	return ""
}

func moContentIsData(o map[string]any) string {
	before, okB := moObj(o["before"])
	after, okA := moObj(o["after"])
	if !okB || !okA {
		return "the state before and after was not observed"
	}
	for _, key := range []string{"tools", "scopes", "approval"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			return "returned content changed the " + key
		}
	}
	if n, ok := moInt(o["unapprovedCallsAfter"]); !ok || n != 0 {
		return "a tool call followed the returned content without a fresh approval"
	}
	if o["contentRecordedAs"] != "data" {
		return "the returned content was not recorded as data"
	}
	return ""
}

func moServerIdentity(o map[string]any) string {
	configured := moStrs(o["configuredDigests"])
	launched, _ := o["launchedDigest"].(string)
	if len(configured) == 0 || moHas(configured, launched) {
		return "the launched artifact is in the configured set" + moNotRun
	}
	if o["decision"] != "refused" {
		return "the client started a server whose artifact digest is absent from the configured set"
	}
	if !moHas(configured, moStr(o["namedExpected"])) {
		return "the refusal does not name the digest the client expected"
	}
	return ""
}

func moTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case json.Number:
		return t.String() != "0"
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

func moCallRecord(o map[string]any) string {
	records, ok := o["records"].([]any)
	if !ok || len(records) != 2 {
		return "the test needs one approved call and one call with no approval decision"
	}
	objects := make([]map[string]any, 0, 2)
	for i, r := range records {
		m, ok := moObj(r)
		if !ok {
			return fmt.Sprintf("record %d is not an object", i+1)
		}
		for _, name := range []string{"server", "toolDigest", "principal", "approvalState", "argumentsDigest", "outcome"} {
			if !moTruthy(m[name]) {
				return fmt.Sprintf("record %d does not carry %s", i+1, name)
			}
		}
		objects = append(objects, m)
	}
	if reflect.DeepEqual(objects[0]["approvalState"], objects[1]["approvalState"]) {
		return "a call with no approval decision is recorded the same as an approved one"
	}
	return ""
}

// moChainBreak returns the sequence number of the first record whose
// predecessor link fails, -1 for a malformed record, and 0 for an intact chain.
func moChainBreak(stream []any) (int, error) {
	var previous any
	for _, item := range stream {
		record, ok := moObj(item)
		if !ok {
			return -1, nil
		}
		expected := ""
		if previous != nil {
			raw, err := pythonCompactJSON(previous)
			if err != nil {
				return 0, err
			}
			expected = sha(raw)
		}
		if record["prev"] != expected {
			if seq, ok := moInt(record["seq"]); ok {
				return seq, nil
			}
			return -1, nil
		}
		previous = record
	}
	return 0, nil
}

func moTamperEvident(o map[string]any) string {
	stream, ok := o["stream"].([]any)
	if !ok || len(stream) == 0 {
		return "no record stream was observed"
	}
	broken, err := moChainBreak(stream)
	if err != nil {
		return "the record stream cannot be hashed: " + err.Error()
	}
	if broken == 0 {
		return "the stream is intact, so the deletion test was not run"
	}
	if holder := moStr(o["headHolder"]); holder == "" || holder == "client" {
		return "the head is held by the client alone"
	}
	verification, ok := moObj(o["verification"])
	if !ok || verification["result"] != "fail" {
		return "verification passed a stream with a record deleted"
	}
	if at, ok := moInt(verification["breakAt"]); !ok || at != broken {
		return "verification failed without naming the break"
	}
	resigned, ok := moObj(o["verificationAfterResign"])
	if !ok || resigned["result"] != "fail" {
		return "verification against the published head passed after the client re-signed the stream alone"
	}
	return ""
}

func moUntrustedWorkspace(o map[string]any) string {
	untrusted, started := moStrs(o["untrustedConfigServers"]), moStrs(o["started"])
	if len(untrusted) == 0 {
		return "the workspace carried no server configuration" + moNotRun
	}
	for _, name := range untrusted {
		if moHas(started, name) {
			return "a server from an untrusted workspace configuration started"
		}
	}
	if o["refusalReported"] != true {
		return "the refusal was not reported"
	}
	reported := sortedStrings(moStrs(o["reportedStarted"]))
	if !reflect.DeepEqual(reported, sortedStrings(started)) {
		return "the report does not list the servers that did start"
	}
	return ""
}

func moEndUserAttribution(o map[string]any) string {
	calls, ok := o["calls"].([]any)
	unbound := false
	for _, c := range calls {
		if m, isObj := moObj(c); isObj && m["userBound"] == false {
			unbound = true
		}
	}
	if !ok || !unbound {
		return "no call without a bound user was sent" + moNotRun
	}
	for i, c := range calls {
		m, ok := moObj(c)
		if !ok {
			return fmt.Sprintf("call %d is not an object", i+1)
		}
		if m["userBound"] == true && m["decision"] != "accepted" {
			return fmt.Sprintf("call %d carried a bound user and was refused", i+1)
		}
		if m["userBound"] == false {
			if m["decision"] != "refused" {
				return fmt.Sprintf("call %d could not be attributed to a user and was accepted", i+1)
			}
			if !moTruthy(m["recordedReason"]) {
				return fmt.Sprintf("call %d was refused and no reason was recorded", i+1)
			}
		}
	}
	return ""
}

func moDeclaredArgumentsOnly(o map[string]any) string {
	declared, held := moStrs(o["declaredParameters"]), moStrs(o["sessionHeld"])
	if len(declared) == 0 || len(held) == 0 {
		return "the session held nothing beyond the declared parameters" + moNotRun
	}
	var extra []string
	for _, k := range moStrs(o["requestLogKeys"]) {
		if !moHas(declared, k) {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		return fmt.Sprintf("the request carried fields the schema does not declare: %v", extra)
	}
	return ""
}

func moVerdict(record map[string]any) (string, string) {
	requirement := moStr(record["requirement"])
	rule, ok := moRules[requirement]
	if !ok {
		return "reject", fmt.Sprintf("no rule for requirement %q", requirement)
	}
	observation, ok := moObj(record["observation"])
	if !ok {
		return "reject", "the record carries no observation"
	}
	if reason := rule(observation); reason != "" {
		return "reject", reason
	}
	return "accept", ""
}

func moIdentify(kind string, conditions []string, record any) (string, error) {
	cs := make([]any, len(conditions))
	for i, c := range conditions {
		cs[i] = c
	}
	raw, err := pythonCompactJSON(map[string]any{"kind": kind, "conditions": cs, "payload": record})
	if err != nil {
		return "", err
	}
	return "v" + sha(raw)[:16], nil
}

func moCheckRegistry(reg moRegistry, res *Result) (map[string]bool, map[string][]string) {
	requirements := map[string]bool{}
	for _, r := range reg.Requirements {
		requirements[r.ID] = true
	}
	threats := map[string][]string{}
	for _, t := range reg.Threats {
		threats[t.ID] = t.TestedBy
	}
	for _, prefix := range []string{"MCPVS", "MCPTM"} {
		ids := sortedKeys(requirements)
		if prefix == "MCPTM" {
			ids = sortedKeys(threats)
		}
		var numbers []int
		for _, id := range ids {
			if m := moIdentifier.FindStringSubmatch(id); m != nil && m[1] == prefix {
				n, _ := strconv.Atoi(m[2])
				numbers = append(numbers, n)
			}
		}
		sort.Ints(numbers)
		minted := len(numbers) == len(ids)
		for i, n := range numbers {
			minted = minted && n == i+1
		}
		if !minted {
			res.Findings = append(res.Findings,
				fmt.Sprintf("%s identifiers are not minted as 1..%d: %v", prefix, len(ids), ids))
		}
	}
	for _, threat := range sortedKeys(threats) {
		if len(threats[threat]) == 0 {
			res.Findings = append(res.Findings, threat+" names no requirement that tests it")
		}
		for _, r := range threats[threat] {
			if !requirements[r] {
				res.Findings = append(res.Findings,
					fmt.Sprintf("%s is tested by %s, which the registry does not mint", threat, r))
			}
		}
	}
	if !reflect.DeepEqual(sortedKeys(requirements), sortedKeys(moRules)) {
		res.Findings = append(res.Findings, "the registry and this reader's rules name different requirements")
	}
	return requirements, threats
}

func (mcpOWASP) Judge(dir string, manifest []byte) (*Result, error) {
	var m moManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("MANIFEST.json does not parse: %w", err)
	}
	rawRegistry, err := readIn(dir, m.Registry)
	if err != nil {
		return nil, fmt.Errorf("the registry %q cannot be read: %w", m.Registry, err)
	}
	var reg moRegistry
	if err := json.Unmarshal(rawRegistry, &reg); err != nil {
		return nil, fmt.Errorf("the registry %q does not parse: %w", m.Registry, err)
	}
	res := &Result{}
	requirements, threats := moCheckRegistry(reg, res)

	entries := append([]moEntry(nil), m.Vectors...)
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].ID < entries[b].ID })
	records := map[string]map[string]any{}
	kinds := map[string]map[string]bool{}
	for r := range requirements {
		kinds[r] = map[string]bool{}
	}
	index := map[string]int{}
	ids, files := []string{}, []string{}
	for _, e := range entries {
		member := Member{ID: e.ID, Kind: e.Kind}
		ids, files = append(ids, e.ID), append(files, e.Record)
		raw, err := readIn(dir, e.Record)
		if err != nil {
			member.Findings = append(member.Findings, "the manifest names a record file that does not exist")
			index[e.ID] = len(res.Members)
			res.Members = append(res.Members, member)
			continue
		}
		decoded, err := decodeJSONNumbers(raw)
		record, isObj := decoded.(map[string]any)
		if err != nil || !isObj {
			member.Findings = append(member.Findings, "the record is not a JSON object")
			index[e.ID] = len(res.Members)
			res.Members = append(res.Members, member)
			continue
		}
		records[e.ID] = record
		requirement := moStr(record["requirement"])
		if len(e.Conditions) != 1 || e.Conditions[0] != requirement {
			member.Findings = append(member.Findings, "cites a condition other than the requirement its record tests")
		}
		if id, err := moIdentify(e.Kind, e.Conditions, record); err != nil || id != e.ID {
			member.Findings = append(member.Findings, "identifier does not recompute from the member's own bytes")
		}
		if got, reason := moVerdict(record); got != e.Kind {
			member.Findings = append(member.Findings,
				fmt.Sprintf("declares %s and the rule answers %s: %s", e.Kind, got, reason))
		}
		if seen, ok := kinds[requirement]; ok {
			seen[e.Kind] = true
		}
		index[e.ID] = len(res.Members)
		res.Members = append(res.Members, member)
	}
	for _, e := range entries {
		if e.Kind != "reject" {
			continue
		}
		twin, okT := records[e.Twin]
		mine, okM := records[e.ID]
		at := index[e.ID]
		if !okT || !okM {
			res.Members[at].Findings = append(res.Members[at].Findings, "names no accepting twin")
			continue
		}
		a, _ := moObj(twin["observation"])
		b, _ := moObj(mine["observation"])
		keys := map[string]bool{}
		for k := range a {
			keys[k] = true
		}
		for k := range b {
			keys[k] = true
		}
		var differing []string
		for _, k := range sortedKeys(keys) {
			if !reflect.DeepEqual(a[k], b[k]) {
				differing = append(differing, k)
			}
		}
		if len(differing) != 1 || twin["requirement"] != mine["requirement"] {
			res.Members[at].Findings = append(res.Members[at].Findings,
				fmt.Sprintf("differs from its accepting twin in %v, not in exactly one field", differing))
		}
	}
	for _, r := range sortedKeys(kinds) {
		if !kinds[r]["accept"] || !kinds[r]["reject"] || len(kinds[r]) != 2 {
			res.Findings = append(res.Findings,
				fmt.Sprintf("%s carries %v members, not one accept and one reject", r, sortedKeys(kinds[r])))
		}
	}
	for _, t := range sortedKeys(threats) {
		reached := map[string]bool{}
		for _, r := range threats[t] {
			for k := range kinds[r] {
				reached[k] = true
			}
		}
		if !reached["accept"] || !reached["reject"] {
			res.Findings = append(res.Findings,
				fmt.Sprintf("%s reaches %v members through %v", t, sortedKeys(reached), threats[t]))
		}
	}
	counts := map[string]int{"accept": 0, "reject": 0}
	for _, e := range entries {
		counts[e.Kind]++
	}
	if msg := countsDisagree(m.Counts, counts); msg != "" {
		res.Findings = append(res.Findings, msg)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil || digest != m.CorpusDigest {
		res.Findings = append(res.Findings, "corpusDigest does not match the record files on disk")
	}
	return res, nil
}
