package corpusreaders

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func init() { register(containmentJournal{}) }

// containmentJournal judges corpora/vectors-containment-journal/. Each member
// is one multi-agent run's hash-chained journal (topology, deliveries,
// containment decisions, fallbacks, restarts, assessments, restorations,
// responses and tool calls), and a receipt member adds the blast-radius
// receipt beside it. The reader applies the Python reader's rules in the same
// order and names the first that fails:
//
//  1. contract_id_missing, contract_id_unknown;
//  2. record_not_canonical: a float, NaN or Infinity, a repeated member, an
//     integer of magnitude 2^53 or more, or a string outside printable ASCII;
//  3. record_malformed: a missing or unknown member, a wrong type, an agent
//     the run does not list, a bad edge list, digest or time (30 February
//     included), or an unsorted list;
//  4. closed_vocabulary_violation;
//  5. the chain: chain_seq_gap, chain_broken, chain_time_reversed,
//     topology_missing;
//  6. the walk over the entries with the graph in force: each delivery, each
//     decision's deltas and detector estimates, each fallback's posture, each
//     restart, assessment and admitted restoration, each response, each
//     admitted retrieval's inclusion in the snapshot and each tool call;
//  7. the run-level claims.
//
// A receipt is judged only when the journal is allowed, and the reach it
// claims is recomputed from the journal alone.
type containmentJournal struct{}

const (
	cjBase              = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
	cjContractID        = cjBase + "containment-journal"
	cjReceiptContractID = cjBase + "blast-radius-receipt"
	cjZero              = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

func (containmentJournal) Suite() string { return "containment-journal/v1" }

type cjVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained json.RawMessage   `json:"retained"`
}

type cjObject = map[string]any

func (containmentJournal) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v cjVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = cjJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func cjJudgeMember(caseDir string, v cjVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	record, bad, err := cjReadStrict(caseDir, "record.json")
	if err != nil {
		return append(findings, err.Error())
	}
	if finding := cjRetainedFinding(record, v.Retained); finding != "" {
		findings = append(findings, finding)
	}
	got, err := cjVerify(caseDir, record, bad)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// cjVerify is the reference reader's verify: the journal, then the receipt
// beside it when the journal is allowed.
func cjVerify(caseDir string, record any, bad bool) (scDecision, error) {
	if reason := cjJudgeJournal(record, bad); reason != "" {
		return scDecision{"deny", reason}, nil
	}
	if !existsIn(caseDir, "receipt.json") {
		return scDecision{"allow", "containment_consistent"}, nil
	}
	receipt, receiptBad, err := cjReadStrict(caseDir, "receipt.json")
	if err != nil {
		return scDecision{}, err
	}
	journal, _ := record.(cjObject)
	if reason := cjJudgeReceipt(receipt, receiptBad, journal); reason != "" {
		return scDecision{"deny", reason}, nil
	}
	return scDecision{"allow", "blast_radius_consistent"}, nil
}

// ---- strict reading -------------------------------------------------------

func cjReadStrict(caseDir, name string) (any, bool, error) {
	body, err := readIn(caseDir, name)
	if err != nil {
		return nil, false, fmt.Errorf("%s cannot be read: %w", name, err)
	}
	value, bad, err := cjStrict(body)
	if err != nil {
		return nil, false, fmt.Errorf("%s does not parse: %w", name, err)
	}
	return value, bad, nil
}

// cjStrict parses JSON the way the Python reader does: it reads NaN and
// Infinity, keeps the last of a repeated member, and reports, rather than
// refuses, anything outside the canonical subset.
func cjStrict(data []byte) (any, bool, error) {
	if !utf8.Valid(data) {
		return nil, false, errors.New("not UTF-8")
	}
	data, constants := cjConstants(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	repeated := false
	value, err := cjDecode(dec, &repeated)
	if err != nil {
		return nil, false, err
	}
	if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
		return nil, false, errors.New("trailing data")
	}
	return value, constants || repeated || !cjCanonical(value), nil
}

// cjConstants replaces each NaN, Infinity and -Infinity token outside a string
// with 0, which Go's decoder can read, and reports whether there was one.
func cjConstants(data []byte) ([]byte, bool) {
	out := make([]byte, 0, len(data))
	found, inString, escaped := false, false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			escaped, inString = c == '\\' && !escaped, inString && (c != '"' || escaped)
			continue
		}
		if c == '"' {
			inString = true
		}
		if token := cjConstantAt(data[i:]); token > 0 {
			out, found = append(out, '0'), true
			i += token - 1
			continue
		}
		out = append(out, c)
	}
	return out, found
}

func cjConstantAt(rest []byte) int {
	for _, token := range []string{"NaN", "Infinity", "-Infinity"} {
		if bytes.HasPrefix(rest, []byte(token)) {
			return len(token)
		}
	}
	return 0
}

func cjDecode(dec *json.Decoder, repeated *bool) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	if delim == '[' {
		list := []any{}
		for dec.More() {
			item, err := cjDecode(dec, repeated)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
		}
		_, err = dec.Token()
		return list, err
	}
	object := cjObject{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		if _, seen := object[name]; seen {
			*repeated = true
		}
		item, err := cjDecode(dec, repeated)
		if err != nil {
			return nil, err
		}
		object[name] = item
	}
	_, err = dec.Token()
	return object, err
}

func cjPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var cjLimit = new(big.Int).Lsh(big.NewInt(1), 53)

func cjCanonical(value any) bool {
	switch v := value.(type) {
	case json.Number:
		n, ok := new(big.Int).SetString(v.String(), 10)
		return ok && new(big.Int).Abs(n).Cmp(cjLimit) < 0
	case string:
		return cjPrintable(v)
	case []any:
		for _, item := range v {
			if !cjCanonical(item) {
				return false
			}
		}
	case cjObject:
		for key, item := range v {
			if !cjPrintable(key) || !cjCanonical(item) {
				return false
			}
		}
	}
	return true
}

// ---- typed access ---------------------------------------------------------

func cjInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil && !strings.ContainsAny(n.String(), ".eE")
}

func cjStr(e cjObject, name string) string { s, _ := e[name].(string); return s }

func cjBool(e cjObject, name string) bool { b, _ := e[name].(bool); return b }

func cjNum(e cjObject, name string) int64 { n, _ := cjInt(e[name]); return n }

func cjStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

type cjEdge = [2]string

func cjEdgeList(v any) []cjEdge {
	list, _ := v.([]any)
	out := make([]cjEdge, 0, len(list))
	for _, item := range list {
		pair := cjStrings(item)
		if len(pair) == 2 {
			out = append(out, cjEdge{pair[0], pair[1]})
		}
	}
	return out
}

func cjEdgeSet(v any) map[cjEdge]bool {
	set := map[cjEdge]bool{}
	for _, edge := range cjEdgeList(v) {
		set[edge] = true
	}
	return set
}

func cjListed(set map[cjEdge]bool) []cjEdge {
	out := make([]cjEdge, 0, len(set))
	for edge := range set {
		out = append(out, edge)
	}
	sort.Slice(out, func(a, b int) bool { return cjEdgeLess(out[a], out[b]) })
	return out
}

func cjEdgeLess(a, b cjEdge) bool { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]) }

func cjMinus(a, b map[cjEdge]bool) map[cjEdge]bool {
	out := map[cjEdge]bool{}
	for edge := range a {
		if !b[edge] {
			out[edge] = true
		}
	}
	return out
}

func cjSameEdges(a, b []cjEdge) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cjSameStrings(a, b []string) bool {
	return len(a) == len(b) && (len(a) == 0 || strings.Join(a, "\x00") == strings.Join(b, "\x00"))
}

func cjIsolated(agents []string, edges map[cjEdge]bool) []string {
	senders := map[string]bool{}
	for edge := range edges {
		senders[edge[0]] = true
	}
	out := []string{}
	for _, agent := range agents {
		if !senders[agent] {
			out = append(out, agent)
		}
	}
	return out
}

var (
	cjDigestShape  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	cjTimeShape    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	cjDecimalShape = regexp.MustCompile(`^[0-9]\.[0-9]{6}$`)
)

func cjAt(stamp string) (time.Time, bool) {
	if !cjTimeShape.MatchString(stamp) {
		return time.Time{}, false
	}
	at, err := time.Parse("2006-01-02T15:04:05Z", stamp)
	return at, err == nil
}

// ---- shapes ---------------------------------------------------------------

type cjAgents = map[string]bool

func cjIntIn(v any, low int64, high int64) bool {
	n, ok := cjInt(v)
	return ok && n >= low && (high < 0 || n <= high)
}

func cjSortedUnique(v []any, less func(a, b any) bool) bool {
	for i := 1; i < len(v); i++ {
		if !less(v[i-1], v[i]) {
			return false
		}
	}
	return true
}

func cjStringLess(a, b any) bool { return a.(string) < b.(string) }

func cjEdgeAnyLess(a, b any) bool {
	return cjEdgeLess(cjEdgeList([]any{a})[0], cjEdgeList([]any{b})[0])
}

func cjListing(kind string, v any, agents cjAgents) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if !cjShape(kind, item, agents) {
			return false
		}
	}
	return cjSortedUnique(list, cjStringLess)
}

func cjEdgeShape(v any, agents cjAgents) bool {
	pair, ok := v.([]any)
	if !ok || len(pair) != 2 {
		return false
	}
	from, fok := pair[0].(string)
	to, tok := pair[1].(string)
	return fok && tok && from != to && agents[from] && agents[to]
}

func cjEdgesShape(v any, agents cjAgents) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if !cjEdgeShape(item, agents) {
			return false
		}
	}
	return cjSortedUnique(list, cjEdgeAnyLess)
}

func cjEstimatesShape(v any, agents cjAgents) bool {
	object, ok := v.(cjObject)
	if !ok || len(object) != len(agents) {
		return false
	}
	for agent, value := range object {
		s, sok := value.(string)
		if !agents[agent] || !sok || !cjDecimalShape.MatchString(s) {
			return false
		}
	}
	return true
}

func cjDigestsShape(v any, agents cjAgents) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if !cjShape("digest", item, agents) {
			return false
		}
	}
	return true
}

const cjProofDepth = 64

func cjProofShape(v any, _ cjAgents) bool {
	list, ok := v.([]any)
	if !ok || len(list) > cjProofDepth {
		return false
	}
	for _, item := range list {
		step, sok := item.([]any)
		if !sok || len(step) != 2 {
			return false
		}
		if _, word := step[0].(string); !word || !cjShape("digest", step[1], nil) {
			return false
		}
	}
	return true
}

var cjShapes map[string]func(any, cjAgents) bool

func init() {
	cjShapes = map[string]func(any, cjAgents) bool{
		"bool":    func(v any, _ cjAgents) bool { _, ok := v.(bool); return ok },
		"word":    func(v any, _ cjAgents) bool { _, ok := v.(string); return ok },
		"text":    func(v any, _ cjAgents) bool { s, ok := v.(string); return ok && len(s) <= 300 },
		"count":   func(v any, _ cjAgents) bool { return cjIntIn(v, 0, -1) },
		"score":   func(v any, _ cjAgents) bool { return v == nil || cjIntIn(v, 0, 10) },
		"score10": func(v any, _ cjAgents) bool { return cjIntIn(v, 0, 10) },
		"agent":   func(v any, agents cjAgents) bool { s, ok := v.(string); return ok && agents[s] },
		"digest": func(v any, _ cjAgents) bool {
			s, ok := v.(string)
			return ok && cjDigestShape.MatchString(s)
		},
		"time": func(v any, _ cjAgents) bool {
			s, ok := v.(string)
			_, valid := cjAt(s)
			return ok && valid
		},
		"digests":   cjDigestsShape,
		"agents":    func(v any, agents cjAgents) bool { return cjListing("agent", v, agents) },
		"words":     func(v any, agents cjAgents) bool { return cjListing("word", v, agents) },
		"edges":     cjEdgesShape,
		"estimates": cjEstimatesShape,
		"proof":     cjProofShape,
	}
}

func cjShape(kind string, v any, agents cjAgents) bool { return cjShapes[kind](v, agents) }

type cjMember struct{ name, kind string }

var cjEventMembers = map[string][]cjMember{
	"topology": {{"edges", "edges"}},
	"delivery": {{"sender", "agent"}, {"receiver", "agent"}, {"bodyDigest", "digest"},
		{"edgeInForce", "bool"}, {"dropped", "bool"}},
	"decision": {{"basis", "word"}, {"responseFunction", "word"}, {"edges", "edges"},
		{"removed", "edges"}, {"added", "edges"}, {"isolated", "agents"}},
	"fallback": {{"edges", "edges"}, {"failurePosture", "word"}, {"error", "text"}},
	"restart": {{"agent", "agent"}, {"remediated", "bool"}, {"memoryCleared", "bool"},
		{"configBefore", "digest"}, {"configAfter", "digest"}},
	"assessment": {{"agent", "agent"}, {"score", "score"}, {"availability", "word"},
		{"witness", "word"}},
	"restoration": {{"agent", "agent"}, {"admitted", "bool"}, {"threshold", "score10"},
		{"evidence", "digests"}, {"ruleDigest", "digest"}},
	"response": {{"decision", "word"}, {"alertAt", "time"}, {"authority", "text"},
		{"reason", "text"}},
	"tool_call": {{"agent", "agent"}, {"tool", "text"}},
	"retrieval": {{"agent", "agent"}, {"documentDigest", "digest"}, {"admitted", "bool"},
		{"proof", "proof"}},
	"refusal": {{"sender", "agent"}, {"receiver", "agent"}, {"bodyDigest", "digest"},
		{"reasonCode", "word"}},
}

// cjToolCallOptional are the revision 1.1 members a tool call may carry;
// refusalReason is present exactly when refused is true.
var cjToolCallOptional = []cjMember{{"refused", "bool"}, {"refusalReason", "text"},
	{"grantChainDigest", "digest"}}

var cjTopOptional = []cjMember{{"componentProfileDigest", "digest"}, {"snapshotRoot", "digest"}}

var cjBaseMembers = []cjMember{{"seq", "count"}, {"prev", "digest"}, {"at", "time"}, {"event", "word"}}

var cjClaimKinds = map[string]string{"channelsClosed": "bool", "restorationGated": "bool",
	"defendedThroughout": "bool", "detectorDriven": "bool", "responseBoundSeconds": "count",
	"retrievalAttested": "bool", "authorityChainChecked": "bool"}

var cjTopMembers = []string{"agents", "claims", "contractId", "enforcement", "entries",
	"messageFields", "runId"}

func cjKeys(object cjObject) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cjMembersOK(object cjObject, members []cjMember, agents cjAgents) bool {
	for _, m := range members {
		value, present := object[m.name]
		if !present || !cjShape(m.kind, value, agents) {
			return false
		}
	}
	return true
}

func cjEntryMalformed(v any, agents cjAgents) bool {
	entry, ok := v.(cjObject)
	if !ok || !cjMembersOK(entry, cjBaseMembers, agents) {
		return true
	}
	event := cjStr(entry, "event")
	members, known := cjEventMembers[event]
	if !known {
		return false
	}
	members = append([]cjMember{}, members...)
	if event == "decision" && strings.HasPrefix(cjStr(entry, "basis"), "detector_") {
		members = append(members, cjMember{"riskEstimates", "estimates"}, cjMember{"detectorInputs", "words"})
	}
	if event == "response" && cjStr(entry, "decision") == "act" {
		members = append(members, cjMember{"actedAt", "time"})
	}
	if event == "tool_call" {
		for _, m := range cjToolCallOptional {
			if _, present := entry[m.name]; present {
				members = append(members, m)
			}
		}
		_, reason := entry["refusalReason"]
		if refused, _ := entry["refused"].(bool); reason != refused {
			return true
		}
	}
	if len(entry) != len(cjBaseMembers)+len(members) {
		return true
	}
	return !cjMembersOK(entry, members, agents)
}

func cjTopMalformed(record cjObject) bool {
	allowed := map[string]bool{}
	for _, name := range cjTopMembers {
		if _, present := record[name]; !present {
			return true
		}
		allowed[name] = true
	}
	for _, m := range cjTopOptional {
		if value, present := record[m.name]; present && !cjShape(m.kind, value, nil) {
			return true
		}
		allowed[m.name] = true
	}
	for name := range record {
		if !allowed[name] {
			return true
		}
	}
	return false
}

func cjMalformed(record cjObject) bool {
	if cjTopMalformed(record) {
		return true
	}
	list, ok := record["agents"].([]any)
	if !ok || len(list) < 2 || !cjListing("word", list, nil) {
		return true
	}
	agents := cjAgents{}
	for _, agent := range cjStrings(list) {
		agents[agent] = true
	}
	_, runOK := record["runId"].(string)
	_, enforcementOK := record["enforcement"].(string)
	claims, claimsOK := record["claims"].(cjObject)
	if !runOK || !enforcementOK || !claimsOK || !cjShape("words", record["messageFields"], agents) {
		return true
	}
	for name, value := range claims {
		kind, known := cjClaimKinds[name]
		if !known || !cjShape(kind, value, agents) {
			return true
		}
	}
	entries, ok := record["entries"].([]any)
	if !ok || len(entries) == 0 {
		return true
	}
	for _, entry := range entries {
		if cjEntryMalformed(entry, agents) {
			return true
		}
	}
	return false
}

var cjClosed = map[string][]string{
	"event": {"topology", "delivery", "decision", "fallback", "restart", "assessment",
		"restoration", "response", "tool_call", "retrieval", "refusal"},
	"basis": {"detector_online_label", "detector_no_label", "random_rate_matched",
		"ground_truth_oracle", "fixed_schedule", "evidence_gate"},
	"responseFunction": {"restriction", "isolation", "restoration"},
	"failurePosture":   {"fail_open", "fail_closed"},
	"availability":     {"scored", "no_output", "judge_missing"},
	"witness":          {"SELF", "EXTERNAL"},
	"decision":         {"act", "continue", "escalate"},
	"reasonCode":       {"budget_exhausted", "purpose_out_of_scope"},
}

var cjClosedOrder = []string{"event", "basis", "responseFunction", "failurePosture",
	"availability", "witness", "decision", "reasonCode"}

func cjIn(value any, words []string) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	for _, word := range words {
		if s == word {
			return true
		}
	}
	return false
}

func cjClosedViolation(record cjObject, entries []cjObject) bool {
	if !cjIn(record["enforcement"], []string{"advisory", "enforced"}) {
		return true
	}
	for _, entry := range entries {
		for _, member := range cjClosedOrder {
			if value, present := entry[member]; present && !cjIn(value, cjClosed[member]) {
				return true
			}
		}
		if cjProofSideViolation(entry["proof"]) {
			return true
		}
	}
	return false
}

func cjProofSideViolation(v any) bool {
	proof, _ := v.([]any)
	for _, item := range proof {
		if step := cjStrings(item); !cjIn(step[0], []string{"left", "right"}) {
			return true
		}
	}
	return false
}

// cjDigest is the digest a later entry cites: sha256 over the entry's
// canonical bytes, which for an integer-only, ASCII-only value are what
// CPython's json.dumps(sort_keys=True, separators=(",", ":")) writes.
func cjDigest(entry cjObject) string {
	data, err := pythonCompactJSON(entry)
	if err != nil {
		return ""
	}
	return "sha256:" + sha(data)
}

func cjChainFailure(entries []cjObject) string {
	for index, entry := range entries {
		if cjNum(entry, "seq") != int64(index) {
			return "chain_seq_gap"
		}
	}
	expected := cjZero
	for _, entry := range entries {
		if cjStr(entry, "prev") != expected {
			return "chain_broken"
		}
		expected = cjDigest(entry)
	}
	for i := 1; i < len(entries); i++ {
		before, _ := cjAt(cjStr(entries[i-1], "at"))
		after, _ := cjAt(cjStr(entries[i], "at"))
		if after.Before(before) {
			return "chain_time_reversed"
		}
	}
	if cjStr(entries[0], "event") != "topology" {
		return "topology_missing"
	}
	for _, entry := range entries[1:] {
		if cjStr(entry, "event") == "topology" {
			return "topology_missing"
		}
	}
	return ""
}

// cjJudgeJournal is the first rule a journal fails, or "" when it passes them all.
func cjJudgeJournal(value any, bad bool) string {
	record, ok := value.(cjObject)
	if !ok {
		return "contract_id_missing"
	}
	contract, present := record["contractId"]
	switch {
	case !present:
		return "contract_id_missing"
	case contract != cjContractID:
		return "contract_id_unknown"
	case bad:
		return "record_not_canonical"
	case cjMalformed(record):
		return "record_malformed"
	}
	entries := cjEntries(record)
	if cjClosedViolation(record, entries) {
		return "closed_vocabulary_violation"
	}
	if failure := cjChainFailure(entries); failure != "" {
		return failure
	}
	walk := newCJWalk(record, entries)
	if failure := walk.run(); failure != "" {
		return failure
	}
	return cjClaimsFailure(record, entries)
}

func cjEntries(record cjObject) []cjObject {
	list, _ := record["entries"].([]any)
	out := make([]cjObject, 0, len(list))
	for _, item := range list {
		entry, _ := item.(cjObject)
		out = append(out, entry)
	}
	return out
}

// ---- the walk -------------------------------------------------------------

type cjWalk struct {
	record     cjObject
	claims     cjObject
	agents     []string
	entries    []cjObject
	graph      map[cjEdge]bool
	isolatedAt map[string]int
	admitted   map[string][]int
	byDigest   map[string]int
}

func newCJWalk(record cjObject, entries []cjObject) *cjWalk {
	w := &cjWalk{record: record, entries: entries, agents: cjStrings(record["agents"]),
		admitted: map[string][]int{}, byDigest: map[string]int{}}
	w.claims, _ = record["claims"].(cjObject)
	w.graph = cjEdgeSet(entries[0]["edges"])
	w.isolatedAt = map[string]int{}
	for _, agent := range cjIsolated(w.agents, w.graph) {
		w.isolatedAt[agent] = 0
	}
	for index, entry := range entries {
		w.byDigest[cjDigest(entry)] = index
	}
	return w
}

func (w *cjWalk) run() string {
	for index := 1; index < len(w.entries); index++ {
		entry := w.entries[index]
		var failure string
		switch cjStr(entry, "event") {
		case "delivery":
			failure = w.delivery(entry)
		case "decision":
			failure = w.decision(index, entry)
		case "fallback":
			failure = w.fallback(index, entry)
		case "restart":
			failure = cjRestart(entry)
		case "assessment":
			failure = cjAssessment(entry)
		case "restoration":
			failure = w.restoration(index, entry)
		case "response":
			failure = w.response(entry)
		case "refusal":
			failure = w.refusal(entry)
		case "retrieval":
			failure = w.retrieval(entry)
		case "tool_call":
			failure = w.toolCall(entry)
		}
		if failure != "" {
			return failure
		}
	}
	return ""
}

func (w *cjWalk) replace(index int, edges map[cjEdge]bool) {
	w.graph = edges
	next := map[string]int{}
	for _, agent := range cjIsolated(w.agents, edges) {
		since, held := w.isolatedAt[agent]
		if !held {
			since = index
		}
		next[agent] = since
	}
	w.isolatedAt = next
}

func (w *cjWalk) delivery(entry cjObject) string {
	inForce := w.graph[cjEdge{cjStr(entry, "sender"), cjStr(entry, "receiver")}]
	dropped := cjBool(entry, "dropped")
	switch {
	case cjBool(entry, "edgeInForce") != inForce:
		return "edge_flag_mismatch"
	case dropped && inForce:
		return "drop_over_present_edge"
	case !dropped && !inForce && cjStr(w.record, "enforcement") == "enforced":
		return "delivered_over_absent_edge"
	}
	return ""
}

func (w *cjWalk) decision(index int, entry cjObject) string {
	next := cjEdgeSet(entry["edges"])
	removed, added := cjEdgeList(entry["removed"]), cjEdgeList(entry["added"])
	isolated := cjStrings(entry["isolated"])
	function := cjStr(entry, "responseFunction")
	switch {
	case !cjSameEdges(removed, cjListed(cjMinus(w.graph, next))) ||
		!cjSameEdges(added, cjListed(cjMinus(next, w.graph))):
		return "edge_delta_mismatch"
	case !cjSameStrings(isolated, cjIsolated(w.agents, next)):
		return "isolated_set_mismatch"
	case (function == "restriction" || function == "isolation") && len(added) > 0:
		return "topology_expansion_not_restriction"
	}
	if strings.HasPrefix(cjStr(entry, "basis"), "detector_") {
		if failure := w.detector(entry, len(removed) > 0 || len(isolated) > 0); failure != "" {
			return failure
		}
	}
	if function == "restoration" && cjBool(w.claims, "restorationGated") {
		if failure := w.gated(index, isolated); failure != "" {
			return failure
		}
	}
	w.replace(index, next)
	return ""
}

func (w *cjWalk) detector(entry cjObject, cuts bool) string {
	fields := map[string]bool{}
	for _, field := range cjStrings(w.record["messageFields"]) {
		fields[field] = true
	}
	for _, input := range cjStrings(entry["detectorInputs"]) {
		if !fields[input] {
			return "detector_inputs_absent"
		}
	}
	if cjUniform(entry["riskEstimates"]) && cuts {
		return "decision_not_supported_by_estimates"
	}
	return ""
}

func cjUniform(v any) bool {
	estimates, _ := v.(cjObject)
	seen := map[any]bool{}
	for _, value := range estimates {
		seen[value] = true
	}
	return len(seen) == 1
}

// gated requires, for every agent the decision returns, an admitted
// restoration later than the change that last isolated it.
func (w *cjWalk) gated(index int, isolated []string) string {
	still := map[string]bool{}
	for _, agent := range isolated {
		still[agent] = true
	}
	for agent, since := range w.isolatedAt {
		if still[agent] {
			continue
		}
		found := false
		for _, at := range w.admitted[agent] {
			found = found || (since < at && at < index)
		}
		if !found {
			return "reenable_without_restoration"
		}
	}
	return ""
}

func (w *cjWalk) fallback(index int, entry cjObject) string {
	next := cjEdgeSet(entry["edges"])
	complete := map[cjEdge]bool{}
	for _, a := range w.agents {
		for _, b := range w.agents {
			if a != b {
				complete[cjEdge{a, b}] = true
			}
		}
	}
	posture := cjStr(entry, "failurePosture")
	if cjSameEdges(cjListed(next), cjListed(complete)) && posture != "fail_open" {
		return "posture_contradicted"
	}
	if cjSameEdges(cjListed(next), cjListed(w.graph)) && posture != "fail_closed" {
		return "posture_contradicted"
	}
	w.replace(index, next)
	return ""
}

func cjRestart(entry cjObject) string {
	changed := cjStr(entry, "configBefore") != cjStr(entry, "configAfter")
	if cjBool(entry, "remediated") != changed {
		return "remediation_not_evidenced"
	}
	if !cjBool(entry, "memoryCleared") {
		return "restart_memory_not_cleared"
	}
	return ""
}

func cjAssessment(entry cjObject) string {
	scored := cjStr(entry, "availability") == "scored"
	if !scored && entry["score"] != nil {
		return "missing_score_coerced"
	}
	if scored && entry["score"] == nil {
		return "score_missing_unflagged"
	}
	return ""
}

func (w *cjWalk) restoration(index int, entry cjObject) string {
	if !cjBool(entry, "admitted") {
		return ""
	}
	evidence := cjStrings(entry["evidence"])
	if len(evidence) == 0 {
		return "restoration_without_evidence"
	}
	var cited []cjObject
	for _, item := range evidence {
		at, known := w.byDigest[item]
		if !known || at >= index {
			return "restoration_evidence_unresolved"
		}
		cited = append(cited, w.entries[at])
	}
	agent := cjStr(entry, "agent")
	if failure := cjCitedEvidence(cited, agent, cjNum(entry, "threshold")); failure != "" {
		return failure
	}
	w.admitted[agent] = append(w.admitted[agent], index)
	return ""
}

func cjCitedEvidence(cited []cjObject, agent string, threshold int64) string {
	restarted := false
	var latest cjObject
	for _, c := range cited {
		if cjStr(c, "agent") != agent {
			continue
		}
		switch cjStr(c, "event") {
		case "restart":
			restarted = true
		case "assessment":
			if latest == nil || cjNum(c, "seq") > cjNum(latest, "seq") {
				latest = c
			}
		}
	}
	switch {
	case !restarted:
		return "restoration_without_restart"
	case latest == nil:
		return "restoration_without_assessment"
	case latest["score"] == nil:
		return "restoration_evidence_not_scored"
	case cjStr(latest, "witness") == "SELF":
		return "restoration_evidence_self_witnessed"
	case cjNum(latest, "score") >= threshold:
		return "restoration_evidence_above_threshold"
	}
	return ""
}

func (w *cjWalk) response(entry cjObject) string {
	if cjStr(entry, "decision") != "act" {
		if cjStr(entry, "authority") == "" || cjStr(entry, "reason") == "" {
			return "decision_without_authority"
		}
		return ""
	}
	alert, _ := cjAt(cjStr(entry, "alertAt"))
	acted, _ := cjAt(cjStr(entry, "actedAt"))
	delay := int64(acted.Sub(alert) / time.Second)
	if delay < 0 {
		return "response_time_inverted"
	}
	if bound, present := cjInt(w.claims["responseBoundSeconds"]); present && delay > bound {
		return "response_bound_exceeded"
	}
	return ""
}

// refusal refuses a refusal recorded over an edge not in force: that message
// had no edge to cross, so the record misstates a drop as a policy refusal.
func (w *cjWalk) refusal(entry cjObject) string {
	if !w.graph[cjEdge{cjStr(entry, "sender"), cjStr(entry, "receiver")}] {
		return "refusal_over_absent_edge"
	}
	return ""
}

// retrieval refuses an admitted document whose inclusion path does not lead to
// the run's snapshotRoot, once the run names a root or claims attestation.
func (w *cjWalk) retrieval(entry cjObject) string {
	root, named := w.record["snapshotRoot"].(string)
	if !cjBool(entry, "admitted") || (!named && !cjBool(w.claims, "retrievalAttested")) {
		return ""
	}
	if !named || cjMerkleRoot(cjStr(entry, "documentDigest"), entry["proof"]) != root {
		return "retrieval_admitted_outside_snapshot"
	}
	return ""
}

// cjMerkleRoot hashes an inclusion path as RFC 9162 section 2.1 does: the leaf
// is SHA-256 over 0x00 and the document digest's 32 bytes, and each step hashes
// 0x01 with the sibling on the side the step names and the node so far.
func cjMerkleRoot(document string, proof any) string {
	leaf, _ := hex.DecodeString(strings.TrimPrefix(document, "sha256:"))
	sum := sha256.Sum256(append([]byte{0}, leaf...))
	node := sum[:]
	steps, _ := proof.([]any)
	for _, item := range steps {
		step := cjStrings(item)
		other, _ := hex.DecodeString(strings.TrimPrefix(step[1], "sha256:"))
		pair := append(append([]byte{1}, node...), other...)
		if step[0] == "left" {
			pair = append(append([]byte{1}, other...), node...)
		}
		next := sha256.Sum256(pair)
		node = next[:]
	}
	return "sha256:" + hex.EncodeToString(node)
}

// toolCall refuses a tool call that ran for an agent with no outgoing edge in
// the graph in force.
func (w *cjWalk) toolCall(entry cjObject) string {
	if !cjUnrefused(entry) {
		return ""
	}
	agent := cjStr(entry, "agent")
	for edge := range w.graph {
		if edge[0] == agent {
			return ""
		}
	}
	return "tool_call_by_isolated_agent"
}

func cjUnrefused(entry cjObject) bool {
	refused, _ := entry["refused"].(bool)
	return cjStr(entry, "event") == "tool_call" && !refused
}

func cjClaimsFailure(record cjObject, entries []cjObject) string {
	claims, _ := record["claims"].(cjObject)
	if cjBool(claims, "channelsClosed") && cjStr(record, "enforcement") == "advisory" {
		return "advisory_claimed_as_enforced"
	}
	failedOpen, informative := false, false
	for _, entry := range entries {
		event := cjStr(entry, "event")
		failedOpen = failedOpen || (event == "fallback" && cjStr(entry, "failurePosture") == "fail_open")
		if event == "decision" && strings.HasPrefix(cjStr(entry, "basis"), "detector_") &&
			!cjUniform(entry["riskEstimates"]) {
			informative = true
		}
	}
	if cjBool(claims, "defendedThroughout") && failedOpen {
		return "defended_claim_after_fail_open"
	}
	if cjBool(claims, "detectorDriven") && !informative {
		return "detector_output_uninformative"
	}
	if cjBool(claims, "authorityChainChecked") {
		for _, entry := range entries {
			if _, bound := entry["grantChainDigest"]; cjUnrefused(entry) && !bound {
				return "tool_call_authority_unbound"
			}
		}
	}
	return ""
}

// ---- the receipt ----------------------------------------------------------

type cjReach struct {
	agents     []string
	deliveries int64
	toolCalls  int64
}

func cjReachFrom(entries []cjObject, subject string, fromSeq int64) cjReach {
	tainted := map[string]bool{subject: true}
	var found cjReach
	for _, entry := range entries[fromSeq:] {
		switch cjStr(entry, "event") {
		case "delivery":
			if !cjBool(entry, "dropped") && tainted[cjStr(entry, "sender")] {
				tainted[cjStr(entry, "receiver")] = true
				found.deliveries++
			}
		case "tool_call":
			if tainted[cjStr(entry, "agent")] {
				found.toolCalls++
			}
		}
	}
	for agent := range tainted {
		if agent != subject {
			found.agents = append(found.agents, agent)
		}
	}
	sort.Strings(found.agents)
	return found
}

func cjReceiptMalformed(receipt, record cjObject) bool {
	agents := cjAgents{}
	for _, agent := range cjStrings(record["agents"]) {
		agents[agent] = true
	}
	journal, jok := receipt["journal"].(cjObject)
	reached, rok := receipt["reached"].(cjObject)
	_, runOK := journal["runId"].(string)
	switch {
	case !cjSameStrings(cjKeys(receipt), []string{"contractId", "fromSeq", "journal", "reached", "subject"}):
		return true
	case !jok || !cjSameStrings(cjKeys(journal), []string{"entries", "head", "runId"}) || !runOK ||
		!cjShape("digest", journal["head"], agents) || !cjShape("count", journal["entries"], agents):
		return true
	case !cjShape("agent", receipt["subject"], agents) || !cjShape("count", receipt["fromSeq"], agents) ||
		cjNum(receipt, "fromSeq") >= int64(len(cjEntries(record))):
		return true
	case !rok || !cjSameStrings(cjKeys(reached), []string{"agents", "deliveries", "toolCalls"}) ||
		!cjShape("agents", reached["agents"], agents):
		return true
	}
	for _, agent := range cjStrings(reached["agents"]) {
		if agent == cjStr(receipt, "subject") {
			return true
		}
	}
	return !cjShape("count", reached["deliveries"], agents) || !cjShape("count", reached["toolCalls"], agents)
}

// cjJudgeReceipt is the first rule a receipt fails against an allowed journal, or "".
func cjJudgeReceipt(value any, bad bool, record cjObject) string {
	receipt, ok := value.(cjObject)
	if !ok {
		return "receipt_contract_id_missing"
	}
	contract, present := receipt["contractId"]
	switch {
	case !present:
		return "receipt_contract_id_missing"
	case contract != cjReceiptContractID:
		return "receipt_contract_id_unknown"
	case bad || cjReceiptMalformed(receipt, record):
		return "receipt_malformed"
	}
	entries := cjEntries(record)
	journal, _ := receipt["journal"].(cjObject)
	if cjStr(journal, "runId") != cjStr(record, "runId") ||
		cjStr(journal, "head") != cjDigest(entries[len(entries)-1]) ||
		cjNum(journal, "entries") != int64(len(entries)) {
		return "receipt_journal_mismatch"
	}
	found := cjReachFrom(entries, cjStr(receipt, "subject"), cjNum(receipt, "fromSeq"))
	reached, _ := receipt["reached"].(cjObject)
	claimed := cjReach{agents: cjStrings(reached["agents"]), deliveries: cjNum(reached, "deliveries"),
		toolCalls: cjNum(reached, "toolCalls")}
	listed := map[string]bool{}
	for _, agent := range claimed.agents {
		listed[agent] = true
	}
	for _, agent := range found.agents {
		if !listed[agent] {
			return "blast_radius_understated"
		}
	}
	if claimed.deliveries < found.deliveries || claimed.toolCalls < found.toolCalls {
		return "blast_radius_understated"
	}
	if !cjSameStrings(claimed.agents, found.agents) || claimed.deliveries != found.deliveries ||
		claimed.toolCalls != found.toolCalls {
		return "blast_radius_overstated"
	}
	return ""
}

// ---- retained fields ------------------------------------------------------

// cjRetainedFinding compares what the Python reader keeps from a journal (its
// enforcement and the count of each event) with what the manifest declares.
func cjRetainedFinding(value any, declared json.RawMessage) string {
	record, _ := value.(cjObject)
	list, _ := record["entries"].([]any)
	events := map[string]any{}
	count := 0
	for _, item := range list {
		entry, ok := item.(cjObject)
		if !ok {
			continue
		}
		count++
		event, _ := entry["event"].(string)
		n, _ := events[event].(json.Number)
		next, _ := n.Int64()
		events[event] = json.Number(fmt.Sprint(next + 1))
	}
	kept := cjObject{"enforcement": record["enforcement"], "entries": json.Number(fmt.Sprint(count)),
		"events": events}
	want, err := decodeJSONNumbers(declared)
	if err != nil {
		return "retained fields: the manifest's do not parse"
	}
	got, gerr := pythonCompactJSON(kept)
	expected, eerr := pythonCompactJSON(want)
	if gerr != nil || eerr != nil || !bytes.Equal(got, expected) {
		return "retained fields: the record gives something other than the manifest declares"
	}
	return ""
}
