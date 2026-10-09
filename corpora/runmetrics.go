package corpora

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// armRejections judges a Run object of draft-arsentev-agent-run-metrics-00.
// It is the Go statement of packaging/agent_evidence_vectors/runmetrics.py:
// the same sentences, bound to the same ARM-R-nnn identifiers, in the same
// order, so the parity test can diff the two over the corpus.

var (
	armStatuses   = set("running", "completed", "failed", "aborted")
	armEnded      = set("completed", "failed", "aborted")
	armRunMembers = set("version", "run_id", "parent_run_id", "root_run_id", "start", "end", "status",
		"termination_reason", "agent", "models", "step_count", "steps", "totals",
		"subtree_totals", "cost", "labels", "errors", "revision", "trace_id")
	armIdentifiers = []string{"run_id", "parent_run_id", "root_run_id"}
	armTimestamp   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
	armAmount      = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
)

func armR(n int) string { return "ARM-R-" + pad3(n) }

func pad3(n int) string {
	s := "000" + itoa(n)
	return s[len(s)-3:]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

type armRejects map[string]bool

func (r armRejects) add(n int) { r[armR(n)] = true }

func armShapeErrors(value any) []string {
	document, ok := value.(map[string]any)
	if !ok {
		return []string{"the document is not a JSON object"}
	}
	var out []string
	for _, member := range []string{"version", "run_id", "start", "status", "step_count", "totals"} {
		if _, present := document[member]; !present {
			out = append(out, "the Run carries no "+member+" member")
		}
	}
	if raw, present := document["step_count"]; present {
		if _, isInt := intValue(raw); !isInt {
			out = append(out, "step_count is present and is not an integer")
		}
	}
	if raw, present := document["steps"]; present {
		steps, ok := raw.([]any)
		if !ok {
			out = append(out, "steps is present and is not an array")
		}
		for i, step := range steps {
			object, ok := step.(map[string]any)
			if !ok {
				out = append(out, "steps["+itoa(i)+"] is not an object")
				continue
			}
			_, indexOK := intValue(object["index"])
			if !indexOK || !isStr(object["kind"]) {
				out = append(out, "steps["+itoa(i)+"] carries no integer index or no string kind")
				continue
			}
			out = armShapeLedger(object["usage"], "steps["+itoa(i)+"].usage", out)
		}
	}
	for _, key := range []string{"totals", "subtree_totals"} {
		out = armShapeLedger(document[key], key, out)
	}
	return out
}

// armShapeLedger: a Usage object's cache_writes, when present, is an array of
// objects (section 3.5).
func armShapeLedger(value any, where string, out []string) []string {
	usage, ok := value.(map[string]any)
	if !ok {
		return out
	}
	raw, present := usage["cache_writes"]
	if !present {
		return out
	}
	writes, good := raw.([]any)
	for _, write := range writes {
		if !isObj(write) {
			good = false
		}
	}
	if !good {
		out = append(out, where+".cache_writes is present and is not a list of objects")
	}
	return out
}

func armSteps(run map[string]any) []map[string]any {
	raw, _ := run["steps"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, step := range raw {
		out = append(out, step.(map[string]any))
	}
	return out
}

func armTimestampOK(v any) bool {
	s, ok := v.(string)
	return ok && armTimestamp.MatchString(s)
}

func armRowsRunStatus(run map[string]any, out armRejects) {
	if version, _ := run["version"].(string); version != "1" {
		out.add(1)
	}
	status, _ := run["status"].(string)
	_, hasEnd := run["end"]
	switch {
	case !armStatuses[status]:
		out.add(4)
	case armEnded[status] != hasEnd:
		out.add(2)
	}
	if armTimestampOK(run["start"]) && armTimestampOK(run["end"]) {
		if run["end"].(string) < run["start"].(string) {
			out.add(3)
		}
	}
	if steps, ok := run["steps"].([]any); ok {
		if count, isInt := intValue(run["step_count"]); isInt && count < int64(len(steps)) {
			out.add(5)
		}
	}
}

func armRowsRunMembers(run map[string]any, out armRejects) {
	root, hasRoot := run["root_run_id"]
	_, hasParent := run["parent_run_id"]
	if hasRoot && !hasParent && !jsonEqual(root, run["run_id"]) {
		out.add(16)
	}
	for member := range run {
		if !armRunMembers[member] && !strings.HasPrefix(member, "x-") {
			out.add(21)
			break
		}
	}
	if raw, present := run["labels"]; present && raw != nil {
		labels, ok := raw.(map[string]any)
		if !ok {
			out.add(18)
		} else {
			for _, v := range labels {
				if !isStr(v) {
					out.add(18)
					break
				}
			}
		}
	}
	if cost, ok := run["cost"].(map[string]any); ok {
		amount, isString := cost["amount"].(string)
		if !isString || !armAmount.MatchString(amount) {
			out.add(17)
		}
	}
}

func armRowsTimestampsAndIdentifiers(run map[string]any, out armRejects) {
	stamps := []any{run["start"], run["end"]}
	for _, step := range armSteps(run) {
		stamps = append(stamps, step["start"], step["end"])
	}
	for _, s := range stamps {
		if s != nil && !armTimestampOK(s) {
			out.add(19)
			break
		}
	}
	var names []any
	for _, key := range armIdentifiers {
		if v, present := run[key]; present {
			names = append(names, v)
		}
	}
	for _, step := range armSteps(run) {
		if v, present := step["invocation_id"]; present {
			names = append(names, v)
		}
		if tool, ok := step["tool"].(map[string]any); ok {
			if v, present := tool["name"]; present {
				names = append(names, v)
			}
		}
	}
	for _, n := range names {
		s, ok := n.(string)
		if !ok || len([]rune(s)) == 0 || len([]rune(s)) > 128 {
			out.add(20)
			break
		}
	}
}

// armCounters reads a Usage object's counters as integers, reporting whether
// every one is a non-negative integer.
func armCounters(usage map[string]any) (map[string]int64, bool) {
	counters := map[string]int64{}
	for key, v := range usage {
		if key == "cache_writes" {
			continue
		}
		n, ok := intValue(v)
		if !ok || n < 0 {
			return nil, false
		}
		counters[key] = n
	}
	return counters, true
}

func armRowsUsage(value any, out armRejects) {
	usage, ok := value.(map[string]any)
	if !ok {
		return
	}
	counters, ok := armCounters(usage)
	if !ok {
		out.add(9)
		return
	}
	read, write := counters["cache_read_tokens"], counters["cache_write_tokens"]
	if input, present := counters["input_tokens"]; present {
		if read > input {
			out.add(10)
		} else if read+write > input {
			out.add(11)
		}
	}
	if output, present := counters["output_tokens"]; present && counters["reasoning_tokens"] > output {
		out.add(22)
	}
	writes, ok := usage["cache_writes"].([]any)
	if !ok {
		return
	}
	lifetimes := map[string]bool{}
	duplicate := false
	var sum int64
	counts := true
	for _, raw := range writes {
		item, _ := raw.(map[string]any)
		lifetime, _ := item["lifetime"].(string)
		if lifetimes[lifetime] {
			duplicate = true
		}
		lifetimes[lifetime] = true
		// A tokens member that is not a non-negative integer is not a count,
		// so the sum the sentence equates with cache_write_tokens does not exist.
		tokens, isInt := intValue(item["tokens"])
		if !isInt || tokens < 0 {
			counts = false
		}
		sum += tokens
	}
	if duplicate {
		out.add(13)
	}
	if !counts || sum != write {
		out.add(14)
	}
}

func armRowsSteps(run map[string]any, out armRejects) {
	steps := armSteps(run)
	if !armStepsOrdered(steps) {
		out.add(6)
	}
	invocations := map[string]bool{}
	repeated := false
	for _, step := range steps {
		armRowsStepKind(step, out)
		if id, ok := step["invocation_id"].(string); ok && step["kind"] == "model_invocation" {
			if invocations[id] {
				repeated = true
			}
			invocations[id] = true
		}
		armRowsUsage(step["usage"], out)
	}
	if repeated {
		out.add(15)
	}
}

// armStepsOrdered: indexes strictly increase and consecutive starts are both
// strings and non-decreasing, as the Python rail reads them; a lone step with
// no start is not out of order with anything.
func armStepsOrdered(steps []map[string]any) bool {
	seen := map[int64]bool{}
	ordered := true
	var previous int64
	var previousStart string
	previousOK := false
	for i, step := range steps {
		index, _ := intValue(step["index"])
		start, startOK := step["start"].(string)
		if seen[index] || (i > 0 && index < previous) {
			ordered = false
		}
		if i > 0 && (!previousOK || !startOK || previousStart > start) {
			ordered = false
		}
		seen[index] = true
		previous, previousStart, previousOK = index, start, startOK
	}
	return ordered
}

// armRowsStepKind: a model invocation carries usage and a model object; a
// tool call carries a tool object and no usage.
func armRowsStepKind(step map[string]any, out armRejects) {
	kind, _ := step["kind"].(string)
	switch kind {
	case "model_invocation":
		if !isObj(step["usage"]) || !isObj(step["model"]) {
			out.add(7)
		}
	case "tool_call":
		_, hasUsage := step["usage"]
		if !isObj(step["tool"]) || hasUsage {
			out.add(8)
		}
	}
}

func armRowsTotals(run map[string]any, out armRejects) {
	totals, totalsOK := run["totals"].(map[string]any)
	armRowsUsage(run["totals"], out)
	steps, ok := run["steps"].([]any)
	count, countOK := intValue(run["step_count"])
	if !ok || !totalsOK || !countOK || count != int64(len(steps)) {
		return
	}
	sums := map[string]int64{}
	members := map[string]bool{}
	for _, step := range armSteps(run) {
		usage, ok := step["usage"].(map[string]any)
		if !ok {
			continue
		}
		counters, ok := armCounters(usage)
		if !ok {
			return
		}
		for key, n := range counters {
			sums[key] += n
			members[key] = true
		}
	}
	for key := range totals {
		if key != "cache_writes" {
			members[key] = true
		}
	}
	keys := make([]string, 0, len(members))
	for key := range members {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !numberEquals64(totals[key], sums[key]) {
			out.add(12)
			return
		}
	}
}

// numberEquals64 is numberEquals over an int64 expectation; a missing member
// is never equal, as Python's totals.get(member) != expected reads it.
func numberEquals64(v any, want int64) bool {
	number, ok := v.(json.Number)
	if !ok {
		return false
	}
	f, err := number.Float64()
	return err == nil && f == float64(want)
}

func armRejections(document map[string]any) []string {
	out := armRejects{}
	armRowsRunStatus(document, out)
	armRowsRunMembers(document, out)
	armRowsTimestampsAndIdentifiers(document, out)
	armRowsSteps(document, out)
	armRowsTotals(document, out)
	ids := make([]string, 0, len(out))
	for id := range out {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
