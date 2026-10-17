package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The records of a done run, and the rules a reader names a refused record under.
//
// This file mirrors packaging/agent_evidence_vectors/donerecords.py rule for rule and
// code for code, and spec/predicates/done-records.md states the rules. A record is
// refused at the first rule it breaks, in the order the specification lists them, so
// the two rails give one code.

// doneObject is a decoded JSON object.
type doneObject = map[string]any

// doneError is a refused record: no verdict was reached.
type doneError struct{ code string }

func (e *doneError) Error() string { return e.code }

func refuse(code string) error { return &doneError{code} }

var (
	doneMutations = map[string]bool{"write": true, "create": true, "rename": true, "link": true,
		"unlink": true, "truncate": true, "chmod": true}
	doneHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// doneVerifierID is a URI: a scheme, a colon and at least one more character, no white space.
	doneVerifierID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$`)
	doneInstant    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	doneInt        = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	doneOrigin     = []string{"claim_id", "invocation_id", "producer", "vantage", "witness_scope"}
)

const doneMaxArtifact = 16 * 1024 * 1024

// doneStrictJSON parses UTF-8 JSON, refusing a duplicate member and a non-JSON number.
func doneStrictJSON(data []byte, record string) (any, error) {
	if !utf8.Valid(data) {
		return nil, refuse(record + "_json_invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := doneDecode(dec, record)
	if err == nil {
		if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
			err = refuse(record + "_json_invalid")
		}
	}
	if err != nil {
		var refused *doneError
		if errors.As(err, &refused) {
			return nil, err
		}
		if doneHasConstant(data) {
			return nil, refuse(record + "_json_number")
		}
		return nil, refuse(record + "_json_invalid")
	}
	return value, nil
}

func doneDecode(dec *json.Decoder, record string) (any, error) {
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
			item, err := doneDecode(dec, record)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
		}
		_, err = dec.Token()
		return list, err
	}
	object := doneObject{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		if _, seen := object[name]; seen {
			return nil, refuse(record + "_json_duplicate_key")
		}
		item, err := doneDecode(dec, record)
		if err != nil {
			return nil, err
		}
		object[name] = item
	}
	_, err = dec.Token()
	return object, err
}

// doneHasConstant reports a bare NaN or Infinity outside any string.
func doneHasConstant(data []byte) bool {
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case !inString && (bytes.HasPrefix(data[i:], []byte("NaN")) ||
			bytes.HasPrefix(data[i:], []byte("Infinity")) ||
			bytes.HasPrefix(data[i:], []byte("-Infinity"))):
			return true
		}
	}
	return false
}

func doneFields(value any, record string, required []string, optional ...string) (doneObject, error) {
	object, ok := value.(doneObject)
	if !ok {
		return nil, refuse(record + "_fields")
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed[name] = true
		if _, present := object[name]; !present {
			return nil, refuse(record + "_fields")
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return nil, refuse(record + "_fields")
		}
	}
	return object, nil
}

func doneText(value any, code string) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return "", refuse(code)
	}
	return text, nil
}

func doneDigest(value any, code string) (string, error) {
	text, ok := value.(string)
	if !ok || !doneHex64.MatchString(text) {
		return "", refuse(code)
	}
	return text, nil
}

func doneInstantOf(value any, code string) (time.Time, error) {
	text, ok := value.(string)
	if !ok || !doneInstant.MatchString(text) {
		return time.Time{}, refuse(code)
	}
	moment, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		return time.Time{}, refuse(code)
	}
	return moment, nil
}

// doneInteger returns an integer member; JSON `1.0` and `1e2` are not integers.
func doneInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || !doneInt.MatchString(number.String()) {
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil
}

func doneCount(value any, code string) (int64, error) {
	n, ok := doneInteger(value)
	if !ok || n < 0 {
		return 0, refuse(code)
	}
	return n, nil
}

func doneExit(value any, code string) (int64, error) {
	n, ok := doneInteger(value)
	if !ok || n < -255 || n > 255 {
		return 0, refuse(code)
	}
	return n, nil
}

func doneChoice(value any, code string, allowed ...string) (string, error) {
	text, ok := value.(string)
	if ok {
		for _, name := range allowed {
			if text == name {
				return text, nil
			}
		}
	}
	return "", refuse(code)
}

func doneRelPath(value any, code string) (string, error) {
	name, err := doneText(value, code)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", refuse(code)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", refuse(code)
		}
	}
	return name, nil
}

func doneArgv(value any, code string) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil, refuse(code)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil, refuse(code)
		}
		out = append(out, text)
	}
	if out[0] == "" {
		return nil, refuse(code)
	}
	return out, nil
}

func doneUnder(name, prefix string) bool {
	return name == prefix || strings.HasPrefix(name, prefix+"/")
}

// doneProtects reports whether a protected entry covers a path after its excluded names.
func doneProtects(entry doneObject, name string) bool {
	path, _ := entry["path"].(string)
	if !doneUnder(name, path) {
		return false
	}
	if name == path {
		return true
	}
	excluded := map[string]bool{}
	if list, ok := entry["exclude"].([]any); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				excluded[text] = true
			}
		}
	}
	for _, part := range strings.Split(name[len(path)+1:], "/") {
		if excluded[part] {
			return false
		}
	}
	return true
}

// doneTreeDigest is the SHA-256 of sorted "<sha256>  <path>\n" lines.
func doneTreeDigest(files map[string]string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var lines strings.Builder
	for _, name := range names {
		lines.WriteString(files[name] + "  " + name + "\n")
	}
	sum := sha256.Sum256([]byte(lines.String()))
	return hex.EncodeToString(sum[:])
}

func doneProtectedEntry(item any) (doneObject, error) {
	entry, err := doneFields(item, "contract_protected_path", []string{"path", "kind", "sha256"}, "exclude")
	if err != nil {
		return nil, err
	}
	if _, err = doneRelPath(entry["path"], "contract_protected_path_not_normalized"); err != nil {
		return nil, err
	}
	kind, err := doneChoice(entry["kind"], "contract_protected_kind", "file", "directory")
	if err != nil {
		return nil, err
	}
	if _, err = doneDigest(entry["sha256"], "contract_digest_malformed"); err != nil {
		return nil, err
	}
	if names, present := entry["exclude"]; present {
		if err = doneExclude(kind, names); err != nil {
			return nil, err
		}
	}
	return entry, nil
}

func doneExclude(kind string, value any) error {
	list, ok := value.([]any)
	if kind != "directory" || !ok || len(list) == 0 {
		return refuse("contract_exclude_invalid")
	}
	seen := map[string]bool{}
	for _, item := range list {
		name, ok := item.(string)
		if !ok || name == "" || name == "." || name == ".." || strings.Contains(name, "/") ||
			strings.ContainsRune(name, 0) || seen[name] {
			return refuse("contract_exclude_invalid")
		}
		seen[name] = true
	}
	return nil
}

func doneAcceptance(value any) error {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return refuse("contract_acceptance_empty")
	}
	seen := map[string]bool{}
	for _, item := range list {
		entry, err := doneFields(item, "contract_acceptance", []string{"id", "argv"})
		if err != nil {
			return err
		}
		name, err := doneText(entry["id"], "contract_acceptance_id")
		if err != nil {
			return err
		}
		if _, err = doneArgv(entry["argv"], "contract_acceptance_argv"); err != nil {
			return err
		}
		if seen[name] {
			return refuse("contract_acceptance_duplicate_id")
		}
		seen[name] = true
	}
	return nil
}

func doneContract(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "contract")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "contract", []string{"schema_version", "contract_id",
		"protected_paths", "acceptance", "adequacy"}, "task", "heldout_split_sha256",
		"mutant_set_sha256", "authority_sha256")
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-done-contract/v1" {
		return nil, refuse("contract_schema_unsupported")
	}
	if _, err = doneText(record["contract_id"], "contract_id"); err != nil {
		return nil, err
	}
	if task, present := record["task"]; present {
		if _, err = doneText(task, "contract_task"); err != nil {
			return nil, err
		}
	}
	for _, key := range []string{"heldout_split_sha256", "mutant_set_sha256", "authority_sha256"} {
		if v, present := record[key]; present {
			if _, err = doneDigest(v, "contract_digest_malformed"); err != nil {
				return nil, err
			}
		}
	}
	if err = doneProtectedList(record["protected_paths"]); err != nil {
		return nil, err
	}
	if err = doneAcceptance(record["acceptance"]); err != nil {
		return nil, err
	}
	return record, doneAdequacy(record["adequacy"])
}

func doneProtectedList(value any) error {
	list, ok := value.([]any)
	if !ok {
		return refuse("contract_protected_paths_type")
	}
	seen := map[string]bool{}
	for _, item := range list {
		entry, err := doneProtectedEntry(item)
		if err != nil {
			return err
		}
		path, _ := entry["path"].(string)
		if seen[path] {
			return refuse("contract_protected_duplicate")
		}
		seen[path] = true
	}
	return nil
}

func doneAdequacy(value any) error {
	adequacy, err := doneFields(value, "contract_adequacy", []string{"mutants", "killed"})
	if err != nil {
		return err
	}
	mutants, err := doneCount(adequacy["mutants"], "contract_adequacy_count")
	if err != nil {
		return err
	}
	killed, err := doneCount(adequacy["killed"], "contract_adequacy_count")
	if err != nil {
		return err
	}
	if killed > mutants {
		return refuse("contract_adequacy_overcount")
	}
	return nil
}

func doneOriginFields(record doneObject, name string) error {
	for _, key := range doneOrigin[:3] {
		if _, err := doneText(record[key], name+"_"+key); err != nil {
			return err
		}
	}
	if _, err := doneChoice(record["vantage"], name+"_vantage", "independent", "self_reported"); err != nil {
		return err
	}
	_, err := doneChoice(record["witness_scope"], name+"_witness_scope", "PEER", "EXTERNAL")
	return err
}

func doneTree(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "tree")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "tree", append([]string{"schema_version", "tree_sha256", "files"}, doneOrigin...))
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-tree/v1" {
		return nil, refuse("tree_schema_unsupported")
	}
	if err = doneOriginFields(record, "tree"); err != nil {
		return nil, err
	}
	files, ok := record["files"].(doneObject)
	if !ok {
		return nil, refuse("tree_files_type")
	}
	digests := map[string]string{}
	for name, item := range files {
		if _, err = doneRelPath(name, "tree_path_not_normalized"); err != nil {
			return nil, err
		}
		digest, err := doneDigest(item, "tree_digest_malformed")
		if err != nil {
			return nil, err
		}
		digests[name] = digest
	}
	declared, err := doneDigest(record["tree_sha256"], "tree_digest_malformed")
	if err != nil {
		return nil, err
	}
	if doneTreeDigest(digests) != declared {
		return nil, refuse("tree_digest_mismatch")
	}
	return record, nil
}

func doneScope(value any, name string) (doneObject, error) {
	found, err := doneFields(value, name+"_scope", []string{"id", "start", "end"})
	if err != nil {
		return nil, err
	}
	if _, err = doneText(found["id"], name+"_scope_id"); err != nil {
		return nil, err
	}
	start, err := doneInstantOf(found["start"], name+"_scope_instant")
	if err != nil {
		return nil, err
	}
	end, err := doneInstantOf(found["end"], name+"_scope_instant")
	if err != nil {
		return nil, err
	}
	if end.Before(start) {
		return nil, refuse(name + "_scope_order")
	}
	return found, nil
}

func doneGaps(record doneObject) error {
	coverage, err := doneChoice(record["coverage"], "observation_coverage", "complete", "incomplete", "unknown")
	if err != nil {
		return err
	}
	gaps, present := record["gaps"]
	list, _ := gaps.([]any)
	if coverage == "incomplete" {
		if _, ok := gaps.([]any); !ok || len(list) == 0 {
			return refuse("observation_gaps_required")
		}
	} else if present {
		return refuse("observation_gaps_unexpected")
	}
	scope, _ := record["scope"].(doneObject)
	start, err := doneInstantOf(scope["start"], "observation_scope_instant")
	if err != nil {
		return err
	}
	end, err := doneInstantOf(scope["end"], "observation_scope_instant")
	if err != nil {
		return err
	}
	for _, item := range list {
		gap, err := doneFields(item, "observation_gap", []string{"start", "end"})
		if err != nil {
			return err
		}
		from, err := doneInstantOf(gap["start"], "observation_gap_instant")
		if err != nil {
			return err
		}
		to, err := doneInstantOf(gap["end"], "observation_gap_instant")
		if err != nil {
			return err
		}
		if from.Before(start) || !from.Before(to) || to.After(end) {
			return refuse("observation_gap_outside_scope")
		}
	}
	return nil
}

func doneEvent(item any, execIDs map[string]bool) (doneObject, error) {
	event, err := doneFields(item, "observation_event", []string{"id", "type", "time", "step"},
		"path", "target", "argv", "exit", "origin")
	if err != nil {
		return nil, err
	}
	if _, err = doneText(event["id"], "observation_event_id"); err != nil {
		return nil, err
	}
	kind, err := doneText(event["type"], "observation_event_type")
	if err != nil {
		return nil, err
	}
	if _, err = doneCount(event["step"], "observation_step"); err != nil {
		return nil, err
	}
	if origin, present := event["origin"]; present {
		if name, ok := origin.(string); !ok || !execIDs[name] {
			return nil, refuse("observation_origin_unknown")
		}
	}
	if kind == "exec" {
		return event, doneExecEvent(event)
	}
	return event, doneFileEvent(event, kind)
}

func doneExecEvent(event doneObject) error {
	if _, err := doneArgv(event["argv"], "observation_exec_argv"); err != nil {
		return err
	}
	if v, present := event["exit"]; present {
		if _, err := doneExit(v, "observation_exec_exit"); err != nil {
			return err
		}
	}
	_, hasPath := event["path"]
	_, hasTarget := event["target"]
	if hasPath || hasTarget {
		return refuse("observation_exec_path")
	}
	return nil
}

func doneFileEvent(event doneObject, kind string) error {
	_, hasArgv := event["argv"]
	_, hasExit := event["exit"]
	if hasArgv || hasExit {
		return refuse("observation_argv_on_file_event")
	}
	_, hasPath := event["path"]
	if doneMutations[kind] && !hasPath {
		return refuse("observation_path_required")
	}
	if hasPath {
		if _, err := doneRelPath(event["path"], "observation_path_not_normalized"); err != nil {
			return err
		}
	}
	if target, present := event["target"]; present {
		if kind != "rename" && kind != "link" {
			return refuse("observation_target_unexpected")
		}
		if _, err := doneRelPath(target, "observation_path_not_normalized"); err != nil {
			return err
		}
	}
	return nil
}

func doneEvents(record doneObject) error {
	value, present := record["events"]
	if !present {
		return nil
	}
	list, ok := value.([]any)
	if !ok {
		return refuse("observation_events_type")
	}
	scope, _ := record["scope"].(doneObject)
	start, _ := doneInstantOf(scope["start"], "observation_scope_instant")
	end, _ := doneInstantOf(scope["end"], "observation_scope_instant")
	seen, execIDs := map[string]bool{}, map[string]bool{}
	previous := int64(-1)
	for _, item := range list {
		event, err := doneEvent(item, execIDs)
		if err != nil {
			return err
		}
		moment, err := doneInstantOf(event["time"], "observation_event_instant")
		if err != nil {
			return err
		}
		id, _ := event["id"].(string)
		if seen[id] || moment.Before(start) || moment.After(end) {
			return refuse("observation_event_duplicate_or_outside")
		}
		step, _ := doneInteger(event["step"])
		if step <= previous {
			return refuse("observation_steps_not_increasing")
		}
		previous = step
		seen[id] = true
		if event["type"] == "exec" {
			execIDs[id] = true
		}
	}
	return nil
}

func doneObservation(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "observation")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "observation", append([]string{"schema_version", "scope", "coverage"}, doneOrigin...), "events", "gaps")
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-observation/v2" {
		return nil, refuse("observation_schema_unsupported")
	}
	if err = doneOriginFields(record, "observation"); err != nil {
		return nil, err
	}
	if _, err = doneScope(record["scope"], "observation"); err != nil {
		return nil, err
	}
	if err = doneGaps(record); err != nil {
		return nil, err
	}
	return record, doneEvents(record)
}

func doneCapability(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "capability")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "capability", []string{"schema_version", "claim_id", "invocation_id", "producer", "visible_event_types"})
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-capabilities/v1" {
		return nil, refuse("capability_schema_unsupported")
	}
	for _, key := range doneOrigin[:3] {
		if _, err = doneText(record[key], "capability_"+key); err != nil {
			return nil, err
		}
	}
	types, ok := record["visible_event_types"].([]any)
	if !ok {
		return nil, refuse("capability_types")
	}
	seen := map[string]bool{}
	for _, item := range types {
		name, ok := item.(string)
		if !ok || name == "" {
			return nil, refuse("capability_types")
		}
		if seen[name] {
			return nil, refuse("capability_types_duplicate")
		}
		seen[name] = true
	}
	return record, nil
}

func doneGrade(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "grade")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "grade", append([]string{"schema_version", "contract_sha256", "tree_sha256", "results"}, doneOrigin...))
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-acceptance-grade/v1" {
		return nil, refuse("grade_schema_unsupported")
	}
	if err = doneOriginFields(record, "grade"); err != nil {
		return nil, err
	}
	for _, key := range []string{"contract_sha256", "tree_sha256"} {
		if _, err = doneDigest(record[key], "grade_digest_malformed"); err != nil {
			return nil, err
		}
	}
	results, ok := record["results"].([]any)
	if !ok {
		return nil, refuse("grade_results_type")
	}
	seen := map[string]bool{}
	for _, item := range results {
		entry, err := doneFields(item, "grade_result", []string{"id", "argv", "exit"})
		if err != nil {
			return nil, err
		}
		name, err := doneText(entry["id"], "grade_result_id")
		if err != nil {
			return nil, err
		}
		if _, err = doneArgv(entry["argv"], "grade_result_argv"); err != nil {
			return nil, err
		}
		if _, err = doneExit(entry["exit"], "grade_result_exit"); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, refuse("grade_result_duplicate_id")
		}
		seen[name] = true
	}
	return record, nil
}

func doneClaims(data []byte) (doneObject, error) {
	value, err := doneStrictJSON(data, "claims")
	if err != nil {
		return nil, err
	}
	record, err := doneFields(value, "claims", []string{"schema_version", "claim_id", "invocation_id", "producer", "claims"})
	if err != nil {
		return nil, err
	}
	if record["schema_version"] != "probity-tool-claims/v1" {
		return nil, refuse("claims_schema_unsupported")
	}
	for _, key := range doneOrigin[:3] {
		if _, err = doneText(record[key], "claims_"+key); err != nil {
			return nil, err
		}
	}
	list, ok := record["claims"].([]any)
	if !ok {
		return nil, refuse("claims_type")
	}
	seen := map[string]bool{}
	for _, item := range list {
		entry, err := doneFields(item, "claims_entry", []string{"id", "argv"}, "exit")
		if err != nil {
			return nil, err
		}
		name, err := doneText(entry["id"], "claims_entry_id")
		if err != nil {
			return nil, err
		}
		if _, err = doneArgv(entry["argv"], "claims_entry_argv"); err != nil {
			return nil, err
		}
		if v, present := entry["exit"]; present {
			if _, err = doneExit(v, "claims_entry_exit"); err != nil {
				return nil, err
			}
		}
		if seen[name] {
			return nil, refuse("claims_duplicate_id")
		}
		seen[name] = true
	}
	return record, nil
}

func doneIndependent(record, pin doneObject, observedParty string) bool {
	return record["vantage"] == "independent" && pin["vantage"] == "independent" &&
		record["producer"] == pin["producer"] && record["producer"] != observedParty
}

func doneScopeOf(pairs ...[2]doneObject) string {
	for _, pair := range pairs {
		if pair[0]["witness_scope"] != "EXTERNAL" || pair[1]["witness_scope"] != "EXTERNAL" {
			return "PEER"
		}
	}
	return "EXTERNAL"
}

// --- consumer case and policy ------------------------------------------------------------

// doneMemberFile reads a regular, non-link file under root; nil means absent.
func doneMemberFile(root, name, code string) ([]byte, error) {
	target := filepath.Join(root, name)
	info, err := os.Lstat(target) // #nosec G703 -- a path the corpus member names inside the directory the caller named
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > doneMaxArtifact {
		return nil, refuse(code)
	}
	return os.ReadFile(target) // #nosec G304,G703 -- a corpus member the caller named
}

func doneArtifact(root string, meta any) ([]byte, doneObject, error) {
	found, err := doneFields(meta, "case_artifact", []string{"path", "sha256", "length"})
	if err != nil {
		return nil, nil, err
	}
	rel, err := doneText(found["path"], "case_artifact_path")
	if err != nil {
		return nil, nil, err
	}
	if strings.ContainsRune(rel, 0) || strings.HasPrefix(rel, "/") {
		return nil, nil, refuse("case_artifact_path_not_normalized")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, nil, refuse("case_artifact_path_not_normalized")
		}
	}
	pinned, err := doneDigest(found["sha256"], "case_artifact_digest_malformed")
	if err != nil {
		return nil, nil, err
	}
	length, ok := doneInteger(found["length"])
	if !ok || length < 0 || length > doneMaxArtifact {
		return nil, nil, refuse("case_artifact_length")
	}
	data, err := doneMemberFile(root, rel, "case_artifact_unsafe")
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		return nil, doneObject{"status": "unavailable"}, nil
	}
	if int64(len(data)) != length || sha(data) != pinned {
		return nil, nil, refuse("case_artifact_binding_mismatch")
	}
	return data, doneObject{"status": "bound", "sha256": pinned}, nil
}

func doneWitness(caseDoc, policy doneObject, id, root string, observed bool) ([]byte, doneObject, error) {
	witnesses, _ := policy["witnesses"].(doneObject)
	raw, present := witnesses[id]
	if !present {
		return nil, nil, refuse("policy_witness_unknown")
	}
	needed := []string{"artifact", "sha256", "authority"}
	if observed {
		needed = append(needed, "producer", "vantage", "witness_scope")
	}
	pinIn, err := doneFields(raw, "policy_witness", needed)
	if err != nil {
		return nil, nil, err
	}
	artifactID, err := doneText(pinIn["artifact"], "policy_witness_artifact")
	if err != nil {
		return nil, nil, err
	}
	artifacts, _ := caseDoc["artifacts"].(doneObject)
	meta, present := artifacts[artifactID]
	if !present {
		return nil, nil, refuse("case_artifact_unknown")
	}
	pinned, err := doneDigest(pinIn["sha256"], "policy_witness_digest_malformed")
	if err != nil {
		return nil, nil, err
	}
	if _, err = doneText(pinIn["authority"], "policy_witness_authority"); err != nil {
		return nil, nil, err
	}
	data, binding, err := doneArtifact(root, meta)
	if err != nil {
		return nil, nil, err
	}
	if binding["sha256"] != pinned {
		data = nil
	}
	pin := doneObject{"artifact": artifactID, "consumer_pinned_sha256": pinned}
	if observed {
		if pin["producer"], err = doneText(pinIn["producer"], "policy_witness_producer"); err != nil {
			return nil, nil, err
		}
		if pin["vantage"], err = doneChoice(pinIn["vantage"], "policy_witness_vantage", "independent", "self_reported"); err != nil {
			return nil, nil, err
		}
		if pin["witness_scope"], err = doneChoice(pinIn["witness_scope"], "policy_witness_scope", "PEER", "EXTERNAL"); err != nil {
			return nil, nil, err
		}
	}
	return data, pin, nil
}

// doneStart validates the case and policy envelopes and returns the case's assessment.
func doneStart(caseValue, policyValue any, claimType string, assessmentFields []string) (string, doneObject, doneObject, doneObject, error) {
	caseDoc, err := doneFields(caseValue, "case", []string{"schema_version", "case_id", "artifacts"})
	if err != nil {
		return "", nil, nil, nil, err
	}
	policy, err := doneFields(policyValue, "policy", []string{"schema_version", "witnesses", "assessments"})
	if err != nil {
		return "", nil, nil, nil, err
	}
	if caseDoc["schema_version"] != "probity-case/v1" || policy["schema_version"] != "probity-policy/v1" {
		return "", nil, nil, nil, refuse("case_schema_unsupported")
	}
	caseID, err := doneText(caseDoc["case_id"], "case_id")
	if err != nil {
		return "", nil, nil, nil, err
	}
	_, artifactsOK := caseDoc["artifacts"].(doneObject)
	_, witnessesOK := policy["witnesses"].(doneObject)
	if !artifactsOK || !witnessesOK {
		return "", nil, nil, nil, refuse("case_objects")
	}
	assessments, ok := policy["assessments"].(doneObject)
	if !ok || assessments[caseID] == nil {
		return "", nil, nil, nil, refuse("policy_assessment_missing")
	}
	assessment, err := doneFields(assessments[caseID], "policy_assessment", assessmentFields)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if assessment["claim_type"] != claimType {
		return "", nil, nil, nil, refuse("policy_claim_type_unsupported")
	}
	return caseID, assessment, caseDoc, policy, nil
}

type doneBound struct {
	data []byte
	pin  doneObject
}

// doneBind binds each named witness role; true roles need producer, vantage and scope pins.
func doneBind(caseDoc, policy, assessment doneObject, root string, roles []string, observed map[string]bool) (map[string]doneBound, error) {
	ids := map[string]string{}
	seenID := map[string]bool{}
	for _, role := range roles {
		id, err := doneText(assessment[role+"_witness"], "policy_"+role+"_witness")
		if err != nil {
			return nil, err
		}
		if seenID[id] {
			return nil, refuse("policy_witness_shared")
		}
		seenID[id] = true
		ids[role] = id
	}
	out := map[string]doneBound{}
	seenArtifact := map[string]bool{}
	for _, role := range roles {
		data, pin, err := doneWitness(caseDoc, policy, ids[role], root, observed[role])
		if err != nil {
			return nil, err
		}
		artifact, _ := pin["artifact"].(string)
		if seenArtifact[artifact] {
			return nil, refuse("policy_artifact_shared")
		}
		seenArtifact[artifact] = true
		out[role] = doneBound{data, pin}
	}
	return out, nil
}
